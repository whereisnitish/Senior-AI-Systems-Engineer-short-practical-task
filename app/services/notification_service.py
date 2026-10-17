"""Notification outbox with exactly-once queuing and honest delivery states.

* Queuing is idempotent through ``dedupe_key`` (e.g. ``reminder:<task>:3``).
* Dispatch is a three-phase protocol: mark ``sending`` (commit) -> call provider
  outside any DB transaction -> record the result. A crash between phases leaves
  ``sending``, which startup recovery turns into ``uncertain`` (never auto-resent).
* With no provider configured, notifications become ``not_delivered_no_provider``
  and are shown on the dashboard. They are dispatched automatically once a
  provider is configured.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.clock import Clock
from app.config import Settings
from app.database import session_scope
from app.enums import DeliveryStatus, NotificationKind, TaskStatus
from app.integrations.notifications.base import Notifier, SendResult
from app.logging_setup import log_event
from app.models import HumanTask, Notification, new_id
from app.reliability import RetryPolicy
from app.security.redaction import Redactor

logger = logging.getLogger("app.notifications")
# Mirrors task_manager.TERMINAL_STATUSES (not imported: task_manager depends on this module).
_CLOSED_TASK_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED})


@dataclass
class DispatchSummary:
    sent: int = 0
    not_delivered_no_provider: int = 0
    failed: int = 0
    retry_scheduled: int = 0
    uncertain: int = 0
    superseded: int = 0
    notification_ids: list[str] = field(default_factory=list)


class NotificationService:
    def __init__(self, *, settings: Settings, clock: Clock, notifier: Notifier, redactor: Redactor):
        self.settings = settings
        self.clock = clock
        self.notifier = notifier
        self.redactor = redactor
        self._policy = RetryPolicy(max_attempts=max(1, min(settings.notification_max_attempts, 10)), base_delay=60, max_delay=1800)
        self._rng = random.Random()

    def queue(
        self,
        session: Session,
        *,
        recipient_id: str,
        kind: NotificationKind,
        subject: str,
        body: str,
        dedupe_key: str,
        task_id: str | None = None,
    ) -> tuple[Notification, bool]:
        existing = session.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
        if existing is not None:
            return existing, False
        now = self.clock.now()
        notification = Notification(
            id=new_id("ntf"),
            task_id=task_id,
            recipient_id=recipient_id,
            kind=kind,
            channel="email",
            # No CR/LF in subjects: they become email headers (header injection / ValueError).
            subject=self.redactor.redact_text(" ".join(subject.split()))[:200],
            body=self.redactor.redact_text(body),
            delivery_status=DeliveryStatus.PENDING,
            dedupe_key=dedupe_key,
            attempt_count=0,
            next_attempt_at=now,
            created_at=now,
        )
        try:
            with session.begin_nested():
                session.add(notification)
                session.flush()
        except IntegrityError:
            existing = session.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
            if existing is None:
                raise
            return existing, False
        log_event(
            logger,
            "notification.queued",
            task_id=task_id,
            action=f"queue_{kind.value}",
            outcome="queued",
            notification_id=notification.id,
            recipient_id=recipient_id,
        )
        return notification, True

    def dispatch_pending(self, factory: sessionmaker[Session], *, limit: int = 100) -> DispatchSummary:
        summary = DispatchSummary()
        now = self.clock.now()
        statuses = [DeliveryStatus.PENDING]
        if self.notifier.configured:
            statuses.append(DeliveryStatus.NOT_DELIVERED_NO_PROVIDER)
        with session_scope(factory) as session:
            ids = session.scalars(
                select(Notification.id)
                .where(
                    Notification.delivery_status.in_(statuses),
                    or_(Notification.next_attempt_at.is_(None), Notification.next_attempt_at <= now),
                )
                .order_by(Notification.created_at)
                .limit(limit)
            ).all()
        for notification_id in ids:
            summary.notification_ids.append(notification_id)
            if self._supersede_if_task_closed(factory, notification_id, statuses):
                summary.superseded += 1
                continue
            if not self.notifier.configured:
                with session_scope(factory) as session:
                    n = session.get(Notification, notification_id)
                    if n is not None and n.delivery_status == DeliveryStatus.PENDING:
                        n.delivery_status = DeliveryStatus.NOT_DELIVERED_NO_PROVIDER
                        n.last_error = "No notification provider configured; shown on dashboard only (not delivered)"
                        summary.not_delivered_no_provider += 1
                        log_event(
                            logger,
                            "notification.not_delivered",
                            level=logging.WARNING,
                            task_id=n.task_id,
                            action="dispatch",
                            outcome="not_delivered_no_provider",
                            notification_id=n.id,
                        )
                continue
            # Phase 1: claim the notification atomically (conditional UPDATE: only one dispatcher wins).
            with session_scope(factory) as session:
                claimed = session.execute(
                    update(Notification)
                    .where(Notification.id == notification_id, Notification.delivery_status.in_(statuses))
                    .values(delivery_status=DeliveryStatus.SENDING, attempt_count=Notification.attempt_count + 1)
                    .execution_options(synchronize_session=False)
                ).rowcount
                if claimed != 1:
                    continue
                n = session.get(Notification, notification_id)
                session.refresh(n)
                to_email, subject, body, attempt = n.recipient.email, n.subject, n.body, n.attempt_count
            # Phase 2: talk to the provider outside any transaction.
            try:
                result = self.notifier.send(to_email=to_email, subject=subject, body=body)
            except Exception as exc:  # noqa: BLE001 - one bad message must not abort the batch
                # Raised inside our adapter before or while sending: we cannot tell whether it went out.
                result = SendResult("uncertain", f"notifier raised {type(exc).__name__}")
            # Phase 3: record the outcome.
            with session_scope(factory) as session:
                n = session.get(Notification, notification_id)
                assert n is not None
                n.last_error = self.redactor.redact_text(result.detail) if result.status != "sent" else None
                if result.status == "sent":
                    n.delivery_status = DeliveryStatus.SENT
                    n.sent_at = self.clock.now()
                    summary.sent += 1
                elif result.status == "uncertain":
                    n.delivery_status = DeliveryStatus.UNCERTAIN
                    summary.uncertain += 1
                elif result.retryable and attempt < self._policy.max_attempts:
                    n.delivery_status = DeliveryStatus.PENDING
                    n.next_attempt_at = self.clock.now() + timedelta(seconds=self._policy.delay_for(attempt, self._rng))
                    summary.retry_scheduled += 1
                else:
                    n.delivery_status = DeliveryStatus.FAILED
                    summary.failed += 1
                log_event(
                    logger,
                    "notification.dispatched",
                    level=logging.INFO if result.status == "sent" else logging.WARNING,
                    task_id=n.task_id,
                    action="dispatch",
                    outcome=n.delivery_status.value,
                    retry_count=attempt - 1,
                    notification_id=n.id,
                    error=n.last_error,
                )
        return summary

    def _supersede_if_task_closed(self, factory: sessionmaker[Session], notification_id: str, statuses: list[DeliveryStatus]) -> bool:
        """A backlog (e.g. queued before a provider existed) must not announce work that is already finished."""
        with session_scope(factory) as session:
            n = session.get(Notification, notification_id)
            if n is None or n.task_id is None or n.delivery_status not in statuses:
                return False
            task = session.get(HumanTask, n.task_id)
            if task is None or task.status not in _CLOSED_TASK_STATUSES:
                return False
            n.delivery_status = DeliveryStatus.SUPERSEDED
            n.last_error = f"Not sent: the task was already {task.status.value} when this {n.kind.value} was dispatched"
            log_event(
                logger, "notification.superseded", task_id=n.task_id, action="dispatch", outcome="superseded",
                notification_id=n.id, task_status=task.status.value,
            )
            return True

    def requeue(self, session: Session, notification_id: str) -> Notification:
        """Explicit human decision to resend an uncertain/failed notification."""
        from app.errors import Conflict, NotFound

        n = session.get(Notification, notification_id)
        if n is None:
            raise NotFound("notification not found")
        if n.delivery_status not in (DeliveryStatus.UNCERTAIN, DeliveryStatus.FAILED):
            raise Conflict(f"only uncertain or failed notifications can be requeued (status is {n.delivery_status.value})")
        n.delivery_status = DeliveryStatus.PENDING
        n.next_attempt_at = self.clock.now()
        return n
