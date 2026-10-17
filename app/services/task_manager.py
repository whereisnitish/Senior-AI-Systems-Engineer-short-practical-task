"""Human task lifecycle: creation, assignment, validated transitions, completion.

Reliability properties:

* ``create_task`` is idempotent: a stable ``idempotency_key`` with a unique
  constraint means repeated/concurrent creation returns the existing task.
* ``complete`` locks the row (``FOR UPDATE`` on PostgreSQL; ``BEGIN IMMEDIATE`` on
  SQLite) and uses an optimistic version counter. A repeated completion returns
  the stored result with ``already_completed=True`` and triggers no side effects.
* Completion side effects (workflow advancement, downstream task creation) run in
  the same transaction as the status change, so they commit or roll back together.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.clock import Clock
from app.config import Settings
from app.enums import (
    NotificationKind,
    PersonStatus,
    TaskOrigin,
    TaskPriority,
    TaskStatus,
    TaskType,
    VerificationLabel,
)
from app.errors import InvalidTransition, NotFound, PermissionDenied, ValidationFailed
from app.logging_setup import log_event
from app.models import HumanTask, Person, TaskEvent, new_id
from app.security.authorization import Actor
from app.security.redaction import Redactor
from app.security.secret_handling import reject_secret_material
from app.services.notification_service import NotificationService
from app.services.task_types import (
    ValidatedOutcome,
    get_spec,
    render_task_text,
    validate_outcome,
)

logger = logging.getLogger("app.tasks")

ACTIVE_STATUSES = frozenset(
    {TaskStatus.PENDING, TaskStatus.IN_PROGRESS, TaskStatus.WAITING_FOR_HUMAN, TaskStatus.OVERDUE, TaskStatus.BLOCKED}
)
TERMINAL_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED})
WORKING_STATUSES = frozenset({TaskStatus.PENDING, TaskStatus.IN_PROGRESS, TaskStatus.WAITING_FOR_HUMAN})

ALLOWED_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset(
        {
            TaskStatus.IN_PROGRESS,
            TaskStatus.WAITING_FOR_HUMAN,
            TaskStatus.COMPLETED,
            TaskStatus.OVERDUE,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.IN_PROGRESS: frozenset(
        {
            TaskStatus.WAITING_FOR_HUMAN,
            TaskStatus.COMPLETED,
            TaskStatus.OVERDUE,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.WAITING_FOR_HUMAN: frozenset(
        {
            TaskStatus.IN_PROGRESS,
            TaskStatus.COMPLETED,
            TaskStatus.OVERDUE,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.OVERDUE: frozenset(
        {
            TaskStatus.IN_PROGRESS,
            TaskStatus.WAITING_FOR_HUMAN,
            TaskStatus.COMPLETED,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.BLOCKED: frozenset(
        {
            TaskStatus.PENDING,
            TaskStatus.IN_PROGRESS,
            TaskStatus.WAITING_FOR_HUMAN,
            TaskStatus.OVERDUE,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
    TaskStatus.FAILED: frozenset(),
}

CompletionHandler = Callable[[Session, HumanTask, ValidatedOutcome, Actor], None]
TransitionHook = Callable[[Session, HumanTask, TaskStatus, TaskStatus, Actor], None]
PostCompletionHook = Callable[[Session, HumanTask, Actor], None]
# Raises (e.g. PermissionDenied) to veto a completion before anything is changed.
CompletionGuard = Callable[[Session, HumanTask, Actor], None]


@dataclass
class CompletionResult:
    task: HumanTask
    already_completed: bool


class TaskManager:
    def __init__(self, *, settings: Settings, clock: Clock, redactor: Redactor, notifications: NotificationService):
        self.settings = settings
        self.clock = clock
        self.redactor = redactor
        self.notifications = notifications
        self._handlers: dict[TaskType, CompletionHandler] = {}
        self._transition_hooks: list[TransitionHook] = []
        self._post_completion_hooks: list[PostCompletionHook] = []
        self._completion_guards: list[CompletionGuard] = []

    # -- registration ----------------------------------------------------------
    def register_completion_handler(self, task_type: TaskType, handler: CompletionHandler) -> None:
        if task_type in self._handlers:
            raise RuntimeError(f"duplicate completion handler for {task_type}")
        self._handlers[task_type] = handler

    def register_transition_hook(self, hook: TransitionHook) -> None:
        self._transition_hooks.append(hook)

    def register_post_completion_hook(self, hook: PostCompletionHook) -> None:
        self._post_completion_hooks.append(hook)

    def register_completion_guard(self, guard: CompletionGuard) -> None:
        self._completion_guards.append(guard)

    # -- queries -----------------------------------------------------------------
    @staticmethod
    def get(session: Session, task_id: str) -> HumanTask:
        task = session.get(HumanTask, task_id)
        if task is None:
            raise NotFound("task not found")
        return task

    @staticmethod
    def get_for_update(session: Session, task_id: str) -> HumanTask:
        task = session.scalar(select(HumanTask).where(HumanTask.id == task_id).with_for_update())
        if task is None:
            raise NotFound("task not found")
        return task

    @staticmethod
    def find_by_key(session: Session, key: str) -> HumanTask | None:
        return session.scalar(select(HumanTask).where(HumanTask.idempotency_key == key))

    # -- creation ------------------------------------------------------------------
    def create_task(
        self,
        session: Session,
        *,
        task_type: TaskType,
        owner_id: str,
        idempotency_key: str,
        account_id: str | None = None,
        context: dict[str, Any] | None = None,
        title: str | None = None,
        description: str | None = None,
        due_at: datetime | None = None,
        priority: TaskPriority | None = None,
        supervisor_id: str | None = None,
        payload: dict[str, Any] | None = None,
        origin: TaskOrigin = TaskOrigin.PROVISIONING,
        initial_status: TaskStatus = TaskStatus.PENDING,
        actor: Actor | None = None,
    ) -> tuple[HumanTask, bool]:
        existing = self.find_by_key(session, idempotency_key)
        if existing is not None:
            return existing, False
        owner = session.get(Person, owner_id)
        if owner is None:
            raise NotFound("task owner not found")
        if owner.status != PersonStatus.ACTIVE:
            raise ValidationFailed("task owner must be an active person (not departing or offboarded)")
        spec = get_spec(task_type)
        rendered_title, rendered_description = render_task_text(task_type, context or {})
        now = self.clock.now()
        task = HumanTask(
            id=new_id("tsk"),
            task_type=task_type,
            origin=origin,
            account_id=account_id,
            title=(title or rendered_title)[:200],
            description=description or rendered_description,
            owner_id=owner_id,
            supervisor_id=supervisor_id or owner.supervisor_id,
            due_at=due_at or now + timedelta(hours=spec.due_hours),
            priority=priority or spec.priority,
            status=initial_status,
            created_at=now,
            updated_at=now,
            payload=self.redactor.redact(payload or {}),
            outcome={},
            idempotency_key=idempotency_key,
        )
        try:
            with session.begin_nested():
                session.add(task)
                session.flush()
        except IntegrityError:
            existing = self.find_by_key(session, idempotency_key)
            if existing is None:
                raise
            return existing, False
        self._record_event(session, task, "created", None, task.status, actor, {"idempotency_key": idempotency_key})
        self.notifications.queue(
            session,
            recipient_id=owner_id,
            kind=NotificationKind.ASSIGNMENT,
            subject=f"[Ops task] {task.title}",
            body=self._notification_body(task, "You have been assigned a task."),
            dedupe_key=f"assignment:{task.id}:{owner_id}",
            task_id=task.id,
        )
        log_event(
            logger,
            "task.created",
            account_id=account_id,
            task_id=task.id,
            action=f"create_{task_type.value}",
            outcome="created",
            owner_id=owner_id,
            due_at=task.due_at.isoformat(),
        )
        return task, True

    # -- authorisation ----------------------------------------------------------------
    @staticmethod
    def ensure_can_act(task: HumanTask, actor: Actor, *, allow_owner: bool = True) -> None:
        if actor.is_admin:
            return
        if actor.person_id and actor.person_id == task.supervisor_id:
            return
        if allow_owner and actor.person_id and actor.person_id == task.owner_id:
            return
        who = "the task owner, the task supervisor or an admin" if allow_owner else "the task supervisor or an admin"
        raise PermissionDenied(f"Only {who} may do this")

    # -- transitions ------------------------------------------------------------------
    def transition(
        self,
        session: Session,
        task: HumanTask,
        to_status: TaskStatus,
        *,
        actor: Actor | None,
        event_type: str = "status_changed",
        detail: dict[str, Any] | None = None,
    ) -> None:
        old = task.status
        if old == to_status:
            return
        if to_status not in ALLOWED_TRANSITIONS[old]:
            raise InvalidTransition(f"Cannot move a task from '{old.value}' to '{to_status.value}'")
        task.status = to_status
        task.updated_at = self.clock.now()
        self._record_event(session, task, event_type, old, to_status, actor, detail or {})
        for hook in self._transition_hooks:
            hook(session, task, old, to_status, actor or _system())
        log_event(
            logger,
            "task.status_changed",
            account_id=task.account_id,
            task_id=task.id,
            action=event_type,
            outcome=to_status.value,
            from_status=old.value,
        )

    def start(self, session: Session, task_id: str, *, actor: Actor) -> HumanTask:
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor)
        if task.status == TaskStatus.IN_PROGRESS:
            return task
        self.transition(session, task, TaskStatus.IN_PROGRESS, actor=actor, event_type="started")
        return task

    def block(self, session: Session, task_id: str, *, actor: Actor, reason: str) -> HumanTask:
        reject_secret_material("reason", reason)
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor)
        if task.status == TaskStatus.BLOCKED:
            return task
        task.blocker_detail = self.redactor.redact_text(reason)[:2000]
        self.transition(session, task, TaskStatus.BLOCKED, actor=actor, event_type="blocked", detail={"reason": reason})
        self._notify_blocked(session, task)
        return task

    def _blocker_recipient(self, session: Session, task: HumanTask) -> Person | None:
        """Supervisor (task, then owner's), else whoever holds escalation_default - never the owner."""
        candidates = [session.get(Person, task.supervisor_id) if task.supervisor_id else None]
        owner = session.get(Person, task.owner_id)
        candidates.append(owner.supervisor if owner else None)
        for person in candidates:
            if person is not None and person.status == PersonStatus.ACTIVE and person.id != task.owner_id:
                return person
        for person in session.scalars(select(Person).where(Person.status == PersonStatus.ACTIVE).order_by(Person.created_at)):
            if "escalation_default" in (person.responsibilities or []) and person.id != task.owner_id:
                return person
        return None

    def _notify_blocked(self, session: Session, task: HumanTask) -> None:
        """A blocker is escalated immediately - it must not wait for the original deadline."""
        recipient = self._blocker_recipient(session, task)
        if recipient is None:
            log_event(logger, "task.blocker_unrouted", level=logging.WARNING, account_id=task.account_id, task_id=task.id, action="block", outcome="no_recipient")
            return
        session.flush()
        blocked_count = len(session.scalars(select(TaskEvent.id).where(TaskEvent.task_id == task.id, TaskEvent.event_type == "blocked")).all())
        self.notifications.queue(
            session,
            recipient_id=recipient.id,
            kind=NotificationKind.ESCALATION,
            subject=f"[Blocked] {task.title}",
            body=self._notification_body(task, f"A task owned by {task.owner.full_name if task.owner else task.owner_id} is BLOCKED: {task.blocker_detail}"),
            dedupe_key=f"blocked:{task.id}:{blocked_count}",
            task_id=task.id,
        )

    def reassign_system(self, session: Session, task: HumanTask, new_owner_id: str, *, reason: str) -> HumanTask:
        """Reassignment performed by the system (e.g. the owner is being offboarded)."""
        previous = task.owner_id
        task.owner_id = new_owner_id
        if task.supervisor_id in (previous, new_owner_id):
            new_owner = session.get(Person, new_owner_id)
            task.supervisor_id = new_owner.supervisor_id if new_owner else None
        task.updated_at = self.clock.now()
        self._record_event(session, task, "reassigned", task.status, task.status, None, {"from_owner": previous, "to_owner": new_owner_id, "reason": reason})
        self.notifications.queue(
            session,
            recipient_id=new_owner_id,
            kind=NotificationKind.ASSIGNMENT,
            subject=f"[Ops task] {task.title}",
            body=self._notification_body(task, f"A task has been reassigned to you ({reason})."),
            dedupe_key=f"assignment:{task.id}:{new_owner_id}",
            task_id=task.id,
        )
        return task

    def unblock(self, session: Session, task_id: str, *, actor: Actor, note: str | None = None) -> HumanTask:
        reject_secret_material("note", note)
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor)
        if task.status != TaskStatus.BLOCKED:
            raise InvalidTransition("task is not blocked")
        target = TaskStatus.OVERDUE if self.clock.now() > task.due_at else TaskStatus.IN_PROGRESS
        task.blocker_detail = None
        self.transition(session, task, target, actor=actor, event_type="unblocked", detail={"note": note or ""})
        return task

    def fail(self, session: Session, task_id: str, *, actor: Actor, reason: str, outcome_uncertain: bool) -> HumanTask:
        reject_secret_material("reason", reason)
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor)
        if task.status == TaskStatus.FAILED:
            return task
        task.error_detail = self.redactor.redact_text(reason)[:2000]
        task.payload = {**(task.payload or {}), "outcome_uncertain": bool(outcome_uncertain)}
        self.transition(
            session,
            task,
            TaskStatus.FAILED,
            actor=actor,
            event_type="failed",
            detail={"reason": reason, "outcome_uncertain": bool(outcome_uncertain)},
        )
        return task

    def cancel(self, session: Session, task_id: str, *, actor: Actor, reason: str) -> HumanTask:
        reject_secret_material("reason", reason)
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor, allow_owner=False)
        return self.cancel_task(session, task, actor=actor, reason=reason)

    def cancel_task(self, session: Session, task: HumanTask, *, actor: Actor | None, reason: str) -> HumanTask:
        if task.status == TaskStatus.CANCELLED:
            return task
        task.error_detail = self.redactor.redact_text(reason)[:2000]
        self.transition(session, task, TaskStatus.CANCELLED, actor=actor, event_type="cancelled", detail={"reason": reason})
        return task

    def assign(
        self, session: Session, task_id: str, *, actor: Actor, owner_id: str, supervisor_id: str | None = None
    ) -> HumanTask:
        task = self.get_for_update(session, task_id)
        self.ensure_can_act(task, actor, allow_owner=False)
        if task.status in TERMINAL_STATUSES:
            raise InvalidTransition("cannot reassign a finished task")
        owner = session.get(Person, owner_id)
        if owner is None or owner.status != PersonStatus.ACTIVE:
            raise ValidationFailed("new owner must be an active person")
        if supervisor_id is not None:
            supervisor = session.get(Person, supervisor_id)
            if supervisor is None or supervisor.status != PersonStatus.ACTIVE:
                raise ValidationFailed("supervisor must be an active person")
        previous = task.owner_id
        task.owner_id = owner_id
        task.supervisor_id = supervisor_id or task.supervisor_id or owner.supervisor_id
        task.updated_at = self.clock.now()
        self._record_event(
            session, task, "assigned", task.status, task.status, actor, {"from_owner": previous, "to_owner": owner_id}
        )
        self.notifications.queue(
            session,
            recipient_id=owner_id,
            kind=NotificationKind.ASSIGNMENT,
            subject=f"[Ops task] {task.title}",
            body=self._notification_body(task, "A task has been assigned to you."),
            dedupe_key=f"assignment:{task.id}:{owner_id}",
            task_id=task.id,
        )
        log_event(logger, "task.assigned", account_id=task.account_id, task_id=task.id, action="assign", outcome="assigned")
        return task

    # -- completion -------------------------------------------------------------------
    def complete(
        self,
        session: Session,
        task_id: str,
        *,
        actor: Actor,
        outcome: dict[str, Any] | None,
        evidence_ref: str,
        note: str | None = None,
    ) -> CompletionResult:
        task = self.get_for_update(session, task_id)
        if task.status == TaskStatus.COMPLETED:
            log_event(
                logger,
                "task.completion_duplicate",
                account_id=task.account_id,
                task_id=task.id,
                action="complete",
                outcome="already_completed_no_side_effects",
            )
            return CompletionResult(task, already_completed=True)
        self.ensure_can_act(task, actor)
        for guard in self._completion_guards:
            guard(session, task, actor)
        if task.status in TERMINAL_STATUSES:
            raise InvalidTransition(f"Cannot complete a task that is '{task.status.value}'")
        evidence_ref = (evidence_ref or "").strip()
        if len(evidence_ref) < 3:
            raise ValidationFailed(
                "evidence_ref is required: give a reference to what you observed (ticket ID, vault reference, "
                "or a short description). Never attach secrets."
            )
        if len(evidence_ref) > 300:
            raise ValidationFailed("evidence_ref must be at most 300 characters")
        reject_secret_material("evidence_ref", evidence_ref)
        reject_secret_material("note", note)
        if note and len(note) > 2000:
            raise ValidationFailed("note must be at most 2000 characters")
        validated = validate_outcome(
            task.task_type, outcome, allowed_vault_schemes=self.settings.allowed_vault_schemes
        )
        old = task.status
        if TaskStatus.COMPLETED not in ALLOWED_TRANSITIONS[old]:
            raise InvalidTransition(f"Cannot complete a task that is '{old.value}'")
        now = self.clock.now()
        task.status = TaskStatus.COMPLETED
        task.completed_at = now
        task.completed_by_id = actor.person_id
        task.completion_evidence_ref = evidence_ref
        task.completion_note = note
        task.verification_source = VerificationLabel.HUMAN_CONFIRMED
        task.outcome = validated.stored
        task.updated_at = now
        handler = self._handlers.get(task.task_type)
        if handler is not None:
            handler(session, task, validated, actor)
        self._record_event(
            session,
            task,
            "completed",
            old,
            TaskStatus.COMPLETED,
            actor,
            {"evidence_ref": evidence_ref, "verification": task.verification_source.value},
        )
        for hook in self._transition_hooks:
            hook(session, task, old, TaskStatus.COMPLETED, actor)
        for post_hook in self._post_completion_hooks:
            post_hook(session, task, actor)
        session.flush()
        log_event(
            logger,
            "task.completed",
            account_id=task.account_id,
            task_id=task.id,
            action=f"complete_{task.task_type.value}",
            outcome="completed",
            verification_source=task.verification_source.value,
            evidence_ref=evidence_ref,
        )
        return CompletionResult(task, already_completed=False)

    # -- helpers --------------------------------------------------------------------------
    def _record_event(
        self,
        session: Session,
        task: HumanTask,
        event_type: str,
        from_status: TaskStatus | None,
        to_status: TaskStatus | None,
        actor: Actor | None,
        detail: dict[str, Any],
    ) -> None:
        session.add(
            TaskEvent(
                task_id=task.id,
                event_type=event_type,
                from_status=from_status.value if from_status else None,
                to_status=to_status.value if to_status else None,
                actor_id=actor.audit_id if actor else "system",
                detail=self.redactor.redact(detail),
                created_at=self.clock.now(),
            )
        )

    def record_event(self, session: Session, task: HumanTask, event_type: str, detail: dict[str, Any]) -> None:
        self._record_event(session, task, event_type, task.status, task.status, None, detail)

    def _notification_body(self, task: HumanTask, lead: str) -> str:
        return (
            f"{lead}\n\nTask: {task.title}\nDue: {task.due_at.isoformat()}\nPriority: {task.priority.value}\n"
            f"Open: {self.settings.public_base_url}/dashboard/tasks/{task.id}\n\n"
            "Never reply with passwords, codes or backup codes. Store secrets in the vault and record the reference."
        )


def _system() -> Actor:
    from app.security.authorization import SYSTEM_ACTOR

    return SYSTEM_ACTOR
