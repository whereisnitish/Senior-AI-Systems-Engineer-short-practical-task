"""Reminders, overdue marking and escalation.

Throttling is based on persisted state, not on how often the scheduler runs:

* A reminder is due when ``reminder_interval`` (shorter once overdue) has passed
  since the last reminder (or since creation), up to ``max_reminders``.
* Escalation starts ``escalation_grace`` after the deadline, repeats at most every
  ``escalation_repeat`` hours, up to ``max_escalations`` levels. Level 1 goes to the
  task supervisor (or the owner's supervisor); level 2 goes one step further up
  (or to the person holding the ``escalation_default`` responsibility).
* Every notification has a dedupe key (``reminder:<task>:<n>``,
  ``escalation:<task>:<level>``), so running the cycle twice, or from two
  processes, cannot double-send.
* Blocked tasks get no owner reminders (the owner is waiting on someone else) but
  are escalated once past their deadline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clock import Clock
from app.config import Settings
from app.enums import NotificationKind, PersonStatus, Responsibility, TaskStatus
from app.logging_setup import log_event
from app.models import HumanTask, Person
from app.services.notification_service import NotificationService
from app.services.task_manager import ACTIVE_STATUSES, WORKING_STATUSES, TaskManager

logger = logging.getLogger("app.reminders")


@dataclass
class ReminderCycleResult:
    evaluated: int = 0
    marked_overdue: list[str] = field(default_factory=list)
    reminders_sent: list[str] = field(default_factory=list)
    escalations: list[str] = field(default_factory=list)
    escalation_target_missing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "evaluated": self.evaluated,
            "marked_overdue": self.marked_overdue,
            "reminders_queued": self.reminders_sent,
            "escalations_queued": self.escalations,
            "escalation_target_missing": self.escalation_target_missing,
            "note": "Notifications are queued in the outbox; see /api/v1/notifications for actual delivery status.",
        }


def find_responsible(session: Session, responsibility: Responsibility, *, exclude: set[str] | None = None) -> Person | None:
    exclude = exclude or set()
    for person in session.scalars(
        select(Person).where(Person.status == PersonStatus.ACTIVE).order_by(Person.created_at, Person.id)
    ):
        if responsibility.value in (person.responsibilities or []) and person.id not in exclude:
            return person
    return None


class ReminderService:
    def __init__(self, *, settings: Settings, clock: Clock, tasks: TaskManager, notifications: NotificationService):
        self.settings = settings
        self.clock = clock
        self.tasks = tasks
        self.notifications = notifications

    def _escalation_target(self, session: Session, task: HumanTask, level: int) -> Person | None:
        chain: list[Person] = []
        start = session.get(Person, task.supervisor_id) if task.supervisor_id else None
        if start is None:
            owner = session.get(Person, task.owner_id)
            start = owner.supervisor if owner else None
        current = start
        seen: set[str] = set()
        while current is not None and current.id not in seen and len(chain) < 5:
            seen.add(current.id)
            if current.status == PersonStatus.ACTIVE and current.id != task.owner_id:
                chain.append(current)
            current = current.supervisor
        if len(chain) >= level:
            return chain[level - 1]
        fallback = find_responsible(session, Responsibility.ESCALATION_DEFAULT, exclude={task.owner_id})
        if fallback is not None and fallback not in chain:
            return fallback
        return chain[-1] if chain else None

    def run_cycle(self, session: Session) -> ReminderCycleResult:
        now = self.clock.now()
        result = ReminderCycleResult()
        reminder_interval = timedelta(hours=self.settings.reminder_interval_hours)
        overdue_interval = timedelta(hours=self.settings.overdue_reminder_interval_hours)
        grace = timedelta(hours=self.settings.escalation_grace_hours)
        repeat = timedelta(hours=self.settings.escalation_repeat_hours)

        tasks = session.scalars(
            select(HumanTask).where(HumanTask.status.in_(list(ACTIVE_STATUSES))).order_by(HumanTask.due_at)
        ).all()
        for task in tasks:
            result.evaluated += 1
            if task.status in WORKING_STATUSES and now > task.due_at:
                self.tasks.transition(session, task, TaskStatus.OVERDUE, actor=None, event_type="marked_overdue")
                result.marked_overdue.append(task.id)

            # Owner reminders (not for blocked tasks).
            if task.status != TaskStatus.BLOCKED and task.reminder_count < self.settings.max_reminders:
                interval = overdue_interval if task.status == TaskStatus.OVERDUE else reminder_interval
                last = task.last_reminder_at or task.created_at
                if now - last >= interval:
                    number = task.reminder_count + 1
                    _, created = self.notifications.queue(
                        session,
                        recipient_id=task.owner_id,
                        kind=NotificationKind.REMINDER,
                        subject=f"[Reminder {number}] {task.title}",
                        body=(
                            f"Reminder {number}: '{task.title}' is {task.status.value.replace('_', ' ')}; "
                            f"due {task.due_at.isoformat()}.\nOpen: {self.settings.public_base_url}/dashboard/tasks/{task.id}"
                        ),
                        dedupe_key=f"reminder:{task.id}:{number}",
                        task_id=task.id,
                    )
                    task.reminder_count = number
                    task.last_reminder_at = now
                    task.updated_at = now
                    if created:
                        self.tasks.record_event(session, task, "reminder_queued", {"reminder_number": number})
                        result.reminders_sent.append(task.id)

            # Escalation for overdue or blocked-past-deadline tasks.
            past_deadline = now >= task.due_at + grace
            if past_deadline and task.escalation_count < self.settings.max_escalations:
                due_for_escalation = task.escalated_at is None or now - task.escalated_at >= repeat
                if due_for_escalation:
                    level = task.escalation_count + 1
                    target = self._escalation_target(session, task, level)
                    if target is None:
                        if task.id not in result.escalation_target_missing:
                            result.escalation_target_missing.append(task.id)
                        log_event(
                            logger,
                            "task.escalation_target_missing",
                            level=logging.WARNING,
                            account_id=task.account_id,
                            task_id=task.id,
                            action="escalate",
                            outcome="no_target",
                        )
                        continue
                    reason = f"blocked: {task.blocker_detail}" if task.status == TaskStatus.BLOCKED else "overdue"
                    owner_name = task.owner.full_name if task.owner else task.owner_id
                    _, created = self.notifications.queue(
                        session,
                        recipient_id=target.id,
                        kind=NotificationKind.ESCALATION,
                        subject=f"[Escalation L{level}] {task.title}",
                        body=(
                            f"Escalation level {level}: '{task.title}' owned by {owner_name} is {reason} "
                            f"(due {task.due_at.isoformat()}).\nOpen: {self.settings.public_base_url}/dashboard/tasks/{task.id}"
                        ),
                        dedupe_key=f"escalation:{task.id}:{level}",
                        task_id=task.id,
                    )
                    task.escalation_count = level
                    task.escalated_at = now
                    task.updated_at = now
                    if created:
                        self.tasks.record_event(
                            session, task, "escalated", {"level": level, "escalated_to": target.id, "reason": reason}
                        )
                        result.escalations.append(task.id)
                        log_event(
                            logger,
                            "task.escalated",
                            account_id=task.account_id,
                            task_id=task.id,
                            action="escalate",
                            outcome=f"level_{level}",
                            escalated_to=target.id,
                        )
        log_event(logger, "reminders.cycle_completed", action="reminder_cycle", outcome="completed", **{
            "evaluated": result.evaluated,
            "marked_overdue_count": len(result.marked_overdue),
            "reminders_count": len(result.reminders_sent),
            "escalations_count": len(result.escalations),
        })
        return result
