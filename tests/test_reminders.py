"""Reminder throttling, overdue escalation and honest notification delivery states."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.enums import (
    DeliveryStatus,
    NotificationKind,
    OperatorRole,
    TaskStatus,
    TaskType,
)
from app.integrations.notifications.base import Notifier, SendResult
from app.models import HumanTask, Notification
from tests.conftest import T0, Env


def _task(env: Env, owner: str, *, due_hours: float = 72, key: str = "manual:reminder-01", supervisor: str | None = None) -> str:
    with env.container.uow() as s:
        task, _ = env.container.tasks.create_task(
            s, task_type=TaskType.MANUAL, owner_id=owner, idempotency_key=key,
            context={"title": "Reminder test task", "description": "test"}, due_at=T0 + timedelta(hours=due_hours),
            supervisor_id=supervisor,
        )
        return task.id


def _cycle(env: Env):
    with env.container.uow() as s:
        return env.container.reminders.run_cycle(s)


def _notes(env: Env, task_id: str, kind: NotificationKind) -> list[Notification]:
    with env.container.uow() as s:
        return list(s.scalars(select(Notification).where(Notification.task_id == task_id, Notification.kind == kind).order_by(Notification.created_at)))


def _get(env: Env, task_id: str) -> HumanTask:
    with env.container.uow() as s:
        return s.get(HumanTask, task_id)


def test_reminders_are_throttled_by_persisted_interval(env, team):
    task_id = _task(env, team["operator"])
    env.clock.advance(hours=12)
    assert _cycle(env).reminders_sent == []
    env.clock.advance(hours=12)  # 24h after creation
    assert _cycle(env).reminders_sent == [task_id]
    assert _cycle(env).reminders_sent == []  # same instant: no repeat
    env.clock.advance(hours=12)
    assert _cycle(env).reminders_sent == []  # only 12h since the last reminder
    env.clock.advance(hours=12)
    assert _cycle(env).reminders_sent == [task_id]
    task = _get(env, task_id)
    assert task.reminder_count == 2 and task.last_reminder_at == T0 + timedelta(hours=48)
    assert [n.dedupe_key for n in _notes(env, task_id, NotificationKind.REMINDER)] == [f"reminder:{task_id}:1", f"reminder:{task_id}:2"]


def test_overdue_escalation_levels_and_cap(env, team):
    task_id = _task(env, team["operator"])  # operator -> supervisor Sam (owner) -> Morgan (security)
    env.clock.set(T0 + timedelta(hours=73))
    result = _cycle(env)
    assert result.marked_overdue == [task_id] and result.escalations == [task_id]
    task = _get(env, task_id)
    assert task.status == TaskStatus.OVERDUE and task.escalation_count == 1
    level1 = _notes(env, task_id, NotificationKind.ESCALATION)
    assert [n.recipient_id for n in level1] == [team["owner"]]
    env.clock.advance(hours=1)
    assert _cycle(env).escalations == []  # repeat interval not reached
    env.clock.advance(hours=24)
    assert _cycle(env).escalations == [task_id]
    level2 = _notes(env, task_id, NotificationKind.ESCALATION)
    assert [n.recipient_id for n in level2] == [team["owner"], team["security"]]
    env.clock.advance(hours=48)
    assert _cycle(env).escalations == []  # MAX_ESCALATIONS=2
    assert _get(env, task_id).escalation_count == 2


def test_max_reminders_cap(tmp_path):
    env = Env(tmp_path, max_reminders=2)
    owner = env.person("Owner One")
    task_id = _task(env, owner, due_hours=1000)
    for _ in range(6):
        env.clock.advance(hours=25)
        _cycle(env)
    assert _get(env, task_id).reminder_count == 2
    env.container.engine.dispose()


def test_blocked_task_is_escalated_but_owner_not_reminded(env, team):
    task_id = _task(env, team["operator"], due_hours=10)
    with env.container.uow() as s:
        env.container.tasks.block(s, task_id, actor=env.actor(team["operator"]), reason="waiting on IT for the alias")
    immediate = _notes(env, task_id, NotificationKind.ESCALATION)
    assert len(immediate) == 1 and immediate[0].recipient_id == team["owner"]  # supervisor told at once, not at the deadline
    assert immediate[0].dedupe_key == f"blocked:{task_id}:1"
    env.clock.advance(hours=30)
    result = _cycle(env)
    assert result.reminders_sent == [] and result.escalations == [task_id]
    escalations = _notes(env, task_id, NotificationKind.ESCALATION)
    assert len(escalations) == 2 and "blocked: waiting on IT" in escalations[1].body
    assert _get(env, task_id).status == TaskStatus.BLOCKED


def test_missing_escalation_target_is_reported(tmp_path):
    env = Env(tmp_path)
    loner = env.person("No Supervisor")
    task_id = _task(env, loner, due_hours=1)
    env.clock.advance(hours=2)
    result = _cycle(env)
    assert result.escalation_target_missing == [task_id] and result.escalations == []
    assert "task.escalation_target_missing" in env.read_logs()
    env.container.engine.dispose()


def test_escalation_falls_back_to_escalation_default(tmp_path):
    env = Env(tmp_path)
    loner = env.person("No Supervisor")
    fallback = env.person("Duty Manager", responsibilities=("escalation_default",))
    task_id = _task(env, loner, due_hours=1)
    env.clock.advance(hours=2)
    assert _cycle(env).escalations == [task_id]
    assert _notes(env, task_id, NotificationKind.ESCALATION)[0].recipient_id == fallback
    env.container.engine.dispose()


def test_without_provider_notifications_are_marked_not_delivered(env, team):
    task_id = _task(env, team["operator"])
    summary = env.container.notifications.dispatch_pending(env.container.session_factory)
    assert summary.not_delivered_no_provider == 1 and summary.sent == 0
    note = _notes(env, task_id, NotificationKind.ASSIGNMENT)[0]
    assert note.delivery_status == DeliveryStatus.NOT_DELIVERED_NO_PROVIDER
    assert "notification.not_delivered" in env.read_logs()


class ScriptedNotifier(Notifier):
    name = "scripted"
    configured = True

    def __init__(self, results: list[SendResult]):
        self.results = list(results)
        self.sent: list[str] = []

    def send(self, *, to_email: str, subject: str, body: str) -> SendResult:
        self.sent.append(subject)
        return self.results.pop(0) if self.results else SendResult("sent")


def test_retryable_failure_is_retried_with_backoff_then_sent(env, team):
    notifier = ScriptedNotifier([SendResult("failed", "relay busy", retryable=True)])
    env.container.notifications.notifier = notifier
    task_id = _task(env, team["operator"])
    summary = env.container.notifications.dispatch_pending(env.container.session_factory)
    assert summary.retry_scheduled == 1
    note = _notes(env, task_id, NotificationKind.ASSIGNMENT)[0]
    assert note.delivery_status == DeliveryStatus.PENDING and note.next_attempt_at > T0
    assert env.container.notifications.dispatch_pending(env.container.session_factory).sent == 0  # backoff respected
    env.clock.advance(hours=1)
    assert env.container.notifications.dispatch_pending(env.container.session_factory).sent == 1
    assert _notes(env, task_id, NotificationKind.ASSIGNMENT)[0].delivery_status == DeliveryStatus.SENT


def test_uncertain_send_is_never_auto_resent(env, team):
    notifier = ScriptedNotifier([SendResult("uncertain", "connection dropped during DATA")])
    env.container.notifications.notifier = notifier
    task_id = _task(env, team["operator"])
    env.container.notifications.dispatch_pending(env.container.session_factory)
    env.clock.advance(hours=5)
    env.container.notifications.dispatch_pending(env.container.session_factory)
    assert len(notifier.sent) == 1
    note = _notes(env, task_id, NotificationKind.ASSIGNMENT)[0]
    assert note.delivery_status == DeliveryStatus.UNCERTAIN
    with env.container.uow() as s:
        env.container.notifications.requeue(s, note.id)  # explicit human decision
    env.container.notifications.dispatch_pending(env.container.session_factory)
    assert len(notifier.sent) == 2


def test_previously_undelivered_are_sent_once_provider_configured(env, team):
    task_id = _task(env, team["operator"])
    env.container.notifications.dispatch_pending(env.container.session_factory)
    env.container.notifications.notifier = ScriptedNotifier([])
    assert env.container.notifications.dispatch_pending(env.container.session_factory).sent == 1
    assert _notes(env, task_id, NotificationKind.ASSIGNMENT)[0].delivery_status == DeliveryStatus.SENT


def test_reminder_api_requires_permission_and_reports_delivery(env, team, account):
    client = env.client()
    assert client.post("/api/v1/tasks/reminders/run", headers=env.headers(team["owner"], OperatorRole.VIEWER)).status_code == 403
    env.clock.advance(hours=25)
    body = client.post("/api/v1/tasks/reminders/run", headers=env.headers(team["owner"], OperatorRole.OPERATOR)).json()
    assert len(body["reminders_queued"]) == 3 and len(body["escalations_queued"]) == 3
    assert body["dispatch"]["not_delivered_no_provider"] >= 6 and body["dispatch"]["sent"] == 0
    overdue = client.get("/api/v1/tasks/overdue", headers=env.headers(team["owner"], OperatorRole.VIEWER)).json()
    assert len(overdue) == 3 and all(t["is_overdue"] for t in overdue)
