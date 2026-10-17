"""Task creation, assignment, validated transitions and completion rules."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.enums import (
    NotificationKind,
    OperatorRole,
    PersonStatus,
    ProvisioningStatus,
    TaskStatus,
    TaskType,
)
from app.errors import InvalidTransition, PermissionDenied, ValidationFailed
from app.models import InstagramAccount, Notification, Person, TaskEvent
from tests.conftest import T0


def _manual(env, owner_id, key="manual:test-key-001", supervisor=None):
    with env.container.uow() as s:
        return env.container.tasks.create_task(
            s, task_type=TaskType.MANUAL, owner_id=owner_id, idempotency_key=key,
            context={"title": "Check the brand kit", "description": "Confirm the brand kit is complete."},
            due_at=T0 + timedelta(hours=72), supervisor_id=supervisor,
        )


def test_create_task_is_idempotent_and_notifies_owner_once(env, team):
    first, created = _manual(env, team["operator"])
    second, created_again = _manual(env, team["operator"])
    assert created and not created_again and first.id == second.id
    with env.container.uow() as s:
        notes = s.scalars(select(Notification).where(Notification.task_id == first.id)).all()
        assert [n.kind for n in notes] == [NotificationKind.ASSIGNMENT]
        assert s.scalars(select(TaskEvent).where(TaskEvent.task_id == first.id)).all()[0].event_type == "created"


def test_task_owner_must_be_active(env, team):
    with env.container.uow() as s:
        s.get(Person, team["departing"]).status = PersonStatus.DEPARTING
    with pytest.raises(ValidationFailed):
        _manual(env, team["departing"])


def test_assignment_changes_owner_and_queues_notification(env, team, account):
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    with env.container.uow() as s:
        env.container.tasks.assign(s, task.id, actor=env.actor(team["security"], OperatorRole.ADMIN), owner_id=team["operator"])
    reassigned = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    assert reassigned.owner_id == team["operator"]
    with env.container.uow() as s:
        assert s.scalar(select(Notification).where(Notification.dedupe_key == f"assignment:{task.id}:{team['operator']}"))
        assert any(e.event_type == "assigned" for e in s.scalars(select(TaskEvent).where(TaskEvent.task_id == task.id)))


def test_owner_cannot_reassign_or_cancel_own_task(env, team):
    task, _ = _manual(env, team["operator"])
    operator = env.actor(team["operator"])
    with pytest.raises(PermissionDenied):
        with env.container.uow() as s:
            env.container.tasks.cancel(s, task.id, actor=operator, reason="do not want it")
    with pytest.raises(PermissionDenied):
        with env.container.uow() as s:
            env.container.tasks.assign(s, task.id, actor=operator, owner_id=team["owner"])


def test_valid_transition_path(env, team):
    task, _ = _manual(env, team["operator"])
    operator = env.actor(team["operator"])
    tm = env.container.tasks
    with env.container.uow() as s:
        assert tm.start(s, task.id, actor=operator).status == TaskStatus.IN_PROGRESS
    with env.container.uow() as s:
        assert tm.block(s, task.id, actor=operator, reason="waiting for brand kit from marketing").status == TaskStatus.BLOCKED
    with env.container.uow() as s:
        assert tm.unblock(s, task.id, actor=operator).status == TaskStatus.IN_PROGRESS
    result = env.complete(task.id, operator, {"done": True}, evidence="brand kit checked in shared drive (test)")
    assert result.task.status == TaskStatus.COMPLETED and not result.already_completed
    with env.container.uow() as s:
        events = [e.event_type for e in s.scalars(select(TaskEvent).where(TaskEvent.task_id == task.id).order_by(TaskEvent.id))]
    assert events == ["created", "started", "blocked", "unblocked", "completed"]


def test_unblock_after_deadline_returns_to_overdue(env, team):
    task, _ = _manual(env, team["operator"])
    operator = env.actor(team["operator"])
    with env.container.uow() as s:
        env.container.tasks.block(s, task.id, actor=operator, reason="waiting on IT")
    env.clock.advance(hours=100)
    with env.container.uow() as s:
        assert env.container.tasks.unblock(s, task.id, actor=operator).status == TaskStatus.OVERDUE


def test_invalid_transitions_are_rejected(env, team):
    tm = env.container.tasks
    admin = env.actor(team["security"], OperatorRole.ADMIN)
    done, _ = _manual(env, team["operator"], key="manual:done-task-01")
    env.complete(done.id, admin, {"done": True})
    with pytest.raises(InvalidTransition):
        with env.container.uow() as s:
            tm.start(s, done.id, actor=admin)
    cancelled, _ = _manual(env, team["operator"], key="manual:cancel-task-1")
    with env.container.uow() as s:
        tm.cancel(s, cancelled.id, actor=admin, reason="not needed")
    with pytest.raises(InvalidTransition):
        env.complete(cancelled.id, admin, {"done": True})
    failed, _ = _manual(env, team["operator"], key="manual:failed-task-1")
    with env.container.uow() as s:
        tm.fail(s, failed.id, actor=admin, reason="gave up", outcome_uncertain=False)
    with pytest.raises(InvalidTransition):
        with env.container.uow() as s:
            tm.start(s, failed.id, actor=admin)
    pending, _ = _manual(env, team["operator"], key="manual:pending-task1")
    with pytest.raises(InvalidTransition):
        with env.container.uow() as s:
            tm.unblock(s, pending.id, actor=admin)


def test_completion_requires_evidence_and_valid_outcome(env, team, account):
    task = env.open_task(account, TaskType.ASSIGN_COMPANY_PHONE)
    owner = env.actor(team["owner"])
    with pytest.raises(ValidationFailed):
        env.complete(task.id, owner, {"phone_assignment_ref": "TEL-1", "phone_number": "+447700900123", "number_control": "company_controlled"}, evidence="")
    with pytest.raises(ValidationFailed) as missing:
        env.complete(task.id, owner, {"phone_assignment_ref": "TEL-1"})
    fields = {d["field"] for d in missing.value.details}
    assert {"phone_number", "number_control"} <= fields
    with pytest.raises(ValidationFailed) as unknown:
        env.complete(task.id, owner, {"phone_assignment_ref": "TEL-1", "phone_number": "+447700900123", "number_control": "company_controlled", "password": "x"})
    assert {"field": "password", "problem": "unexpected field"} in unknown.value.details
    with pytest.raises(ValidationFailed):
        env.complete(task.id, owner, {"phone_assignment_ref": "TEL-1", "phone_number": "07700 900123", "number_control": "company_controlled"})
    assert env.open_task(account, TaskType.ASSIGN_COMPANY_PHONE).status == TaskStatus.PENDING  # nothing was half-applied


def test_only_owner_supervisor_or_admin_can_complete(env, team, account):
    task = env.open_task(account, TaskType.ASSIGN_COMPANY_EMAIL)
    outcome = {"email_assignment_ref": "IT-REQ-4821", "email_address": "ig-lumenlab@testco.example", "mailbox_control": "company_controlled"}
    with pytest.raises(PermissionDenied):
        env.complete(task.id, env.actor(team["operator"]), outcome)
    result = env.complete(task.id, env.actor(team["security"]), outcome)  # owner's supervisor
    assert result.task.completed_by_id == team["security"]


def test_blocking_a_provisioning_task_blocks_the_account_and_resumes(env, team, account):
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.block(s, task.id, actor=owner, reason="Instagram shows a checkpoint on the company device")
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.BLOCKED
        assert acc.blocker_code == "TASK_BLOCKED:handle_availability_check"
        assert acc.status_before_block == ProvisioningStatus.AWAITING_HANDLE_CHECK
    with env.container.uow() as s:
        env.container.tasks.unblock(s, task.id, actor=owner, note="checkpoint cleared by account owner")
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_HANDLE_CHECK and acc.blocker_code is None


def test_api_task_endpoints(env, team, account):
    client = env.client()
    owner_headers = env.headers(team["owner"], OperatorRole.OPERATOR)
    tasks = client.get("/api/v1/tasks", params={"open_only": True, "account_id": account}, headers=owner_headers).json()
    handle_task = next(t for t in tasks if t["task_type"] == "handle_availability_check")
    detail = client.get(f"/api/v1/tasks/{handle_task['id']}", headers=owner_headers).json()
    assert {f["name"] for f in detail["completion_requirements"]["outcome_fields"]} == {"selected_handle", "checked_via"}
    assert client.post(f"/api/v1/tasks/{handle_task['id']}/start", headers=owner_headers).json()["status"] == "in_progress"
    done = client.post(
        f"/api/v1/tasks/{handle_task['id']}/complete",
        json={"outcome": {"selected_handle": "@LumenLabTestBrand", "checked_via": "instagram_app"}, "evidence_ref": "searched handle in official app (test)"},
        headers=owner_headers,
    )
    assert done.status_code == 200 and done.json()["task"]["status"] == "completed"
    assert done.json()["task"]["outcome"]["selected_handle"] == "lumenlabtestbrand"  # normalised
    missing = client.post(f"/api/v1/tasks/tsk_{'0' * 32}/complete", json={"outcome": {}, "evidence_ref": "x"}, headers=owner_headers)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"


def test_manual_task_api_requires_aware_due_date_and_key(env, team):
    client = env.client()
    headers = env.headers(team["owner"], OperatorRole.OPERATOR)
    body = {"title": "Collect brand kit", "description": "Ask marketing for the kit", "owner_id": team["operator"], "due_at": "2026-10-20T10:00:00Z", "idempotency_key": "brand-kit-0001"}
    created = client.post("/api/v1/tasks", json=body, headers=headers)
    assert created.status_code == 201 and created.json()["created"] is True
    assert client.post("/api/v1/tasks", json=body, headers=headers).json()["created"] is False
    naive = client.post("/api/v1/tasks", json={**body, "due_at": "2026-10-20T10:00:00", "idempotency_key": "brand-kit-0002"}, headers=headers)
    assert naive.status_code == 422
