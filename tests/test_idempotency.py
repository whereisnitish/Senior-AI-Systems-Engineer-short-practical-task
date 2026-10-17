"""Idempotency, concurrency, restart persistence and safe handling of uncertain outcomes."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.container import build_container
from app.enums import (
    AuditRunStatus,
    AuditTrigger,
    DeliveryStatus,
    NotificationKind,
    OperatorRole,
    ProvisioningStatus,
    StepState,
    TaskStatus,
    TaskType,
)
from app.errors import Conflict, DomainError
from app.models import (
    AuditRun,
    HumanTask,
    InstagramAccount,
    Notification,
    TaskEvent,
    new_id,
)
from app.services.recovery import run_startup_recovery
from tests.conftest import OUTCOMES, PASSWORD_REF, T0


def _to_signup(env, team, account):
    env.seed_vault()
    owner = env.actor(team["owner"], OperatorRole.ADMIN)
    for task_type in (TaskType.HANDLE_AVAILABILITY_CHECK, TaskType.ASSIGN_COMPANY_EMAIL, TaskType.ASSIGN_COMPANY_PHONE):
        env.complete_type(account, task_type, owner)
    return env.open_task(account, TaskType.ACCOUNT_SIGNUP)


def test_duplicate_completion_has_no_side_effects(env, team, account):
    owner = env.actor(team["owner"])
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    first = env.complete(task.id, owner, OUTCOMES[TaskType.HANDLE_AVAILABILITY_CHECK])
    count = len(env.tasks(account))
    second = env.complete(task.id, owner, {"selected_handle": "somethingelse", "checked_via": "instagram_app"})
    assert not first.already_completed and second.already_completed
    assert second.task.outcome["selected_handle"] == "lumenlabtestbrand"  # original result kept
    assert len(env.tasks(account)) == count
    with env.container.uow() as s:
        completed_events = s.scalar(select(func.count(TaskEvent.id)).where(TaskEvent.task_id == task.id, TaskEvent.event_type == "completed"))
    assert completed_events == 1


def test_api_duplicate_completion_returns_flag(env, team, account):
    signup = _to_signup(env, team, account)
    client = env.client()
    headers = env.headers(team["owner"], OperatorRole.OPERATOR)
    body = {"outcome": OUTCOMES[TaskType.ACCOUNT_SIGNUP], "evidence_ref": "profile visible while logged in (test)"}
    first = client.post(f"/api/v1/tasks/{signup.id}/complete", json=body, headers=headers)
    second = client.post(f"/api/v1/tasks/{signup.id}/complete", json=body, headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json()["already_completed"] is False and second.json()["already_completed"] is True
    assert len(env.tasks(account, TaskType.ACCOUNT_VERIFICATION)) == 1
    assert len(env.tasks(account, TaskType.ACCOUNT_SIGNUP)) == 1


def test_repeated_advance_creates_no_duplicate_tasks(env, team, account):
    before = [t.id for t in env.tasks(account)]
    for _ in range(5):
        with env.container.uow() as s:
            env.container.provisioning.advance(s, s.get(InstagramAccount, account))
    assert [t.id for t in env.tasks(account)] == before


def test_concurrent_completion_creates_exactly_one_downstream_task(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"], OperatorRole.ADMIN)
    barrier = threading.Barrier(4)
    results, errors = [], []

    def worker() -> None:
        barrier.wait()
        try:
            results.append(env.complete(signup.id, owner, OUTCOMES[TaskType.ACCOUNT_SIGNUP]))
        except (DomainError, Exception) as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert sum(not r.already_completed for r in results) == 1
    assert sum(r.already_completed for r in results) == 3
    assert len(env.tasks(account, TaskType.ACCOUNT_VERIFICATION)) == 1


def test_brand_key_unique_constraint_backstops_duplicates(env, team, account):
    with pytest.raises(IntegrityError):
        with env.container.uow() as s:
            s.add(InstagramAccount(id=new_id("acc"), brand_name="dup", brand_key="lumen-lab-test-brand", owner_id=team["owner"], created_at=T0, updated_at=T0))
            s.flush()


def test_failed_signup_with_uncertain_outcome_requires_reconciliation(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.fail(s, signup.id, actor=owner, reason="browser crashed after submitting the signup form", outcome_uncertain=True)
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_RECONCILIATION
        assert acc.signup_attempt == 1
    recon = env.open_task(account, TaskType.SIGNUP_RECONCILIATION)
    assert recon.status == TaskStatus.WAITING_FOR_HUMAN
    assert "outcome uncertain" in recon.description and "Nobody may sign up again" in recon.description
    assert len(env.tasks(account, TaskType.ACCOUNT_SIGNUP)) == 1  # no blind retry
    for _ in range(3):  # restarts / repeated evaluation never create a second signup
        with env.container.uow() as s:
            env.container.provisioning.advance(s, s.get(InstagramAccount, account))
    assert len(env.tasks(account, TaskType.ACCOUNT_SIGNUP)) == 1
    assert len(env.tasks(account, TaskType.SIGNUP_RECONCILIATION)) == 1


def test_reconciliation_does_not_exist_creates_next_attempt(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.fail(s, signup.id, actor=owner, reason="signup form errored", outcome_uncertain=True)
    env.complete_type(account, TaskType.SIGNUP_RECONCILIATION, owner, {"external_account_state": "does_not_exist"})
    signups = env.tasks(account, TaskType.ACCOUNT_SIGNUP)
    assert len(signups) == 2
    second = next(t for t in signups if t.idempotency_key.endswith(":account_signup:a2"))
    assert "attempt 2" in second.title and second.status == TaskStatus.PENDING
    with env.container.uow() as s:
        assert s.get(InstagramAccount, account).signup_attempt == 2


def test_reconciliation_exists_controlled_resumes_without_second_signup(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.fail(s, signup.id, actor=owner, reason="network dropped at the last step", outcome_uncertain=True)
    env.complete_type(
        account, TaskType.SIGNUP_RECONCILIATION, owner,
        {"external_account_state": "exists_controlled", "password_vault_ref": PASSWORD_REF},
    )
    assert len(env.tasks(account, TaskType.ACCOUNT_SIGNUP)) == 1
    assert env.open_task(account, TaskType.ACCOUNT_VERIFICATION)
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        step = next(x for x in acc.steps if x.step.value == "signup")
        assert step.state == StepState.COMPLETED and step.verification.value == "human_confirmed"
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_VERIFICATION


def test_reconciliation_exists_not_controlled_blocks(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.cancel(s, signup.id, actor=env.actor(team["security"], OperatorRole.ADMIN), reason="unsure what happened")
    env.complete_type(account, TaskType.SIGNUP_RECONCILIATION, owner, {"external_account_state": "exists_not_controlled"})
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.BLOCKED
        assert acc.blocker_code == "HANDLE_EXISTS_NOT_CONTROLLED"
    assert len(env.tasks(account, TaskType.ACCOUNT_SIGNUP)) == 1


def test_operator_requested_reconciliation_stops_active_signup(env, team, account):
    signup = _to_signup(env, team, account)
    client = env.client()
    response = client.post(
        f"/api/v1/accounts/{account}/reconcile",
        json={"reason": "operator lost track of whether the signup finished"},
        headers=env.headers(team["owner"], OperatorRole.OPERATOR),
    )
    assert response.status_code == 200
    assert response.json()["reconciliation_task"]["task_type"] == "signup_reconciliation"
    assert next(t for t in env.tasks(account, TaskType.ACCOUNT_SIGNUP) if t.id == signup.id).status == TaskStatus.CANCELLED
    again = client.post(f"/api/v1/accounts/{account}/reconcile", json={"reason": "asking twice"}, headers=env.headers(team["owner"], OperatorRole.OPERATOR))
    assert again.json()["reconciliation_task"]["id"] == response.json()["reconciliation_task"]["id"]


def test_restart_persists_state_and_recovery_is_idempotent(env, team, account):
    _to_signup(env, team, account)
    before = {(t.id, t.status) for t in env.tasks(account)}
    restarted = build_container(env.settings, clock=env.clock)
    try:
        first = run_startup_recovery(restarted)
        second = run_startup_recovery(restarted)
        with restarted.uow() as s:
            after = {(t.id, t.status) for t in s.scalars(select(HumanTask).where(HumanTask.account_id == account))}
        assert after == before  # pending work is resumed, not assumed failed or recreated
        assert first["accounts_re_evaluated"] == 1 and second["open_tasks_resumed_by_status"] == first["open_tasks_resumed_by_status"]
    finally:
        restarted.engine.dispose()


def test_recovery_marks_interrupted_runs_and_uncertain_sends(env, team, account):
    with env.container.uow() as s:
        s.add(AuditRun(id=new_id("aud"), trigger=AuditTrigger.SCHEDULED, idempotency_key="weekly:2026-W42", status=AuditRunStatus.RUNNING, started_at=T0))
        s.add(Notification(id=new_id("ntf"), recipient_id=team["owner"], kind=NotificationKind.REMINDER, subject="s", body="b", delivery_status=DeliveryStatus.SENDING, dedupe_key="test:sending", created_at=T0))
    summary = run_startup_recovery(env.container)
    assert summary["audit_runs_marked_interrupted"] == 1 and summary["notifications_marked_uncertain"] == 1
    with env.container.uow() as s:
        assert s.scalar(select(AuditRun.status)) == AuditRunStatus.INTERRUPTED
        assert s.scalar(select(Notification.delivery_status).where(Notification.dedupe_key == "test:sending")) == DeliveryStatus.UNCERTAIN
    # The interrupted weekly run is resumed under the same key, not duplicated.
    run = env.container.audits.run_weekly_if_due(env.container.session_factory, actor=env.actor(team["security"], OperatorRole.ADMIN))
    assert run.status == AuditRunStatus.COMPLETED and run.attempt_count == 2
    with env.container.uow() as s:
        assert s.scalar(select(func.count(AuditRun.id))) == 1


def test_failed_signup_attempt_cannot_later_be_completed(env, team, account):
    signup = _to_signup(env, team, account)
    owner = env.actor(team["owner"])
    with env.container.uow() as s:
        env.container.tasks.fail(s, signup.id, actor=owner, reason="unsure", outcome_uncertain=True)
    with pytest.raises(DomainError) as raised:
        env.complete(signup.id, owner, OUTCOMES[TaskType.ACCOUNT_SIGNUP])
    assert raised.value.code == "invalid_transition"
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert next(x for x in acc.steps if x.step.value == "signup").state == StepState.PENDING


def test_reconciliation_rejected_once_signup_confirmed(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_VERIFICATION)
    with pytest.raises(Conflict):
        with env.container.uow() as s:
            env.container.provisioning.request_reconciliation(s, account, actor=env.actor(team["owner"]), reason="double check")
