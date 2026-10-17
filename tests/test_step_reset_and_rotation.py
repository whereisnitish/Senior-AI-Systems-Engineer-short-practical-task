"""Resetting a completed pre-signup step, and rotating an exposed API token."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.enums import OperatorRole, ProvisioningStatus, TaskStatus, TaskType
from app.models import HumanTask, InstagramAccount, Notification, TaskEvent
from tests.conftest import Env

REASON = "placeholder evidence recorded during setup; redo the check properly"


def _reset(env: Env, account: str, step: str, headers: dict, reason: str = REASON):
    return env.client().post(f"/api/v1/accounts/{account}/steps/{step}/reset", headers=headers, json={"reason": reason})


def test_handle_step_reset_keeps_history_and_issues_a_fresh_task(env, team, account):
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, env.actor(team["owner"]))
    old = env.tasks(account, TaskType.HANDLE_AVAILABILITY_CHECK)[0]
    response = _reset(env, account, "handle_selected", env.headers(team["security"], OperatorRole.ADMIN))
    assert response.status_code == 200, response.text
    new_task = response.json()["new_task"]
    assert new_task["id"] != old.id and new_task["status"] == "pending"
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.selected_handle is None and acc.handle_status.value == "not_checked"
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_HANDLE_CHECK
        step = next(st for st in acc.steps if st.step.value == "handle_selected")
        assert step.state.value == "pending" and step.verification.value == "unverified" and step.evidence_ref is None
        history = s.get(HumanTask, old.id)
        assert history.status == TaskStatus.COMPLETED  # the original confirmation is kept, not rewritten
        event = s.scalar(select(TaskEvent).where(TaskEvent.task_id == old.id, TaskEvent.event_type == "step_reset"))
        assert event is not None and event.detail["superseded_evidence"] == "observed in Instagram settings (test)"
        assert s.scalar(select(HumanTask.idempotency_key).where(HumanTask.id == new_task["id"])).endswith(":g2")
        assert s.scalar(select(Notification).where(Notification.task_id == new_task["id"])) is not None  # owner told
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, env.actor(team["owner"]))
    with env.container.uow() as s:
        assert s.get(InstagramAccount, account).selected_handle == "lumenlabtestbrand"


def test_email_reset_clears_the_recorded_contact(env, team, account):
    env.complete_type(account, TaskType.ASSIGN_COMPANY_EMAIL, env.actor(team["owner"]))
    assert _reset(env, account, "company_email", env.headers(team["security"], OperatorRole.ADMIN)).status_code == 200
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.company_email_ref is None and acc.company_email_hint is None and acc.company_email_control.value == "unknown"


def test_reset_is_refused_after_signup_for_unfinished_or_later_steps_and_for_non_admins(env, team, account):
    admin = env.headers(team["security"], OperatorRole.ADMIN)
    assert _reset(env, account, "handle_selected", admin).status_code == 409  # nothing completed yet
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_VERIFICATION)  # signup confirmed
    assert _reset(env, account, "handle_selected", admin).status_code == 409
    assert _reset(env, account, "two_factor", admin).status_code == 409
    assert _reset(env, account, "handle_selected", env.headers(team["owner"], OperatorRole.OPERATOR)).status_code == 403
    secret = _reset(env, account, "handle_selected", admin, reason="the password: Hunter2-very-secret was wrong")
    assert secret.status_code == 422 and "Hunter2" not in secret.text


@pytest.fixture
def rotate(env, monkeypatch, tmp_path):
    import scripts.rotate_token as cli

    monkeypatch.setattr(cli, "cli_container", lambda _name: env.container)
    token_file = tmp_path / "rotated" / "token.txt"

    def run(email: str) -> str:
        monkeypatch.setattr("sys.argv", ["rotate_token", "--email", email, "--token-file", str(token_file)])
        cli.main()
        return token_file.read_text(encoding="utf-8").strip()

    return run


def test_rotation_revokes_the_exposed_token_and_its_sessions(env, team, rotate, capsys):
    client = env.client()
    exposed = env.token(team["owner"], OperatorRole.ADMIN)
    assert client.post("/login", data={"token": exposed}, follow_redirects=False).status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 200
    fresh = rotate("sam.rivera@testco.example")
    assert fresh != exposed and fresh not in capsys.readouterr().out  # written to the file, never printed
    assert client.get("/api/v1/accounts", headers={"Authorization": f"Bearer {exposed}"}).status_code == 401
    assert client.get("/dashboard", follow_redirects=False).status_code == 303  # its dashboard session is gone too
    me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {fresh}"})
    assert me.status_code == 200 and me.json()["role"] == "admin"
