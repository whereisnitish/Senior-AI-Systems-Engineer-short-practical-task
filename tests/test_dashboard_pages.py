"""Every dashboard page renders with real data, and page actions behave safely."""

from __future__ import annotations

import re

from app.enums import AuditTrigger, OperatorRole, RoleName, TaskType


def _signed_in(env, person_id):
    client = env.client()
    client.post("/login", data={"token": env.token(person_id, OperatorRole.ADMIN)})
    return client


def _csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', html).group(1)


def test_all_pages_render_with_data(env, team, account):
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.TEMPORARY_TEST_ROLE, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(team["security"], OperatorRole.ADMIN))
    with env.container.uow() as s:
        env.container.offboarding.start(s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="leaving")
    client = _signed_in(env, team["security"])
    task_id = env.tasks(account, TaskType.ACCOUNT_SIGNUP)[0].id
    expectations = {
        "/dashboard": ["Account register", "Needs attention", "System status", "10 / 10 steps"],
        "/dashboard/accounts": ["Account register", "Lumen Lab Test Brand"],
        f"/dashboard/accounts/{account}": ["Provisioning", "People and roles", "temporary test role"],
        "/dashboard/tasks": ["Human tasks", "Open"],
        "/dashboard/tasks?view=completed": ["Sign up @lumenlabtestbrand"],
        f"/dashboard/tasks/{task_id}": ["Outcome", "History", "human confirmed"],
        "/dashboard/audit": ["Security audit", "Verification labels", "Check results"],
        "/dashboard/offboarding": ["Jordan Patel", "Completed", "Pending", "Blocked"],
        "/dashboard/proxies": ["Approved proxies", "No approved proxies configured"],
        "/dashboard/notifications": ["Notifications", "not delivered"],
    }
    for path, needles in expectations.items():
        page = client.get(path)
        assert page.status_code == 200, path
        for needle in needles:
            assert needle in page.text, f"{needle!r} missing on {path}"
        assert "style=" not in page.text  # strict CSP: no inline styles anywhere


def test_failed_page_action_shows_fixed_message_and_blocks_open_redirect(env, team, account):
    client = _signed_in(env, team["security"])
    csrf = _csrf(client.get("/dashboard").text)
    # No proxy health-check endpoint configured -> fixed, non-reflected error message.
    response = client.post("/dashboard/run/proxies", data={"csrf_token": csrf, "next": "/dashboard/proxies"}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/dashboard/proxies?error=")
    page = client.get(response.headers["location"])
    assert "configuration is incomplete" in page.text or "health-check endpoint" in page.text
    # A crafted "next" pointing off-site falls back to the dashboard.
    evil = client.post("/dashboard/run/reminders", data={"csrf_token": csrf, "next": "https://evil.example/x"}, follow_redirects=False)
    assert evil.headers["location"].startswith("/dashboard/notifications")
    reflected = client.get("/dashboard?error=<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in reflected.text


def test_viewer_cannot_run_page_actions(env, team, account):
    client = env.client()
    client.post("/login", data={"token": env.token(team["operator"], OperatorRole.VIEWER)})
    csrf = _csrf(client.get("/dashboard").text)
    response = client.post("/dashboard/run/audit", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303 and "error=forbidden" in response.headers["location"]
