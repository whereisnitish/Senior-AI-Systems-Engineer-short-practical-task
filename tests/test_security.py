"""Authentication, role-based authorisation, safe defaults and the dashboard session."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.enums import OperatorRole, TaskType
from app.main import create_app
from app.models import ApiCredential
from app.security.authentication import revoke_person_credentials
from tests.conftest import PROFILE, Env


def test_unauthenticated_and_invalid_tokens_are_rejected(env, team):
    client = env.client()
    missing = client.get("/api/v1/accounts")
    assert missing.status_code == 401 and missing.headers["WWW-Authenticate"] == "Bearer"
    assert missing.json()["error"]["code"] == "unauthenticated"
    assert client.get("/api/v1/accounts", headers={"Authorization": "Bearer iom_notarealtoken"}).status_code == 401
    assert client.get("/api/v1/accounts", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.post("/api/v1/accounts", json={}).status_code == 401  # write without auth


@pytest.mark.parametrize(
    "role,method,path,body,expected",
    [
        (OperatorRole.VIEWER, "get", "/api/v1/accounts", None, 200),
        (OperatorRole.VIEWER, "post", "/api/v1/accounts", {"brand_name": "X Brand", "owner_id": "OWNER"}, 403),
        (OperatorRole.OPERATOR, "post", "/api/v1/accounts", {"brand_name": "X Brand", "owner_id": "OWNER"}, 201),
        (OperatorRole.OPERATOR, "post", "/api/v1/audits/run", None, 403),
        (OperatorRole.OPERATOR, "post", "/api/v1/people", {"full_name": "New Person", "email": "new@testco.example"}, 403),
        (OperatorRole.OPERATOR, "post", "/api/v1/offboarding", {"person_id": "OWNER", "reason": "test"}, 403),
        (OperatorRole.OPERATOR, "post", "/api/v1/reports/export", None, 403),
        (OperatorRole.AUDITOR, "post", "/api/v1/audits/run", None, 201),
        (OperatorRole.AUDITOR, "post", "/api/v1/accounts", {"brand_name": "X Brand", "owner_id": "OWNER"}, 403),
        (OperatorRole.ADMIN, "post", "/api/v1/people", {"full_name": "New Person", "email": "new@testco.example"}, 201),
    ],
)
def test_role_permissions(env, team, role, method, path, body, expected):
    if body:
        body = {k: (team["owner"] if v == "OWNER" else v) for k, v in body.items()}
    response = env.client().request(method.upper(), path, json=body, headers=env.headers(team["security"], role))
    assert response.status_code == expected, response.text


def test_access_register_changes_require_admin(env, team, account):
    client = env.client()
    body = {"person_id": team["operator"], "role": "content_publisher"}
    assert client.post(f"/api/v1/accounts/{account}/assignments", json=body, headers=env.headers(team["owner"], OperatorRole.OPERATOR)).status_code == 403
    ok = client.post(f"/api/v1/accounts/{account}/assignments", json=body, headers=env.headers(team["security"], OperatorRole.ADMIN))
    assert ok.status_code == 201 and ok.json()["people_and_roles"][0]["status"] == "requested"


def test_business_admin_count_is_capped(env, team, account):
    client = env.client()
    admin = env.headers(team["security"], OperatorRole.ADMIN)
    for person in ("owner", "security"):
        assert client.post(f"/api/v1/accounts/{account}/assignments", json={"person_id": team[person], "role": "business_admin"}, headers=admin).status_code == 201
    third = client.post(f"/api/v1/accounts/{account}/assignments", json={"person_id": team["operator"], "role": "business_admin"}, headers=admin)
    assert third.status_code == 409


def test_credential_issue_returns_token_once_and_stores_only_hmac(env, team):
    client = env.client()
    response = client.post(f"/api/v1/people/{team['operator']}/credentials", json={"role": "viewer", "label": "laptop"}, headers=env.headers(team["security"], OperatorRole.ADMIN))
    assert response.status_code == 201 and response.headers["Cache-Control"] == "no-store"
    raw = response.json()["token"]
    with env.container.uow() as s:
        stored = s.scalar(select(ApiCredential).where(ApiCredential.id == response.json()["credential_id"]))
        assert stored.token_hash != raw and len(stored.token_hash) == 64
    db_bytes = (env.tmp_path / "test.db").read_bytes() + b"".join(p.read_bytes() for p in env.tmp_path.glob("test.db-*"))
    assert raw.encode() not in db_bytes
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {raw}"}).json()["role"] == "viewer"


def test_revoked_credentials_stop_working(env, team):
    token = env.token(team["operator"], OperatorRole.OPERATOR)
    client = env.client()
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    with env.container.uow() as s:
        revoke_person_credentials(s, team["operator"], now=env.clock.now(), reason="test")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_security_headers_and_correlation_id(env, team):
    response = env.client().get("/health/live", headers={"X-Correlation-ID": "demo-correlation-0001"})
    assert response.headers["X-Correlation-ID"] == "demo-correlation-0001"
    for header in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy", "Cache-Control"):
        assert header in response.headers
    bad = env.client().get("/health/live", headers={"X-Correlation-ID": "<script>"})
    assert bad.headers["X-Correlation-ID"] != "<script>"


def test_cors_is_closed_by_default(env):
    response = env.client().get("/health/live", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in response.headers}


def test_production_mode_hides_docs_and_enforces_trusted_hosts(tmp_path):
    env = Env(tmp_path, app_env="production", vault_backend="reference_only", trusted_hosts="testserver")
    client = TestClient(create_app(env.settings, env.container, run_recovery=False))
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404
    assert "Strict-Transport-Security" in client.get("/health/live").headers
    other = TestClient(create_app(env.settings, env.container, run_recovery=False), base_url="http://attacker.example")
    assert other.get("/health/live").status_code == 400
    env.container.engine.dispose()


def test_development_docs_available(env):
    assert env.client().get("/openapi.json").status_code == 200


def test_consistent_error_shape(env, team):
    client = env.client()
    not_found = client.get(f"/api/v1/accounts/acc_{'0' * 32}", headers=env.headers(team["owner"], OperatorRole.VIEWER)).json()
    assert set(not_found["error"]) == {"code", "message", "details", "correlation_id"} and not_found["error"]["code"] == "not_found"
    unknown_route = client.get("/api/v1/nope").json()
    assert unknown_route["error"]["code"] == "http_error"


def test_health_and_readiness(env):
    client = env.client()
    assert client.get("/health/live").json() == {"status": "ok"}
    ready = client.get("/health/ready")
    assert ready.status_code == 200 and ready.json()["checks"]["database"] == "ok"


def test_readiness_fails_without_schema(tmp_path):
    from app.container import build_container
    from tests.conftest import make_settings

    settings = make_settings(tmp_path)
    container = build_container(settings)  # no create_all: schema missing
    client = TestClient(create_app(settings, container, run_recovery=False))
    response = client.get("/health/ready")
    assert response.status_code == 503 and "schema_missing" in response.json()["checks"]["database"]
    container.engine.dispose()


def _csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', html).group(1)


def test_dashboard_requires_login_and_csrf(env, team, account):
    client = env.client()
    redirect = client.get("/dashboard", follow_redirects=False)
    assert redirect.status_code == 303 and redirect.headers["location"] == "/login"
    assert client.post("/login", data={"token": "iom_wrong"}).status_code == 401
    token = env.token(team["owner"], OperatorRole.OPERATOR)
    login = client.post("/login", data={"token": token}, follow_redirects=False)
    assert login.status_code == 303
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Account register" in page.text and "Lumen Lab Test Brand" in page.text
    assert "SYNTHETIC DEMO DATA" in page.text and "not delivered" in page.text
    forged = client.post("/dashboard/run/reminders", data={"csrf_token": "0" * 64}, follow_redirects=False)
    assert forged.status_code == 403
    good = client.post("/dashboard/run/reminders", data={"csrf_token": _csrf(page.text)}, follow_redirects=False)
    assert good.status_code == 303


def test_dashboard_task_completion_form(env, team, account):
    client = env.client()
    client.post("/login", data={"token": env.token(team["owner"], OperatorRole.OPERATOR)})
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    page = client.get(f"/dashboard/tasks/{task.id}")
    assert page.status_code == 200 and "Record completion" in page.text and "SAFETY RULES" in page.text
    csrf = _csrf(page.text)
    rejected = client.post(f"/dashboard/tasks/{task.id}/complete", data={"csrf_token": csrf, "outcome.selected_handle": "bad handle!", "outcome.checked_via": "instagram_app", "evidence_ref": "checked"})
    assert rejected.status_code == 422 and "selected_handle" in rejected.text
    done = client.post(
        f"/dashboard/tasks/{task.id}/complete",
        data={"csrf_token": csrf, "outcome.selected_handle": "lumenlabtestbrand", "outcome.checked_via": "instagram_app", "evidence_ref": "searched in official app"},
        follow_redirects=False,
    )
    assert done.status_code == 303 and "notice=completed" in done.headers["location"]
    assert "completed" in client.get(f"/dashboard/tasks/{task.id}").text


def test_dashboard_escapes_user_content(env, team):
    env.create_account(team["owner"], brand="<script>alert(1)</script> Brand", profile={**PROFILE})
    client = env.client()
    client.post("/login", data={"token": env.token(team["owner"], OperatorRole.VIEWER)})
    page = client.get("/dashboard").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
