"""Secrets never reach logs, error responses or reports - even when deliberately supplied."""

from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.enums import AuditTrigger, OperatorRole, TaskType
from app.errors import SecretMaterialRejected, ValidationFailed
from app.integrations.vault import DevMemoryVault
from app.integrations.vault.base import VaultError
from app.security.redaction import Redactor
from app.security.secret_handling import (
    SecretValue,
    find_secret_material,
    validate_vault_ref,
)
from tests.conftest import TEST_SECRET_KEY, make_settings

SYNTH_SECRET = "SYNTHETIC-SECRET-hunter2-Zx81"
SYNTH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXRlc3Q"


@pytest.mark.parametrize(
    "text,secret",
    [
        ("Authorization: Bearer abcDEF123456ghijkl", "abcDEF123456ghijkl"),
        ("proxy=http://user01:Sup3rS3cret@proxy.example:3128", "Sup3rS3cret"),
        ("password=correct-horse-battery", "correct-horse-battery"),
        ('{"api_key": "AKIAEXAMPLEKEY"} token: tok_live_998877', "tok_live_998877"),
        (f"jwt {SYNTH_TOKEN}", SYNTH_TOKEN),
        ("my backup codes 1234 5678 and 8765-4321", "1234 5678"),
        ("operator token iom_abcdefghijklmnopqrstuvwxyz012345", "iom_abcdefghijklmnopqrstuvwxyz012345"),
        ("meta EAABsbCS1iHgBAFakeTokenValue1234567890", "EAABsbCS1iHgBAFakeTokenValue1234567890"),
        ("call +44 7700 900123 now", "7700 900123"),
        ("-----BEGIN PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----", "MIIEv"),
        ("session cookie sessionid=abc123def456", "abc123def456"),
    ],
)
def test_pattern_redaction(text, secret):
    assert secret not in Redactor().redact_text(text)


def test_email_masking_keeps_domain():
    out = Redactor().redact_text("alias is ig-lumenlab@testco.example")
    assert "ig-lumenlab@" not in out and "i***@testco.example" in out


def test_registered_secrets_are_redacted_in_any_format():
    redactor = Redactor()
    redactor.register_secret("plainvaluewithoutpattern")
    assert "plainvaluewithoutpattern" not in redactor.redact_text("x=plainvaluewithoutpattern;")
    assert redactor.contains_registered_secret("..plainvaluewithoutpattern..")


def test_key_based_redaction_keeps_references_and_metadata():
    data = {
        "password": "hunter2",
        "backup_codes_vault_ref": "devvault://a/b",
        "backup_codes": {"vault_ref": "devvault://a/b", "status": "present_in_vault", "codes": ["11112222", "33334444"]},
        "credentials": {"username": "u-1", "password": "p-1"},
        "headers": {"Authorization": "Basic dXNlcjpwYXNz", "Cookie": "sid=1", "X-Correlation-ID": "abc"},
        "token_prefix": "iom_abc",
        "nested": [{"client_secret": "s", "ok": 1}],
    }
    out = Redactor().redact(data)
    assert out["password"] == "[REDACTED]"
    assert out["backup_codes_vault_ref"] == "devvault://a/b"
    assert out["backup_codes"]["vault_ref"] == "devvault://a/b" and out["backup_codes"]["status"] == "present_in_vault"
    assert out["backup_codes"]["codes"] == ["[REDACTED]", "[REDACTED]"]
    assert out["credentials"] == {"username": "[REDACTED]", "password": "[REDACTED]"}
    assert out["headers"]["Authorization"] == "[REDACTED]" and out["headers"]["Cookie"] == "[REDACTED]"
    assert out["headers"]["X-Correlation-ID"] == "abc"
    assert out["nested"][0] == {"client_secret": "[REDACTED]", "ok": 1}


def test_secret_value_wrapper_never_reveals_itself():
    secret = SecretValue(SYNTH_SECRET)
    for rendering in (str(secret), repr(secret), f"{secret}", "%s" % secret):
        assert SYNTH_SECRET not in rendering
    assert secret.reveal() == SYNTH_SECRET
    with pytest.raises(TypeError):
        json.dumps(secret)


@pytest.mark.parametrize(
    "text",
    ["codes 1234 5678", "my password: hunter2", "Bearer abcdefghijklmnop", "otp code 123456", "https://u:p@host/x", "sessionid=abc"],
)
def test_secret_material_detection(text):
    assert find_secret_material(text)


@pytest.mark.parametrize("text", ["password is stored in the vault", "ticket IT-REQ-4821", "observed profile instagram.com/lumen", "tsk_" + "a1" * 16])
def test_benign_text_is_not_flagged(text):
    assert not find_secret_material(text)


def test_task_note_with_backup_codes_is_rejected_and_never_echoed_or_logged(env, team, account):
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    client = env.client()
    response = client.post(
        f"/api/v1/tasks/{task.id}/complete",
        json={
            "outcome": {"selected_handle": "lumenlabtestbrand", "checked_via": "instagram_app"},
            "evidence_ref": "checked in app",
            "note": "backup codes are 4821 7730 and 1190 2284",
        },
        headers=env.headers(team["owner"], OperatorRole.OPERATOR),
    )
    assert response.status_code == 422 and response.json()["error"]["code"] == "secret_material_rejected"
    for fragment in ("4821 7730", "1190 2284"):
        assert fragment not in response.text and fragment not in env.read_logs()
    assert env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK).status.value == "pending"


def test_validation_errors_never_echo_submitted_values(env, team):
    response = env.client().post(
        "/api/v1/accounts",
        json={"brand_name": "Brand", "owner_id": team["owner"], "password": SYNTH_SECRET},
        headers=env.headers(team["owner"], OperatorRole.OPERATOR),
    )
    assert response.status_code == 422
    assert SYNTH_SECRET not in response.text
    assert all(set(detail) == {"loc", "msg", "type"} for detail in response.json()["error"]["details"])  # no "input" echo
    assert SYNTH_SECRET not in env.read_logs()


def test_secret_in_vault_ref_field_is_rejected(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_SIGNUP)
    task = env.open_task(account, TaskType.ACCOUNT_SIGNUP)
    with pytest.raises(ValidationFailed) as raised:
        env.complete(task.id, env.actor(team["owner"]), {"platform_handle": "lumenlabtestbrand", "password_vault_ref": "MyPassw0rd!IsHere"})
    assert "MyPassw0rd" not in json.dumps(raised.value.details) and "MyPassw0rd" not in raised.value.message


def test_exception_messages_with_secrets_are_redacted_in_logs(env):
    env.container.redactor.register_secret(SYNTH_SECRET)
    logger = logging.getLogger("app.test")
    try:
        raise RuntimeError(f"vault call failed with token={SYNTH_SECRET} and Bearer abcdefghijklmnopqr")
    except RuntimeError:
        logger.exception("integration failure", extra={"event": "test.failure", "fields": {"password": SYNTH_SECRET, "detail": SYNTH_SECRET}})
    logs = env.read_logs()
    assert "test.failure" in logs and SYNTH_SECRET not in logs and "abcdefghijklmnopqr" not in logs


def test_http_access_log_never_contains_query_strings_or_bodies(env, team):
    client = env.client()
    client.get("/api/v1/tasks", params={"owner_id": "access_token=leakme123"}, headers=env.headers(team["owner"], OperatorRole.VIEWER))
    client.post("/api/v1/accounts", json={"brand_name": "Some Brand", "owner_id": team["owner"]}, headers=env.headers(team["owner"], OperatorRole.OPERATOR))
    access_lines = [json.loads(line) for line in env.read_logs().splitlines() if '"event": "http.request"' in line]
    assert len(access_lines) == 2
    assert all("leakme123" not in json.dumps(line) and "Some Brand" not in json.dumps(line) for line in access_lines)
    assert "leakme123" not in env.read_logs()


def test_reports_contain_no_secrets_after_full_flow(env, team, account):
    env.provision(account, team["owner"])
    env.container.redactor.register_secret(SYNTH_SECRET)
    env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(team["security"], OperatorRole.ADMIN))
    with env.container.uow() as s:
        env.container.reports.export_all(s)
    secrets = ["SYNTHETIC-password-lumenlab-1", "SYNTHETIC-backup-codes-set-1", "SYNTHETIC-totp-seed-1", SYNTH_SECRET, TEST_SECRET_KEY]
    files = list(env.settings.reports_dir.rglob("*.*"))
    assert len(files) >= 5
    for path in files:
        content = path.read_text(encoding="utf-8")
        for secret in secrets:
            assert secret not in content, f"{secret} leaked into {path.name}"
    assert TEST_SECRET_KEY not in env.read_logs()


def test_dev_vault_refuses_real_values_and_production():
    from app.clock import SystemClock

    vault = DevMemoryVault(app_env="test", redactor=Redactor(), clock=SystemClock())
    with pytest.raises(VaultError):
        vault.write_fields("devvault://x", {"value": SecretValue("a-real-looking-password")})
    with pytest.raises(VaultError):
        vault.write_fields("vault://x", {"value": SecretValue("SYNTHETIC-ok")})
    with pytest.raises(RuntimeError):
        DevMemoryVault(app_env="production", redactor=Redactor(), clock=SystemClock())


def test_settings_require_a_strong_secret_key(tmp_path):
    for bad in (None, "short", "change-me-change-me-change-me-change-me-123"):
        with pytest.raises(ValidationError):
            make_settings(tmp_path, app_secret_key=bad)


def test_production_refuses_dev_vault_and_docs(tmp_path):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, app_env="production", vault_backend="dev_memory", trusted_hosts="ops.testco.example")
    with pytest.raises(ValidationError):
        make_settings(tmp_path, app_env="production", vault_backend="reference_only", docs_enabled=True, trusted_hosts="ops.testco.example")
    with pytest.raises(ValidationError):
        make_settings(tmp_path, app_env="production", vault_backend="reference_only")  # TRUSTED_HOSTS missing
    prod = make_settings(tmp_path, app_env="production", vault_backend="reference_only", trusted_hosts="ops.testco.example")
    assert prod.docs_are_enabled is False and prod.cookie_secure is True


@pytest.mark.parametrize("ref", ["vault://user:pass@host/x", "hunter2", "ftp://x/y", "vault://a/b c"])
def test_vault_reference_validation(ref):
    with pytest.raises(ValidationFailed):
        validate_vault_ref(ref, ["vault", "devvault"])


def test_secret_material_rejected_error_type(env, team, account):
    task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    with pytest.raises(SecretMaterialRejected):
        env.complete(task.id, env.actor(team["owner"]), {"selected_handle": "lumenlabtestbrand", "checked_via": "instagram_app"}, evidence="password: hunter2")


def test_settings_object_does_not_leak_secret_key(tmp_path):
    settings: Settings = make_settings(tmp_path)
    assert TEST_SECRET_KEY not in repr(settings) and TEST_SECRET_KEY not in str(settings.model_dump())
