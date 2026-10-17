"""scripts/vault_check.py and Windows-friendly token files, against a simulated Vault HTTP API."""

from __future__ import annotations

import codecs

import httpx

from app.integrations.vault import HashiCorpKV2Vault
from app.security.redaction import Redactor
from scripts.vault_check import run_checks
from tests.conftest import make_settings
from tests.test_integrations import VAULT_TOKEN

SMTP_SECRET = "SYNTHETIC-smtp-app-password"


def _vault(tmp_path, *, policy_too_broad: bool, token_bytes: bytes | None = None):
    token_file = tmp_path / "vault-token"
    token_file.write_bytes(token_bytes if token_bytes is not None else VAULT_TOKEN.encode())
    settings = make_settings(
        tmp_path, vault_backend="hashicorp_kv2", vault_addr="http://127.0.0.1:8200", vault_token_file=token_file,
        smtp_password_vault_ref="vault://smtp/gmail#password",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/sys/health":
            return httpx.Response(200, json={"sealed": False})
        assert request.headers["X-Vault-Token"] == VAULT_TOKEN
        if path.startswith("/v1/secret/metadata/instagram/"):
            return httpx.Response(404, json={"errors": []})
        if path.startswith("/v1/secret/data/instagram/"):
            return httpx.Response(404 if policy_too_broad else 403, json={"errors": ["permission denied"]})
        if path == "/v1/secret/data/smtp/gmail":
            return httpx.Response(200, json={"data": {"data": {"password": SMTP_SECRET}, "metadata": {"version": 1}}})
        if path == "/v1/secret/data/proxies/a":
            return httpx.Response(200, json={"data": {"data": {"username": "SYNTHETIC-u", "password": "SYNTHETIC-p"}}})
        return httpx.Response(403, json={"errors": ["permission denied"]})

    redactor = Redactor()
    vault = HashiCorpKV2Vault(settings=settings, redactor=redactor, client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _s: None)
    return vault, settings, redactor


def test_vault_check_passes_with_the_least_privilege_policy(tmp_path):
    vault, settings, _ = _vault(tmp_path, policy_too_broad=False)
    result = run_checks(vault, settings, handle="demo_workaccount", proxy_refs=[("proxy a credential", "vault://proxies/a")])
    by_name = {c["check"]: c for c in result["checks"]}
    assert result["ok"] is True
    assert by_name["value denied: Instagram password"]["ok"] is True
    assert by_name["metadata readable: Instagram backup codes"]["detail"] == "metadata answered: no entry stored yet"
    assert by_name["runtime secret: SMTP password"]["ok"] is True
    assert by_name["runtime secret: Meta token"]["ok"] is None  # not configured: skipped, not passed
    assert SMTP_SECRET not in str(result)  # statuses only, never values


def test_vault_check_fails_when_the_token_may_read_instagram_values(tmp_path):
    vault, settings, _ = _vault(tmp_path, policy_too_broad=True)
    result = run_checks(vault, settings, handle="demo_workaccount", proxy_refs=[])
    assert result["ok"] is False
    assert "policy is too broad" in next(c for c in result["checks"] if c["check"] == "value denied: Instagram password")["detail"]


def test_reports_say_a_candidate_run_vault_is_not_the_company_vault(tmp_path):
    from tests.conftest import Env

    vault, _, _ = _vault(tmp_path, policy_too_broad=False)
    env = Env(tmp_path / "env", environment_label="candidate_provided_test_environment")
    env.container.reports.vault = vault
    with env.container.uow() as s:
        notes = env.container.reports.report_meta(s, "x")["notes"]
    assert any("candidate-run HashiCorp Vault (not the company vault)" in n for n in notes)
    env.container.engine.dispose()


def test_token_file_written_by_windows_powershell_is_read_correctly(tmp_path):
    utf16 = codecs.BOM_UTF16_LE + (VAULT_TOKEN + "\r\n").encode("utf-16-le")  # what PowerShell 5.1 '>' writes
    vault, settings, redactor = _vault(tmp_path, policy_too_broad=False, token_bytes=utf16)
    assert vault.read("vault://smtp/gmail#password").reveal() == SMTP_SECRET  # the handler asserted the exact token
    assert redactor.contains_registered_secret(VAULT_TOKEN)
    (tmp_path / "b").mkdir()
    vault2, _, _ = _vault(tmp_path / "b", policy_too_broad=False, token_bytes=codecs.BOM_UTF8 + VAULT_TOKEN.encode())
    assert vault2.read("vault://smtp/gmail#password").reveal() == SMTP_SECRET
