"""Behaviour with missing integrations, and the configured adapters against simulated transports."""

from __future__ import annotations

import json
import smtplib
import socket

import httpx
import pytest

from app.enums import AuditTrigger, OperatorRole, RoleName, TaskType, VerificationLabel
from app.errors import ValidationFailed
from app.integrations.meta import MetaGraphReadOnly, MetaLinkCheck, MetaNotConfigured
from app.integrations.meta.base import MetaIntegration
from app.integrations.notifications import SmtpNotifier
from app.integrations.vault import (
    HashiCorpKV2Vault,
    ReferenceOnlyVault,
    VaultOperationUnsupported,
    VaultSecretNotFound,
    VaultUnavailable,
    inspect_ref,
)
from app.models import InstagramAccount
from app.security.redaction import Redactor
from app.security.secret_handling import SecretValue
from tests.conftest import OUTCOMES, Env, make_settings

VAULT_TOKEN = "hvs.SYNTHETICvaulttokenForTests0123456789"


def test_reference_only_vault_never_touches_secrets():
    vault = ReferenceOnlyVault()
    with pytest.raises(VaultOperationUnsupported):
        vault.read("vault://team/instagram/password")
    inspection = inspect_ref(vault, "vault://team/instagram/password")
    assert inspection.exists is None and inspection.label is None


def test_reference_only_mode_labels_vault_facts_human_confirmed(tmp_path):
    env = Env(tmp_path, vault_backend="reference_only")
    security = env.person("Morgan Lee", responsibilities=("security_owner",))
    owner = env.person("Sam Rivera", supervisor=security)
    account = env.create_account(owner)
    actor = env.actor(owner, OperatorRole.ADMIN)
    env.add_role(account, owner, RoleName.BUSINESS_ADMIN, owner)
    refs = {
        TaskType.ACCOUNT_SIGNUP: {"platform_handle": "lumenlabtestbrand", "password_vault_ref": "vault://team/instagram/lumen/password"},
        TaskType.ENABLE_TWO_FACTOR: {
            "two_factor_method": "authenticator_app",
            "backup_codes_vault_ref": "vault://team/instagram/lumen/backup-codes",
            "totp_seed_vault_ref": "vault://team/instagram/lumen/totp",
            "two_factor_enabled": True,
        },
    }
    for task_type in (
        TaskType.HANDLE_AVAILABILITY_CHECK, TaskType.ASSIGN_COMPANY_EMAIL, TaskType.ASSIGN_COMPANY_PHONE, TaskType.ACCOUNT_SIGNUP,
        TaskType.ACCOUNT_VERIFICATION, TaskType.ENABLE_TWO_FACTOR, TaskType.COMPLETE_PROFILE, TaskType.CONVERT_TO_BUSINESS,
        TaskType.LINK_META_BUSINESS, TaskType.ASSIGN_PEOPLE_ROLES,
    ):
        env.complete_type(account, task_type, actor, refs.get(task_type, OUTCOMES[task_type]))
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status.value == "provisioned"
        assert acc.backup_codes_verification == VerificationLabel.HUMAN_CONFIRMED
        assert acc.password_ref_verification == VerificationLabel.HUMAN_CONFIRMED
    run = env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=actor)
    checks = {c["check_name"]: c for c in run.summary["accounts"][0]["checks"]}
    assert checks["backup_codes_in_vault"]["verification"] == "human_confirmed"
    assert "not machine-verifiable" in checks["backup_codes_in_vault"]["description"]
    env.container.engine.dispose()


class FakeKV:
    """Simulates the documented HashiCorp Vault KV v2 HTTP API in memory."""

    def __init__(self):
        self.data: dict[str, list[dict]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_next: list[Exception | int] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        assert request.headers["X-Vault-Token"] == VAULT_TOKEN
        if self.fail_next:
            item = self.fail_next.pop(0)
            if isinstance(item, Exception):
                raise item
            return httpx.Response(item, json={"errors": ["simulated"]})
        _, _, mount, kind, *rest = request.url.path.split("/")
        path = "/".join(rest)
        versions = self.data.get(path, [])
        if kind == "data" and request.method == "GET":
            if not versions:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(200, json={"data": {"data": versions[-1], "metadata": {"version": len(versions)}}})
        if kind == "data" and request.method == "POST":
            body = json.loads(request.content)
            cas = (body.get("options") or {}).get("cas")
            if cas is not None and cas != len(versions):
                return httpx.Response(400, json={"errors": ["check-and-set parameter did not match the current version"]})
            self.data.setdefault(path, []).append(body["data"])
            return httpx.Response(200, json={"data": {"version": len(self.data[path]), "created_time": "2026-10-12T09:00:00Z"}})
        if kind == "metadata":
            if not versions:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(200, json={"data": {"current_version": len(versions), "updated_time": "2026-10-12T09:00:00Z"}})
        return httpx.Response(400)


def _kv_vault(tmp_path, fake: FakeKV) -> tuple[HashiCorpKV2Vault, Redactor]:
    token_file = tmp_path / "vault-token"
    token_file.write_text(VAULT_TOKEN, encoding="utf-8")
    settings = make_settings(tmp_path, vault_backend="hashicorp_kv2", vault_addr="http://vault.test.invalid:8200", vault_token_file=token_file)
    redactor = Redactor()
    client = httpx.Client(transport=httpx.MockTransport(fake.handler))
    return HashiCorpKV2Vault(settings=settings, redactor=redactor, client=client, sleep=lambda _s: None), redactor


def test_hashicorp_kv2_adapter_read_write_metadata(tmp_path):
    fake = FakeKV()
    vault, redactor = _kv_vault(tmp_path, fake)
    assert redactor.contains_registered_secret(VAULT_TOKEN)  # the vault token itself is redacted everywhere
    meta = vault.write_fields("vault://instagram/lumen/password", {"value": SecretValue("SYNTHETIC-kv-secret-1")}, cas=0)
    assert meta.version == 1
    assert vault.read("vault://instagram/lumen/password").reveal() == "SYNTHETIC-kv-secret-1"
    assert redactor.contains_registered_secret("SYNTHETIC-kv-secret-1")
    assert vault.metadata("vault://instagram/lumen/password").version == 1
    assert vault.metadata("vault://instagram/missing").exists is False
    with pytest.raises(VaultSecretNotFound):
        vault.read_fields("vault://instagram/missing")
    with pytest.raises(Exception, match="check-and-set"):
        vault.write_fields("vault://instagram/lumen/password", {"value": SecretValue("SYNTHETIC-2")}, cas=0)


def test_hashicorp_reads_retry_but_uncertain_writes_do_not(tmp_path):
    fake = FakeKV()
    vault, _ = _kv_vault(tmp_path, fake)
    vault.write_fields("vault://a/b", {"value": SecretValue("SYNTHETIC-1")})
    fake.fail_next = [503, httpx.ConnectError("refused")]
    assert vault.read("vault://a/b").reveal() == "SYNTHETIC-1"  # third attempt succeeds
    fake.calls.clear()
    fake.fail_next = [httpx.ReadTimeout("timed out after sending")]
    with pytest.raises(VaultUnavailable) as raised:
        vault.write_fields("vault://a/b", {"value": SecretValue("SYNTHETIC-2")})
    assert raised.value.outcome_uncertain is True and len(fake.calls) == 1  # never blindly retried
    fake.fail_next = [503, 503, 503]
    with pytest.raises(VaultUnavailable):
        vault.read("vault://a/b")


def test_meta_not_configured_is_unverified():
    check = MetaNotConfigured().check_instagram_link("biz", "handle")
    assert check.status == "unknown" and check.verification == VerificationLabel.UNVERIFIED


def _meta(tmp_path, responses: list) -> tuple[MetaGraphReadOnly, list[httpx.Request], Env]:
    env = Env(tmp_path)
    env.vault_put("devvault://meta/token", value="SYNTHETIC-meta-app-token-abc123")
    settings = make_settings(
        tmp_path, meta_integration="graph_readonly", meta_graph_api_version="v99.0", meta_business_id="biz-test-0001",
        meta_access_token_vault_ref="devvault://meta/token",
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    meta = MetaGraphReadOnly(
        settings=settings, vault=env.container.vault, redactor=env.container.redactor,
        client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _s: None,
    )
    return meta, seen, env


def test_meta_graph_readonly_against_simulated_transport(tmp_path):
    page = httpx.Response(200, json={"data": [{"id": "17841", "username": "lumenlabtestbrand"}]})
    meta, seen, env = _meta(tmp_path, [httpx.Response(500), page])
    check = meta.check_instagram_link("biz-test-0001", "LumenLabTestBrand")
    assert check.status == "linked" and check.verification == VerificationLabel.INTEGRATION_VERIFIED
    assert seen[-1].url.path == "/v99.0/biz-test-0001/instagram_accounts" and seen[-1].method == "GET"
    assert "SYNTHETIC-meta-app-token-abc123" not in env.read_logs()
    meta2, _, env2 = _meta(tmp_path / "b", [httpx.Response(200, json={"data": []})])
    assert meta2.check_instagram_link("biz-test-0001", "x").status == "not_linked"
    meta3, _, env3 = _meta(tmp_path / "c", [httpx.Response(503)] * 3)
    unavailable = meta3.check_instagram_link("biz-test-0001", "x")
    assert unavailable.status == "unknown" and unavailable.verification == VerificationLabel.UNVERIFIED
    for e in (env, env2, env3):
        e.container.engine.dispose()


class FakeMeta(MetaIntegration):
    name = "fake"
    configured = True

    def __init__(self, status: str):
        self.status = status

    def check_instagram_link(self, business_id: str, handle: str) -> MetaLinkCheck:
        label = VerificationLabel.INTEGRATION_VERIFIED
        return MetaLinkCheck(self.status, label, f"fake-meta:{business_id}", "simulated")

    def health(self):
        return {"status": "fake"}


def test_meta_integration_upgrades_or_blocks_human_confirmation(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.LINK_META_BUSINESS)
    env.container.provisioning.meta = FakeMeta("not_linked")
    with pytest.raises(ValidationFailed):
        env.complete_type(account, TaskType.LINK_META_BUSINESS, env.actor(team["owner"]))
    env.container.provisioning.meta = FakeMeta("linked")
    env.complete_type(account, TaskType.LINK_META_BUSINESS, env.actor(team["owner"]))
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.meta_link_verification == VerificationLabel.INTEGRATION_VERIFIED
        assert next(x for x in acc.steps if x.step.value == "meta_link").evidence_ref == "fake-meta:biz-test-0001"


class FakeSMTP:
    behaviour = "ok"
    instances: list = []

    def __init__(self, host, port, timeout):
        self.logged_in = None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, message):
        if FakeSMTP.behaviour == "refused":
            raise smtplib.SMTPRecipientsRefused({"x@y": (550, b"no")})
        if FakeSMTP.behaviour == "timeout":
            raise socket.timeout("timed out")


def test_smtp_notifier_outcomes(env):
    env.vault_put("devvault://smtp/password", value="SYNTHETIC-smtp-pass")
    settings = make_settings(env.tmp_path / "smtp", notification_backend="smtp", smtp_host="smtp.test.invalid", smtp_from="ops@testco.example", smtp_username="ops", smtp_password_vault_ref="devvault://smtp/password")
    notifier = SmtpNotifier(settings=settings, vault=env.container.vault, redactor=env.container.redactor, smtp_factory=FakeSMTP)
    FakeSMTP.behaviour = "ok"
    assert notifier.send(to_email="a@testco.example", subject="s", body="b").status == "sent"
    assert FakeSMTP.instances[-1].logged_in == ("ops", "SYNTHETIC-smtp-pass")
    FakeSMTP.behaviour = "refused"
    refused = notifier.send(to_email="a@testco.example", subject="s", body="b")
    assert refused.status == "failed" and not refused.retryable
    FakeSMTP.behaviour = "timeout"
    assert notifier.send(to_email="a@testco.example", subject="s", body="b").status == "uncertain"


def test_integrations_endpoint_reports_honest_status(env, team):
    body = env.client().get("/api/v1/integrations", headers=env.headers(team["owner"], OperatorRole.VIEWER)).json()
    assert body["instagram"]["status"] == "no_automation_by_design"
    assert body["vault"]["backend"] == "dev_memory" and body["vault"]["production_grade"] is False
    assert body["meta"]["configured"] is False and body["notifications"]["configured"] is False
    assert body["email_alias_provisioning"]["status"] == "not_integrated"
