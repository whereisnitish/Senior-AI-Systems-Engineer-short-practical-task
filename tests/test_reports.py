"""Account register, audit/offboarding reports and the redacted run log."""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.enums import AuditTrigger, OperatorRole, TaskType
from app.services.report_service import SecretLeakDetected


def _export(env):
    with env.container.uow() as s:
        return env.container.reports.export_all(s)


def test_account_register_exports_json_markdown_csv(env, team, account):
    env.provision(account, team["owner"])
    written = _export(env)
    paths = written["account_register"]
    assert [p.rsplit(".", 1)[1] for p in paths] == ["json", "md", "csv"]
    data = json.loads(open(paths[0], encoding="utf-8").read())
    assert data["report_meta"]["data_classification"] == "SYNTHETIC_DEMO_DATA"
    acc = data["accounts"][0]
    assert acc["provisioning_status"] == "provisioned"
    assert acc["two_factor"] == {"status": "enabled", "method": "authenticator_app", "verification": "human_confirmed"}
    assert acc["backup_codes"]["vault_ref"].startswith("devvault://") and acc["backup_codes"]["verification"] == "integration_verified"
    assert acc["recovery"]["email_control"] == "company_controlled"
    assert acc["people_and_roles"][0]["role"] == "business_admin"
    assert acc["company_contacts"]["email_hint"] == "i***@testco.example"
    md = open(paths[1], encoding="utf-8").read()
    assert "# Account register" in md and "SYNTHETIC_DEMO_DATA" in md and "### People and roles" in md
    rows = list(csv.DictReader(io.StringIO(open(paths[2], encoding="utf-8").read())))
    assert rows[0]["status"] == "provisioned" and rows[0]["handle"] == "lumenlabtestbrand"


def test_register_reflects_incomplete_state_honestly(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_VERIFICATION)
    with env.container.uow() as s:
        acc = env.container.reports.account_register(s)["accounts"][0]
    assert acc["provisioning_status"] == "awaiting_verification"
    assert acc["provisioning_gaps"] and any("platform_verification" in g for g in acc["provisioning_gaps"])
    assert acc["recovery"]["email_verification"] == "unverified" and acc["two_factor"]["status"] == "unknown"
    assert [t["task_type"] for t in acc["open_tasks"]] == ["account_verification"]


def test_offboarding_report_has_completed_pending_blocked(env, team, account):
    from tests.test_offboarding import _setup, _start

    _setup(env, team, account)
    case_id, _ = _start(env, team)
    written = _export(env)
    json_path, md_path = written["offboarding_reports"][0]
    data = json.loads(open(json_path, encoding="utf-8").read())
    case = data["case"]
    assert case["completed"] and case["pending"] and case["blocked"]
    assert all(a["verification"] in ("integration_verified", "human_confirmed", "unverified") for a in case["completed"])
    assert data["outstanding_risks"]
    md = open(md_path, encoding="utf-8").read()
    assert "## Blocked" in md and "NO_PROXY_PROVIDER_ADMIN" in md


def test_audit_report_included_in_export(env, team, account):
    env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.CLI, actor=env.actor(team["security"], OperatorRole.ADMIN))
    written = _export(env)
    assert written["audit_report_latest"][0].endswith("audit_report_latest.json")
    data = json.loads(open(written["audit_report_latest"][0], encoding="utf-8").read())
    assert data["open_findings"] and data["check_results"][0]["checks"]
    for finding in data["open_findings"]:
        assert finding["severity"] and finding["verification"] and "remediation_task" in finding


def test_run_log_export_is_structured_redacted_jsonl(env, team, account):
    env.provision(account, team["owner"])
    path = _export(env)["run_log"]
    lines = [json.loads(line) for line in open(path, encoding="utf-8").read().splitlines()]
    assert lines
    completed = [line for line in lines if line["event"] == "task.completed"]
    assert completed
    for field in ("ts", "correlation_id", "event", "account_id", "task_id", "action", "outcome", "verification_source"):
        assert field in completed[0]
    text = open(path, encoding="utf-8").read()
    for secret in ("SYNTHETIC-password-lumenlab-1", "SYNTHETIC-backup-codes-set-1"):
        assert secret not in text


def test_leak_guard_deletes_a_report_containing_a_registered_secret(env, tmp_path):
    env.container.redactor.register_secret("SYNTHETIC-guard-test-value")
    path = tmp_path / "bad.md"
    path.write_text("oops SYNTHETIC-guard-test-value", encoding="utf-8")
    with pytest.raises(SecretLeakDetected):
        env.container.reports.assert_no_secrets(path)
    assert not path.exists()


def test_report_api(env, team, account):
    client = env.client()
    viewer = env.headers(team["owner"], OperatorRole.VIEWER)
    md = client.get("/api/v1/reports/account-register", params={"format": "md"}, headers=viewer)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert client.get("/api/v1/reports/account-register", params={"format": "csv"}, headers=viewer).status_code == 200
    assert client.post("/api/v1/reports/export", headers=viewer).status_code == 403
    export = client.post("/api/v1/reports/export", headers=env.headers(team["security"], OperatorRole.AUDITOR))
    assert export.status_code == 200 and export.json()["account_register"]
    log = client.get("/api/v1/reports/run-log", params={"limit": 5}, headers=env.headers(team["security"], OperatorRole.ADMIN))
    assert log.status_code == 200 and len(log.json()) <= 5
