"""Weekly security audit: verification labels, deduplication, remediation, scheduling."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select

from app.enums import (
    AssignmentStatus,
    AuditRunStatus,
    AuditTrigger,
    ControlStatus,
    FindingStatus,
    OperatorRole,
    PersonStatus,
    RoleName,
    Severity,
    TaskOrigin,
    TaskPriority,
    TaskType,
    TwoFactorMethod,
    VerificationLabel,
)
from app.models import (
    AccountAssignment,
    AuditFinding,
    AuditRun,
    HumanTask,
    InstagramAccount,
    Person,
)
from tests.conftest import BACKUP_REF, OUTCOMES, T0, Env


def _audit(env: Env, actor_id: str, key: str | None = None) -> AuditRun:
    return env.container.audits.run(
        env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(actor_id, OperatorRole.ADMIN), idempotency_key=key
    )


def _open(env: Env) -> list[AuditFinding]:
    with env.container.uow() as s:
        return list(s.scalars(select(AuditFinding).where(AuditFinding.status == FindingStatus.OPEN).order_by(AuditFinding.check_name)))


def _checks(run: AuditRun) -> dict[str, dict]:
    return {c["fingerprint"]: c for c in run.summary["accounts"][0]["checks"]}


def test_mid_provisioning_missing_evidence_is_unverified_not_failure(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ENABLE_TWO_FACTOR)
    run = _audit(env, team["security"])
    checks = _checks(run)
    tfa = checks["two_factor_enabled"]
    assert tfa["outcome"] == "finding" and tfa["verification"] == "unverified" and tfa["severity"] == "medium"
    assert "not evidence that 2FA is disabled" in tfa["description"]
    assert checks["backup_codes_in_vault"]["verification"] == "unverified"
    assert checks["recovery_email_company_controlled"]["outcome"] == "pass"
    assert checks["provisioning_tasks_complete"]["verification"] == "integration_verified"
    # Covered by the open provisioning task - no duplicate remediation task is created.
    finding = next(f for f in _open(env) if f.check_name == "two_factor_enabled")
    provisioning_task = env.open_task(account, TaskType.ENABLE_TWO_FACTOR)
    assert finding.remediation_task_id == provisioning_task.id
    assert len(env.tasks(account, TaskType.ENABLE_TWO_FACTOR)) == 1


def test_fully_provisioned_account_passes_with_honest_labels(env, team, account):
    env.provision(account, team["owner"])
    run = _audit(env, team["security"])
    checks = _checks(run)
    assert _open(env) == []
    assert checks["backup_codes_in_vault"]["verification"] == "integration_verified"  # dev vault metadata
    assert checks["two_factor_enabled"]["verification"] == "human_confirmed"
    assert checks["meta_business_association"]["verification"] == "human_confirmed"
    assert "not configured" in checks["meta_business_association"]["description"]
    assert all(c["outcome"] in ("pass", "not_applicable") for c in checks.values())


def test_sms_two_factor_is_low_severity_and_remediated(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ENABLE_TWO_FACTOR)
    env.complete_type(account, TaskType.ENABLE_TWO_FACTOR, env.actor(team["owner"]), {**OUTCOMES[TaskType.ENABLE_TWO_FACTOR], "two_factor_method": "sms"})
    for task_type in (TaskType.COMPLETE_PROFILE, TaskType.CONVERT_TO_BUSINESS, TaskType.LINK_META_BUSINESS, TaskType.ASSIGN_PEOPLE_ROLES):
        env.complete_type(account, task_type, env.actor(team["owner"]))
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "two_factor_enabled")
    assert finding.severity == Severity.LOW and finding.verification == VerificationLabel.HUMAN_CONFIRMED
    with env.container.uow() as s:
        task = s.get(HumanTask, finding.remediation_task_id)
        assert task.origin == TaskOrigin.AUDIT and task.owner_id == team["owner"] and task.priority == TaskPriority.LOW
        assert task.due_at == T0 + timedelta(hours=336)


def test_missing_vault_entry_is_integration_verified_and_remediation_resolves_it(env, team, account):
    env.provision(account, team["owner"])
    env.container.vault.delete(BACKUP_REF)
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "backup_codes_in_vault")
    assert finding.severity == Severity.HIGH and finding.verification == VerificationLabel.INTEGRATION_VERIFIED
    task = next(t for t in env.tasks(account, TaskType.STORE_BACKUP_CODES))
    assert task.origin == TaskOrigin.AUDIT and task.priority == TaskPriority.HIGH and task.payload["finding_id"] == finding.id
    new_ref = "devvault://instagram/lumenlab/backup-codes-v2"
    env.vault_put(new_ref, value="SYNTHETIC-backup-codes-set-2")
    env.complete(task.id, env.actor(team["owner"]), {"backup_codes_vault_ref": new_ref, "codes_regenerated": True}, evidence="new set stored in vault (test)")
    assert not [f for f in _open(env) if f.check_name == "backup_codes_in_vault"]  # re-checked immediately
    with env.container.uow() as s:
        resolved = s.get(AuditFinding, finding.id)
        assert resolved.status == FindingStatus.RESOLVED and resolved.resolved_at is not None


def test_repeated_audits_deduplicate_findings_and_tasks(env, team, account):
    env.provision(account, team["owner"])
    env.container.vault.delete(BACKUP_REF)
    for _ in range(3):
        _audit(env, team["security"])
    findings = [f for f in _open(env) if f.check_name == "backup_codes_in_vault"]
    assert len(findings) == 1 and findings[0].occurrence_count == 3
    assert len(env.tasks(account, TaskType.STORE_BACKUP_CODES)) == 1


def test_completed_remediation_with_persisting_finding_gets_next_generation(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        s.get(InstagramAccount, account).two_factor_method = TwoFactorMethod.SMS
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "two_factor_enabled")
    first_task = finding.remediation_task_id
    # Human "completes" but still reports SMS: the finding stays open; the next audit opens generation 2.
    env.complete(first_task, env.actor(team["owner"]), {**OUTCOMES[TaskType.ENABLE_TWO_FACTOR], "two_factor_method": "sms"})
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "two_factor_enabled")
    assert finding.remediation_task_id != first_task and finding.remediation_generation == 2


def test_stale_access_detected_and_review_resolves_it(env, team, account):
    env.provision(account, team["owner"])
    env.clock.advance(days=31)
    _audit(env, team["security"])
    stale = next(f for f in _open(env) if f.check_name == "access_records_fresh")
    assert stale.verification == VerificationLabel.UNVERIFIED and stale.severity == Severity.MEDIUM
    review = env.open_task(account, TaskType.REVIEW_ACCESS)
    env.complete(review.id, env.actor(team["owner"]), {"access_matches_register": True}, evidence="compared Business Suite people list (test)")
    assert not [f for f in _open(env) if f.check_name == "access_records_fresh"]


def test_offboarded_person_with_active_role_is_critical(env, team, account):
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.INSIGHTS_ANALYST, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    with env.container.uow() as s:
        s.get(Person, team["departing"]).status = PersonStatus.OFFBOARDED
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "people_roles_match_register")
    assert finding.severity == Severity.CRITICAL


def test_non_company_recovery_contact_is_high(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        s.get(InstagramAccount, account).recovery_email_control = ControlStatus.NON_COMPANY
    _audit(env, team["security"])
    finding = next(f for f in _open(env) if f.check_name == "recovery_email_company_controlled")
    assert finding.severity == Severity.HIGH and finding.verification == VerificationLabel.HUMAN_CONFIRMED
    assert env.open_task(account, TaskType.CONFIRM_RECOVERY_CONTACTS)


def test_no_active_admin_is_flagged(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        for a in s.scalars(select(AccountAssignment).where(AccountAssignment.account_id == account)):
            a.status = AssignmentStatus.REMOVED
    _audit(env, team["security"])
    assert any(f.fingerprint == "people_roles_match_register:no_admin" for f in _open(env))


def test_weekly_run_is_once_per_iso_week(env, team, account):
    audits = env.container.audits
    actor = env.actor(team["security"], OperatorRole.ADMIN)
    env.clock.set(T0 - timedelta(hours=1))  # Monday 08:00, before the 09:00 schedule
    assert audits.run_weekly_if_due(env.container.session_factory, actor=actor) is None
    env.clock.set(T0 + timedelta(minutes=5))
    first = audits.run_weekly_if_due(env.container.session_factory, actor=actor)
    again = audits.run_weekly_if_due(env.container.session_factory, actor=actor)
    assert first.id == again.id and first.idempotency_key == "weekly:2026-W42"
    env.clock.advance(days=7)
    nxt = audits.run_weekly_if_due(env.container.session_factory, actor=actor)
    assert nxt.id != first.id and nxt.idempotency_key == "weekly:2026-W43"
    with env.container.uow() as s:
        assert s.scalar(select(func.count(AuditRun.id))) == 2


def test_audit_writes_timestamped_json_and_markdown(env, team, account):
    run = _audit(env, team["security"])
    data = json.loads(Path(run.report_json_path).read_text(encoding="utf-8"))
    assert data["report_meta"]["data_classification"] == "SYNTHETIC_DEMO_DATA"
    assert set(data["report_meta"]["verification_labels"]) == {"integration_verified", "human_confirmed", "unverified"}
    assert data["audit_run"]["id"] == run.id and "unresolved_issues" in data
    md = Path(run.report_md_path).read_text(encoding="utf-8")
    assert "# Security audit report" in md and "Open findings" in md
    assert run.status == AuditRunStatus.COMPLETED


def test_audit_api_permissions_and_idempotency_key(env, team, account):
    client = env.client()
    assert client.post("/api/v1/audits/run", headers=env.headers(team["operator"], OperatorRole.OPERATOR)).status_code == 403
    auditor = env.headers(team["security"], OperatorRole.AUDITOR)
    first = client.post("/api/v1/audits/run", headers={**auditor, "Idempotency-Key": "demo-run-1"})
    second = client.post("/api/v1/audits/run", headers={**auditor, "Idempotency-Key": "demo-run-1"})
    assert first.status_code == 201 and second.status_code == 200 and first.json()["id"] == second.json()["id"]
    findings = client.get("/api/v1/audits/findings", headers=auditor).json()
    assert findings and all(f["verification"] in ("integration_verified", "human_confirmed", "unverified") for f in findings)
    report = client.get(f"/api/v1/audits/{first.json()['id']}", headers=auditor).json()
    assert report["audit_run"]["status"] == "completed"
