"""Reports and records must say honestly where the test resources came from."""

from __future__ import annotations

from sqlalchemy import select

from app.enums import (
    AuditTrigger,
    ControlStatus,
    OperatorRole,
    RoleName,
    Severity,
    TaskType,
    VerificationLabel,
)
from app.models import AuditFinding, InstagramAccount
from tests.conftest import OUTCOMES, PROFILE, Env


def _live_account(env: Env) -> tuple[str, str]:
    owner = env.person("Account Owner")
    with env.container.uow() as s:
        account, _ = env.container.provisioning.create_account(
            s, brand_name="Live Test Brand", owner_id=owner, actor=env.actor(owner, OperatorRole.ADMIN), profile=PROFILE, is_synthetic=False
        )
        return owner, account.id


def test_candidate_provided_environment_is_labelled_in_records_and_reports(tmp_path):
    env = Env(tmp_path, environment_label="candidate_provided_test_environment")
    owner, account_id = _live_account(env)
    with env.container.uow() as s:
        assert s.get(InstagramAccount, account_id).environment == "candidate_provided_test_environment"
        meta = env.container.reports.report_meta(s, "Account register")
    assert meta["data_classification"] == "CANDIDATE_PROVIDED_TEST_ENVIRONMENT"
    assert any("not company-authorised" in note for note in meta["notes"])
    client = env.client()
    client.post("/login", data={"token": env.token(owner, OperatorRole.VIEWER)})
    assert "resources: candidate provided test environment" in client.get("/dashboard").text
    env.container.engine.dispose()


def test_personal_phone_substitute_is_recorded_and_flagged_not_hidden(env, team, account):
    owner = env.actor(team["owner"], OperatorRole.ADMIN)
    env.seed_vault()
    env.add_role(account, team["owner"], RoleName.BUSINESS_ADMIN, team["owner"])
    for task_type in (TaskType.HANDLE_AVAILABILITY_CHECK, TaskType.ASSIGN_COMPANY_EMAIL):
        env.complete_type(account, task_type, owner)
    env.complete_type(
        account, TaskType.ASSIGN_COMPANY_PHONE, owner,
        {"phone_assignment_ref": "SELF-PHONE-1", "phone_number": "+447700900123", "number_control": "personal_number_substitute"},
    )
    for task_type in (
        TaskType.ACCOUNT_SIGNUP, TaskType.ACCOUNT_VERIFICATION, TaskType.ENABLE_TWO_FACTOR, TaskType.COMPLETE_PROFILE,
        TaskType.CONVERT_TO_BUSINESS, TaskType.LINK_META_BUSINESS, TaskType.ASSIGN_PEOPLE_ROLES,
    ):
        env.complete_type(account, task_type, owner, OUTCOMES[task_type])
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.company_phone_control == ControlStatus.NON_COMPANY
        assert acc.recovery_phone_control == ControlStatus.NON_COMPANY  # the confirmation cannot launder it
    env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=owner)
    with env.container.uow() as s:
        finding = s.scalar(select(AuditFinding).where(AuditFinding.check_name == "recovery_phone_company_controlled"))
        assert finding.severity == Severity.HIGH and finding.verification == VerificationLabel.HUMAN_CONFIRMED
        assert finding.remediation_task_id is not None


def test_company_environment_is_the_default_label(tmp_path):
    env = Env(tmp_path)
    _live_account(env)
    with env.container.uow() as s:
        assert env.container.reports.report_meta(s, "x")["data_classification"] == "COMPANY_TEST_ENVIRONMENT"
    env.container.engine.dispose()
