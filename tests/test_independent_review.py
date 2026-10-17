"""Regressions for defects found in the independent pre-submission review (2026-10-17).

Each test reproduces one defect against the code as it was before the fix:

* the roles audit check reported ``pass / human_confirmed`` when no role had been
  granted or confirmed (seen in the live audit report);
* a roles finding upgraded an ``unverified`` assignment to ``human_confirmed``;
* a vault outage at the moment a rotation was confirmed skipped the
  "version must increase" check and completed the action as human-confirmed;
* vault access recorded for a departing person after the final verification was
  issued let the person be marked offboarded with removals still pending;
* HashiCorp KV v2 metadata treated a deleted/destroyed current version as present;
* the Meta check reported a verified "not linked" after reading only part of the
  listing, and followed paging links to other hosts with the token attached;
* a notification backlog for tasks already closed was sent once a provider was
  configured (misleading reminders);
* a personal-provider mailbox could only be recorded by whitelisting its domain,
  which made the audit report it as company-controlled.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.enums import (
    AuditTrigger,
    ControlStatus,
    CredentialKind,
    DeliveryStatus,
    NotificationKind,
    OffboardingActionStatus,
    OffboardingActionType,
    OffboardingCaseStatus,
    OperatorRole,
    PersonStatus,
    RoleName,
    Severity,
    TaskStatus,
    TaskType,
    VerificationLabel,
)
from app.errors import ValidationFailed
from app.integrations.notifications.base import SendResult
from app.integrations.vault import VaultUnavailable, inspect_ref
from app.models import AccountAssignment, AuditFinding, HumanTask, InstagramAccount, Notification, Person
from tests.conftest import OUTCOMES, PASSWORD_REF, Env, make_settings
from tests.test_integrations import _kv_vault, _meta
from tests.test_offboarding import _by_type, _complete_offboarding_task, _setup, _start
from tests.test_reminders import _notes, _task


def _audit(env: Env, admin: str):
    return env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(admin, OperatorRole.ADMIN))


def _role_checks(run) -> list[dict]:
    return [c for c in run.summary["accounts"][0]["checks"] if c["check_name"] == "people_roles_match_register"]


# ---------------------------------------------------------------- audit labels
def test_roles_check_claims_nothing_before_any_role_is_granted(env, team, account):
    env.add_role(account, team["owner"], RoleName.BUSINESS_ADMIN, team["owner"])  # requested, never granted
    checks = _role_checks(_audit(env, team["security"]))
    assert len(checks) == 1
    assert checks[0]["outcome"] == "not_applicable" and checks[0]["verification"] == "unverified"
    assert "requested" in checks[0]["description"]


def test_roles_pass_after_confirmation_is_human_confirmed(env, team, account):
    env.provision(account, team["owner"])
    checks = _role_checks(_audit(env, team["security"]))
    assert [(c["outcome"], c["verification"]) for c in checks] == [("pass", "human_confirmed")]


def test_roles_finding_keeps_the_assignments_own_label(env, team, account):
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.INSIGHTS_ANALYST, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    with env.container.uow() as s:
        s.get(Person, team["departing"]).status = PersonStatus.OFFBOARDED
        assignment = s.scalar(select(AccountAssignment).where(AccountAssignment.person_id == team["departing"]))
        assignment.verification = VerificationLabel.UNVERIFIED  # nobody ever confirmed this grant
    _audit(env, team["security"])
    with env.container.uow() as s:
        finding = s.scalar(select(AuditFinding).where(AuditFinding.check_name == "people_roles_match_register"))
        assert finding.severity == Severity.CRITICAL and finding.verification == VerificationLabel.UNVERIFIED


# ---------------------------------------------------------------- offboarding
def test_vault_outage_at_rotation_confirmation_blocks_instead_of_skipping_the_version_check(env, team, account, monkeypatch):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    assert rotation.detail["baseline_version"] == 1

    def outage(_ref):
        raise VaultUnavailable("simulated vault outage")

    monkeypatch.setattr(env.container.vault, "metadata", outage)
    _complete_offboarding_task(env, rotation, team["owner"])
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    assert rotation.status == OffboardingActionStatus.BLOCKED and rotation.blocker_code == "VAULT_UNAVAILABLE"

    monkeypatch.undo()  # the vault is back and the human really did store a new version
    env.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-2")
    with env.container.uow() as s:
        env.container.offboarding.reconcile(s, env.container.offboarding.get_case(s, case_id), actor=env.actor(team["security"], OperatorRole.ADMIN))
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    assert rotation.status == OffboardingActionStatus.COMPLETED
    assert rotation.verification == VerificationLabel.INTEGRATION_VERIFIED and "v1->v2" in rotation.evidence_ref


def _role_only_departure(env: Env, team: dict[str, str], account: str) -> str:
    """Departing tester holds only the temporary test role; their role removal is confirmed."""
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.TEMPORARY_TEST_ROLE, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    case_id, _ = _start(env, team)
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    _complete_offboarding_task(env, removal, removal.owner_id)
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.task_id is not None  # the final verification has been issued
    return case_id


def test_access_found_after_final_verification_reopens_it_and_holds_the_register(env, team, account):
    case_id = _role_only_departure(env, team, account)
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    with env.container.uow() as s:  # discovered late: the tester could read the password entry all along
        env.container.provisioning.add_credential_access(
            s, person_id=team["departing"], vault_ref=PASSWORD_REF, credential_kind=CredentialKind.INSTAGRAM_PASSWORD,
            account_id=account, actor=env.actor(team["security"], OperatorRole.ADMIN),
        )
    _complete_offboarding_task(env, verify, team["security"])  # verifier attests before reconciliation ran

    with env.container.uow() as s:
        assert s.get(Person, team["departing"]).status == PersonStatus.DEPARTING
    register = _by_type(env, case_id, OffboardingActionType.UPDATE_REGISTER)[0]
    assert register.status != OffboardingActionStatus.COMPLETED
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.status == OffboardingActionStatus.PENDING and verify.task_id is None and verify.detail["waiting_on"]
    assert verify.detail["reopened"] == 1

    env.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-2")
    for action_type in (OffboardingActionType.REMOVE_VAULT_ACCESS, OffboardingActionType.ROTATE_CREDENTIAL):
        for action in _by_type(env, case_id, action_type):
            _complete_offboarding_task(env, action, action.owner_id)
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.task_id is not None and verify.task_generation == 2  # a fresh verification covering the new access
    _complete_offboarding_task(env, verify, team["security"])
    with env.container.uow() as s:
        assert s.get(Person, team["departing"]).status == PersonStatus.OFFBOARDED
        assert env.container.offboarding.get_case(s, case_id).status == OffboardingCaseStatus.COMPLETED


def test_recording_access_for_a_departing_person_via_api_updates_the_open_case(env, team, account):
    case_id = _role_only_departure(env, team, account)
    verify_task_id = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0].task_id
    response = env.client().post(
        f"/api/v1/people/{team['departing']}/credential-access",
        headers=env.headers(team["security"], OperatorRole.ADMIN),
        json={"vault_ref": PASSWORD_REF, "credential_kind": "instagram_password", "account_id": account},
    )
    assert response.status_code in (200, 201), response.text
    removals = _by_type(env, case_id, OffboardingActionType.REMOVE_VAULT_ACCESS)
    assert len(removals) == 1 and removals[0].task_id is not None
    with env.container.uow() as s:  # the open verification request no longer covers everything: withdrawn
        assert s.get(HumanTask, verify_task_id).status == TaskStatus.CANCELLED
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.status == OffboardingActionStatus.PENDING and verify.task_id is None


# ---------------------------------------------------------------- vault and Meta adapters
class _KVMetadataOnly:
    def __init__(self, versions: dict[str, dict], current: int):
        self.versions, self.current = versions, current

    def handler(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"current_version": self.current, "updated_time": "2026-10-12T09:00:00Z", "versions": self.versions}}
        )


@pytest.mark.parametrize(
    ("current", "expected_exists"),
    [
        ({"deletion_time": "", "destroyed": False}, True),
        ({"deletion_time": "2026-10-12T10:00:00Z", "destroyed": False}, False),  # soft-deleted
        ({"deletion_time": "", "destroyed": True}, False),  # destroyed
        ({"deletion_time": "2999-01-01T00:00:00Z", "destroyed": False}, True),  # deletion only scheduled
    ],
)
def test_kv2_metadata_reports_a_deleted_current_version_as_missing(tmp_path, current, expected_exists):
    fake = _KVMetadataOnly({"1": {"deletion_time": "", "destroyed": False}, "2": current}, current=2)
    vault, _ = _kv_vault(tmp_path, fake)
    assert vault.metadata("vault://instagram/lumen/backup-codes").exists is expected_exists
    inspection = inspect_ref(vault, "vault://instagram/lumen/backup-codes")
    assert inspection.exists is expected_exists and inspection.label == VerificationLabel.INTEGRATION_VERIFIED


def test_meta_listing_cut_off_at_the_page_cap_is_unverified_not_a_verified_negative(tmp_path):
    next_url = "https://graph.facebook.com/v99.0/biz-test-0001/instagram_accounts?after=cursor"
    pages = [httpx.Response(200, json={"data": [{"id": str(i), "username": f"other{i}"}], "paging": {"next": next_url}}) for i in range(6)]
    meta, seen, env = _meta(tmp_path, pages)
    check = meta.check_instagram_link("biz-test-0001", "lumenlabtestbrand")
    assert check.status == "unknown" and check.verification == VerificationLabel.UNVERIFIED
    assert len(seen) == 5
    env.container.engine.dispose()


def test_meta_paging_link_to_another_host_is_not_followed_with_the_token(tmp_path):
    page = httpx.Response(200, json={"data": [], "paging": {"next": "https://attacker.example/collect?after=x"}})
    meta, seen, env = _meta(tmp_path, [page, httpx.Response(200, json={"data": []})])
    check = meta.check_instagram_link("biz-test-0001", "lumenlabtestbrand")
    assert check.status == "unknown" and check.verification == VerificationLabel.UNVERIFIED
    assert [r.url.host for r in seen] == ["graph.facebook.com"]
    env.container.engine.dispose()


# ---------------------------------------------------------------- notifications
class _AcceptAll:
    name = "accept_all"
    configured = True

    def __init__(self):
        self.sent: list[str] = []

    def send(self, *, to_email: str, subject: str, body: str) -> SendResult:
        self.sent.append(subject)
        return SendResult("sent", "accepted")


def test_backlog_for_closed_tasks_is_superseded_not_sent_when_a_provider_arrives(env, team):
    open_task = _task(env, team["operator"], key="manual:still-open")
    closed_task = _task(env, team["operator"], key="manual:finished")
    env.container.notifications.dispatch_pending(env.container.session_factory)  # no provider yet
    env.complete(closed_task, env.actor(team["operator"]), {"done": True}, evidence="done in admin console (test)")
    notifier = _AcceptAll()
    env.container.notifications.notifier = notifier
    summary = env.container.notifications.dispatch_pending(env.container.session_factory)
    assert summary.sent == 1 and summary.superseded == 1 and len(notifier.sent) == 1
    assert _notes(env, open_task, NotificationKind.ASSIGNMENT)[0].delivery_status == DeliveryStatus.SENT
    stale = _notes(env, closed_task, NotificationKind.ASSIGNMENT)[0]
    assert stale.delivery_status == DeliveryStatus.SUPERSEDED and "completed" in stale.last_error
    with env.container.uow() as s:
        assert s.scalar(select(Notification).where(Notification.id == stale.id)).sent_at is None


# ---------------------------------------------------------------- authentication throttle
def test_repeated_bad_tokens_are_throttled_then_released(env, team):
    client = env.client()
    good = env.headers(team["owner"], OperatorRole.VIEWER)
    bad = {"Authorization": "Bearer iom_" + "x" * 40}
    for _ in range(env.settings.auth_max_failed_attempts):
        assert client.get("/api/v1/accounts", headers=bad).status_code == 401
    blocked = client.get("/api/v1/accounts", headers=good)  # refused before any token is checked
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0
    assert blocked.json()["error"]["code"] == "too_many_attempts"
    login = client.post("/login", data={"token": "iom_" + "y" * 40})  # the dashboard sign-in shares the limit
    assert login.status_code == 429 and "Too many failed sign-in attempts" in login.text
    env.clock.advance(seconds=env.settings.auth_failure_window_seconds)
    assert client.get("/api/v1/accounts", headers=good).status_code == 200
    assert "auth.failed_attempt" in env.read_logs() and "iom_xxxx" not in env.read_logs()


def test_a_successful_sign_in_clears_earlier_failures(env, team):
    client = env.client()
    good = env.headers(team["owner"], OperatorRole.VIEWER)
    for _ in range(3):
        for _ in range(env.settings.auth_max_failed_attempts - 1):
            client.get("/api/v1/accounts", headers={"Authorization": "Bearer iom_" + "z" * 40})
        assert client.get("/api/v1/accounts", headers=good).status_code == 200


# ---------------------------------------------------------------- consumer mail domains
def test_settings_and_live_env_script_refuse_consumer_mail_domains(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="consumer mail domains"):
        make_settings(tmp_path, company_email_domains="testco.example,Gmail.com")
    import scripts.make_live_env as make_live_env

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["make_live_env", "--meta-business-id", "1234567890", "--email-domain", "gmail.com"])
    with pytest.raises(SystemExit, match="consumer mail domain"):
        make_live_env.main()
    assert not (tmp_path / ".env").exists()


# ---------------------------------------------------------------- business conversion (gap: previously untested)
def test_creator_account_does_not_complete_the_business_conversion(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.CONVERT_TO_BUSINESS)
    with pytest.raises(ValidationFailed):
        env.complete_type(account, TaskType.CONVERT_TO_BUSINESS, env.actor(team["owner"]), {"account_type": "creator", "category_set": True})
    assert env.open_task(account, TaskType.CONVERT_TO_BUSINESS).status == TaskStatus.PENDING
    with env.container.uow() as s:
        assert s.get(InstagramAccount, account).business_account_status.value == "not_started"


# ---------------------------------------------------------------- submission packaging
def test_submission_package_excludes_local_state_and_refuses_known_secrets():
    from scripts.package_submission import _excluded, _scan

    for rel in (".env", ".env.demo", "data/live.db", "data/live_owner_token.local.txt", "data/demo_tokens.local.json",
                "logs/live/run_log.jsonl", ".venv/Lib/site.py", "config/proxies.json", "app/__pycache__/main.cpython-311.pyc",
                "vault.exe", "vault-data/core/_seal-config", "secrets/vault-token"):
        assert _excluded(rel), rel
    for rel in (".env.example", "app/main.py", "reports/live/audit/audit_report_x.md", "config/proxies.example.json", "README.md"):
        assert not _excluded(rel), rel
    known = {"APP_SECRET_KEY from .env": "k3y-" + "x" * 40}
    assert _scan("reports/live/account_register.md", "leaked k3y-" + "x" * 40 + " here", known) == [
        "reports/live/account_register.md: contains APP_SECRET_KEY from .env"
    ]
    token_shaped = "iom_" + "A1b2" * 6
    assert _scan("README.md", f"Bearer {token_shaped}", {})  # token formats are refused outside tests/
    assert _scan("tests/test_x.py", f"Bearer {token_shaped}", {}) == []  # synthetic fixtures are expected there


# ---------------------------------------------------------------- personal mailbox substitute
def test_personal_mailbox_substitute_is_recorded_and_flagged_not_laundered(env, team, account):
    owner = env.actor(team["owner"], OperatorRole.ADMIN)
    env.seed_vault()
    env.add_role(account, team["owner"], RoleName.BUSINESS_ADMIN, team["owner"])
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, owner)
    # Not an approved company domain, but declared honestly as a substitute: accepted, and flagged.
    env.complete_type(
        account, TaskType.ASSIGN_COMPANY_EMAIL, owner,
        {"email_assignment_ref": "SELF-MAIL-1", "email_address": "brand.test@gmail.com", "mailbox_control": "personal_provider_substitute"},
    )
    for task_type in (
        TaskType.ASSIGN_COMPANY_PHONE, TaskType.ACCOUNT_SIGNUP, TaskType.ACCOUNT_VERIFICATION, TaskType.ENABLE_TWO_FACTOR,
        TaskType.COMPLETE_PROFILE, TaskType.CONVERT_TO_BUSINESS, TaskType.LINK_META_BUSINESS, TaskType.ASSIGN_PEOPLE_ROLES,
    ):
        env.complete_type(account, task_type, owner, OUTCOMES[task_type])
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.company_email_control == ControlStatus.NON_COMPANY
        assert acc.recovery_email_control == ControlStatus.NON_COMPANY  # the verification step cannot launder it
    _audit(env, team["security"])
    with env.container.uow() as s:
        finding = s.scalar(select(AuditFinding).where(AuditFinding.check_name == "recovery_email_company_controlled"))
        assert finding.severity == Severity.HIGH and finding.verification == VerificationLabel.HUMAN_CONFIRMED


def test_consumer_mailbox_can_never_be_recorded_as_company_controlled(tmp_path):
    env = Env(tmp_path, company_email_domains="")  # even with no company domain list configured
    owner = env.person("Account Owner", responsibilities=("security_owner",))
    account = env.create_account(owner)
    actor = env.actor(owner, OperatorRole.ADMIN)
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, actor)
    for control in ("company_controlled", "dedicated_test_mailbox"):
        with pytest.raises(ValidationFailed, match="personal-provider mailbox"):
            env.complete_type(
                account, TaskType.ASSIGN_COMPANY_EMAIL, actor,
                {"email_assignment_ref": "SELF-1", "email_address": "brand@gmail.com", "mailbox_control": control},
            )
    env.container.engine.dispose()


def test_audit_flags_a_consumer_mailbox_already_recorded_as_company_controlled(env, team, account):
    """Records made before the guard existed (as in the live run) are surfaced, before and after signup."""
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        acc.company_email_domain, acc.company_email_control, acc.company_email_ref = "gmail.com", ControlStatus.COMPANY_CONTROLLED, "SELF-1"
    _audit(env, team["security"])
    with env.container.uow() as s:
        finding = s.scalar(select(AuditFinding).where(AuditFinding.check_name == "recovery_email_company_controlled"))
        assert finding.severity == Severity.HIGH and "consumer domain (gmail.com)" in finding.description
        assert "reset_step --step company_email" in finding.description
        # The verification step cannot launder it either.
        env.container.provisioning._set_recovery_confirmed(s.get(InstagramAccount, account))
        assert s.get(InstagramAccount, account).recovery_email_control == ControlStatus.NON_COMPANY


def test_company_mailbox_must_still_be_on_an_approved_domain(env, team, account):
    owner = env.actor(team["owner"], OperatorRole.ADMIN)
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, owner)
    with pytest.raises(ValidationFailed):
        env.complete_type(
            account, TaskType.ASSIGN_COMPANY_EMAIL, owner,
            {"email_assignment_ref": "IT-1", "email_address": "brand.test@gmail.com", "mailbox_control": "company_controlled"},
        )
    with pytest.raises(ValidationFailed):  # who controls the mailbox must be stated explicitly
        env.complete_type(
            account, TaskType.ASSIGN_COMPANY_EMAIL, owner, {"email_assignment_ref": "IT-1", "email_address": "ig@testco.example"},
        )
    assert env.open_task(account, TaskType.ASSIGN_COMPANY_EMAIL).status == TaskStatus.PENDING
