"""Offboarding a departing synthetic team member."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.enums import (
    AssignmentStatus,
    BackupCodesStatus,
    CredentialAccessStatus,
    CredentialKind,
    OffboardingActionStatus,
    OffboardingActionType,
    OffboardingCaseStatus,
    OperatorRole,
    PersonStatus,
    RoleName,
    TaskType,
    VerificationLabel,
)
from app.errors import PermissionDenied
from app.models import (
    AccountAssignment,
    CredentialAccess,
    HumanTask,
    InstagramAccount,
    OffboardingAction,
    OffboardingCase,
    Person,
)
from tests.conftest import BACKUP_REF, PASSWORD_REF, Env

PROXY_REF = "devvault://proxies/approved-proxy-a"


def _setup(env: Env, team: dict[str, str], account: str) -> str:
    """Provisioned account; departing tester holds the designated temporary test role and vault access."""
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.TEMPORARY_TEST_ROLE, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    env.vault_put(PROXY_REF, username="SYNTHETIC-proxy-user", password="SYNTHETIC-proxy-pass")
    with env.container.uow() as s:
        for ref, kind, acc in (
            (BACKUP_REF, CredentialKind.BACKUP_CODES, account),
            (PASSWORD_REF, CredentialKind.INSTAGRAM_PASSWORD, account),
            (PROXY_REF, CredentialKind.PROXY_CREDENTIAL, None),
        ):
            env.container.provisioning.add_credential_access(
                s, person_id=team["departing"], vault_ref=ref, credential_kind=kind, account_id=acc, actor=env.actor(team["owner"], OperatorRole.ADMIN)
            )
    return account


def _start(env: Env, team: dict[str, str], **kwargs):
    with env.container.uow() as s:
        case, created = env.container.offboarding.start(
            s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="test team member leaving", **kwargs
        )
        return case.id, created


def _actions(env: Env, case_id: str) -> dict[tuple[str, str], OffboardingAction]:
    with env.container.uow() as s:
        return {(a.action_type.value, a.target_ref): a for a in s.scalars(select(OffboardingAction).where(OffboardingAction.case_id == case_id))}


def _by_type(env: Env, case_id: str, action_type: OffboardingActionType) -> list[OffboardingAction]:
    return [a for (t, _), a in _actions(env, case_id).items() if t == action_type.value]


def test_offboarding_generates_tracked_actions(env, team, account):
    _setup(env, team, account)
    departing_token = env.token(team["departing"], OperatorRole.OPERATOR)
    case_id, created = _start(env, team)
    assert created
    revoke = _by_type(env, case_id, OffboardingActionType.REVOKE_APP_ACCESS)[0]
    assert revoke.status == OffboardingActionStatus.COMPLETED and revoke.verification == VerificationLabel.INTEGRATION_VERIFIED
    assert env.client().get("/api/v1/accounts", headers={"Authorization": f"Bearer {departing_token}"}).status_code == 401
    identify = _by_type(env, case_id, OffboardingActionType.IDENTIFY_ROLES)[0]
    assert identify.status == OffboardingActionStatus.COMPLETED and identify.verification == VerificationLabel.HUMAN_CONFIRMED
    assert identify.detail["roles"][0]["role"] == "temporary_test_role" and identify.detail["roles"][0]["temporary_test_role"]
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    assert removal.status == OffboardingActionStatus.PENDING and removal.owner_id == team["owner"]
    with env.container.uow() as s:
        task = s.get(HumanTask, removal.task_id)
        assert task.owner_id != team["departing"] and task.task_type == TaskType.OFFBOARDING_ACTION
    vault_removals = _by_type(env, case_id, OffboardingActionType.REMOVE_VAULT_ACCESS)
    assert len(vault_removals) == 3 and all(a.owner_id == team["security"] for a in vault_removals)
    assert _by_type(env, case_id, OffboardingActionType.REPLACE_BACKUP_CODES)[0].status == OffboardingActionStatus.PENDING
    rotations = {a.detail["vault_ref"]: a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL)}
    assert rotations[PASSWORD_REF].status == OffboardingActionStatus.PENDING and rotations[PASSWORD_REF].detail["baseline_version"] == 1
    proxy_rotation = rotations[PROXY_REF]
    assert proxy_rotation.status == OffboardingActionStatus.BLOCKED and proxy_rotation.blocker_code == "NO_PROXY_PROVIDER_ADMIN"
    assert proxy_rotation.owner_id == team["security"]  # responsible owner recorded for the blocker
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.status == OffboardingActionStatus.PENDING and verify.task_id is None and verify.detail["waiting_on"]
    with env.container.uow() as s:
        assert s.get(Person, team["departing"]).status == PersonStatus.DEPARTING
        assert s.get(InstagramAccount, account).backup_codes_status == BackupCodesStatus.REPLACEMENT_REQUIRED


def test_task_creation_is_not_claimed_as_access_removal(env, team, account):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    with env.container.uow() as s:
        assignment = s.scalar(select(AccountAssignment).where(AccountAssignment.person_id == team["departing"]))
        assert assignment.status == AssignmentStatus.PENDING_REMOVAL
        access = s.scalar(select(CredentialAccess).where(CredentialAccess.vault_ref == BACKUP_REF))
        assert access.status == CredentialAccessStatus.REVOCATION_PENDING
        report = env.container.reports.offboarding_report(s, env.container.offboarding.get_case(s, case_id))
    assert any("may still hold access" in r for r in report["outstanding_risks"])
    assert any("may be exposed until replaced" in r for r in report["outstanding_risks"])


def test_repeated_offboarding_is_idempotent(env, team, account):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    actions_before = {k: (a.id, a.status, a.task_id) for k, a in _actions(env, case_id).items()}
    tasks_before = len(env.tasks())
    again, created = _start(env, team)
    assert again == case_id and created is False
    for _ in range(3):
        with env.container.uow() as s:
            env.container.offboarding.reconcile(s, env.container.offboarding.get_case(s, case_id), actor=env.actor(team["security"], OperatorRole.ADMIN))
    assert {k: (a.id, a.status, a.task_id) for k, a in _actions(env, case_id).items()} == actions_before
    assert len(env.tasks()) == tasks_before
    with env.container.uow() as s:
        assert s.scalar(select(func.count(OffboardingCase.id))) == 1


def _complete_offboarding_task(env: Env, action: OffboardingAction, actor_id: str) -> None:
    env.complete(action.task_id, env.actor(actor_id, OperatorRole.ADMIN), {"action_completed": True}, evidence="confirmed in admin console (test)")


def test_completing_actions_updates_register_and_closes_case(env, team, account):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    # Assign a provider admin so the blocked proxy rotation can proceed; re-run reconciliation.
    with env.container.uow() as s:
        s.get(Person, team["security"]).responsibilities = ["security_owner", "escalation_default", "vault_admin", "proxy_provider_admin"]
    with env.container.uow() as s:
        env.container.offboarding.reconcile(s, env.container.offboarding.get_case(s, case_id), actor=env.actor(team["security"], OperatorRole.ADMIN))
    proxy_rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PROXY_REF)
    assert proxy_rotation.status == OffboardingActionStatus.PENDING and proxy_rotation.task_id
    # Humans rotate credentials: the vault entries get new versions before confirmation.
    env.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-2")
    env.vault_put(BACKUP_REF, value="SYNTHETIC-backup-codes-set-2")
    env.vault_put(PROXY_REF, username="SYNTHETIC-proxy-user", password="SYNTHETIC-proxy-pass-2")
    for action_type in (
        OffboardingActionType.REMOVE_ACCOUNT_ROLE,
        OffboardingActionType.REMOVE_VAULT_ACCESS,
        OffboardingActionType.ROTATE_CREDENTIAL,
        OffboardingActionType.REPLACE_BACKUP_CODES,
    ):
        for action in _by_type(env, case_id, action_type):
            _complete_offboarding_task(env, action, action.owner_id)
    rotations = _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL)
    assert all(a.status == OffboardingActionStatus.COMPLETED and a.verification == VerificationLabel.INTEGRATION_VERIFIED for a in rotations)
    verify = _by_type(env, case_id, OffboardingActionType.VERIFY_ACCESS_STATE)[0]
    assert verify.task_id is not None
    _complete_offboarding_task(env, verify, team["security"])
    with env.container.uow() as s:
        case = s.get(OffboardingCase, case_id)
        assert case.status == OffboardingCaseStatus.COMPLETED and case.closed_at is not None
        assert s.get(Person, team["departing"]).status == PersonStatus.OFFBOARDED
        assignment = s.scalar(select(AccountAssignment).where(AccountAssignment.person_id == team["departing"]))
        assert assignment.status == AssignmentStatus.REMOVED
        assert s.get(InstagramAccount, account).backup_codes_status == BackupCodesStatus.PRESENT_IN_VAULT
    register = _by_type(env, case_id, OffboardingActionType.UPDATE_REGISTER)[0]
    assert register.status == OffboardingActionStatus.COMPLETED


def test_rotation_without_new_vault_version_is_blocked_not_claimed(env, team, account):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    _complete_offboarding_task(env, rotation, team["owner"])  # human says "rotated" but vault unchanged
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    assert rotation.status == OffboardingActionStatus.BLOCKED and rotation.blocker_code == "VAULT_VERSION_UNCHANGED"
    env.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-2")
    with env.container.uow() as s:
        env.container.offboarding.reconcile(s, env.container.offboarding.get_case(s, case_id), actor=env.actor(team["security"], OperatorRole.ADMIN))
    rotation = next(a for a in _by_type(env, case_id, OffboardingActionType.ROTATE_CREDENTIAL) if a.detail["vault_ref"] == PASSWORD_REF)
    assert rotation.status == OffboardingActionStatus.COMPLETED and "v1->v2" in rotation.evidence_ref


def test_sole_admin_is_never_removed_without_confirmed_replacement(env, team, account):
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.BUSINESS_ADMIN, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    with env.container.uow() as s:  # make the departing person the only active admin
        owner_admin = s.scalar(select(AccountAssignment).where(AccountAssignment.person_id == team["owner"]))
        owner_admin.status = AssignmentStatus.REMOVED
    case_id, _ = _start(env, team)
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    assert removal.status == OffboardingActionStatus.BLOCKED and removal.blocker_code == "SOLE_ADMIN_NO_REPLACEMENT"
    assert removal.task_id is None  # nobody is ever asked to remove the only admin path
    _start(env, team, replacement_admin_id=team["operator"])
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    assert removal.blocker_code == "AWAITING_REPLACEMENT_ADMIN" and removal.task_id is None
    grant = _by_type(env, case_id, OffboardingActionType.GRANT_REPLACEMENT_ADMIN)[0]
    assert grant.task_id is not None
    _complete_offboarding_task(env, grant, team["owner"])
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    assert removal.status == OffboardingActionStatus.PENDING and removal.task_id is not None
    with env.container.uow() as s:
        replacement = s.scalar(select(AccountAssignment).where(AccountAssignment.person_id == team["operator"], AccountAssignment.role == RoleName.BUSINESS_ADMIN))
        assert replacement.status == AssignmentStatus.ACTIVE


def test_blocked_offboarding_task_marks_action_blocked(env, team, account):
    _setup(env, team, account)
    case_id, _ = _start(env, team)
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    with env.container.uow() as s:
        env.container.tasks.block(s, removal.task_id, actor=env.actor(team["owner"]), reason="no permission to edit people in the test business")
    removal = _by_type(env, case_id, OffboardingActionType.REMOVE_ACCOUNT_ROLE)[0]
    assert removal.status == OffboardingActionStatus.BLOCKED and "no permission" in removal.blocker_detail


def test_cannot_offboard_yourself(env, team, account):
    with pytest.raises(PermissionDenied):
        with env.container.uow() as s:
            env.container.offboarding.start(s, person_id=team["security"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="me")


def test_last_app_admin_credential_is_not_revoked(env, team, account):
    env.token(team["departing"], OperatorRole.ADMIN)  # the only admin credential in the system
    with env.container.uow() as s:
        case, _ = env.container.offboarding.start(
            s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="leaving"
        )
        case_id = case.id
    revoke = _by_type(env, case_id, OffboardingActionType.REVOKE_APP_ACCESS)[0]
    assert revoke.status == OffboardingActionStatus.BLOCKED and revoke.blocker_code == "SOLE_APP_ADMIN"


def test_offboarding_api_and_report(env, team, account):
    _setup(env, team, account)
    client = env.client()
    admin = env.headers(team["security"], OperatorRole.ADMIN)
    assert client.post("/api/v1/offboarding", json={"person_id": team["departing"], "reason": "leaving"}, headers=env.headers(team["owner"], OperatorRole.OPERATOR)).status_code == 403
    first = client.post("/api/v1/offboarding", json={"person_id": team["departing"], "reason": "test member leaving"}, headers=admin)
    second = client.post("/api/v1/offboarding", json={"person_id": team["departing"], "reason": "test member leaving"}, headers=admin)
    assert first.status_code == 201 and second.status_code == 200
    case = first.json()["case"]
    assert case["completed"] and case["pending"] and case["blocked"]
    md = client.get(f"/api/v1/offboarding/{case['id']}/report", params={"format": "md"}, headers=admin).text
    for heading in ("## Completed", "## Pending", "## Blocked", "## Outstanding risks"):
        assert heading in md
    assert "does NOT mean access has been removed" in md
