"""Vault-metadata and Meta reads must never run while a database write transaction is open.

Every integration call below checks, from a separate SQLite connection, whether the write
lock is held at that moment. The whole flow goes through the real entry points (API and
audit runner), which keep those reads outside the transaction.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from app.enums import (
    AuditTrigger,
    OffboardingActionStatus,
    OffboardingActionType,
    OperatorRole,
    RoleName,
    TaskType,
    VerificationLabel,
)
from app.integrations.meta.base import MetaIntegration, MetaLinkCheck
from app.integrations.reads import MAX_READS_PER_UNIT, ReadNeeded, run_outside_transaction, vault_inspection
from app.models import InstagramAccount
from tests.conftest import OUTCOMES, PASSWORD_REF, Env


def _write_locked(env: Env) -> bool:
    connection = sqlite3.connect(env.settings.database_url.removeprefix("sqlite:///"), timeout=0, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("ROLLBACK")
        return False
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc):
            return True
        raise
    finally:
        connection.close()


class _LockProbe:
    def __init__(self, env: Env):
        self.env = env
        self.calls: list[str] = []
        self.violations: list[str] = []

    def record(self, what: str) -> None:
        self.calls.append(what)
        if _write_locked(self.env):
            self.violations.append(what)


class _LockCheckingMeta(MetaIntegration):
    name = "lock_checking_fake"
    configured = True

    def __init__(self, probe: _LockProbe):
        self.probe = probe

    def check_instagram_link(self, business_id: str, handle: str) -> MetaLinkCheck:
        self.probe.record(f"meta:{business_id}")
        return MetaLinkCheck("linked", VerificationLabel.INTEGRATION_VERIFIED, f"fake-meta:{business_id}", "simulated")

    def health(self):
        return {"status": "fake"}


@pytest.fixture
def probe(env, monkeypatch) -> _LockProbe:
    probe = _LockProbe(env)
    original = env.container.vault.metadata

    def metadata(ref):
        probe.record(f"vault:{ref}")
        return original(ref)

    monkeypatch.setattr(env.container.vault, "metadata", metadata)
    meta = _LockCheckingMeta(probe)
    env.container.provisioning.meta = meta
    env.container.audits.meta = meta
    return probe


def _complete_via_api(env: Env, admin_headers: dict, account: str, task_type: TaskType, outcome: dict | None = None) -> None:
    task = env.open_task(account, task_type)
    response = env.client().post(
        f"/api/v1/tasks/{task.id}/complete", headers=admin_headers,
        json={"evidence_ref": "observed in Instagram settings (test)", "outcome": outcome or OUTCOMES[task_type]},
    )
    assert response.status_code == 200, response.text


def test_integration_reads_never_hold_the_database_write_lock(env, team, account, probe):
    env.seed_vault()
    env.add_role(account, team["owner"], RoleName.BUSINESS_ADMIN, team["owner"])
    env.add_role(account, team["departing"], RoleName.TEMPORARY_TEST_ROLE, team["owner"])
    admin = env.headers(team["owner"], OperatorRole.ADMIN)
    for task_type in (
        TaskType.HANDLE_AVAILABILITY_CHECK, TaskType.ASSIGN_COMPANY_EMAIL, TaskType.ASSIGN_COMPANY_PHONE,
        TaskType.ACCOUNT_SIGNUP,  # password reference: vault metadata
        TaskType.ACCOUNT_VERIFICATION,
        TaskType.ENABLE_TWO_FACTOR,  # backup codes and TOTP references: vault metadata
        TaskType.COMPLETE_PROFILE, TaskType.CONVERT_TO_BUSINESS,
        TaskType.LINK_META_BUSINESS,  # Meta verification
        TaskType.ASSIGN_PEOPLE_ROLES,
    ):
        _complete_via_api(env, admin, account, task_type)
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status.value == "provisioned"
        assert acc.password_ref_verification == VerificationLabel.INTEGRATION_VERIFIED  # the decision used the read
        assert acc.meta_link_verification == VerificationLabel.INTEGRATION_VERIFIED

    client = env.client()
    assert client.post(f"/api/v1/accounts/{account}/verify-integrations", headers=admin).status_code == 200
    security = env.headers(team["security"], OperatorRole.ADMIN)
    assert client.post("/api/v1/audits/run", headers=security).status_code in (200, 201)
    # Offboarding: rotation baselines and the version check read vault metadata.
    access = client.post(
        f"/api/v1/people/{team['departing']}/credential-access", headers=security,
        json={"vault_ref": PASSWORD_REF, "credential_kind": "instagram_password", "account_id": account},
    )
    assert access.status_code == 201, access.text
    started = client.post("/api/v1/offboarding", headers=security, json={"person_id": team["departing"], "reason": "test team member leaving"})
    assert started.status_code == 201, started.text
    rotation = next(a for a in started.json()["case"]["pending"] if a["action_type"] == OffboardingActionType.ROTATE_CREDENTIAL.value)
    env.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-2")
    done = client.post(
        f"/api/v1/tasks/{rotation['task']['id']}/complete", headers=env.headers(rotation["owner"]["id"], OperatorRole.ADMIN),
        json={"evidence_ref": "rotated in Instagram and stored new version", "outcome": {"action_completed": True}},
    )
    assert done.status_code == 200, done.text
    case = client.get(f"/api/v1/offboarding/{started.json()['case']['id']}", headers=security).json()
    rotated = next(a for a in case["completed"] if a["action_type"] == OffboardingActionType.ROTATE_CREDENTIAL.value)
    assert rotated["verification"] == "integration_verified" and "v1->v2" in rotated["evidence_ref"]

    assert len(probe.calls) >= 10, probe.calls  # the reads really happened ...
    assert probe.violations == []  # ... and none of them while a write transaction was open


def test_events_from_an_aborted_pass_are_not_logged(env, team, account, probe):
    env.seed_vault()
    admin = env.headers(team["owner"], OperatorRole.ADMIN)
    for task_type in (TaskType.HANDLE_AVAILABILITY_CHECK, TaskType.ASSIGN_COMPANY_EMAIL, TaskType.ASSIGN_COMPANY_PHONE):
        _complete_via_api(env, admin, account, task_type)
    signup = env.open_task(account, TaskType.ACCOUNT_SIGNUP)
    _complete_via_api(env, admin, account, TaskType.ACCOUNT_SIGNUP)  # first pass aborts for the vault read
    events = [json.loads(line) for line in env.read_logs().splitlines() if line.strip()]
    completed = [e for e in events if e.get("event") == "task.completed" and e.get("task_id") == signup.id]
    created = [e for e in events if e.get("event") == "task.created" and e.get("action") == "create_account_verification"]
    assert len(completed) == 1 and len(created) == 1


def test_runner_contract(env):
    calls: list[int] = []

    def unit():
        calls.append(1)
        try:
            return vault_inspection(env.container.vault, "devvault://instagram/missing").exists
        except Exception:  # noqa: BLE001 - an ordinary handler must not swallow the read request
            return "swallowed"

    assert run_outside_transaction(unit) is False and len(calls) == 2  # one aborted pass, one real pass

    def greedy():
        for i in range(MAX_READS_PER_UNIT + 1):
            vault_inspection(env.container.vault, f"devvault://instagram/n{i}")

    with pytest.raises(RuntimeError, match="integration reads"):
        run_outside_transaction(greedy)
    assert issubclass(ReadNeeded, BaseException) and not issubclass(ReadNeeded, Exception)


def test_offboarding_rotation_still_blocks_when_metadata_is_unchanged_via_api(env, team, account, probe):
    """The outside-transaction path keeps the existing safety rule: no new version, no completion."""
    env.provision(account, team["owner"])  # test helper: calls services directly, not through an entry point
    probe.calls.clear()
    probe.violations.clear()
    client = env.client()
    security = env.headers(team["security"], OperatorRole.ADMIN)
    client.post(
        f"/api/v1/people/{team['departing']}/credential-access", headers=security,
        json={"vault_ref": PASSWORD_REF, "credential_kind": "instagram_password", "account_id": account},
    )
    case = client.post("/api/v1/offboarding", headers=security, json={"person_id": team["departing"], "reason": "leaving"}).json()["case"]
    rotation = next(a for a in case["pending"] if a["action_type"] == OffboardingActionType.ROTATE_CREDENTIAL.value)
    client.post(
        f"/api/v1/tasks/{rotation['task']['id']}/complete", headers=env.headers(rotation["owner"]["id"], OperatorRole.ADMIN),
        json={"evidence_ref": "said rotated, vault not updated", "outcome": {"action_completed": True}},
    )
    case = client.get(f"/api/v1/offboarding/{case['id']}", headers=security).json()
    blocked = next(a for a in case["blocked"] if a["action_type"] == OffboardingActionType.ROTATE_CREDENTIAL.value)
    assert blocked["status"] == OffboardingActionStatus.BLOCKED.value and blocked["blocker_code"] == "VAULT_VERSION_UNCHANGED"
    assert probe.violations == [] and env.container.audits.run(
        env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(team["security"], OperatorRole.ADMIN)
    ).status.value == "completed"
    assert probe.violations == []
