"""Regression tests for defects found in the independent code review."""

from __future__ import annotations

import smtplib
import threading
import time

import pytest
from sqlalchemy import select

from app.enums import (
    AuditRunStatus,
    AuditTrigger,
    CredentialKind,
    DeliveryStatus,
    NotificationKind,
    OffboardingActionType,
    OperatorRole,
    PersonStatus,
    ProvisioningStep,
    ProxySessionStatus,
    RoleName,
    TaskOrigin,
    TaskStatus,
    TaskType,
    VerificationLabel,
)
from app.errors import Conflict, PermissionDenied
from app.integrations.notifications import SmtpNotifier
from app.integrations.notifications.base import Notifier, SendResult
from app.integrations.vault.base import VaultUnavailable
from app.models import (
    HumanTask,
    InstagramAccount,
    Notification,
    Person,
)
from app.services.recovery import run_startup_recovery
from tests.conftest import Env, make_settings
from tests.test_proxy_manager import ProxyEnv, ok, status


def _audit(env: Env, actor: str):
    return env.container.audits.run(env.container.session_factory, trigger=AuditTrigger.MANUAL, actor=env.actor(actor, OperatorRole.ADMIN))


def test_reference_to_another_vault_product_is_recorded_as_human_confirmed(env, team, account):
    """Was: plain VaultError escaped inspect_ref -> HTTP 500 on signup, crashed offboarding/recovery/audit."""
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_SIGNUP)
    env.complete_type(
        account, TaskType.ACCOUNT_SIGNUP, env.actor(team["owner"]),
        {"platform_handle": "lumenlabtestbrand", "password_vault_ref": "vault://team/instagram/password"},
    )
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.password_ref_verification == VerificationLabel.HUMAN_CONFIRMED
        env.container.provisioning.add_credential_access(
            s, person_id=team["departing"], vault_ref="op://Shared/instagram/backup-codes", credential_kind=CredentialKind.BACKUP_CODES,
            account_id=account, actor=env.actor(team["security"], OperatorRole.ADMIN),
        )
    with env.container.uow() as s:
        case, _ = env.container.offboarding.start(s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="leaving")
        assert case.actions
    assert run_startup_recovery(env.container)["recovery_failures"] == []
    run = _audit(env, team["security"])
    assert run.status == AuditRunStatus.COMPLETED and not run.summary["errors"]


def test_failed_non_signup_task_gets_a_replacement(env, team, account):
    """Was: only signup re-advanced; a failed 2FA task left the account with no open task."""
    env.provision(account, team["owner"], stop_before=TaskType.ENABLE_TWO_FACTOR)
    first = env.open_task(account, TaskType.ENABLE_TWO_FACTOR)
    with env.container.uow() as s:
        env.container.tasks.fail(s, first.id, actor=env.actor(team["owner"]), reason="authenticator app lost", outcome_uncertain=False)
    replacement = env.open_task(account, TaskType.ENABLE_TWO_FACTOR)
    assert replacement.id != first.id and replacement.idempotency_key.endswith(":g2")


def test_cancelled_task_after_provisioning_is_regenerated_on_recovery(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        env.container.provisioning.set_profile_spec(s, account, {"bio": "Updated approved bio"}, actor=env.actor(team["owner"]))
    profile_task = env.open_task(account, TaskType.COMPLETE_PROFILE)
    with env.container.uow() as s:
        env.container.tasks.cancel(s, profile_task.id, actor=env.actor(team["security"], OperatorRole.ADMIN), reason="duplicate")
    assert env.open_task(account, TaskType.COMPLETE_PROFILE).id != profile_task.id
    run_startup_recovery(env.container)
    assert len([t for t in env.tasks(account, TaskType.COMPLETE_PROFILE) if t.status == TaskStatus.PENDING]) == 1


@pytest.fixture
def penv(tmp_path):
    environment = ProxyEnv(tmp_path)
    yield environment
    environment.container.engine.dispose()


def test_rotation_never_moves_past_a_challenge_or_rate_limit(penv):
    """Was: rotate_session rotated to the next proxy after a candidate returned a challenge."""
    penv.net.behaviour["proxy-a"] = ok
    penv.net.behaviour["proxy-b"] = status(403, {"X-Security-Challenge": "required"})
    sid = penv.acquire()
    with pytest.raises(Conflict):
        penv.container.proxies.rotate_session(penv.container.session_factory, sid, reason="scheduled_maintenance")
    session = penv.session(sid)
    assert session.proxy_id == "proxy-a" and session.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW
    assert penv.tasks(task_type=TaskType.PROXY_SECURITY_REVIEW)
    penv.net.behaviour["proxy-b"] = status(429)
    sid2 = penv.acquire("second-purpose")
    with pytest.raises(Conflict):
        penv.container.proxies.rotate_session(penv.container.session_factory, sid2, reason="scheduled_maintenance")
    assert penv.proxy("proxy-b").health_status.value != "unhealthy"


def test_vault_outage_is_unverified_not_integration_verified(env, team, account):
    """Was: required_vault_references passed as integration_verified while the vault was down."""
    env.provision(account, team["owner"])

    def down(_ref):
        raise VaultUnavailable("simulated outage")

    env.container.vault.metadata = down
    run = _audit(env, team["security"])
    checks = {c["fingerprint"]: c for c in run.summary["accounts"][0]["checks"]}
    assert checks["required_vault_references:unverifiable"]["verification"] == "unverified"
    assert checks["backup_codes_in_vault"]["verification"] == "unverified"
    assert not any(c["outcome"] == "pass" and c["check_name"] == "required_vault_references" for c in checks.values())


def test_handle_conflict_creates_an_owned_task(env, team, account):
    env.provision(account, team["owner"], stop_before=TaskType.ACCOUNT_SIGNUP)
    signup = env.open_task(account, TaskType.ACCOUNT_SIGNUP)
    with env.container.uow() as s:
        env.container.tasks.fail(s, signup.id, actor=env.actor(team["owner"]), reason="unsure", outcome_uncertain=True)
    env.complete_type(account, TaskType.SIGNUP_RECONCILIATION, env.actor(team["owner"]), {"external_account_state": "exists_not_controlled"})
    conflict = env.open_task(account, TaskType.MANUAL)
    assert conflict.owner_id == team["security"] and conflict.priority.value == "critical"
    assert "not company-controlled" in conflict.title


def test_departing_persons_open_tasks_are_reassigned(env, team, account):
    """Was: tasks stayed with the departing person (tokens revoked) and kept reminding them."""
    with env.container.uow() as s:
        task, _ = env.container.tasks.create_task(
            s, task_type=TaskType.MANUAL, owner_id=team["departing"], idempotency_key="manual:departing-task-1",
            context={"title": "Prepare brand assets", "description": "x"},
        )
        task_id = task.id
    with env.container.uow() as s:
        case, _ = env.container.offboarding.start(s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="leaving")
        revoke = next(a for a in case.actions if a.action_type == OffboardingActionType.REVOKE_APP_ACCESS)
        assert revoke.detail["open_tasks_reassigned"] == 1
    with env.container.uow() as s:
        moved = s.get(HumanTask, task_id)
        assert moved.owner_id == team["owner"]  # the departing person's supervisor
        assert any(e.event_type == "reassigned" for e in moved.events)


def test_departing_admin_cannot_confirm_their_own_offboarding(env, team, account):
    env.provision(account, team["owner"])
    env.add_role(account, team["departing"], RoleName.TEMPORARY_TEST_ROLE, team["owner"])
    env.complete_type(account, TaskType.ASSIGN_PEOPLE_ROLES, env.actor(team["owner"]))
    with env.container.uow() as s:
        case, _ = env.container.offboarding.start(s, person_id=team["departing"], actor=env.actor(team["security"], OperatorRole.ADMIN), reason="leaving")
        removal = next(a for a in case.actions if a.action_type == OffboardingActionType.REMOVE_ACCOUNT_ROLE)
        task_id = removal.task_id
    with pytest.raises(PermissionDenied):
        env.complete(task_id, env.actor(team["departing"], OperatorRole.ADMIN), {"action_completed": True})


def test_access_cannot_be_recorded_for_an_offboarded_person(env, team, account):
    with env.container.uow() as s:
        s.get(Person, team["departing"]).status = PersonStatus.OFFBOARDED
    with pytest.raises(Conflict):
        with env.container.uow() as s:
            env.container.provisioning.add_credential_access(
                s, person_id=team["departing"], vault_ref="devvault://x/y", credential_kind=CredentialKind.OTHER,
                account_id=None, actor=env.actor(team["security"], OperatorRole.ADMIN),
            )


def test_rerecorded_step_evidence_is_labelled_human_confirmed(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        next(x for x in acc.steps if x.step == ProvisioningStep.META_LINK).verification = VerificationLabel.INTEGRATION_VERIFIED
    with env.container.uow() as s:
        record = env.container.provisioning.record_step_evidence(
            s, account, step=ProvisioningStep.META_LINK, evidence_ref="re-checked in Business Suite", actor=env.actor(team["owner"])
        )
        assert record.verification == VerificationLabel.HUMAN_CONFIRMED


def test_failed_report_writer_does_not_leave_run_running(env, team, account):
    def broken(_session, _run):
        raise OSError("disk full")

    env.container.audits.report_writer = broken
    run = _audit(env, team["security"])
    assert run.status == AuditRunStatus.COMPLETED_WITH_ERRORS and "disk full" in run.error_detail


class SlowNotifier(Notifier):
    name = "slow"
    configured = True

    def __init__(self):
        self.calls = 0
        self.lock = threading.Lock()

    def send(self, *, to_email: str, subject: str, body: str) -> SendResult:
        with self.lock:
            self.calls += 1
        time.sleep(0.05)
        return SendResult("sent")


def test_concurrent_dispatchers_send_each_notification_once(env, team, account):
    notifier = SlowNotifier()
    env.container.notifications.notifier = notifier
    with env.container.uow() as s:
        pending = len(s.scalars(select(Notification).where(Notification.delivery_status == DeliveryStatus.PENDING)).all())
    threads = [threading.Thread(target=env.container.notifications.dispatch_pending, args=(env.container.session_factory,)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert notifier.calls == pending == 3


def test_newline_in_title_cannot_break_notifications(env, team):
    with env.container.uow() as s:
        env.container.tasks.create_task(
            s, task_type=TaskType.MANUAL, owner_id=team["operator"], idempotency_key="manual:newline-title",
            context={"title": "Line one\nBcc: attacker@example.com", "description": "x"}, origin=TaskOrigin.MANUAL,
        )
    with env.container.uow() as s:
        note = s.scalar(select(Notification).where(Notification.kind == NotificationKind.ASSIGNMENT, Notification.recipient_id == team["operator"]))
        assert "\n" not in note.subject


class QuitFailsSMTP:
    def __init__(self, host, port, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        raise smtplib.SMTPServerDisconnected("QUIT timed out")

    def starttls(self):
        pass

    def send_message(self, message):
        return {}


def test_quit_failure_after_acceptance_is_not_a_retryable_failure(env):
    settings = make_settings(env.tmp_path / "smtp", notification_backend="smtp", smtp_host="smtp.test.invalid", smtp_from="ops@testco.example")
    notifier = SmtpNotifier(settings=settings, vault=env.container.vault, redactor=env.container.redactor, smtp_factory=QuitFailsSMTP)
    assert notifier.send(to_email="a@testco.example", subject="hello\r\nworld", body="b").status == "sent"


def test_outbox_survives_a_raising_notifier(env, team):
    class Exploding(Notifier):
        name = "exploding"
        configured = True

        def send(self, **_kwargs):
            raise RuntimeError("adapter bug")

    env.container.notifications.notifier = Exploding()
    with env.container.uow() as s:
        env.container.tasks.create_task(s, task_type=TaskType.MANUAL, owner_id=team["operator"], idempotency_key="manual:explode-1", context={"title": "t", "description": "d"})
    summary = env.container.notifications.dispatch_pending(env.container.session_factory)
    assert summary.uncertain == 1
    with env.container.uow() as s:
        assert not s.scalars(select(Notification).where(Notification.delivery_status == DeliveryStatus.SENDING)).all()
