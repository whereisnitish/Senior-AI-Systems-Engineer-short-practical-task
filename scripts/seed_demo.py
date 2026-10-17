"""Seed an explicitly SYNTHETIC demo dataset and generate the example evidence pack.

Every record is flagged synthetic, every secret is a ``SYNTHETIC-`` placeholder in
the development-only vault, and every "human confirmation" here is performed by a
synthetic persona on a simulated clock. This is NOT a live-account walkthrough;
it exercises the same code paths a live run uses so the mechanics can be shown.

Timeline (simulated, ending at the real current time):
  day 0   account created, handle/email/phone tasks completed, signup assigned
  day 1   reminder 1 for the signup task
  day 2   signup overdue -> overdue reminder + escalation to the supervisor
          signup interrupted (outcome uncertain) -> reconciliation task, no retry
          simulated process restart -> startup recovery resumes open tasks
          reconciliation: account exists and is company-controlled -> resume
  day 2-3 verification, audit #1 (mid-provisioning: 'unverified' findings),
          2FA (SMS), profile, business conversion, Meta link, roles -> provisioned
  day 5   backup-code vault entry goes missing (simulated drift)
  day 8   weekly audit (+ duplicate run skipped, manual run deduplicated),
          backup codes re-stored -> finding resolved; offboarding of the departing
          tester: some actions completed, some pending, one blocked
  now     reminder cycle (notifications NOT delivered: no provider), reports exported

    python -m scripts.seed_demo --reset
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.clock import FrozenClock, utcnow
from app.config import get_settings
from app.container import build_container
from app.database import Base
from app.enums import (
    AuditTrigger,
    CredentialKind,
    OffboardingActionStatus,
    OffboardingActionType,
    OperatorRole,
    Platform,
    RoleName,
    TaskType,
)
from app.logging_setup import close_logging, configure_logging
from app.models import HumanTask, InstagramAccount, OffboardingAction, Person, new_id
from app.security.authentication import issue_api_credential
from app.security.authorization import SYSTEM_ACTOR, Actor
from app.security.secret_handling import SecretValue
from app.services.recovery import run_startup_recovery
from app.services.task_manager import ACTIVE_STATUSES
from scripts._common import cli_container

BRAND = "Lumen Lab Test Brand (SYNTHETIC)"
HANDLE = "lumenlabtestbrand"
REFS = {
    "password": "devvault://instagram/lumen-lab/password",
    "backup": "devvault://instagram/lumen-lab/backup-codes",
    "proxy": "devvault://proxies/approved-proxy-a",
}
PROFILE = {
    "profile_name": "Lumen Lab Test Brand",
    "bio": "SYNTHETIC test brand for an operations-workflow demo. Not a real business. Questions: see link.",
    "profile_link": "https://brand.testco.example/lumen-lab",
    "category": "Product/service",
    "profile_image_ref": "brandkit://lumen-lab/logo-v1.png",
}


def say(step: str, detail: str = "") -> None:
    print(f"  - {step}" + (f": {detail}" if detail else ""))


class Demo:
    def __init__(self, container, clock: FrozenClock):
        self.c = container
        self.clock = clock
        self.people: dict[str, str] = {}

    def actor(self, key: str, role: OperatorRole = OperatorRole.ADMIN) -> Actor:
        return Actor(person_id=self.people[key], role=role.value, display_name=key)

    def open_task(self, account_id: str, task_type: TaskType) -> HumanTask:
        with self.c.uow() as s:
            task = s.scalar(
                select(HumanTask).where(
                    HumanTask.account_id == account_id, HumanTask.task_type == task_type, HumanTask.status.in_(list(ACTIVE_STATUSES))
                )
            )
            assert task is not None, f"expected an open {task_type.value} task"
            return task

    def complete(self, task: HumanTask, who: str, outcome: dict[str, Any], evidence: str) -> None:
        with self.c.uow() as s:
            self.c.tasks.complete(s, task.id, actor=self.actor(who), outcome=outcome, evidence_ref=evidence + " [SYNTHETIC]")

    def vault(self, ref: str, **fields: str) -> None:
        self.c.vault.write_fields(ref, {k: SecretValue(v) for k, v in fields.items()})

    def reminders(self) -> dict[str, Any]:
        with self.c.uow() as s:
            result = self.c.reminders.run_cycle(s).as_dict()
        self.c.notifications.dispatch_pending(self.c.session_factory)
        return result


def _reset(container, settings) -> None:
    with container.uow() as s:
        flags = list(s.scalars(select(InstagramAccount.is_synthetic)))
        if flags and not all(flags):
            raise SystemExit("Refusing to reset: the database contains non-synthetic accounts.")
        for table in reversed(Base.metadata.sorted_tables):
            s.execute(table.delete())
    if settings.dev_vault_file and Path(settings.dev_vault_file).exists():
        Path(settings.dev_vault_file).unlink()
    log = settings.log_dir / "run_log.jsonl"
    close_logging()  # release the file handle before archiving the previous run log
    if log.exists():
        shutil.move(str(log), str(log.with_name(f"run_log.{utcnow().strftime('%Y%m%dT%H%M%SZ')}.jsonl.bak")))
    for sub in ("audit", "offboarding"):
        target = settings.reports_dir / sub
        if target.exists():
            shutil.rmtree(target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="delete existing SYNTHETIC data first (refuses if any real data exists)")
    args = parser.parse_args()
    settings = get_settings()
    if settings.app_env == "production":
        raise SystemExit("seed_demo refuses to run in production")
    if settings.vault_backend != "dev_memory" or not settings.dev_vault_file:
        raise SystemExit("seed_demo needs VAULT_BACKEND=dev_memory and DEV_VAULT_FILE (synthetic vault shared with the server)")

    probe = cli_container("seed", settings)
    with probe.uow() as s:
        has_data = s.scalar(select(InstagramAccount.id).limit(1)) is not None
    if has_data and not args.reset:
        raise SystemExit("Database already contains data. Re-run with --reset to replace the SYNTHETIC demo data.")
    if args.reset:
        _reset(probe, settings)
    probe.engine.dispose()

    real_now = utcnow().replace(microsecond=0)
    clock = FrozenClock(real_now - timedelta(days=9))
    container = build_container(settings, clock=clock)
    configure_logging(settings.log_dir, level=settings.log_level, to_stdout=False, redactor=container.redactor)
    demo = Demo(container, clock)
    print("Seeding SYNTHETIC demo data (simulated clock, synthetic personas, dev-only vault)")

    # ---------------------------------------------------------------- people & app access
    roster = [
        ("security", "Morgan Lee (SYNTHETIC security lead)", None, ["security_owner", "escalation_default", "vault_admin"], OperatorRole.ADMIN),
        ("owner", "Sam Rivera (SYNTHETIC account owner)", "security", [], OperatorRole.ADMIN),
        ("operator", "Alex Chen (SYNTHETIC operator)", "owner", [], OperatorRole.OPERATOR),
        ("publisher", "Riley Kim (SYNTHETIC content publisher)", "owner", [], OperatorRole.VIEWER),
        ("departing", "Jordan Patel (SYNTHETIC departing tester)", "owner", [], OperatorRole.OPERATOR),
        ("auditor", "Casey Ng (SYNTHETIC auditor)", "security", [], OperatorRole.AUDITOR),
    ]
    tokens: dict[str, dict[str, str]] = {}
    with container.uow() as s:
        for key, name, supervisor, responsibilities, role in roster:
            person = Person(
                id=new_id("per"), full_name=name, email=f"{key}.synthetic@testco.example",
                supervisor_id=demo.people.get(supervisor) if supervisor else None,
                responsibilities=responsibilities, is_synthetic=True, created_at=clock.now(), updated_at=clock.now(),
            )
            s.add(person)
            s.flush()
            demo.people[key] = person.id
            _, raw = issue_api_credential(s, person=person, role=role, label="synthetic-demo", secret_key=settings.secret_key_bytes, now=clock.now())
            tokens[key] = {"name": name, "role": role.value, "token": raw}
    token_file = Path("data") / "demo_tokens.local.json"
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(json.dumps({"_warning": "SYNTHETIC demo operator tokens. Local only; git-ignored.", **tokens}, indent=2), encoding="utf-8")
    say("synthetic personas + operator tokens", f"tokens written to {token_file} (not printed)")

    # ---------------------------------------------------------------- synthetic vault entries
    demo.vault(REFS["password"], value=f"SYNTHETIC-pw-{secrets.token_urlsafe(12)}")
    demo.vault(REFS["backup"], value=f"SYNTHETIC-codes-{secrets.token_urlsafe(12)}")
    demo.vault(REFS["proxy"], username="SYNTHETIC-proxy-user", password=f"SYNTHETIC-proxy-{secrets.token_urlsafe(12)}")

    # ---------------------------------------------------------------- day 0: account + identity tasks
    with container.uow() as s:
        account, _ = container.provisioning.create_account(
            s, brand_name=BRAND, owner_id=demo.people["owner"], actor=demo.actor("owner"), keywords=["studio"], profile=PROFILE, is_synthetic=True
        )
        account_id = account.id
        for who, role in (("owner", RoleName.BUSINESS_ADMIN), ("security", RoleName.BUSINESS_ADMIN), ("publisher", RoleName.CONTENT_PUBLISHER), ("departing", RoleName.TEMPORARY_TEST_ROLE)):
            container.provisioning.add_assignment(s, account_id, person_id=demo.people[who], platform=Platform.META_BUSINESS, role=role, actor=demo.actor("security"))
        for who, ref, kind, acc in (
            ("departing", REFS["backup"], CredentialKind.BACKUP_CODES, account_id),
            ("departing", REFS["proxy"], CredentialKind.PROXY_CREDENTIAL, None),
            ("operator", REFS["password"], CredentialKind.INSTAGRAM_PASSWORD, account_id),
        ):
            container.provisioning.add_credential_access(s, person_id=demo.people[who], vault_ref=ref, credential_kind=kind, account_id=acc, actor=demo.actor("security"))
    say("account created", f"{account_id} with handle suggestions + access register")

    clock.advance(hours=1)
    demo.complete(demo.open_task(account_id, TaskType.HANDLE_AVAILABILITY_CHECK), "owner", {"selected_handle": HANDLE, "checked_via": "instagram_app"}, "searched handle in official app; not taken")
    demo.complete(demo.open_task(account_id, TaskType.ASSIGN_COMPANY_EMAIL), "owner", {"email_assignment_ref": "IT-REQ-4821", "email_address": "ig-lumenlab@testco.example", "mailbox_control": "company_controlled"}, "IT ticket IT-REQ-4821 fulfilled")
    demo.complete(demo.open_task(account_id, TaskType.ASSIGN_COMPANY_PHONE), "owner", {"phone_assignment_ref": "TEL-0042", "phone_number": "+447700900123", "number_control": "company_controlled"}, "telecom inventory TEL-0042")
    signup = demo.open_task(account_id, TaskType.ACCOUNT_SIGNUP)
    with container.uow() as s:
        container.tasks.assign(s, signup.id, actor=demo.actor("owner"), owner_id=demo.people["operator"])
    say("handle + company email + phone recorded", "signup task assigned to the operator (48h deadline)")

    # ---------------------------------------------------------------- days 1-2: wait, remind, escalate
    clock.advance(hours=24)
    say("day 1 reminder cycle", str(demo.reminders()["reminders_queued"]))
    clock.advance(hours=25)
    escalation = demo.reminders()
    say("day 2 reminder cycle (signup overdue)", f"overdue={len(escalation['marked_overdue'])} escalations={len(escalation['escalations_queued'])}")
    clock.advance(hours=1)
    with container.uow() as s:
        container.tasks.fail(
            s, signup.id, actor=demo.actor("operator", OperatorRole.OPERATOR),
            reason="Browser crashed right after submitting the signup form; unsure whether the account was created", outcome_uncertain=True,
        )
    say("signup interrupted", "marked FAILED with outcome uncertain -> reconciliation task, no automatic retry")

    # ---------------------------------------------------------------- simulated restart
    clock.advance(hours=1)
    container.engine.dispose()
    container = build_container(settings, clock=clock)
    configure_logging(settings.log_dir, level=settings.log_level, to_stdout=False, redactor=container.redactor)
    demo.c = container
    recovery = run_startup_recovery(container)
    say("simulated process restart", f"recovery resumed open tasks {recovery['open_tasks_resumed_by_status']}; no duplicate signup created")

    clock.advance(hours=1)
    demo.complete(
        demo.open_task(account_id, TaskType.SIGNUP_RECONCILIATION), "owner",
        {"external_account_state": "exists_controlled", "password_vault_ref": REFS["password"]},
        "profile instagram.com/lumenlabtestbrand exists; Instagram welcome email in company alias inbox",
    )
    say("reconciliation", "account exists and is company-controlled -> workflow resumes at verification")

    # ---------------------------------------------------------------- days 2-3: secure & complete
    clock.advance(hours=6)
    verification = demo.open_task(account_id, TaskType.ACCOUNT_VERIFICATION)
    with container.uow() as s:
        container.tasks.assign(s, verification.id, actor=demo.actor("owner"), owner_id=demo.people["operator"])
    demo.complete(
        demo.open_task(account_id, TaskType.ACCOUNT_VERIFICATION), "operator",
        {"email_confirmed_on_platform": True, "phone_confirmed_on_platform": True, "recovery_email_is_company_alias": True, "recovery_phone_is_company_number": True},
        "Accounts Center personal details checked on company device",
    )
    clock.advance(hours=1)
    first_audit = container.audits.run(container.session_factory, trigger=AuditTrigger.MANUAL, actor=demo.actor("security"))
    say("audit #1 (mid-provisioning)", f"{first_audit.summary['totals']} - missing evidence reported as 'unverified', linked to open provisioning tasks")
    clock.advance(hours=1)
    demo.complete(
        demo.open_task(account_id, TaskType.ENABLE_TWO_FACTOR), "owner",
        {"two_factor_method": "sms", "backup_codes_vault_ref": REFS["backup"], "two_factor_enabled": True},
        "2FA enabled in Accounts Center; codes saved straight to vault",
    )
    clock.advance(hours=8)
    demo.complete(demo.open_task(account_id, TaskType.COMPLETE_PROFILE), "owner", {"profile_matches_spec": True}, "live profile compared with approved spec")
    demo.complete(demo.open_task(account_id, TaskType.CONVERT_TO_BUSINESS), "owner", {"account_type": "business", "category_set": True}, "account type shows Business")
    clock.advance(hours=2)
    demo.complete(
        demo.open_task(account_id, TaskType.LINK_META_BUSINESS), "owner",
        {"meta_business_ref": "biz-synthetic-0001", "linked_in_business_suite": True, "linked_in_business_manager": True},
        "account listed under Business settings > Instagram accounts",
    )
    demo.complete(demo.open_task(account_id, TaskType.ASSIGN_PEOPLE_ROLES), "owner", {"roles_granted_as_listed": True}, "people list matches approved register")
    with container.uow() as s:
        say("provisioning", s.get(InstagramAccount, account_id).provisioning_status.value)

    # ---------------------------------------------------------------- day 5: drift
    clock.set(real_now - timedelta(days=4))
    container.vault.delete(REFS["backup"])
    say("simulated drift", "backup-code vault entry removed")

    # ---------------------------------------------------------------- day 8: weekly audit + remediation
    clock.set(real_now - timedelta(days=1))
    weekly_key = container.audits.weekly_key(clock.now())
    weekly = container.audits.run(container.session_factory, trigger=AuditTrigger.SCHEDULED, actor=SYSTEM_ACTOR, idempotency_key=weekly_key)
    duplicate = container.audits.run(container.session_factory, trigger=AuditTrigger.SCHEDULED, actor=SYSTEM_ACTOR, idempotency_key=weekly_key)
    say("weekly audit", f"{weekly_key}: {weekly.summary['totals']}; repeat with same key -> same run ({duplicate.id == weekly.id})")
    clock.advance(minutes=30)
    manual = container.audits.run(container.session_factory, trigger=AuditTrigger.MANUAL, actor=demo.actor("auditor", OperatorRole.AUDITOR))
    say("manual re-run", f"{manual.summary['totals']} (re-detected findings reused, no new remediation tasks)")
    clock.advance(minutes=30)
    demo.vault(REFS["backup"], value=f"SYNTHETIC-codes-{secrets.token_urlsafe(12)}")
    demo.complete(
        demo.open_task(account_id, TaskType.STORE_BACKUP_CODES), "owner",
        {"backup_codes_vault_ref": REFS["backup"], "codes_regenerated": True}, "new backup-code set generated and stored in vault",
    )
    say("remediation", "backup codes re-stored -> finding re-checked and resolved immediately")

    # ---------------------------------------------------------------- day 8: offboarding
    clock.advance(hours=1)
    with container.uow() as s:
        case, _ = container.offboarding.start(
            s, person_id=demo.people["departing"], actor=demo.actor("security"), reason="SYNTHETIC test team member leaving the project"
        )
        case_id = case.id
    say("offboarding started", case_id)
    clock.advance(hours=2)

    def action(action_type: OffboardingActionType, ref_contains: str = "") -> OffboardingAction:
        with container.uow() as s:
            return next(
                a for a in s.scalars(select(OffboardingAction).where(OffboardingAction.case_id == case_id, OffboardingAction.action_type == action_type))
                if ref_contains in a.target_ref
            )

    def complete_action(a: OffboardingAction, who: str, evidence: str) -> None:
        with container.uow() as s:
            task = s.get(HumanTask, a.task_id)
        demo.complete(task, who, {"action_completed": True}, evidence)

    complete_action(action(OffboardingActionType.REMOVE_ACCOUNT_ROLE), "owner", "People list no longer shows the departing tester")
    with container.uow() as s:
        backup_access = next(
            a for a in s.scalars(select(OffboardingAction).where(OffboardingAction.case_id == case_id, OffboardingAction.action_type == OffboardingActionType.REMOVE_VAULT_ACCESS))
            if a.description.endswith(REFS["backup"])
        )
    complete_action(backup_access, "security", "removed from vault group instagram-lumen-codes")
    demo.vault(REFS["backup"], value=f"SYNTHETIC-codes-{secrets.token_urlsafe(12)}")
    complete_action(action(OffboardingActionType.REPLACE_BACKUP_CODES), "owner", "new backup codes generated; old set invalidated")
    with container.uow() as s:
        case = container.offboarding.reconcile(s, container.offboarding.get_case(s, case_id), actor=demo.actor("security"))
        statuses = [a.status for a in case.actions]
    say(
        "offboarding progress",
        f"completed={statuses.count(OffboardingActionStatus.COMPLETED)} pending={statuses.count(OffboardingActionStatus.PENDING)} "
        f"blocked={statuses.count(OffboardingActionStatus.BLOCKED)} (re-run reconciliation created no duplicates)",
    )

    clock.advance(hours=1)
    post = container.audits.run(container.session_factory, trigger=AuditTrigger.MANUAL, actor=demo.actor("auditor", OperatorRole.AUDITOR))
    say("audit after offboarding started", f"{post.summary['totals']} - outstanding offboarding actions surfaced as a finding")

    # ---------------------------------------------------------------- now
    clock.set(real_now)
    final = demo.reminders()
    say("reminder cycle at 'now'", f"reminders={len(final['reminders_queued'])} escalations={len(final['escalations_queued'])} (no provider: not delivered)")
    with container.uow() as s:
        written = container.reports.export_all(s)
    container.engine.dispose()
    print("Evidence pack written (SYNTHETIC):")
    for key, value in written.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
