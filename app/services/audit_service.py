"""Weekly security audit.

Principles:

* Missing data is *missing evidence*, not proof of failure. A check with no
  evidence produces an ``unverified`` finding worded as such ("2FA status has not
  been verified"), never "2FA is disabled".
* Every check result carries a verification label and an evidence reference.
* Findings are keyed by (account, fingerprint). Repeated audits update the open
  finding instead of creating a new one; remediation reuses an active task of the
  same type (including the provisioning task already covering it) before
  creating a new one. A finding that is no longer detected is resolved and its
  audit-created remediation task is closed.
* Scheduled runs use an ISO-week idempotency key, so restarts or overlapping
  schedulers never produce two weekly runs. Interrupted runs are re-run safely.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.clock import Clock
from app.config import CONSUMER_MAIL_DOMAINS, Settings
from app.database import session_scope
from app.enums import (
    AssignmentStatus,
    AuditRunStatus,
    AuditTrigger,
    BackupCodesStatus,
    ControlStatus,
    FindingStatus,
    MetaLinkStatus,
    OffboardingActionStatus,
    PersonStatus,
    ProvisioningStatus,
    ProvisioningStep,
    Responsibility,
    RoleName,
    Severity,
    StepState,
    TaskOrigin,
    TaskPriority,
    TaskStatus,
    TaskType,
    TwoFactorMethod,
    TwoFactorStatus,
    VerificationLabel,
)
from app.errors import ValidationFailed
from app.integrations.meta.base import MetaIntegration
from app.integrations.reads import meta_link_check, run_outside_transaction, vault_inspection
from app.integrations.vault.base import VaultAdapter
from app.logging_setup import log_event
from app.models import (
    AuditFinding,
    AuditRun,
    HumanTask,
    InstagramAccount,
    OffboardingAction,
    Person,
    new_id,
)
from app.security.authorization import Actor
from app.security.redaction import Redactor
from app.security.secret_handling import validate_vault_ref
from app.services.provisioning import MAX_BUSINESS_ADMINS, ProvisioningService
from app.services.reminder_service import find_responsible
from app.services.task_manager import ACTIVE_STATUSES, TaskManager

logger = logging.getLogger("app.audit")

CHECK_RECOVERY_EMAIL = "recovery_email_company_controlled"
CHECK_RECOVERY_PHONE = "recovery_phone_company_controlled"
CHECK_TWO_FACTOR = "two_factor_enabled"
CHECK_BACKUP_CODES = "backup_codes_in_vault"
CHECK_VAULT_REFS = "required_vault_references"
CHECK_META = "meta_business_association"
CHECK_ROLES = "people_roles_match_register"
CHECK_STALE_ACCESS = "access_records_fresh"
CHECK_PROVISIONING = "provisioning_tasks_complete"
CHECK_OUTSTANDING = "outstanding_security_offboarding_actions"
ALL_CHECKS = (
    CHECK_RECOVERY_EMAIL,
    CHECK_RECOVERY_PHONE,
    CHECK_TWO_FACTOR,
    CHECK_BACKUP_CODES,
    CHECK_VAULT_REFS,
    CHECK_META,
    CHECK_ROLES,
    CHECK_STALE_ACCESS,
    CHECK_PROVISIONING,
    CHECK_OUTSTANDING,
)

SEVERITY_DUE_HOURS = {Severity.CRITICAL: 24, Severity.HIGH: 72, Severity.MEDIUM: 168, Severity.LOW: 336}
SEVERITY_PRIORITY = {
    Severity.CRITICAL: TaskPriority.CRITICAL,
    Severity.HIGH: TaskPriority.HIGH,
    Severity.MEDIUM: TaskPriority.NORMAL,
    Severity.LOW: TaskPriority.LOW,
}
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# A run still RUNNING after this long belongs to a dead worker and may be re-run under its key.
STALE_RUN_AFTER = timedelta(hours=1)
# While the provisioning step that would fix a finding is still pending, the
# provisioning workflow already owns the work: no separate remediation task.
REMEDIATION_STEP = {
    TaskType.ENABLE_TWO_FACTOR: ProvisioningStep.TWO_FACTOR,
    TaskType.STORE_BACKUP_CODES: ProvisioningStep.TWO_FACTOR,
    TaskType.STORE_PASSWORD_IN_VAULT: ProvisioningStep.SIGNUP,
    TaskType.LINK_META_BUSINESS: ProvisioningStep.META_LINK,
    TaskType.CONFIRM_RECOVERY_CONTACTS: ProvisioningStep.PLATFORM_VERIFICATION,
    TaskType.REVIEW_ACCESS: ProvisioningStep.ROLES_ASSIGNED,
}


@dataclass
class CheckResult:
    check_name: str
    outcome: str  # pass | finding | not_applicable
    verification: VerificationLabel = VerificationLabel.UNVERIFIED
    description: str = ""
    severity: Severity | None = None
    evidence_ref: str | None = None
    subject: str | None = None
    remediation: TaskType | None = None
    linked_task_ids: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return f"{self.check_name}:{self.subject}" if self.subject else self.check_name

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "outcome": self.outcome,
            "severity": self.severity.value if self.severity else None,
            "verification": self.verification.value,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
            "fingerprint": self.fingerprint,
        }


def _pass(check: str, label: VerificationLabel, description: str, evidence: str | None = None) -> CheckResult:
    return CheckResult(check, "pass", label, description, evidence_ref=evidence)


def _na(check: str, description: str) -> CheckResult:
    return CheckResult(check, "not_applicable", VerificationLabel.UNVERIFIED, description)


def _finding(
    check: str,
    severity: Severity,
    label: VerificationLabel,
    description: str,
    *,
    evidence: str | None = None,
    subject: str | None = None,
    remediation: TaskType | None = None,
    linked: list[str] | None = None,
) -> CheckResult:
    return CheckResult(check, "finding", label, description, severity, evidence, subject, remediation, linked or [])


class AuditService:
    def __init__(
        self,
        *,
        settings: Settings,
        clock: Clock,
        tasks: TaskManager,
        provisioning: ProvisioningService,
        vault: VaultAdapter,
        meta: MetaIntegration,
        redactor: Redactor,
    ):
        self.settings = settings
        self.clock = clock
        self.tasks = tasks
        self.provisioning = provisioning
        self.vault = vault
        self.meta = meta
        self.redactor = redactor
        self.report_writer: Callable[[Session, AuditRun], tuple[str, str]] | None = None

    def register(self) -> None:
        self.tasks.register_post_completion_hook(self._on_task_completed)

    # ------------------------------------------------------------------ checks
    @staticmethod
    def _step(account: InstagramAccount, step: ProvisioningStep):
        return next(s for s in account.steps if s.step == step)

    def _signed_up(self, account: InstagramAccount) -> bool:
        return self._step(account, ProvisioningStep.SIGNUP).state == StepState.COMPLETED

    def _active_task_ids(self, session: Session, account: InstagramAccount, task_type: TaskType) -> list[str]:
        return list(
            session.scalars(
                select(HumanTask.id).where(
                    HumanTask.account_id == account.id,
                    HumanTask.task_type == task_type,
                    HumanTask.status.in_(list(ACTIVE_STATUSES)),
                )
            )
        )

    def _check_recovery(self, account: InstagramAccount, *, kind: str) -> CheckResult:
        check = CHECK_RECOVERY_EMAIL if kind == "email" else CHECK_RECOVERY_PHONE
        if (
            kind == "email"
            and account.company_email_domain in CONSUMER_MAIL_DOMAINS
            and account.company_email_control != ControlStatus.NON_COMPANY
        ):
            # Checked before signup too: a consumer mailbox recorded as company-controlled would launder it.
            fix = (
                "Record it as personal_provider_substitute (before signup: python -m scripts.reset_step --step company_email)."
                if not self._signed_up(account) else "Replace it with a company alias, or record it honestly as a substitute."
            )
            return _finding(
                check, Severity.HIGH, VerificationLabel.HUMAN_CONFIRMED,
                f"The assigned mailbox is on a consumer domain ({account.company_email_domain}) but is recorded as "
                f"company-controlled. {fix}",
                evidence=account.company_email_ref,
            )
        if not self._signed_up(account):
            return _na(check, "Account not yet created on Instagram")
        control = account.recovery_email_control if kind == "email" else account.recovery_phone_control
        label = account.recovery_email_verification if kind == "email" else account.recovery_phone_verification
        evidence = self._step(account, ProvisioningStep.PLATFORM_VERIFICATION).evidence_ref
        if control == ControlStatus.NON_COMPANY:
            return _finding(
                check, Severity.HIGH, label, f"Recovery {kind} is recorded as NOT company-controlled",
                evidence=evidence, remediation=TaskType.CONFIRM_RECOVERY_CONTACTS,
            )
        domains = self.settings.company_email_domains
        if kind == "email" and domains and account.company_email_domain and account.company_email_domain not in domains:
            return _finding(
                check, Severity.HIGH, VerificationLabel.HUMAN_CONFIRMED,
                f"Assigned email domain '{account.company_email_domain}' is not an approved company domain",
                evidence=account.company_email_ref, remediation=TaskType.CONFIRM_RECOVERY_CONTACTS,
            )
        if control == ControlStatus.UNKNOWN or label == VerificationLabel.UNVERIFIED:
            return _finding(
                check, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                f"No evidence on record that the recovery {kind} is company-controlled. This is missing "
                "verification, not proof of a non-company contact.",
                remediation=TaskType.CONFIRM_RECOVERY_CONTACTS,
                linked=None,
            )
        stale_before = self.clock.now() - timedelta(days=self.settings.access_stale_days)
        if account.recovery_last_verified_at and account.recovery_last_verified_at < stale_before:
            return _finding(
                check, Severity.LOW, label,
                f"Recovery {kind} was last confirmed more than {self.settings.access_stale_days} days ago",
                evidence=evidence, remediation=TaskType.CONFIRM_RECOVERY_CONTACTS,
            )
        note = "" if (kind != "email" or domains) else " (COMPANY_EMAIL_DOMAINS not configured: domain not cross-checked)"
        return _pass(check, label, f"Recovery {kind} confirmed company-controlled{note}", evidence)

    def _check_two_factor(self, session: Session, account: InstagramAccount) -> CheckResult:
        if not self._signed_up(account):
            return _na(CHECK_TWO_FACTOR, "Account not yet created on Instagram")
        linked = self._active_task_ids(session, account, TaskType.ENABLE_TWO_FACTOR)
        evidence = self._step(account, ProvisioningStep.TWO_FACTOR).evidence_ref
        if account.two_factor_status == TwoFactorStatus.DISABLED:
            return _finding(
                CHECK_TWO_FACTOR, Severity.CRITICAL, account.two_factor_verification,
                "Two-factor authentication is recorded as disabled", evidence=evidence,
                remediation=TaskType.ENABLE_TWO_FACTOR, linked=linked,
            )
        if account.two_factor_status == TwoFactorStatus.UNKNOWN:
            return _finding(
                CHECK_TWO_FACTOR, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                "Two-factor authentication has not been verified. No integration can read Instagram 2FA state, so "
                "this requires human confirmation; it is not evidence that 2FA is disabled.",
                remediation=TaskType.ENABLE_TWO_FACTOR, linked=linked,
            )
        if account.two_factor_method == TwoFactorMethod.UNKNOWN:
            return _finding(
                CHECK_TWO_FACTOR, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                "Two-factor authentication is enabled but its method is not recorded",
                evidence=evidence, remediation=TaskType.ENABLE_TWO_FACTOR, linked=linked,
            )
        if account.two_factor_method == TwoFactorMethod.SMS:
            return _finding(
                CHECK_TWO_FACTOR, Severity.LOW, account.two_factor_verification,
                "Two-factor authentication uses SMS (SIM-swap risk); prefer an authenticator app or security key",
                evidence=evidence, remediation=TaskType.ENABLE_TWO_FACTOR, linked=linked,
            )
        return _pass(
            CHECK_TWO_FACTOR, account.two_factor_verification,
            f"Two-factor authentication enabled via {account.two_factor_method.value}", evidence,
        )

    def _check_backup_codes(self, session: Session, account: InstagramAccount) -> CheckResult:
        if not self._signed_up(account):
            return _na(CHECK_BACKUP_CODES, "Account not yet created on Instagram")
        if account.backup_codes_status == BackupCodesStatus.REPLACEMENT_REQUIRED:
            linked = [
                a.task_id
                for a in session.scalars(
                    select(OffboardingAction).where(
                        OffboardingAction.account_id == account.id,
                        OffboardingAction.status.in_([OffboardingActionStatus.PENDING, OffboardingActionStatus.IN_PROGRESS, OffboardingActionStatus.BLOCKED]),
                    )
                )
                if a.task_id and a.action_type.value == "replace_backup_codes"
            ]
            return _finding(
                CHECK_BACKUP_CODES, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                "Backup codes may have been exposed to a departing team member; replacement is pending",
                evidence="system-of-record:offboarding", remediation=None if linked else TaskType.STORE_BACKUP_CODES,
                linked=linked,
            )
        linked = self._active_task_ids(session, account, TaskType.ENABLE_TWO_FACTOR)
        if not account.backup_codes_vault_ref:
            return _finding(
                CHECK_BACKUP_CODES, Severity.HIGH, VerificationLabel.UNVERIFIED,
                "No backup-code vault reference is recorded, so it cannot be confirmed that backup codes exist",
                remediation=TaskType.STORE_BACKUP_CODES, linked=linked,
            )
        inspection = vault_inspection(self.vault, account.backup_codes_vault_ref)
        if inspection.exists is False:
            return _finding(
                CHECK_BACKUP_CODES, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                "The vault reports no entry at the recorded backup-code reference",
                evidence=account.backup_codes_vault_ref, remediation=TaskType.STORE_BACKUP_CODES,
            )
        if inspection.exists is None and inspection.label == VerificationLabel.UNVERIFIED:
            return _finding(
                CHECK_BACKUP_CODES, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                f"Backup-code presence could not be verified this run ({inspection.detail}); not a confirmed failure",
            )
        if inspection.exists:
            return _pass(
                CHECK_BACKUP_CODES, VerificationLabel.INTEGRATION_VERIFIED, "Vault entry for backup codes exists",
                f"{account.backup_codes_vault_ref} ({inspection.evidence_ref})",
            )
        if account.backup_codes_status == BackupCodesStatus.PRESENT_IN_VAULT:
            return _pass(
                CHECK_BACKUP_CODES, VerificationLabel.HUMAN_CONFIRMED,
                "Backup codes human-confirmed as stored in the vault (vault presence not machine-verifiable)",
                account.backup_codes_vault_ref,
            )
        return _finding(
            CHECK_BACKUP_CODES, Severity.HIGH, VerificationLabel.UNVERIFIED,
            f"Backup codes status is '{account.backup_codes_status.value}'", remediation=TaskType.STORE_BACKUP_CODES,
        )

    def _check_vault_refs(self, account: InstagramAccount) -> list[CheckResult]:
        if not self._signed_up(account):
            return [_na(CHECK_VAULT_REFS, "Account not yet created on Instagram")]
        results: list[CheckResult] = []
        labels: list[VerificationLabel | None] = []
        unverifiable: list[str] = []
        refs = {"password": account.password_vault_ref, **(account.other_vault_refs or {})}
        if account.two_factor_method == TwoFactorMethod.AUTHENTICATOR_APP and not refs.get("totp_seed"):
            results.append(
                _finding(
                    CHECK_VAULT_REFS, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                    "Authenticator-app 2FA is recorded but no vault reference for its setup key is recorded",
                    subject="totp_seed", remediation=TaskType.ENABLE_TWO_FACTOR,
                )
            )
        for name, ref in refs.items():
            if not ref:
                results.append(
                    _finding(
                        CHECK_VAULT_REFS, Severity.HIGH, VerificationLabel.UNVERIFIED,
                        f"No vault reference recorded for the {name}", subject=name,
                        remediation=TaskType.STORE_PASSWORD_IN_VAULT if name == "password" else None,
                    )
                )
                continue
            try:
                validate_vault_ref(ref, self.settings.allowed_vault_schemes, field=name)
            except ValidationFailed:
                results.append(
                    _finding(
                        CHECK_VAULT_REFS, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                        f"The {name} vault reference is malformed or uses an unconfigured scheme", subject=name,
                        remediation=TaskType.STORE_PASSWORD_IN_VAULT if name == "password" else None,
                    )
                )
                continue
            inspection = vault_inspection(self.vault, ref)
            if inspection.exists is False:
                results.append(
                    _finding(
                        CHECK_VAULT_REFS, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                        f"The vault reports no entry at the {name} reference", evidence=ref, subject=name,
                        remediation=TaskType.STORE_PASSWORD_IN_VAULT if name == "password" else None,
                    )
                )
            elif inspection.exists is None:
                labels.append(inspection.label)
                if inspection.label == VerificationLabel.UNVERIFIED:
                    unverifiable.append(f"{name} ({inspection.detail})")
            else:
                labels.append(VerificationLabel.INTEGRATION_VERIFIED)
        if unverifiable and not results:
            results.append(
                _finding(
                    CHECK_VAULT_REFS, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                    f"Vault references could not be verified this run: {'; '.join(unverifiable)}. Not a confirmed failure.",
                    subject="unverifiable",
                )
            )
        if not results:
            # integration_verified only if the vault actually confirmed every reference.
            label = (
                VerificationLabel.INTEGRATION_VERIFIED
                if labels and all(lbl == VerificationLabel.INTEGRATION_VERIFIED for lbl in labels)
                else VerificationLabel.HUMAN_CONFIRMED
            )
            results.append(_pass(CHECK_VAULT_REFS, label, f"Required vault references present: {', '.join(sorted(refs))}"))
        return results

    def _check_meta(self, session: Session, account: InstagramAccount) -> CheckResult:
        if not self._signed_up(account):
            return _na(CHECK_META, "Account not yet created on Instagram")
        linked = self._active_task_ids(session, account, TaskType.LINK_META_BUSINESS)
        if account.meta_link_status == MetaLinkStatus.MISMATCH:
            return _finding(
                CHECK_META, Severity.HIGH, account.meta_link_verification,
                "The Meta integration does not list this account under the designated business",
                remediation=TaskType.LINK_META_BUSINESS, linked=linked,
            )
        if account.meta_link_status != MetaLinkStatus.LINKED:
            return _finding(
                CHECK_META, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                "The Meta business association has not been confirmed yet",
                remediation=TaskType.LINK_META_BUSINESS, linked=linked,
            )
        expected = self.settings.meta_business_id
        if expected and account.meta_business_ref != expected:
            return _finding(
                CHECK_META, Severity.HIGH, VerificationLabel.HUMAN_CONFIRMED,
                "The linked business does not match the designated test business",
                evidence=account.meta_business_ref, remediation=TaskType.LINK_META_BUSINESS, linked=linked,
            )
        if self.meta.configured:
            check = meta_link_check(self.meta, account.meta_business_ref or "", account.selected_handle or "")
            if check.status == "linked":
                return _pass(CHECK_META, VerificationLabel.INTEGRATION_VERIFIED, check.detail, check.evidence_ref)
            if check.status == "not_linked":
                account.meta_link_status = MetaLinkStatus.MISMATCH
                return _finding(
                    CHECK_META, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED, check.detail,
                    evidence=check.evidence_ref, remediation=TaskType.LINK_META_BUSINESS,
                )
            return _finding(
                CHECK_META, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                f"Could not verify the Meta association this run ({check.detail}); not a confirmed failure",
            )
        return _pass(
            CHECK_META, account.meta_link_verification,
            "Meta business association human-confirmed (Meta integration not configured)",
            self._step(account, ProvisioningStep.META_LINK).evidence_ref,
        )

    def _check_roles(self, session: Session, account: InstagramAccount) -> list[CheckResult]:
        results: list[CheckResult] = []
        now = self.clock.now()
        review_tasks = self._active_task_ids(session, account, TaskType.REVIEW_ACCESS)
        for a in account.assignments:
            person = a.person
            label = a.verification  # a finding is only as verified as the record it rests on
            if a.status == AssignmentStatus.ACTIVE and person.status == PersonStatus.OFFBOARDED:
                results.append(
                    _finding(
                        CHECK_ROLES, Severity.CRITICAL, label,
                        f"Offboarded person {person.full_name} still holds active role {a.role.value}",
                        subject=a.id, remediation=TaskType.REVIEW_ACCESS, linked=review_tasks,
                    )
                )
            elif a.status in (AssignmentStatus.ACTIVE, AssignmentStatus.PENDING_REMOVAL) and person.status == PersonStatus.DEPARTING:
                offboarding_tasks = [
                    x.task_id
                    for x in session.scalars(
                        select(OffboardingAction).where(OffboardingAction.target_ref == f"assignment:{a.id}")
                    )
                    if x.task_id and x.status != OffboardingActionStatus.COMPLETED
                ]
                results.append(
                    _finding(
                        CHECK_ROLES, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                        f"Departing person {person.full_name} still holds role {a.role.value}; removal is tracked in offboarding",
                        evidence="system-of-record:offboarding", subject=a.id, linked=offboarding_tasks,
                    )
                )
            elif a.status == AssignmentStatus.ACTIVE and not a.approved:
                results.append(
                    _finding(
                        CHECK_ROLES, Severity.HIGH, label,
                        f"{person.full_name} holds {a.role.value} but it is not in the approved register",
                        subject=a.id, remediation=TaskType.REVIEW_ACCESS, linked=review_tasks,
                    )
                )
            elif a.status == AssignmentStatus.REQUESTED and now - a.created_at > timedelta(days=7):
                results.append(
                    _finding(
                        CHECK_ROLES, Severity.LOW, VerificationLabel.INTEGRATION_VERIFIED,
                        f"Approved role {a.role.value} for {person.full_name} has not been granted after 7 days",
                        subject=a.id, linked=self._active_task_ids(session, account, TaskType.ASSIGN_PEOPLE_ROLES),
                    )
                )
            elif (
                a.status == AssignmentStatus.ACTIVE
                and a.is_temporary_test_role
                and a.granted_at
                and now - a.granted_at > timedelta(days=14)
            ):
                results.append(
                    _finding(
                        CHECK_ROLES, Severity.MEDIUM, label,
                        f"Temporary test role for {person.full_name} is still active after 14 days",
                        subject=a.id, remediation=TaskType.REVIEW_ACCESS, linked=review_tasks,
                    )
                )
        roles_done = self._step(account, ProvisioningStep.ROLES_ASSIGNED).state == StepState.COMPLETED
        admins = [a for a in account.assignments if a.role == RoleName.BUSINESS_ADMIN and a.status == AssignmentStatus.ACTIVE]
        if roles_done and not admins:
            results.append(
                _finding(
                    CHECK_ROLES, Severity.HIGH, VerificationLabel.HUMAN_CONFIRMED,
                    "No active business admin in the register (administrative access path at risk)",
                    subject="no_admin", remediation=TaskType.REVIEW_ACCESS, linked=review_tasks,
                )
            )
        if len(admins) > MAX_BUSINESS_ADMINS:
            results.append(
                _finding(
                    CHECK_ROLES, Severity.MEDIUM, VerificationLabel.HUMAN_CONFIRMED,
                    f"{len(admins)} business admins exceed the least-privilege limit of {MAX_BUSINESS_ADMINS}",
                    subject="too_many_admins", remediation=TaskType.REVIEW_ACCESS, linked=review_tasks,
                )
            )
        if not results:
            if not account.assignments:
                return [_na(CHECK_ROLES, "No people assigned yet")]
            active = [a for a in account.assignments if a.status == AssignmentStatus.ACTIVE]
            if not active:
                requested = sum(a.status == AssignmentStatus.REQUESTED for a in account.assignments)
                return [
                    _na(
                        CHECK_ROLES,
                        f"No role has been granted or confirmed yet ({requested} approved assignment(s) requested; "
                        "granting them is a provisioning task). Nothing to compare.",
                    )
                ]
            labels = {a.verification for a in active}
            label = (
                VerificationLabel.UNVERIFIED if VerificationLabel.UNVERIFIED in labels
                else VerificationLabel.HUMAN_CONFIRMED if VerificationLabel.HUMAN_CONFIRMED in labels
                else VerificationLabel.INTEGRATION_VERIFIED
            )  # the weakest evidence among the active grants
            results.append(
                _pass(
                    CHECK_ROLES, label,
                    "Register roles match the approved register (platform-side roles human-confirmed; no Meta role integration)",
                )
            )
        return results

    def _check_stale_access(self, session: Session, account: InstagramAccount) -> CheckResult:
        active = [a for a in account.assignments if a.status == AssignmentStatus.ACTIVE]
        if not active:
            return _na(CHECK_STALE_ACCESS, "No active access records")
        threshold = self.clock.now() - timedelta(days=self.settings.access_stale_days)
        stale = [a for a in active if (a.last_verified_at or a.granted_at or a.created_at) < threshold]
        if stale:
            names = ", ".join(sorted(f"{a.person.full_name} ({a.role.value})" for a in stale))
            return _finding(
                CHECK_STALE_ACCESS, Severity.MEDIUM, VerificationLabel.UNVERIFIED,
                f"{len(stale)} access record(s) not verified in the last {self.settings.access_stale_days} days: {names}",
                remediation=TaskType.REVIEW_ACCESS, linked=self._active_task_ids(session, account, TaskType.REVIEW_ACCESS),
            )
        return _pass(
            CHECK_STALE_ACCESS, VerificationLabel.HUMAN_CONFIRMED,
            f"All {len(active)} active access record(s) verified within {self.settings.access_stale_days} days",
        )

    def _check_provisioning(self, session: Session, account: InstagramAccount) -> CheckResult:
        now = self.clock.now()
        pending = [s.step.value for s in account.steps if s.state != StepState.COMPLETED]
        active = session.scalars(
            select(HumanTask).where(
                HumanTask.account_id == account.id,
                HumanTask.origin == TaskOrigin.PROVISIONING,
                HumanTask.status.in_(list(ACTIVE_STATUSES)),
            )
        ).all()
        if not pending and account.provisioning_status == ProvisioningStatus.PROVISIONED:
            return _pass(
                CHECK_PROVISIONING, VerificationLabel.INTEGRATION_VERIFIED,
                "All provisioning steps complete", "system-of-record:account_steps",
            )
        overdue = [t for t in active if t.status == TaskStatus.OVERDUE or (t.due_at < now and t.status != TaskStatus.BLOCKED)]
        blocked = [t for t in active if t.status == TaskStatus.BLOCKED]
        severity = Severity.HIGH if (overdue or blocked or account.provisioning_status == ProvisioningStatus.BLOCKED) else Severity.MEDIUM
        parts = [f"Provisioning incomplete ({account.provisioning_status.value}); pending steps: {', '.join(pending) or 'none'}"]
        if overdue:
            parts.append(f"{len(overdue)} overdue task(s)")
        if blocked or account.blocker_code:
            parts.append(f"blocker: {account.blocker_code or 'task blocked'}")
        return _finding(
            CHECK_PROVISIONING, severity, VerificationLabel.INTEGRATION_VERIFIED, "; ".join(parts),
            evidence="system-of-record:account_steps", linked=[t.id for t in active],
        )

    def _check_outstanding(self, session: Session, account: InstagramAccount) -> list[CheckResult]:
        results: list[CheckResult] = []
        person_ids = {a.person_id for a in account.assignments}
        actions = [
            a
            for a in session.scalars(
                select(OffboardingAction).where(
                    OffboardingAction.status.in_(
                        [OffboardingActionStatus.PENDING, OffboardingActionStatus.IN_PROGRESS, OffboardingActionStatus.BLOCKED]
                    )
                )
            )
            if a.account_id == account.id or (a.account_id is None and a.case.person_id in person_ids)
        ]
        if actions:
            blocked = [a for a in actions if a.status == OffboardingActionStatus.BLOCKED]
            results.append(
                _finding(
                    CHECK_OUTSTANDING, Severity.HIGH if blocked else Severity.MEDIUM, VerificationLabel.INTEGRATION_VERIFIED,
                    f"{len(actions)} offboarding action(s) outstanding ({len(blocked)} blocked)",
                    evidence="system-of-record:offboarding_actions", subject="offboarding",
                    linked=[a.task_id for a in actions if a.task_id],
                )
            )
        now = self.clock.now()
        overdue_remediation = session.scalars(
            select(HumanTask).where(
                HumanTask.account_id == account.id,
                HumanTask.origin == TaskOrigin.AUDIT,
                HumanTask.status.in_(list(ACTIVE_STATUSES)),
                HumanTask.due_at < now,
            )
        ).all()
        if overdue_remediation:
            results.append(
                _finding(
                    CHECK_OUTSTANDING, Severity.MEDIUM, VerificationLabel.INTEGRATION_VERIFIED,
                    f"{len(overdue_remediation)} security remediation task(s) overdue",
                    evidence="system-of-record:tasks", subject="overdue_remediation",
                    linked=[t.id for t in overdue_remediation],
                )
            )
        reviews = session.scalars(
            select(HumanTask).where(
                HumanTask.task_type == TaskType.PROXY_SECURITY_REVIEW,
                HumanTask.status.in_(list(ACTIVE_STATUSES)),
                HumanTask.account_id == account.id,
            )
        ).all()
        if reviews:
            results.append(
                _finding(
                    CHECK_OUTSTANDING, Severity.HIGH, VerificationLabel.INTEGRATION_VERIFIED,
                    f"{len(reviews)} security-challenge review(s) awaiting a human decision",
                    evidence="system-of-record:proxy_sessions", subject="security_challenge_review",
                    linked=[t.id for t in reviews],
                )
            )
        if not results:
            results.append(
                _pass(CHECK_OUTSTANDING, VerificationLabel.INTEGRATION_VERIFIED, "No outstanding offboarding or security actions", "system-of-record:tasks")
            )
        return results

    def evaluate_account(self, session: Session, account: InstagramAccount) -> list[CheckResult]:
        results: list[CheckResult] = [
            self._check_recovery(account, kind="email"),
            self._check_recovery(account, kind="phone"),
            self._check_two_factor(session, account),
            self._check_backup_codes(session, account),
            *self._check_vault_refs(account),
            self._check_meta(session, account),
            *self._check_roles(session, account),
            self._check_stale_access(session, account),
            self._check_provisioning(session, account),
            *self._check_outstanding(session, account),
        ]
        for result in results:
            result.description = self.redactor.redact_text(result.description)
        return results

    # ------------------------------------------------------------------ findings & remediation
    def _remediation_owner(self, session: Session, account: InstagramAccount) -> Person | None:
        if account.owner and account.owner.status == PersonStatus.ACTIVE:
            return account.owner
        return find_responsible(session, Responsibility.SECURITY_OWNER) or find_responsible(session, Responsibility.ESCALATION_DEFAULT)

    def _ensure_remediation(self, session: Session, account: InstagramAccount, finding: AuditFinding, result: CheckResult) -> None:
        if result.linked_task_ids:
            finding.remediation_task_id = result.linked_task_ids[0]
            finding.remediation_blocker = None
            return
        if result.remediation is None:
            return
        current = session.get(HumanTask, finding.remediation_task_id) if finding.remediation_task_id else None
        if current is not None and current.status in ACTIVE_STATUSES:
            return
        reuse = self._active_task_ids(session, account, result.remediation)
        if reuse:
            finding.remediation_task_id = reuse[0]
            return
        step = REMEDIATION_STEP.get(result.remediation)
        if step is not None and self._step(account, step).state != StepState.COMPLETED:
            finding.remediation_blocker = f"covered by the provisioning workflow (step '{step.value}' still pending)"
            return
        owner = self._remediation_owner(session, account)
        if owner is None:
            finding.remediation_blocker = "No active owner or security owner available to assign remediation"
            return
        severity = result.severity or Severity.MEDIUM
        generation = finding.remediation_generation + 1
        ctx = {**self.provisioning._context(session, account), "finding_description": result.description, "finding_id": finding.id}
        task, _ = self.tasks.create_task(
            session,
            task_type=result.remediation,
            owner_id=owner.id,
            idempotency_key=f"remediation:{finding.id}:g{generation}",
            account_id=account.id,
            context=ctx,
            due_at=self.clock.now() + timedelta(hours=SEVERITY_DUE_HOURS[severity]),
            priority=SEVERITY_PRIORITY[severity],
            payload={"finding_id": finding.id, "check_name": finding.check_name},
            origin=TaskOrigin.AUDIT,
        )
        finding.remediation_task_id = task.id
        finding.remediation_generation = generation
        finding.remediation_blocker = None

    def reconcile_findings(
        self,
        session: Session,
        account: InstagramAccount,
        results: list[CheckResult],
        *,
        run_id: str | None,
        only_checks: set[str] | None = None,
    ) -> dict[str, int]:
        now = self.clock.now()
        stats = {"new": 0, "reused": 0, "resolved": 0}
        open_findings = {
            f.fingerprint: f
            for f in session.scalars(
                select(AuditFinding).where(AuditFinding.account_id == account.id, AuditFinding.status == FindingStatus.OPEN)
            )
        }
        seen: set[str] = set()
        evaluated = {r.check_name for r in results}
        for result in results:
            if result.outcome != "finding" or (only_checks and result.check_name not in only_checks):
                continue
            seen.add(result.fingerprint)
            finding = open_findings.get(result.fingerprint)
            if finding is None:
                finding = AuditFinding(
                    id=new_id("fnd"),
                    account_id=account.id,
                    check_name=result.check_name,
                    fingerprint=result.fingerprint,
                    severity=result.severity or Severity.MEDIUM,
                    description=result.description,
                    verification=result.verification,
                    evidence_ref=result.evidence_ref,
                    first_detected_at=now,
                    last_detected_at=now,
                    occurrence_count=1,
                    last_run_id=run_id,
                    status=FindingStatus.OPEN,
                )
                try:
                    with session.begin_nested():
                        session.add(finding)
                        session.flush()
                except IntegrityError:
                    finding = session.scalar(
                        select(AuditFinding).where(
                            AuditFinding.account_id == account.id,
                            AuditFinding.fingerprint == result.fingerprint,
                            AuditFinding.status == FindingStatus.OPEN,
                        )
                    )
                    assert finding is not None
                    stats["reused"] += 1
                else:
                    stats["new"] += 1
            else:
                finding.severity = result.severity or finding.severity
                finding.description = result.description
                finding.verification = result.verification
                finding.evidence_ref = result.evidence_ref
                finding.last_detected_at = now
                finding.occurrence_count += 1
                if run_id:
                    finding.last_run_id = run_id
                stats["reused"] += 1
            self._ensure_remediation(session, account, finding, result)
        for fingerprint, finding in open_findings.items():
            if fingerprint in seen or finding.check_name not in evaluated:
                continue
            if only_checks and finding.check_name not in only_checks:
                continue
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            finding.resolution_note = f"Not detected in audit run {run_id}" if run_id else "Not detected on re-check after remediation"
            stats["resolved"] += 1
            task = session.get(HumanTask, finding.remediation_task_id) if finding.remediation_task_id else None
            if task is not None and task.origin == TaskOrigin.AUDIT and task.status in ACTIVE_STATUSES:
                self.tasks.cancel_task(session, task, actor=None, reason=f"finding {finding.id} resolved")
        return stats

    def _on_task_completed(self, session: Session, task: HumanTask, actor: Actor) -> None:
        if task.account_id is None:
            return
        findings = session.scalars(
            select(AuditFinding).where(
                AuditFinding.remediation_task_id == task.id, AuditFinding.status == FindingStatus.OPEN
            )
        ).all()
        if not findings:
            return
        session.flush()
        account = session.get(InstagramAccount, task.account_id)
        assert account is not None
        session.refresh(account)
        results = self.evaluate_account(session, account)
        self.reconcile_findings(session, account, results, run_id=None, only_checks={f.check_name for f in findings})

    # ------------------------------------------------------------------ runs
    @staticmethod
    def weekly_key(now: datetime) -> str:
        iso = now.isocalendar()
        return f"weekly:{iso.year}-W{iso.week:02d}"

    def scheduled_time_this_week(self, now: datetime) -> datetime:
        monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        return monday + timedelta(days=_WEEKDAYS.index(self.settings.audit_weekly_day), hours=self.settings.audit_weekly_hour_utc)

    def run_weekly_if_due(self, factory: sessionmaker[Session], *, actor: Actor) -> AuditRun | None:
        now = self.clock.now()
        if now < self.scheduled_time_this_week(now):
            return None
        return self.run(factory, trigger=AuditTrigger.SCHEDULED, actor=actor, idempotency_key=self.weekly_key(now))

    def run(
        self,
        factory: sessionmaker[Session],
        *,
        trigger: AuditTrigger,
        actor: Actor,
        idempotency_key: str | None = None,
    ) -> AuditRun:
        now = self.clock.now()
        with session_scope(factory) as session:
            run = None
            if idempotency_key:
                run = session.scalar(select(AuditRun).where(AuditRun.idempotency_key == idempotency_key))
                stale = run is not None and run.status == AuditRunStatus.RUNNING and now - run.started_at > STALE_RUN_AFTER
                if run is not None and not stale and run.status in (
                    AuditRunStatus.COMPLETED,
                    AuditRunStatus.COMPLETED_WITH_ERRORS,
                    AuditRunStatus.RUNNING,
                ):
                    log_event(logger, "audit.run_skipped", action="run_audit", outcome=f"existing_{run.status.value}", audit_run_id=run.id)
                    return run
                if run is not None:
                    run.status = AuditRunStatus.RUNNING
                    run.attempt_count += 1
                    run.started_at = now
                    run.finished_at = None
            if run is None:
                run = AuditRun(
                    id=new_id("aud"),
                    trigger=trigger,
                    idempotency_key=idempotency_key,
                    status=AuditRunStatus.RUNNING,
                    started_at=now,
                    triggered_by_id=actor.person_id,
                    summary={},
                )
                try:
                    with session.begin_nested():
                        session.add(run)
                        session.flush()
                except IntegrityError:
                    existing = session.scalar(select(AuditRun).where(AuditRun.idempotency_key == idempotency_key))
                    assert existing is not None
                    return existing
            run_id = run.id
            account_ids = list(session.scalars(select(InstagramAccount.id).order_by(InstagramAccount.created_at)))
        log_event(logger, "audit.run_started", action="run_audit", outcome="running", audit_run_id=run_id, trigger=trigger.value)

        per_account: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        def audit_account(account_id: str) -> dict[str, Any]:
            with session_scope(factory) as session:
                account = session.get(InstagramAccount, account_id)
                assert account is not None
                results = self.evaluate_account(session, account)
                stats = self.reconcile_findings(session, account, results, run_id=run_id)
                return {
                    "account_id": account.id,
                    "brand_name": account.brand_name,
                    "handle": account.selected_handle,
                    "is_synthetic": account.is_synthetic,
                    "checks": [r.as_dict() for r in results],
                    "findings_new": stats["new"],
                    "findings_reused": stats["reused"],
                    "findings_resolved": stats["resolved"],
                }

        for account_id in account_ids:
            try:
                # Vault and Meta checks happen between passes, never while this account's transaction is open.
                per_account.append(run_outside_transaction(lambda account_id=account_id: audit_account(account_id)))
            except Exception as exc:  # noqa: BLE001 - one account failing must not abort the whole audit
                errors.append({"account_id": account_id, "error": self.redactor.redact_text(f"{type(exc).__name__}: {exc}")})
                logger.exception("audit account evaluation failed", extra={"event": "audit.account_failed", "fields": {"account_id": account_id}})

        with session_scope(factory) as session:
            run = session.get(AuditRun, run_id)
            assert run is not None
            run.summary = {
                "accounts": per_account,
                "errors": errors,
                "totals": {
                    "accounts": len(account_ids),
                    "findings_new": sum(a["findings_new"] for a in per_account),
                    "findings_reused": sum(a["findings_reused"] for a in per_account),
                    "findings_resolved": sum(a["findings_resolved"] for a in per_account),
                },
            }
            if errors and not per_account and account_ids:
                run.status = AuditRunStatus.FAILED
            elif errors:
                run.status = AuditRunStatus.COMPLETED_WITH_ERRORS
            else:
                run.status = AuditRunStatus.COMPLETED
            run.finished_at = self.clock.now()
        if self.report_writer is not None:
            # Separate transaction: a report failure (e.g. the leak guard) never leaves the run RUNNING.
            try:
                with session_scope(factory) as session:
                    run = session.get(AuditRun, run_id)
                    run.report_json_path, run.report_md_path = self.report_writer(session, run)
            except Exception as exc:  # noqa: BLE001
                logger.exception("audit report could not be written", extra={"event": "audit.report_failed", "fields": {"audit_run_id": run_id}})
                with session_scope(factory) as session:
                    run = session.get(AuditRun, run_id)
                    run.status = AuditRunStatus.COMPLETED_WITH_ERRORS
                    run.error_detail = self.redactor.redact_text(f"report not written: {type(exc).__name__}: {exc}")[:2000]
        log_event(
            logger, "audit.run_finished", action="run_audit", outcome=run.status.value, audit_run_id=run_id,
            findings_new=run.summary["totals"]["findings_new"], findings_reused=run.summary["totals"]["findings_reused"],
        )
        return run
