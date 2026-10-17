"""Provisioning workflow for the company-authorised Instagram account.

The workflow is a deterministic function of persisted state (``advance``): given
which steps are complete, it ensures the next human tasks exist (idempotently)
and derives the account status. It is safe to call any number of times - on
every completion, on restart, from recovery - and never repeats an external
action, because every external action is a *human task* with a stable key.

Signup safety: a signup task that fails, is cancelled or is interrupted never
leads directly to a second signup. The next step is always a reconciliation task
asking a human whether the account already exists. Only an explicit
``does_not_exist`` answer increments ``signup_attempt`` and creates a new task.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.clock import Clock
from app.config import CONSUMER_MAIL_DOMAINS, Settings
from app.enums import (
    AssignmentStatus,
    BackupCodesStatus,
    BusinessAccountStatus,
    ControlStatus,
    CredentialAccessStatus,
    CredentialKind,
    HandleStatus,
    MetaLinkStatus,
    PersonStatus,
    Platform,
    ProvisioningStatus,
    ProvisioningStep,
    Responsibility,
    RoleName,
    StepState,
    TaskOrigin,
    TaskPriority,
    TaskStatus,
    TaskType,
    TwoFactorMethod,
    TwoFactorStatus,
    VerificationLabel,
)
from app.errors import Conflict, NotFound, ValidationFailed
from app.integrations.meta.base import MetaIntegration
from app.integrations.reads import meta_link_check, vault_inspection
from app.integrations.vault.base import VaultAdapter
from app.logging_setup import log_event
from app.models import (
    AccountAssignment,
    AccountStep,
    CredentialAccess,
    HumanTask,
    InstagramAccount,
    Person,
    new_id,
)
from app.security.authorization import SYSTEM_ACTOR, Actor
from app.security.redaction import Redactor
from app.security.secret_handling import reject_secret_material, validate_vault_ref
from app.services.handles import brand_key, suggest_handles
from app.services.reminder_service import find_responsible
from app.services.task_manager import ACTIVE_STATUSES, TaskManager
from app.services.task_types import ValidatedOutcome

logger = logging.getLogger("app.provisioning")

BIO_MAX_CHARS = 150
MAX_BUSINESS_ADMINS = 2

ROLE_CATALOG: dict[RoleName, str] = {
    RoleName.BUSINESS_ADMIN: (
        "Full control of the test business portfolio and the Instagram account. Limit to the account owner "
        "and one backup admin."
    ),
    RoleName.CONTENT_PUBLISHER: "Partial access: create and publish content only. No people, settings or billing.",
    RoleName.COMMUNITY_MANAGER: "Partial access: messages and community activity only.",
    RoleName.INSIGHTS_ANALYST: "Partial access: view insights only (read-only).",
    RoleName.TEMPORARY_TEST_ROLE: (
        "Designated temporary test role: partial access (view insights only), time-boxed, used for the "
        "offboarding live test."
    ),
}

PROFILE_FIELDS = ("profile_name", "bio", "profile_link", "category", "profile_image_ref")


class ProvisioningService:
    def __init__(
        self,
        *,
        settings: Settings,
        clock: Clock,
        tasks: TaskManager,
        vault: VaultAdapter,
        meta: MetaIntegration,
        redactor: Redactor,
    ):
        self.settings = settings
        self.clock = clock
        self.tasks = tasks
        self.vault = vault
        self.meta = meta
        self.redactor = redactor

    def register(self) -> None:
        handlers = {
            TaskType.HANDLE_AVAILABILITY_CHECK: self._on_handle_checked,
            TaskType.ASSIGN_COMPANY_EMAIL: self._on_email_assigned,
            TaskType.ASSIGN_COMPANY_PHONE: self._on_phone_assigned,
            TaskType.ACCOUNT_SIGNUP: self._on_signup_completed,
            TaskType.SIGNUP_RECONCILIATION: self._on_reconciliation_completed,
            TaskType.ACCOUNT_VERIFICATION: self._on_verification_completed,
            TaskType.ENABLE_TWO_FACTOR: self._on_two_factor_completed,
            TaskType.COMPLETE_PROFILE: self._on_profile_completed,
            TaskType.CONVERT_TO_BUSINESS: self._on_business_conversion,
            TaskType.LINK_META_BUSINESS: self._on_meta_linked,
            TaskType.ASSIGN_PEOPLE_ROLES: self._on_roles_assigned,
            TaskType.CONFIRM_RECOVERY_CONTACTS: self._on_recovery_confirmed,
            TaskType.STORE_BACKUP_CODES: self._on_backup_codes_stored,
            TaskType.STORE_PASSWORD_IN_VAULT: self._on_password_stored,
            TaskType.REVIEW_ACCESS: self._on_access_reviewed,
        }
        for task_type, handler in handlers.items():
            self.tasks.register_completion_handler(task_type, handler)
        self.tasks.register_transition_hook(self._on_transition)

    # ------------------------------------------------------------------ queries
    @staticmethod
    def get_account(session: Session, account_id: str) -> InstagramAccount:
        account = session.get(InstagramAccount, account_id)
        if account is None:
            raise NotFound("account not found")
        return account

    @staticmethod
    def _steps(account: InstagramAccount) -> dict[ProvisioningStep, AccountStep]:
        return {s.step: s for s in account.steps}

    def provisioning_gaps(self, account: InstagramAccount) -> list[str]:
        gaps: list[str] = []
        for step in account.steps:
            if step.state != StepState.COMPLETED:
                gaps.append(f"step '{step.step.value}' is {step.state.value}")
            elif step.verification == VerificationLabel.UNVERIFIED:
                gaps.append(f"step '{step.step.value}' completed without adequate verification")
        if not account.password_vault_ref:
            gaps.append("no password vault reference recorded")
        if account.two_factor_status != TwoFactorStatus.ENABLED:
            gaps.append("two-factor authentication not confirmed enabled")
        if account.backup_codes_status != BackupCodesStatus.PRESENT_IN_VAULT:
            gaps.append(f"backup codes status is {account.backup_codes_status.value}")
        if any(getattr(account, f) in (None, "") for f in PROFILE_FIELDS):
            gaps.append("profile specification incomplete")
        if not any(
            a.role == RoleName.BUSINESS_ADMIN and a.status == AssignmentStatus.ACTIVE for a in account.assignments
        ):
            gaps.append("no active business_admin assignment")
        return gaps

    # ------------------------------------------------------------------ creation
    def create_account(
        self,
        session: Session,
        *,
        brand_name: str,
        owner_id: str,
        actor: Actor,
        keywords: list[str] | None = None,
        profile: dict[str, Any] | None = None,
        is_synthetic: bool = False,
    ) -> tuple[InstagramAccount, bool]:
        reject_secret_material("brand_name", brand_name)
        key = brand_key(brand_name)
        existing = session.scalar(select(InstagramAccount).where(InstagramAccount.brand_key == key))
        if existing is not None:
            log_event(logger, "account.create_duplicate", account_id=existing.id, action="create_account", outcome="existing_returned")
            return existing, False
        owner = session.get(Person, owner_id)
        if owner is None or owner.status != PersonStatus.ACTIVE:
            raise ValidationFailed("account owner must be an existing, active person")
        now = self.clock.now()
        account = InstagramAccount(
            id=new_id("acc"),
            brand_name=brand_name.strip(),
            brand_key=key,
            is_synthetic=is_synthetic,
            environment="synthetic_demo" if is_synthetic else self.settings.environment_label,
            suggested_handles=suggest_handles(brand_name, keywords or []),
            owner_id=owner_id,
            provisioning_status=ProvisioningStatus.DRAFT,
            other_vault_refs={},
            created_at=now,
            updated_at=now,
        )
        if profile:
            self._apply_profile(account, profile)
        try:
            with session.begin_nested():
                session.add(account)
                session.flush()
        except IntegrityError:
            existing = session.scalar(select(InstagramAccount).where(InstagramAccount.brand_key == key))
            if existing is None:
                raise
            return existing, False
        for step in ProvisioningStep:
            account.steps.append(AccountStep(step=step, state=StepState.PENDING, updated_at=now))
        session.flush()
        log_event(logger, "account.created", account_id=account.id, action="create_account", outcome="created", synthetic=is_synthetic)
        self.advance(session, account, actor=actor)
        return account, True

    # ------------------------------------------------------------------ profile / register
    @staticmethod
    def validate_bio(bio: str | None) -> None:
        if bio is not None and len(bio) > BIO_MAX_CHARS:
            raise ValidationFailed(f"bio must be at most {BIO_MAX_CHARS} characters (got {len(bio)})")

    def _apply_profile(self, account: InstagramAccount, profile: dict[str, Any]) -> bool:
        self.validate_bio(profile.get("bio"))
        for name in ("profile_name", "bio", "category"):
            reject_secret_material(name, profile.get(name))
        changed = False
        for name in PROFILE_FIELDS:
            if name in profile and getattr(account, name) != profile[name]:
                setattr(account, name, profile[name])
                changed = True
        account.bio_char_count = len(account.bio or "")
        return changed

    def set_profile_spec(self, session: Session, account_id: str, profile: dict[str, Any], *, actor: Actor) -> InstagramAccount:
        account = self.get_account(session, account_id)
        if not self._apply_profile(account, profile):
            return account
        account.updated_at = self.clock.now()
        step = self._steps(account)[ProvisioningStep.PROFILE]
        if step.state == StepState.COMPLETED:
            # The live profile no longer matches the approved spec: the step must be redone.
            step.state = StepState.PENDING
            step.verification = VerificationLabel.UNVERIFIED
        self._supersede_active(session, account, TaskType.COMPLETE_PROFILE, "approved profile specification changed")
        log_event(logger, "account.profile_spec_updated", account_id=account.id, action="set_profile_spec", outcome="updated")
        self.advance(session, account, actor=actor)
        return account

    def add_assignment(
        self,
        session: Session,
        account_id: str,
        *,
        person_id: str,
        platform: Platform,
        role: RoleName,
        actor: Actor,
    ) -> AccountAssignment:
        account = self.get_account(session, account_id)
        person = session.get(Person, person_id)
        if person is None or person.status != PersonStatus.ACTIVE:
            raise ValidationFailed("assigned person must be an existing, active person")
        if role == RoleName.BUSINESS_ADMIN:
            admins = [
                a for a in account.assignments
                if a.role == RoleName.BUSINESS_ADMIN and a.status != AssignmentStatus.REMOVED and a.person_id != person_id
            ]
            if len(admins) >= MAX_BUSINESS_ADMINS:
                raise Conflict(f"least privilege: at most {MAX_BUSINESS_ADMINS} business admins per account")
        now = self.clock.now()
        existing = next(
            (a for a in account.assignments if a.person_id == person_id and a.platform == platform and a.role == role),
            None,
        )
        if existing is not None and existing.status != AssignmentStatus.REMOVED:
            return existing
        if existing is not None:
            assignment = existing
            assignment.status = AssignmentStatus.REQUESTED
            assignment.removed_at = None
            assignment.verification = VerificationLabel.UNVERIFIED
        else:
            assignment = AccountAssignment(
                id=new_id("asg"),
                person_id=person_id,
                platform=platform,
                role=role,
                role_description=ROLE_CATALOG[role],
                approved=True,
                status=AssignmentStatus.REQUESTED,
                is_temporary_test_role=(role == RoleName.TEMPORARY_TEST_ROLE),
                created_at=now,
                updated_at=now,
            )
            account.assignments.append(assignment)
        session.flush()
        step = self._steps(account)[ProvisioningStep.ROLES_ASSIGNED]
        if step.state == StepState.COMPLETED:
            step.state = StepState.PENDING
        self._supersede_active(session, account, TaskType.ASSIGN_PEOPLE_ROLES, "approved access register changed")
        log_event(
            logger, "account.assignment_requested", account_id=account.id, action="add_assignment", outcome="requested",
            assignment_id=assignment.id, role=role.value,
        )
        self.advance(session, account, actor=actor)
        return assignment

    def add_credential_access(
        self,
        session: Session,
        *,
        person_id: str,
        vault_ref: str,
        credential_kind: CredentialKind,
        account_id: str | None,
        actor: Actor,
    ) -> CredentialAccess:
        validate_vault_ref(vault_ref, self.settings.allowed_vault_schemes)
        person = session.get(Person, person_id)
        if person is None:
            raise NotFound("person not found")
        if person.status == PersonStatus.OFFBOARDED:
            # Access for an offboarded person must not exist; recording it would never be revoked.
            raise Conflict("person is offboarded: new access is refused. If access still exists, remove it now and record an incident task")
        if account_id is not None:
            self.get_account(session, account_id)
        existing = session.scalar(
            select(CredentialAccess).where(CredentialAccess.person_id == person_id, CredentialAccess.vault_ref == vault_ref)
        )
        now = self.clock.now()
        if existing is not None:
            if existing.status == CredentialAccessStatus.REVOKED:
                existing.status = CredentialAccessStatus.ACTIVE
                existing.revoked_at = None
                existing.granted_at = now
            return existing
        access = CredentialAccess(
            id=new_id("cra"),
            person_id=person_id,
            account_id=account_id,
            vault_ref=vault_ref,
            credential_kind=credential_kind,
            status=CredentialAccessStatus.ACTIVE,
            verification=VerificationLabel.HUMAN_CONFIRMED,
            granted_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(access)
        session.flush()
        log_event(logger, "access.credential_access_recorded", account_id=account_id, action="add_credential_access", outcome="recorded")
        return access

    # ------------------------------------------------------------------ blockers / reconciliation
    def _set_blocker(self, account: InstagramAccount, code: str, detail: str, task_id: str | None = None) -> None:
        if account.provisioning_status != ProvisioningStatus.BLOCKED:
            account.status_before_block = account.provisioning_status
            account.provisioning_status = ProvisioningStatus.BLOCKED
            account.blocked_at = self.clock.now()
        account.blocker_code = code[:80]
        account.blocker_detail = self.redactor.redact_text(detail)[:2000]
        account.blocker_task_id = task_id
        account.updated_at = self.clock.now()
        log_event(logger, "account.blocked", level=logging.WARNING, account_id=account.id, task_id=task_id, action="block", outcome=code)

    def _clear_blocker(self, account: InstagramAccount) -> None:
        if account.provisioning_status == ProvisioningStatus.BLOCKED:
            account.provisioning_status = account.status_before_block or ProvisioningStatus.DRAFT
        account.status_before_block = None
        account.blocker_code = None
        account.blocker_detail = None
        account.blocker_task_id = None
        account.blocked_at = None
        account.updated_at = self.clock.now()
        log_event(logger, "account.unblocked", account_id=account.id, action="unblock", outcome="cleared")

    def set_blocker(self, session: Session, account_id: str, *, code: str, detail: str, actor: Actor) -> InstagramAccount:
        reject_secret_material("detail", detail)
        account = self.get_account(session, account_id)
        self._set_blocker(account, code, detail)
        return account

    def clear_blocker(self, session: Session, account_id: str, *, actor: Actor) -> InstagramAccount:
        account = self.get_account(session, account_id)
        if account.provisioning_status != ProvisioningStatus.BLOCKED:
            raise Conflict("account is not blocked")
        if account.blocker_task_id:
            task = session.get(HumanTask, account.blocker_task_id)
            if task is not None and task.status == TaskStatus.BLOCKED:
                raise Conflict("this blocker comes from a blocked task; unblock or resolve that task instead")
        self._clear_blocker(account)
        self.advance(session, account, actor=actor)
        return account

    def request_reconciliation(self, session: Session, account_id: str, *, actor: Actor, reason: str) -> HumanTask:
        """Operator says 'we are not sure what happened on Instagram': stop the signup and ask a human."""
        reject_secret_material("reason", reason)
        account = self.get_account(session, account_id)
        if self._steps(account)[ProvisioningStep.SIGNUP].state == StepState.COMPLETED:
            raise Conflict("signup is already confirmed; nothing to reconcile")
        signup = self.tasks.find_by_key(session, self._signup_key(account))
        if signup is None:
            raise Conflict("no signup task exists yet; nothing to reconcile")
        if signup.status in ACTIVE_STATUSES:
            self.tasks.cancel_task(session, signup, actor=actor, reason=f"reconciliation requested: {reason}")
        else:
            self.advance(session, account, actor=actor)
        recon = self._latest(session, account, TaskType.SIGNUP_RECONCILIATION)
        if recon is None:
            raise Conflict("reconciliation could not be created")
        return recon

    # ------------------------------------------------------------------ workflow engine
    def _owner_for(self, session: Session, account: InstagramAccount) -> Person | None:
        if account.owner and account.owner.status == PersonStatus.ACTIVE:
            return account.owner
        return find_responsible(session, Responsibility.SECURITY_OWNER) or find_responsible(
            session, Responsibility.ESCALATION_DEFAULT
        )

    def _context(self, session: Session, account: InstagramAccount) -> dict[str, Any]:
        visible = [a for a in account.assignments if a.approved and a.status != AssignmentStatus.REMOVED]
        roles_block = "\n".join(
            f"- {a.person.full_name}: {a.role.value} on {a.platform.value} - {a.role_description}"
            + (" [TEMPORARY TEST ROLE]" if a.is_temporary_test_role else "")
            for a in visible
        ) or "- (no approved people yet: an admin must add assignments to the access register first)"
        if all(getattr(account, f) for f in PROFILE_FIELDS):
            profile_block = (
                f"- Name: {account.profile_name}\n- Bio ({account.bio_char_count}/{BIO_MAX_CHARS}): {account.bio}\n"
                f"- Link: {account.profile_link}\n- Category: {account.category}\n- Profile image: {account.profile_image_ref}"
            )
        else:
            profile_block = "(profile not fully specified yet - an operator must set it before this can be completed)"
        return {
            "brand": account.brand_name,
            "handle": account.selected_handle or "(handle not selected)",
            "suggestions": "\n".join(f"- {h}" for h in account.suggested_handles or []),
            "email_ref": account.company_email_ref,
            "email_hint": account.company_email_hint,
            "phone_ref": account.company_phone_ref,
            "phone_hint": account.company_phone_hint,
            "company_domains": ", ".join(self.settings.company_email_domains) or "COMPANY_EMAIL_DOMAINS not configured",
            "attempt": account.signup_attempt,
            "profile_block": profile_block,
            "roles_block": roles_block,
            "business_ref": self.settings.meta_business_id or "the designated test business (META_BUSINESS_ID not configured)",
            "category": account.category or "(not specified)",
        }

    def _latest(self, session: Session, account: InstagramAccount, task_type: TaskType) -> HumanTask | None:
        return session.scalar(
            select(HumanTask)
            .where(
                HumanTask.account_id == account.id,
                HumanTask.task_type == task_type,
                HumanTask.origin == TaskOrigin.PROVISIONING,
            )
            .order_by(HumanTask.created_at.desc(), HumanTask.id.desc())
            .limit(1)
        )

    def _supersede_active(self, session: Session, account: InstagramAccount, task_type: TaskType, reason: str) -> None:
        latest = self._latest(session, account, task_type)
        if latest is not None and latest.status in ACTIVE_STATUSES:
            self.tasks.cancel_task(session, latest, actor=SYSTEM_ACTOR, reason=f"superseded: {reason}")

    def _ensure(
        self,
        session: Session,
        account: InstagramAccount,
        task_type: TaskType,
        ctx: dict[str, Any],
        *,
        key: str | None = None,
        initial_status: TaskStatus = TaskStatus.PENDING,
        extra_ctx: dict[str, Any] | None = None,
    ) -> HumanTask | None:
        if key is None:
            # Reuse any active task of this type (e.g. an audit remediation already covering it).
            active = session.scalar(
                select(HumanTask).where(
                    HumanTask.account_id == account.id,
                    HumanTask.task_type == task_type,
                    HumanTask.status.in_(list(ACTIVE_STATUSES)),
                )
            )
            if active is not None:
                return active
            previous = session.scalars(
                select(HumanTask.id).where(
                    HumanTask.account_id == account.id,
                    HumanTask.task_type == task_type,
                    HumanTask.origin == TaskOrigin.PROVISIONING,
                )
            ).all()
            key = f"{account.id}:{task_type.value}:g{len(previous) + 1}"
        owner = self._owner_for(session, account)
        if owner is None:
            self._set_blocker(account, "NO_ACTIVE_OWNER", "No active owner or security owner is available to receive tasks")
            return None
        task, _ = self.tasks.create_task(
            session,
            task_type=task_type,
            owner_id=owner.id,
            idempotency_key=key,
            account_id=account.id,
            context={**ctx, **(extra_ctx or {})},
            origin=TaskOrigin.PROVISIONING,
            initial_status=initial_status,
        )
        return task

    @staticmethod
    def _signup_key(account: InstagramAccount) -> str:
        return f"{account.id}:account_signup:a{account.signup_attempt}"

    def _advance_signup(self, session: Session, account: InstagramAccount, ctx: dict[str, Any]) -> ProvisioningStatus:
        signup = self.tasks.find_by_key(session, self._signup_key(account))
        recon_prefix = f"{account.id}:signup_reconciliation:a{account.signup_attempt}:r"
        recons = session.scalars(
            select(HumanTask).where(HumanTask.idempotency_key.like(recon_prefix + "%")).order_by(HumanTask.created_at)
        ).all()
        if any(r.status in ACTIVE_STATUSES for r in recons):
            return ProvisioningStatus.AWAITING_RECONCILIATION
        if signup is None:
            self._ensure(session, account, TaskType.ACCOUNT_SIGNUP, ctx, key=self._signup_key(account))
            return ProvisioningStatus.AWAITING_SIGNUP
        if signup.status in ACTIVE_STATUSES:
            return ProvisioningStatus.AWAITING_SIGNUP
        if signup.status in (TaskStatus.FAILED, TaskStatus.CANCELLED):
            # Never retry signup blindly: the external outcome is unknown until a human reconciles it.
            uncertain = (signup.payload or {}).get("outcome_uncertain")
            reason = f"signup task {signup.status.value}" + (", outcome uncertain" if uncertain else "")
            if signup.error_detail:
                reason += f": {signup.error_detail}"
            self._ensure(
                session,
                account,
                TaskType.SIGNUP_RECONCILIATION,
                ctx,
                key=f"{recon_prefix}{len(recons) + 1}",
                initial_status=TaskStatus.WAITING_FOR_HUMAN,
                extra_ctx={"reason": reason},
            )
            log_event(
                logger, "provisioning.reconciliation_required", level=logging.WARNING, account_id=account.id,
                task_id=signup.id, action="advance_signup", outcome="reconciliation_task_ensured",
            )
            return ProvisioningStatus.AWAITING_RECONCILIATION
        return ProvisioningStatus.AWAITING_VERIFICATION

    def advance(self, session: Session, account: InstagramAccount, *, actor: Actor | None = None) -> InstagramAccount:
        """Idempotently ensure the next human tasks exist and derive the account status."""
        if account.provisioning_status == ProvisioningStatus.BLOCKED:
            return account
        steps = self._steps(account)

        def done(step: ProvisioningStep) -> bool:
            return steps[step].state == StepState.COMPLETED

        ctx = self._context(session, account)
        for step, task_type in (
            (ProvisioningStep.HANDLE_SELECTED, TaskType.HANDLE_AVAILABILITY_CHECK),
            (ProvisioningStep.COMPANY_EMAIL, TaskType.ASSIGN_COMPANY_EMAIL),
            (ProvisioningStep.COMPANY_PHONE, TaskType.ASSIGN_COMPANY_PHONE),
        ):
            if not done(step):
                self._ensure(session, account, task_type, ctx)

        if not done(ProvisioningStep.HANDLE_SELECTED):
            status = ProvisioningStatus.AWAITING_HANDLE_CHECK
        elif not (done(ProvisioningStep.COMPANY_EMAIL) and done(ProvisioningStep.COMPANY_PHONE)):
            status = ProvisioningStatus.AWAITING_CONTACT_ASSIGNMENT
        elif not done(ProvisioningStep.SIGNUP):
            status = self._advance_signup(session, account, ctx)
        elif not done(ProvisioningStep.PLATFORM_VERIFICATION):
            self._ensure(session, account, TaskType.ACCOUNT_VERIFICATION, ctx)
            status = ProvisioningStatus.AWAITING_VERIFICATION
        elif not done(ProvisioningStep.TWO_FACTOR):
            self._ensure(session, account, TaskType.ENABLE_TWO_FACTOR, ctx)
            status = ProvisioningStatus.AWAITING_SECURITY_SETUP
        elif not (done(ProvisioningStep.PROFILE) and done(ProvisioningStep.BUSINESS_CONVERSION)):
            if not done(ProvisioningStep.PROFILE):
                self._ensure(session, account, TaskType.COMPLETE_PROFILE, ctx)
            if not done(ProvisioningStep.BUSINESS_CONVERSION):
                self._ensure(session, account, TaskType.CONVERT_TO_BUSINESS, ctx)
            status = ProvisioningStatus.AWAITING_PROFILE_SETUP
        elif not (done(ProvisioningStep.META_LINK) and done(ProvisioningStep.ROLES_ASSIGNED)):
            if not done(ProvisioningStep.META_LINK):
                self._ensure(session, account, TaskType.LINK_META_BUSINESS, ctx)
            if not done(ProvisioningStep.ROLES_ASSIGNED):
                self._ensure(session, account, TaskType.ASSIGN_PEOPLE_ROLES, ctx)
            status = ProvisioningStatus.AWAITING_META_LINK
        else:
            status = ProvisioningStatus.PROVISIONED if not self.provisioning_gaps(account) else ProvisioningStatus.AWAITING_META_LINK

        if account.provisioning_status == ProvisioningStatus.BLOCKED:  # _ensure may have blocked it
            return account
        if account.provisioning_status == ProvisioningStatus.PROVISIONED and status != ProvisioningStatus.PROVISIONED:
            # Once provisioned the account stays provisioned; drift is reported by the audit and fixed via tasks.
            return account
        if status != account.provisioning_status:
            previous = account.provisioning_status
            account.provisioning_status = status
            account.updated_at = self.clock.now()
            if status == ProvisioningStatus.PROVISIONED:
                account.provisioned_at = self.clock.now()
            log_event(
                logger, "account.status_changed", account_id=account.id, action="advance",
                outcome=status.value, from_status=previous.value,
            )
        return account

    # ------------------------------------------------------------------ hooks
    def _on_transition(self, session: Session, task: HumanTask, old: TaskStatus, new: TaskStatus, actor: Actor) -> None:
        if task.origin != TaskOrigin.PROVISIONING or task.account_id is None:
            return
        account = session.get(InstagramAccount, task.account_id)
        if account is None:
            return
        if new == TaskStatus.BLOCKED:
            self._set_blocker(
                account, f"TASK_BLOCKED:{task.task_type.value}", task.blocker_detail or "task blocked", task_id=task.id
            )
        elif old == TaskStatus.BLOCKED and account.blocker_task_id == task.id:
            self._clear_blocker(account)
            self.advance(session, account, actor=actor)
        elif new in (TaskStatus.FAILED, TaskStatus.CANCELLED):
            # Signup goes to reconciliation; any other step gets its next-generation task, so a
            # pending step is never left without an owned, reminded task.
            self.advance(session, account, actor=actor)

    # ------------------------------------------------------------------ completion helpers
    def _account_for(self, session: Session, task: HumanTask) -> InstagramAccount:
        if task.account_id is None:
            raise ValidationFailed("task is not linked to an account")
        return self.get_account(session, task.account_id)

    def _touch_verified(self, account: InstagramAccount, label: VerificationLabel, evidence_ref: str | None) -> None:
        now = self.clock.now()
        account.last_verified_at = now
        account.verification_source = label
        account.evidence_ref = evidence_ref
        account.updated_at = now

    def _complete_step(
        self,
        account: InstagramAccount,
        step: ProvisioningStep,
        task: HumanTask,
        actor: Actor,
        label: VerificationLabel = VerificationLabel.HUMAN_CONFIRMED,
        evidence_ref: str | None = None,
    ) -> None:
        record = self._steps(account)[step]
        now = self.clock.now()
        record.state = StepState.COMPLETED
        record.verification = label
        record.evidence_ref = evidence_ref or task.completion_evidence_ref
        record.task_id = task.id
        record.completed_at = now
        record.completed_by_id = actor.person_id
        record.updated_at = now
        self._touch_verified(account, label, record.evidence_ref)

    def _vault_label(self, ref: str, field: str) -> tuple[VerificationLabel, str | None]:
        inspection = vault_inspection(self.vault, ref)
        if inspection.exists is False:
            raise ValidationFailed(
                f"No vault entry exists at {field}. Store the secret in the vault first, then complete the task.",
                details=[{"field": field, "problem": "vault entry not found"}],
            )
        if inspection.label is None:
            return VerificationLabel.HUMAN_CONFIRMED, None
        if inspection.label == VerificationLabel.UNVERIFIED:
            log_event(logger, "vault.reference_unverified", level=logging.WARNING, action="inspect_ref", outcome="unverified", detail=inspection.detail)
        return inspection.label, inspection.evidence_ref

    def _record_password_ref(self, account: InstagramAccount, ref: str) -> None:
        label, _ = self._vault_label(ref, "password_vault_ref")
        account.password_vault_ref = ref
        account.password_ref_verification = label

    def _record_backup_codes(self, account: InstagramAccount, ref: str) -> None:
        label, _ = self._vault_label(ref, "backup_codes_vault_ref")
        account.backup_codes_vault_ref = ref
        account.backup_codes_status = BackupCodesStatus.PRESENT_IN_VAULT
        account.backup_codes_verification = label

    # ------------------------------------------------------------------ completion handlers
    def _on_handle_checked(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        handle = outcome.get("selected_handle")
        clash = session.scalar(
            select(InstagramAccount.id).where(InstagramAccount.selected_handle == handle, InstagramAccount.id != account.id)
        )
        if clash is not None:
            raise Conflict("that handle is already selected for another account in the register")
        account.selected_handle = handle
        account.handle_status = HandleStatus.AVAILABLE_HUMAN_CONFIRMED
        self._complete_step(account, ProvisioningStep.HANDLE_SELECTED, task, actor)
        self.advance(session, account, actor=actor)

    def _on_email_assigned(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        domain = outcome.get("email_domain")
        substitute = outcome.get("mailbox_control") == "personal_provider_substitute"
        if not substitute and domain in CONSUMER_MAIL_DOMAINS:
            # Whatever COMPANY_EMAIL_DOMAINS says, a free consumer mailbox is never company-controlled.
            raise ValidationFailed(
                f"A {domain} mailbox is a personal-provider mailbox, not a company-controlled one. Record it as "
                "personal_provider_substitute: the step still completes, and the audit reports it honestly.",
                details=[{"field": "mailbox_control", "problem": "consumer mail domain cannot be company_controlled"}],
            )
        allowed = self.settings.company_email_domains
        # A declared substitute is accepted and flagged; a mailbox claimed as company-controlled must prove its domain.
        if not substitute and allowed and domain not in allowed:
            raise ValidationFailed(
                "The alias is not on an approved company domain. If it is a personal-provider mailbox, record it as "
                "personal_provider_substitute instead.",
                details=[{"field": "email_address", "problem": "domain is not listed in COMPANY_EMAIL_DOMAINS"}],
            )
        account.company_email_ref = outcome.get("email_assignment_ref")
        account.company_email_hint = outcome.get("email_hint")
        account.company_email_domain = domain
        account.company_email_control = ControlStatus.NON_COMPANY if substitute else ControlStatus.COMPANY_CONTROLLED
        self._complete_step(account, ProvisioningStep.COMPANY_EMAIL, task, actor)
        self.advance(session, account, actor=actor)

    def _on_phone_assigned(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        account.company_phone_ref = outcome.get("phone_assignment_ref")
        account.company_phone_hint = outcome.get("phone_hint")
        account.company_phone_control = (
            ControlStatus.NON_COMPANY
            if outcome.get("number_control") == "personal_number_substitute"
            else ControlStatus.COMPANY_CONTROLLED
        )
        self._complete_step(account, ProvisioningStep.COMPANY_PHONE, task, actor)
        self.advance(session, account, actor=actor)

    def _on_signup_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        if task.idempotency_key != self._signup_key(account):
            raise Conflict("this signup task belongs to a superseded attempt")
        if outcome.get("platform_handle") != account.selected_handle:
            raise ValidationFailed(
                "platform_handle does not match the selected handle. If Instagram assigned a different handle, "
                "block this task so the handle decision can be reviewed.",
                details=[{"field": "platform_handle", "problem": "does not match selected handle"}],
            )
        self._record_password_ref(account, outcome.get("password_vault_ref"))
        account.handle_status = HandleStatus.CLAIMED_ON_PLATFORM
        self._complete_step(account, ProvisioningStep.SIGNUP, task, actor)
        self.advance(session, account, actor=actor)

    def _on_reconciliation_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        state = outcome.get("external_account_state")
        signup = self.tasks.find_by_key(session, self._signup_key(account))
        if state == "exists_controlled":
            ref = outcome.get("password_vault_ref")
            if not ref:
                raise ValidationFailed(
                    "password_vault_ref is required when the account exists",
                    details=[{"field": "password_vault_ref", "problem": "required for exists_controlled"}],
                )
            self._record_password_ref(account, ref)
            account.handle_status = HandleStatus.CLAIMED_ON_PLATFORM
            self._complete_step(account, ProvisioningStep.SIGNUP, task, actor)
            if signup is not None and signup.status in ACTIVE_STATUSES:
                self.tasks.cancel_task(session, signup, actor=actor, reason="superseded: reconciliation confirmed the account exists")
        elif state == "does_not_exist":
            if signup is not None and signup.status in ACTIVE_STATUSES:
                self.tasks.cancel_task(session, signup, actor=actor, reason="superseded: reconciliation found no account")
            account.signup_attempt += 1
        else:
            record = self._steps(account)[ProvisioningStep.SIGNUP]
            record.state = StepState.BLOCKED
            detail = (
                f"@{account.selected_handle} exists on Instagram but is not controlled by the company alias. "
                "Escalate to the account owner; do not attempt recovery workarounds or create another account."
            )
            self._set_blocker(account, "HANDLE_EXISTS_NOT_CONTROLLED", detail)
            owner = find_responsible(session, Responsibility.SECURITY_OWNER) or self._owner_for(session, account)
            if owner is not None:
                # An owned, reminded and escalated task so the blocker never sits unnoticed.
                self.tasks.create_task(
                    session,
                    task_type=TaskType.MANUAL,
                    owner_id=owner.id,
                    idempotency_key=f"{account.id}:handle_conflict:a{account.signup_attempt}",
                    account_id=account.id,
                    context={
                        "title": f"Resolve blocker: @{account.selected_handle} exists but is not company-controlled",
                        "description": detail + "\nDecide with the account owner: recover it only through Instagram's "
                        "official support channels, or choose a different handle. When resolved, clear the account "
                        "blocker (DELETE /api/v1/accounts/{id}/blocker) to resume the workflow.",
                    },
                    priority=TaskPriority.CRITICAL,
                    origin=TaskOrigin.PROVISIONING,
                    initial_status=TaskStatus.WAITING_FOR_HUMAN,
                    actor=actor,
                )
        log_event(
            logger, "provisioning.reconciled", account_id=account.id, task_id=task.id, action="reconcile_signup",
            outcome=state, verification_source="human_confirmed",
        )
        self.advance(session, account, actor=actor)

    def _set_recovery_confirmed(self, account: InstagramAccount) -> None:
        # The recovery email is the assigned mailbox; it is only as company-controlled as that mailbox is.
        domain_ok = not self.settings.company_email_domains or account.company_email_domain in self.settings.company_email_domains
        company_mailbox = (
            account.company_email_control != ControlStatus.NON_COMPANY
            and domain_ok
            and account.company_email_domain not in CONSUMER_MAIL_DOMAINS
        )
        account.recovery_email_control = ControlStatus.COMPANY_CONTROLLED if company_mailbox else ControlStatus.NON_COMPANY
        account.recovery_email_verification = VerificationLabel.HUMAN_CONFIRMED
        # The recovery phone is the assigned number; it is only as company-controlled as that number is.
        account.recovery_phone_control = (
            ControlStatus.NON_COMPANY if account.company_phone_control == ControlStatus.NON_COMPANY else ControlStatus.COMPANY_CONTROLLED
        )
        account.recovery_phone_verification = VerificationLabel.HUMAN_CONFIRMED
        account.recovery_last_verified_at = self.clock.now()

    def _on_verification_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        self._set_recovery_confirmed(account)
        self._complete_step(account, ProvisioningStep.PLATFORM_VERIFICATION, task, actor)
        self.advance(session, account, actor=actor)

    def _on_recovery_confirmed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        self._set_recovery_confirmed(account)
        self._touch_verified(account, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref)

    def _on_two_factor_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        account.two_factor_status = TwoFactorStatus.ENABLED
        account.two_factor_method = TwoFactorMethod(outcome.get("two_factor_method"))
        account.two_factor_verification = VerificationLabel.HUMAN_CONFIRMED
        self._record_backup_codes(account, outcome.get("backup_codes_vault_ref"))
        totp_ref = outcome.get("totp_seed_vault_ref")
        if totp_ref:
            self._vault_label(totp_ref, "totp_seed_vault_ref")
            account.other_vault_refs = {**(account.other_vault_refs or {}), "totp_seed": totp_ref}
        if self._steps(account)[ProvisioningStep.TWO_FACTOR].state != StepState.COMPLETED:
            self._complete_step(account, ProvisioningStep.TWO_FACTOR, task, actor)
        else:
            self._touch_verified(account, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref)
        self.advance(session, account, actor=actor)

    def _on_backup_codes_stored(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        self._record_backup_codes(account, outcome.get("backup_codes_vault_ref"))
        self._touch_verified(account, account.backup_codes_verification, task.completion_evidence_ref)

    def _on_password_stored(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        self._record_password_ref(account, outcome.get("password_vault_ref"))
        self._touch_verified(account, account.password_ref_verification, task.completion_evidence_ref)

    def _on_profile_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        missing = [f for f in PROFILE_FIELDS if not getattr(account, f)]
        if missing:
            raise Conflict(
                "The approved profile specification is incomplete; an operator must set it first",
                details={"missing": missing},
            )
        self.validate_bio(account.bio)
        self._complete_step(account, ProvisioningStep.PROFILE, task, actor)
        self.advance(session, account, actor=actor)

    def _on_business_conversion(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        if outcome.get("account_type") != "business":
            raise ValidationFailed(
                "The account must be converted to a business account (creator accounts do not meet this workflow)",
                details=[{"field": "account_type", "problem": "must be business"}],
            )
        account.business_account_status = BusinessAccountStatus.CONVERTED
        self._complete_step(account, ProvisioningStep.BUSINESS_CONVERSION, task, actor)
        self.advance(session, account, actor=actor)

    def _on_meta_linked(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        ref = outcome.get("meta_business_ref")
        expected = self.settings.meta_business_id
        if expected and ref != expected:
            raise ValidationFailed(
                "meta_business_ref does not match the designated test business",
                details=[{"field": "meta_business_ref", "problem": "does not match META_BUSINESS_ID"}],
            )
        check = meta_link_check(self.meta, ref, account.selected_handle or "")
        if check.status == "not_linked":
            raise ValidationFailed(
                "The Meta integration does not list this Instagram account under the business yet. Check the link "
                "in Business Suite and complete the task again.",
                details=[{"field": "meta_business_ref", "problem": "integration reports not linked"}],
            )
        label = VerificationLabel.INTEGRATION_VERIFIED if check.status == "linked" else VerificationLabel.HUMAN_CONFIRMED
        account.meta_business_ref = ref
        account.meta_link_status = MetaLinkStatus.LINKED
        account.meta_link_verification = label
        self._complete_step(account, ProvisioningStep.META_LINK, task, actor, label=label, evidence_ref=check.evidence_ref)
        self.advance(session, account, actor=actor)

    def _on_roles_assigned(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        approved = [a for a in account.assignments if a.approved and a.status in (AssignmentStatus.REQUESTED, AssignmentStatus.ACTIVE)]
        if not any(a.role == RoleName.BUSINESS_ADMIN for a in approved):
            raise Conflict("The approved access register must include at least one business_admin before roles are confirmed")
        now = self.clock.now()
        for assignment in approved:
            if assignment.status == AssignmentStatus.REQUESTED:
                assignment.status = AssignmentStatus.ACTIVE
                assignment.granted_at = now
            assignment.verification = VerificationLabel.HUMAN_CONFIRMED
            assignment.evidence_ref = task.completion_evidence_ref
            assignment.last_verified_at = now
            assignment.updated_at = now
        self._complete_step(account, ProvisioningStep.ROLES_ASSIGNED, task, actor)
        self.advance(session, account, actor=actor)

    def _on_access_reviewed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        account = self._account_for(session, task)
        now = self.clock.now()
        for assignment in account.assignments:
            if assignment.status == AssignmentStatus.ACTIVE:
                assignment.last_verified_at = now
                if assignment.verification != VerificationLabel.INTEGRATION_VERIFIED:
                    assignment.verification = VerificationLabel.HUMAN_CONFIRMED
                assignment.evidence_ref = task.completion_evidence_ref
                assignment.person.last_access_review_at = now
        self._touch_verified(account, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref)

    # ------------------------------------------------------------------ verification
    def record_step_evidence(
        self, session: Session, account_id: str, *, step: ProvisioningStep, evidence_ref: str, actor: Actor
    ) -> AccountStep:
        reject_secret_material("evidence_ref", evidence_ref)
        account = self.get_account(session, account_id)
        record = self._steps(account)[step]
        if record.state != StepState.COMPLETED:
            raise Conflict("evidence can only be re-confirmed for a completed step; complete its task instead")
        now = self.clock.now()
        # The new evidence is a human's re-confirmation, so that is its label (never inherit a machine label).
        record.verification = VerificationLabel.HUMAN_CONFIRMED
        record.evidence_ref = evidence_ref
        record.updated_at = now
        self._touch_verified(account, record.verification, evidence_ref)
        log_event(
            logger, "account.step_reverified", account_id=account.id, action="record_step_evidence", outcome=step.value,
            verification_source=record.verification.value, evidence_ref=evidence_ref,
        )
        return record

    RESETTABLE_STEPS = (ProvisioningStep.HANDLE_SELECTED, ProvisioningStep.COMPANY_EMAIL, ProvisioningStep.COMPANY_PHONE)

    def reset_step(self, session: Session, account_id: str, *, step: ProvisioningStep, reason: str, actor: Actor) -> HumanTask | None:
        """Withdraw a completed pre-signup decision (handle, email, phone) so its task is done again.

        Only before signup: once the account exists on Instagram, those facts describe the live account and
        are corrected through new evidence or the audit, never by rewriting history. The completed task is
        kept as it was (with a ``step_reset`` event); a fresh task of the next generation replaces it.
        """
        reject_secret_material("reason", reason)
        if step not in self.RESETTABLE_STEPS:
            raise Conflict(
                f"step '{step.value}' cannot be reset; only {', '.join(s.value for s in self.RESETTABLE_STEPS)} can, before signup"
            )
        account = self.get_account(session, account_id)
        steps = self._steps(account)
        if steps[ProvisioningStep.SIGNUP].state == StepState.COMPLETED:
            raise Conflict("signup is already confirmed: these details now describe the live account; record new evidence instead")
        record = steps[step]
        if record.state != StepState.COMPLETED:
            raise Conflict(f"step '{step.value}' is not completed; complete its open task instead")
        previous_task = session.get(HumanTask, record.task_id) if record.task_id else None
        if previous_task is not None:
            self.tasks.record_event(
                session, previous_task, "step_reset",
                {"reason": self.redactor.redact_text(reason), "reset_by": actor.audit_id, "superseded_evidence": record.evidence_ref},
            )
        now = self.clock.now()
        record.state = StepState.PENDING
        record.verification = VerificationLabel.UNVERIFIED
        record.evidence_ref = None
        record.task_id = None
        record.completed_at = None
        record.completed_by_id = None
        record.updated_at = now
        if step == ProvisioningStep.HANDLE_SELECTED:
            account.selected_handle = None
            account.handle_status = HandleStatus.NOT_CHECKED
        elif step == ProvisioningStep.COMPANY_EMAIL:
            account.company_email_ref = account.company_email_hint = account.company_email_domain = None
            account.company_email_control = ControlStatus.UNKNOWN
        else:
            account.company_phone_ref = account.company_phone_hint = None
            account.company_phone_control = ControlStatus.UNKNOWN
        account.updated_at = now
        log_event(
            logger, "account.step_reset", level=logging.WARNING, account_id=account.id,
            task_id=previous_task.id if previous_task else None, action="reset_step", outcome=step.value,
        )
        self.advance(session, account, actor=actor)
        task_type = {
            ProvisioningStep.HANDLE_SELECTED: TaskType.HANDLE_AVAILABILITY_CHECK,
            ProvisioningStep.COMPANY_EMAIL: TaskType.ASSIGN_COMPANY_EMAIL,
            ProvisioningStep.COMPANY_PHONE: TaskType.ASSIGN_COMPANY_PHONE,
        }[step]
        return session.scalar(
            select(HumanTask).where(
                HumanTask.account_id == account.id, HumanTask.task_type == task_type, HumanTask.status.in_(list(ACTIVE_STATUSES))
            )
        )

    def verify_integrations(self, session: Session, account_id: str) -> dict[str, Any]:
        """Re-check everything that an integration can verify (vault metadata, Meta association)."""
        account = self.get_account(session, account_id)
        results: dict[str, Any] = {}
        for field, ref in (
            ("password_vault_ref", account.password_vault_ref),
            ("backup_codes_vault_ref", account.backup_codes_vault_ref),
            *((f"other_vault_refs.{k}", v) for k, v in (account.other_vault_refs or {}).items()),
        ):
            if not ref:
                results[field] = {"status": "not_recorded", "verification": VerificationLabel.UNVERIFIED.value}
                continue
            inspection = vault_inspection(self.vault, ref)
            label = inspection.label
            results[field] = {
                "status": {True: "exists", False: "missing", None: "unknown"}[inspection.exists],
                "verification": label.value if label else "no_machine_evidence",
                "detail": inspection.detail,
            }
            if field == "password_vault_ref" and label is not None and inspection.exists is not None:
                account.password_ref_verification = label
            if field == "backup_codes_vault_ref" and label is not None and inspection.exists is not None:
                account.backup_codes_verification = label
                if inspection.exists is False:
                    account.backup_codes_status = BackupCodesStatus.MISSING
        if account.meta_business_ref and account.selected_handle:
            check = meta_link_check(self.meta, account.meta_business_ref, account.selected_handle)
            results["meta_link"] = {"status": check.status, "verification": check.verification.value, "detail": check.detail}
            if check.status == "linked":
                account.meta_link_verification = VerificationLabel.INTEGRATION_VERIFIED
            elif check.status == "not_linked":
                account.meta_link_status = MetaLinkStatus.MISMATCH
                account.meta_link_verification = VerificationLabel.INTEGRATION_VERIFIED
        log_event(logger, "account.integrations_verified", account_id=account.id, action="verify_integrations", outcome="checked")
        return results
