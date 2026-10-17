"""Offboarding a departing (test) team member.

``start`` is idempotent (one open case per person, enforced by a partial unique
index) and ``reconcile`` can be run any number of times: it creates missing
actions (dedupe keys), never marks an action complete without evidence, and
never resets completed ones - with one deliberate exception: if new access is
recorded for the person after the final verification, that verification is
reopened, because it no longer covers everything. Creating a task is *not*
treated as removing access.

Safety rules:
* A business-admin role is never queued for removal if it is the account's only
  administrative access path. A replacement admin must be granted (and confirmed)
  first; without a designated replacement the action is BLOCKED.
* The person's own ops-manager credentials are revoked by this system directly
  (integration-verified) unless that would remove the last admin credential.
* Credential rotation is confirmed by a human; when the vault exposes metadata the
  entry's version must have increased, otherwise the action is blocked as
  inconsistent rather than reported as done.
* Where no owner/permission exists (e.g. no proxy-provider administrator), the
  action is BLOCKED with a reason and a responsible owner, never silently skipped.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.clock import Clock
from app.config import Settings
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
    Responsibility,
    RoleName,
    TaskOrigin,
    TaskStatus,
    TaskType,
    VerificationLabel,
)
from app.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from app.integrations.reads import vault_inspection
from app.integrations.vault.base import VaultAdapter
from app.logging_setup import log_event
from app.models import (
    AccountAssignment,
    ApiCredential,
    CredentialAccess,
    HumanTask,
    InstagramAccount,
    OffboardingAction,
    OffboardingCase,
    Person,
    new_id,
)
from app.security.authentication import (
    active_credential_count,
    revoke_person_credentials,
)
from app.security.authorization import Actor
from app.security.redaction import Redactor
from app.security.secret_handling import reject_secret_material
from app.services.provisioning import ROLE_CATALOG, ProvisioningService
from app.services.reminder_service import find_responsible
from app.services.task_manager import ACTIVE_STATUSES, TaskManager

logger = logging.getLogger("app.offboarding")

PREREQUISITE_TYPES = (
    OffboardingActionType.GRANT_REPLACEMENT_ADMIN,
    OffboardingActionType.REMOVE_ACCOUNT_ROLE,
    OffboardingActionType.REMOVE_VAULT_ACCESS,
    OffboardingActionType.ROTATE_CREDENTIAL,
    OffboardingActionType.REPLACE_BACKUP_CODES,
)
SOLE_ADMIN_CODES = ("SOLE_ADMIN_NO_REPLACEMENT", "AWAITING_REPLACEMENT_ADMIN")
FINISHED = (OffboardingActionStatus.COMPLETED, OffboardingActionStatus.CANCELLED)


class OffboardingService:
    def __init__(
        self,
        *,
        settings: Settings,
        clock: Clock,
        tasks: TaskManager,
        provisioning: ProvisioningService,
        vault: VaultAdapter,
        redactor: Redactor,
    ):
        self.settings = settings
        self.clock = clock
        self.tasks = tasks
        self.provisioning = provisioning
        self.vault = vault
        self.redactor = redactor

    def register(self) -> None:
        self.tasks.register_post_completion_hook(self._on_task_completed)
        self.tasks.register_transition_hook(self._on_task_transition)
        self.tasks.register_completion_guard(self._guard_self_completion)

    def _guard_self_completion(self, session: Session, task: HumanTask, actor: Actor) -> None:
        """The departing person may never confirm their own offboarding actions (even as an admin)."""
        action = self._action_for(session, task)
        if action is not None and actor.person_id is not None and actor.person_id == action.case.person_id:
            raise PermissionDenied("the person being offboarded cannot complete actions in their own offboarding case")

    def _reassign_open_tasks(self, session: Session, case: OffboardingCase, person: Person) -> int:
        """Hand the departing person's open tasks to someone who can still act on them."""
        moved = 0
        open_tasks = session.scalars(
            select(HumanTask).where(HumanTask.owner_id == person.id, HumanTask.status.in_(list(ACTIVE_STATUSES)))
        ).all()
        for task in open_tasks:
            account = session.get(InstagramAccount, task.account_id) if task.account_id else None
            target = None
            if person.supervisor and person.supervisor.status == PersonStatus.ACTIVE:
                target = person.supervisor
            target = target or self._platform_operator(session, account, person.id)
            if target is None:
                continue
            self.tasks.reassign_system(session, task, target.id, reason=f"previous owner is being offboarded (case {case.id})")
            moved += 1
        for task in session.scalars(
            select(HumanTask).where(HumanTask.supervisor_id == person.id, HumanTask.status.in_(list(ACTIVE_STATUSES)))
        ):
            task.supervisor_id = person.supervisor_id if person.supervisor_id != task.owner_id else None
        if moved:
            log_event(logger, "offboarding.tasks_reassigned", action="reassign_open_tasks", outcome=str(moved), case_id=case.id)
        return moved

    # ------------------------------------------------------------------ entry points
    @staticmethod
    def get_case(session: Session, case_id: str) -> OffboardingCase:
        case = session.get(OffboardingCase, case_id)
        if case is None:
            raise NotFound("offboarding case not found")
        return case

    def start(
        self,
        session: Session,
        *,
        person_id: str,
        actor: Actor,
        reason: str,
        replacement_admin_id: str | None = None,
    ) -> tuple[OffboardingCase, bool]:
        reject_secret_material("reason", reason)
        person = session.get(Person, person_id)
        if person is None:
            raise NotFound("person not found")
        if actor.person_id == person_id:
            raise PermissionDenied("you cannot offboard yourself")
        if replacement_admin_id is not None:
            replacement = session.get(Person, replacement_admin_id)
            if replacement is None or replacement.status != PersonStatus.ACTIVE or replacement.id == person_id:
                raise ValidationFailed("replacement admin must be a different, active person")
        existing = session.scalar(
            select(OffboardingCase).where(OffboardingCase.person_id == person_id, OffboardingCase.status == OffboardingCaseStatus.OPEN)
        )
        if existing is not None:
            if replacement_admin_id and existing.replacement_admin_id is None:
                existing.replacement_admin_id = replacement_admin_id
            self.reconcile(session, existing, actor=actor)
            return existing, False
        if person.status == PersonStatus.OFFBOARDED:
            raise Conflict("person is already offboarded")
        now = self.clock.now()
        case = OffboardingCase(
            id=new_id("off"),
            person_id=person_id,
            status=OffboardingCaseStatus.OPEN,
            reason=reason[:300],
            requested_by_id=actor.person_id,
            replacement_admin_id=replacement_admin_id,
            created_at=now,
            updated_at=now,
        )
        try:
            with session.begin_nested():
                session.add(case)
                session.flush()
        except IntegrityError:
            existing = session.scalar(
                select(OffboardingCase).where(OffboardingCase.person_id == person_id, OffboardingCase.status == OffboardingCaseStatus.OPEN)
            )
            if existing is None:
                raise
            return existing, False
        person.status = PersonStatus.DEPARTING
        log_event(logger, "offboarding.started", action="start_offboarding", outcome="case_opened", case_id=case.id, person_id=person_id)
        self.reconcile(session, case, actor=actor)
        return case, True

    # ------------------------------------------------------------------ helpers
    def _ensure_action(
        self,
        session: Session,
        case: OffboardingCase,
        action_type: OffboardingActionType,
        target_ref: str,
        description: str,
        *,
        account_id: str | None = None,
    ) -> OffboardingAction:
        key = f"{case.id}:{action_type.value}:{target_ref}"
        action = session.scalar(select(OffboardingAction).where(OffboardingAction.dedupe_key == key))
        if action is not None:
            return action
        now = self.clock.now()
        action = OffboardingAction(
            id=new_id("ofa"),
            case_id=case.id,
            account_id=account_id,
            action_type=action_type,
            target_ref=target_ref,
            description=description,
            status=OffboardingActionStatus.PENDING,
            verification=VerificationLabel.UNVERIFIED,
            dedupe_key=key,
            detail={},
            created_at=now,
            updated_at=now,
        )
        try:
            with session.begin_nested():
                session.add(action)
                session.flush()
        except IntegrityError:
            action = session.scalar(select(OffboardingAction).where(OffboardingAction.dedupe_key == key))
            assert action is not None
        return action

    def _block(self, action: OffboardingAction, code: str, detail: str, owner: Person | None) -> None:
        if action.status == OffboardingActionStatus.BLOCKED and action.blocker_code == code:
            return
        action.status = OffboardingActionStatus.BLOCKED
        action.blocker_code = code
        action.blocker_detail = self.redactor.redact_text(detail)
        action.owner_id = owner.id if owner else action.owner_id
        action.updated_at = self.clock.now()
        log_event(
            logger, "offboarding.action_blocked", level=logging.WARNING, account_id=action.account_id,
            action=action.action_type.value, outcome=code, case_id=action.case_id, offboarding_action_id=action.id,
        )

    def _unblock(self, action: OffboardingAction) -> None:
        if action.status == OffboardingActionStatus.BLOCKED:
            action.status = OffboardingActionStatus.PENDING
            action.blocker_code = None
            action.blocker_detail = None
            action.updated_at = self.clock.now()

    def _complete(self, action: OffboardingAction, label: VerificationLabel, evidence: str, detail: dict[str, Any] | None = None) -> None:
        action.status = OffboardingActionStatus.COMPLETED
        action.verification = label
        action.evidence_ref = evidence[:300]
        action.blocker_code = None
        action.blocker_detail = None
        action.completed_at = self.clock.now()
        action.updated_at = self.clock.now()
        if detail:
            action.detail = {**(action.detail or {}), **self.redactor.redact(detail)}
        log_event(
            logger, "offboarding.action_completed", account_id=action.account_id, action=action.action_type.value,
            outcome="completed", verification_source=label.value, evidence_ref=evidence, case_id=action.case_id,
        )

    def _ensure_task(
        self, session: Session, case: OffboardingCase, action: OffboardingAction, owner: Person, title: str, instructions: str
    ) -> HumanTask:
        current = session.get(HumanTask, action.task_id) if action.task_id else None
        if current is not None and (current.status in ACTIVE_STATUSES or current.status == TaskStatus.COMPLETED):
            return current
        action.task_generation += 1
        task, _ = self.tasks.create_task(
            session,
            task_type=TaskType.OFFBOARDING_ACTION,
            owner_id=owner.id,
            idempotency_key=f"offboarding:{action.id}:g{action.task_generation}",
            account_id=action.account_id,
            context={"action_title": title, "action_instructions": instructions},
            payload={"offboarding_action_id": action.id, "case_id": case.id, "action_type": action.action_type.value},
            origin=TaskOrigin.OFFBOARDING,
        )
        action.task_id = task.id
        action.owner_id = owner.id
        action.updated_at = self.clock.now()
        return task

    @staticmethod
    def _active_admins(account: InstagramAccount, *, exclude: str) -> list[AccountAssignment]:
        return [
            a
            for a in account.assignments
            if a.role == RoleName.BUSINESS_ADMIN
            and a.status == AssignmentStatus.ACTIVE
            and a.person_id != exclude
            and a.person.status == PersonStatus.ACTIVE
        ]

    def _platform_operator(self, session: Session, account: InstagramAccount | None, departing_id: str) -> Person | None:
        """Someone (not the departing person) who can act on the account in Meta/Instagram."""
        if account is not None:
            for admin in self._active_admins(account, exclude=departing_id):
                return admin.person
            if account.owner and account.owner.status == PersonStatus.ACTIVE and account.owner_id != departing_id:
                return account.owner
        return find_responsible(session, Responsibility.SECURITY_OWNER, exclude={departing_id})

    @staticmethod
    def _last_app_admin(session: Session, person_id: str) -> bool:
        others = session.scalar(
            select(func.count(ApiCredential.id))
            .join(Person, Person.id == ApiCredential.person_id)
            .where(
                ApiCredential.active.is_(True),
                ApiCredential.role == OperatorRole.ADMIN,
                ApiCredential.person_id != person_id,
                Person.status == PersonStatus.ACTIVE,
            )
        )
        mine = session.scalar(
            select(func.count(ApiCredential.id)).where(
                ApiCredential.active.is_(True), ApiCredential.role == OperatorRole.ADMIN, ApiCredential.person_id == person_id
            )
        )
        return bool(mine) and not others

    # ------------------------------------------------------------------ reconcile
    def reconcile(self, session: Session, case: OffboardingCase, *, actor: Actor) -> OffboardingCase:
        if case.status == OffboardingCaseStatus.COMPLETED:
            return case
        person = case.person
        now = self.clock.now()
        case.reconcile_count += 1
        case.updated_at = now
        name = person.full_name

        # 1. This application's own access: revoked directly (integration-verified).
        app_access = self._ensure_action(
            session, case, OffboardingActionType.REVOKE_APP_ACCESS, f"ops-manager:person:{person.id}",
            "Revoke this application's API tokens and dashboard sessions for the person",
        )
        if app_access.status not in FINISHED:
            if self._last_app_admin(session, person.id):
                self._block(
                    app_access, "SOLE_APP_ADMIN",
                    "This person holds the only active admin credential for this application. Issue an admin credential "
                    "to another active person first, then re-run reconciliation.",
                    find_responsible(session, Responsibility.SECURITY_OWNER, exclude={person.id}),
                )
            else:
                revoked = revoke_person_credentials(session, person.id, now=now, reason=f"offboarding case {case.id}")
                remaining = active_credential_count(session, person.id)
                if remaining == 0:
                    self._complete(
                        app_access, VerificationLabel.INTEGRATION_VERIFIED,
                        f"ops-manager:api_credentials revoked={revoked} active_remaining=0",
                        {"revoked_count": revoked},
                    )
        reassigned = self._reassign_open_tasks(session, case, person)
        if reassigned:
            app_access.detail = {**(app_access.detail or {}), "open_tasks_reassigned": (app_access.detail or {}).get("open_tasks_reassigned", 0) + reassigned}

        # 2. Identify registered roles.
        assignments = session.scalars(
            select(AccountAssignment).where(AccountAssignment.person_id == person.id).order_by(AccountAssignment.created_at)
        ).all()
        identify = self._ensure_action(
            session, case, OffboardingActionType.IDENTIFY_ROLES, f"person:{person.id}",
            "Identify every registered role and permission the person holds",
        )
        role_inventory = [
            {
                "assignment_id": a.id,
                "account_id": a.account_id,
                "brand": a.account.brand_name,
                "platform": a.platform.value,
                "role": a.role.value,
                "status": a.status.value,
                "temporary_test_role": a.is_temporary_test_role,
                "register_verification": a.verification.value,
            }
            for a in assignments
        ]
        if identify.status not in FINISHED:
            self._complete(
                identify, VerificationLabel.HUMAN_CONFIRMED, "register:account_assignments",
                {"roles": role_inventory, "note": "From the human-confirmed register; platform-side access is re-checked in verify_access_state"},
            )

        # 3. Remove each role (never the only admin path).
        for assignment in assignments:
            if assignment.status == AssignmentStatus.REMOVED:
                continue
            account = assignment.account
            action = self._ensure_action(
                session, case, OffboardingActionType.REMOVE_ACCOUNT_ROLE, f"assignment:{assignment.id}",
                f"Remove {name}'s {assignment.role.value} on {assignment.platform.value} for {account.brand_name}",
                account_id=account.id,
            )
            if action.status in FINISHED:
                continue
            if assignment.role == RoleName.BUSINESS_ADMIN and not self._active_admins(account, exclude=person.id):
                if not self._handle_sole_admin(session, case, action, account, person):
                    continue
            if action.status == OffboardingActionStatus.BLOCKED and action.blocker_code in SOLE_ADMIN_CODES:
                self._unblock(action)
            remover = self._platform_operator(session, account, person.id)
            if remover is None:
                self._block(action, "NO_AUTHORISED_REMOVER", f"No active admin, owner or security owner can remove access on {account.brand_name}", None)
                continue
            if action.status == OffboardingActionStatus.BLOCKED and action.blocker_code == "NO_AUTHORISED_REMOVER":
                self._unblock(action)
            assignment.status = AssignmentStatus.PENDING_REMOVAL
            if action.status != OffboardingActionStatus.BLOCKED:
                self._ensure_task(
                    session, case, action, remover,
                    f"Offboarding: remove {name}'s {assignment.role.value} access on @{account.selected_handle or account.brand_name}",
                    f"In Meta Business Suite for the test business (and Instagram, if the role is granted there), remove "
                    f"{name}'s '{assignment.role.value}' access ({ROLE_CATALOG[assignment.role]}).\n"
                    f"No supported role-removal integration is configured, so this is a guided human step.\n"
                    f"Complete only after the person no longer appears with this access. Evidence: what you observed "
                    f"(e.g. 'People list no longer shows {name}, checked 2026-10-16').",
                )

        # 4. Credentials the person could access.
        accesses = session.scalars(
            select(CredentialAccess).where(CredentialAccess.person_id == person.id).order_by(CredentialAccess.created_at)
        ).all()
        identify_creds = self._ensure_action(
            session, case, OffboardingActionType.IDENTIFY_CREDENTIALS, f"person:{person.id}",
            "Identify every vault entry (credential) the person could access",
        )
        if identify_creds.status not in FINISHED:
            self._complete(
                identify_creds, VerificationLabel.HUMAN_CONFIRMED, "register:credential_access",
                {"credentials": [{"vault_ref": c.vault_ref, "kind": c.credential_kind.value, "account_id": c.account_id} for c in accesses]},
            )
        for access in accesses:
            self._reconcile_credential(session, case, person, access)

        # 5. Verify the resulting access state once everything else is done.
        verify = self._ensure_action(
            session, case, OffboardingActionType.VERIFY_ACCESS_STATE, f"person:{person.id}",
            "Verify on Meta Business Suite, Instagram and the vault that no access remains",
        )
        prerequisites = session.scalars(
            select(OffboardingAction).where(
                OffboardingAction.case_id == case.id, OffboardingAction.action_type.in_(list(PREREQUISITE_TYPES))
            )
        ).all()
        outstanding = [p for p in prerequisites if p.status not in FINISHED]
        if outstanding and verify.status != OffboardingActionStatus.CANCELLED:
            self._withdraw_verification(session, verify)
        if verify.status not in FINISHED:
            if outstanding:
                verify.detail = {**(verify.detail or {}), "waiting_on": [p.id for p in outstanding]}
            else:
                verifier = find_responsible(session, Responsibility.SECURITY_OWNER, exclude={person.id}) or self._platform_operator(
                    session, None, person.id
                )
                if verifier is None:
                    self._block(verify, "NO_VERIFIER", "No active security owner is available to verify the final access state", None)
                else:
                    self._unblock(verify)
                    verify.detail = {**(verify.detail or {}), "waiting_on": []}
                    brands = sorted({a.account.brand_name for a in assignments})
                    self._ensure_task(
                        session, case, verify, verifier,
                        f"Offboarding: verify no access remains for {name}",
                        f"Independently confirm that {name} no longer has any access:\n"
                        f"- Meta Business Suite people list for the test business ({', '.join(brands) or 'no accounts'})\n"
                        f"- Instagram account roles, if any were granted directly\n"
                        f"- Company vault entries listed in this case\n"
                        f"Also confirm no UNREGISTERED access exists (access the register did not know about).",
                    )

        # 6. Update the register once access state is verified.
        register = self._ensure_action(
            session, case, OffboardingActionType.UPDATE_REGISTER, f"person:{person.id}",
            "Mark the person offboarded in the personnel records and the account register",
        )
        if register.status not in FINISHED and verify.status == OffboardingActionStatus.COMPLETED and not outstanding:
            leftovers = [a for a in assignments if a.status != AssignmentStatus.REMOVED]
            if leftovers:
                self._block(register, "ASSIGNMENTS_NOT_REMOVED", f"{len(leftovers)} assignment(s) not confirmed removed", None)
            else:
                person.status = PersonStatus.OFFBOARDED
                person.updated_at = now
                self._complete(
                    register, VerificationLabel.INTEGRATION_VERIFIED,
                    f"register:person:{person.id} status=offboarded assignments_removed={len(assignments)}",
                )

        actions = session.scalars(select(OffboardingAction).where(OffboardingAction.case_id == case.id)).all()
        if actions and all(a.status in FINISHED for a in actions):
            case.status = OffboardingCaseStatus.COMPLETED
            case.closed_at = now
            log_event(logger, "offboarding.completed", action="reconcile", outcome="case_completed", case_id=case.id)
        else:
            log_event(
                logger, "offboarding.reconciled", action="reconcile", outcome="in_progress", case_id=case.id,
                completed=sum(a.status == OffboardingActionStatus.COMPLETED for a in actions),
                blocked=sum(a.status == OffboardingActionStatus.BLOCKED for a in actions),
                pending=sum(a.status in (OffboardingActionStatus.PENDING, OffboardingActionStatus.IN_PROGRESS) for a in actions),
            )
        return case

    def _withdraw_verification(self, session: Session, verify: OffboardingAction) -> None:
        """New access was recorded after the final verification was requested or given.

        That verification no longer covers everything, so it is withdrawn (an open request is
        cancelled) or reopened (a completed one), and the register is not updated until a fresh
        verification follows the new removals. A no-op while verification is merely waiting.
        """
        task = session.get(HumanTask, verify.task_id) if verify.task_id else None
        open_request = task is not None and task.status in ACTIVE_STATUSES
        if verify.status != OffboardingActionStatus.COMPLETED and not open_request:
            return
        detail = dict(verify.detail or {})
        if verify.status == OffboardingActionStatus.COMPLETED:
            detail["superseded_evidence"] = verify.evidence_ref
            verify.status = OffboardingActionStatus.PENDING
            verify.verification = VerificationLabel.UNVERIFIED
            verify.completed_at = None
        detail["reopened"] = int(detail.get("reopened", 0)) + 1
        verify.detail = detail
        verify.task_id = None  # detached before cancelling, so the cancel hook does not re-enter reconcile
        verify.updated_at = self.clock.now()
        if open_request:
            self.tasks.cancel_task(
                session, task, actor=None,
                reason="new access was recorded for this person; verify again once it has been removed",
            )
        log_event(
            logger, "offboarding.verification_reopened", level=logging.WARNING, action="reconcile",
            outcome="verification_reopened", case_id=verify.case_id, offboarding_action_id=verify.id,
        )

    def _handle_sole_admin(
        self, session: Session, case: OffboardingCase, action: OffboardingAction, account: InstagramAccount, person: Person
    ) -> bool:
        """Return True when removal may proceed (another admin is confirmed active)."""
        owner = account.owner if account.owner and account.owner_id != person.id and account.owner.status == PersonStatus.ACTIVE else None
        owner = owner or find_responsible(session, Responsibility.SECURITY_OWNER, exclude={person.id})
        replacement = case.replacement_admin
        if replacement is None or replacement.status != PersonStatus.ACTIVE:
            self._block(
                action, "SOLE_ADMIN_NO_REPLACEMENT",
                f"{person.full_name} is the only active business admin of {account.brand_name}. Removing this role would "
                "remove the only administrative access path. Designate a replacement admin and re-run.",
                owner,
            )
            return False
        replacement_assignment = next(
            (
                a for a in account.assignments
                if a.person_id == replacement.id and a.role == RoleName.BUSINESS_ADMIN and a.platform == action_platform(session, action)
            ),
            None,
        )
        now = self.clock.now()
        if replacement_assignment is None:
            replacement_assignment = AccountAssignment(
                id=new_id("asg"),
                person_id=replacement.id,
                platform=action_platform(session, action),
                role=RoleName.BUSINESS_ADMIN,
                role_description=ROLE_CATALOG[RoleName.BUSINESS_ADMIN],
                approved=True,
                status=AssignmentStatus.REQUESTED,
                created_at=now,
                updated_at=now,
            )
            account.assignments.append(replacement_assignment)
            session.flush()
        elif replacement_assignment.status == AssignmentStatus.REMOVED:
            replacement_assignment.status = AssignmentStatus.REQUESTED
        grant = self._ensure_action(
            session, case, OffboardingActionType.GRANT_REPLACEMENT_ADMIN, f"assignment:{replacement_assignment.id}",
            f"Grant {replacement.full_name} business_admin on {account.brand_name} before removing {person.full_name}",
            account_id=account.id,
        )
        grant.detail = {"assignment_id": replacement_assignment.id}
        if grant.status == OffboardingActionStatus.COMPLETED:
            return True
        grantor = owner
        if grantor is None:
            self._block(grant, "NO_GRANTOR", "No active owner or security owner can grant the replacement admin", None)
        else:
            self._ensure_task(
                session, case, grant, grantor,
                f"Offboarding: grant {replacement.full_name} business admin on {account.brand_name}",
                f"Before {person.full_name}'s admin role is removed, grant {replacement.full_name} full control of the "
                f"Instagram account in the test business, and confirm they can access it. This keeps an "
                f"administrative access path in place.",
            )
        self._block(
            action, "AWAITING_REPLACEMENT_ADMIN",
            f"Waiting for the replacement admin grant ({grant.id}) to be confirmed before removing the only admin",
            owner,
        )
        return False

    def _reconcile_credential(self, session: Session, case: OffboardingCase, person: Person, access: CredentialAccess) -> None:
        account = session.get(InstagramAccount, access.account_id) if access.account_id else None
        label = account.brand_name if account else "shared infrastructure"
        # Remove vault access.
        remove = self._ensure_action(
            session, case, OffboardingActionType.REMOVE_VAULT_ACCESS, f"vault-access:{access.id}",
            f"Remove {person.full_name}'s access to vault entry {access.vault_ref}", account_id=access.account_id,
        )
        if not (remove.detail or {}).get("vault_ref"):
            remove.detail = {**(remove.detail or {}), "vault_ref": access.vault_ref, "credential_kind": access.credential_kind.value}
        if remove.status not in FINISHED:
            vault_admin = find_responsible(session, Responsibility.VAULT_ADMIN, exclude={person.id})
            if vault_admin is None:
                self._block(
                    remove, "NO_VAULT_ADMIN",
                    "No person holds the vault_admin responsibility and this system has no vault permission-management "
                    "integration, so vault access cannot be removed or verified. Assign a vault admin.",
                    find_responsible(session, Responsibility.SECURITY_OWNER, exclude={person.id}),
                )
            else:
                if remove.blocker_code == "NO_VAULT_ADMIN":
                    self._unblock(remove)
                access.status = CredentialAccessStatus.REVOCATION_PENDING
                if remove.status != OffboardingActionStatus.BLOCKED:
                    self._ensure_task(
                        session, case, remove, vault_admin,
                        f"Offboarding: remove {person.full_name}'s vault access to {access.vault_ref}",
                        f"In the company vault, remove {person.full_name} from every group/policy granting access to "
                        f"{access.vault_ref} ({access.credential_kind.value}, {label}). Do not reveal or copy the secret.",
                    )
        # Rotate or replace the credential itself.
        if access.credential_kind == CredentialKind.BACKUP_CODES:
            action_type = OffboardingActionType.REPLACE_BACKUP_CODES
            owner = self._platform_operator(session, account, person.id)
            title = f"Offboarding: replace backup codes for @{account.selected_handle if account else '?'}"
            instructions = (
                "Backup codes may have been seen by the departing person. In Instagram, generate a NEW set of backup "
                f"codes (this invalidates the old set) and store it in the vault at {access.vault_ref} as a new version. "
                "Never paste codes anywhere else."
            )
            if account is not None:
                rotation = self._ensure_action(
                    session, case, action_type, f"credential:{access.vault_ref}", f"Replace possibly exposed backup codes ({label})",
                    account_id=access.account_id,
                )
                if rotation.status not in FINISHED:
                    account.backup_codes_status = BackupCodesStatus.REPLACEMENT_REQUIRED
            else:
                rotation = None
        else:
            action_type = OffboardingActionType.ROTATE_CREDENTIAL
            if access.credential_kind == CredentialKind.PROXY_CREDENTIAL:
                owner = find_responsible(session, Responsibility.PROXY_PROVIDER_ADMIN, exclude={person.id})
                title = f"Offboarding: rotate proxy credential {access.vault_ref}"
                instructions = (
                    f"Ask the approved proxy provider to rotate the credential stored at {access.vault_ref}, store the new "
                    "credential in the vault as a new version, then confirm. The proxy manager picks it up on its next check."
                )
            else:
                owner = self._platform_operator(session, account, person.id)
                title = f"Offboarding: rotate {access.credential_kind.value} {access.vault_ref}"
                instructions = (
                    f"Change this credential on the system it belongs to ({label}), store the new value in the vault at "
                    f"{access.vault_ref} as a new version, and confirm. Do not paste the credential anywhere else."
                )
            rotation = self._ensure_action(
                session, case, action_type, f"credential:{access.vault_ref}",
                f"Rotate {access.credential_kind.value} the person could access ({label})", account_id=access.account_id,
            )
        if rotation is None or rotation.status in FINISHED:
            return
        if "baseline_version" not in (rotation.detail or {}):
            inspection = vault_inspection(self.vault, access.vault_ref)
            rotation.detail = {
                **(rotation.detail or {}),
                "vault_ref": access.vault_ref,
                "baseline_version": inspection.version,
                "vault_metadata_supported": inspection.label is not None and inspection.exists is not None,
                "baseline_detail": inspection.detail,
            }
        if rotation.blocker_code in ("VAULT_VERSION_UNCHANGED", "VAULT_UNAVAILABLE"):
            self._check_rotation(rotation)
            return
        if owner is None:
            code = "NO_PROXY_PROVIDER_ADMIN" if access.credential_kind == CredentialKind.PROXY_CREDENTIAL else "NO_ROTATION_OWNER"
            self._block(
                rotation, code,
                "Nobody holds the proxy_provider_admin responsibility and this system cannot rotate provider credentials; "
                "assign a provider administrator." if code == "NO_PROXY_PROVIDER_ADMIN" else
                "No active admin/owner can rotate this credential",
                find_responsible(session, Responsibility.SECURITY_OWNER, exclude={person.id}),
            )
            return
        if rotation.blocker_code in ("NO_PROXY_PROVIDER_ADMIN", "NO_ROTATION_OWNER"):
            self._unblock(rotation)
        if rotation.status != OffboardingActionStatus.BLOCKED:
            self._ensure_task(session, case, rotation, owner, title, instructions)

    def _check_rotation(self, action: OffboardingAction) -> bool:
        """Cross-check a human-confirmed rotation against vault metadata. True when it may be completed.

        When the vault reported versions at baseline, the check is never skipped: an outage at
        confirmation time blocks the action (re-checked by reconcile) instead of downgrading it
        to a human-only confirmation.
        """
        detail = action.detail or {}
        ref = detail.get("vault_ref")
        baseline = detail.get("baseline_version")
        inspection = vault_inspection(self.vault, ref) if ref else None
        task_evidence = action.evidence_ref or "human confirmation"
        if detail.get("vault_metadata_supported") and inspection is not None:
            if inspection.exists is None:
                self._block(
                    action, "VAULT_UNAVAILABLE",
                    f"Rotation was confirmed by a human, but the vault could not be checked for a new version "
                    f"({inspection.detail}). Re-run reconciliation once the vault is reachable.",
                    action.owner,
                )
                return False
            if inspection.version is not None and (baseline is None or inspection.version > baseline):
                self._complete(
                    action, VerificationLabel.INTEGRATION_VERIFIED,
                    f"vault-metadata:{ref} v{baseline if baseline is not None else 'none'}->v{inspection.version}; {task_evidence}",
                    {"new_version": inspection.version},
                )
                return True
            current = f"still version {inspection.version}" if inspection.exists else "has no current version"
            self._block(
                action, "VAULT_VERSION_UNCHANGED",
                f"Rotation was confirmed by a human but the vault entry {current}. Store the new value at the same "
                "reference, then re-run reconciliation.",
                action.owner,
            )
            return False
        why = detail.get("baseline_detail") or f"vault cannot confirm a new version in {self.vault.name} mode"
        self._complete(action, VerificationLabel.HUMAN_CONFIRMED, f"{task_evidence} (no machine check: {why})")
        return True

    # ------------------------------------------------------------------ task hooks
    def _action_for(self, session: Session, task: HumanTask) -> OffboardingAction | None:
        action_id = (task.payload or {}).get("offboarding_action_id")
        if task.origin != TaskOrigin.OFFBOARDING or not action_id:
            return None
        return session.get(OffboardingAction, action_id)

    def _on_task_completed(self, session: Session, task: HumanTask, actor: Actor) -> None:
        action = self._action_for(session, task)
        if action is None or action.status == OffboardingActionStatus.COMPLETED:
            return
        action.evidence_ref = task.completion_evidence_ref
        now = self.clock.now()
        if action.action_type == OffboardingActionType.REMOVE_ACCOUNT_ROLE:
            assignment = session.get(AccountAssignment, action.target_ref.split(":", 1)[1])
            if assignment is not None:
                assignment.status = AssignmentStatus.REMOVED
                assignment.removed_at = now
                assignment.verification = VerificationLabel.HUMAN_CONFIRMED
                assignment.evidence_ref = task.completion_evidence_ref
            self._complete(action, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref or "")
        elif action.action_type == OffboardingActionType.GRANT_REPLACEMENT_ADMIN:
            assignment = session.get(AccountAssignment, (action.detail or {}).get("assignment_id", ""))
            if assignment is not None:
                assignment.status = AssignmentStatus.ACTIVE
                assignment.granted_at = now
                assignment.last_verified_at = now
                assignment.verification = VerificationLabel.HUMAN_CONFIRMED
                assignment.evidence_ref = task.completion_evidence_ref
            self._complete(action, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref or "")
        elif action.action_type == OffboardingActionType.REMOVE_VAULT_ACCESS:
            access = session.get(CredentialAccess, action.target_ref.split(":", 1)[1])
            if access is not None:
                access.status = CredentialAccessStatus.REVOKED
                access.revoked_at = now
            self._complete(action, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref or "")
        elif action.action_type in (OffboardingActionType.ROTATE_CREDENTIAL, OffboardingActionType.REPLACE_BACKUP_CODES):
            if self._check_rotation(action) and action.action_type == OffboardingActionType.REPLACE_BACKUP_CODES:
                account = session.get(InstagramAccount, action.account_id) if action.account_id else None
                if account is not None:
                    account.backup_codes_status = BackupCodesStatus.PRESENT_IN_VAULT
                    account.backup_codes_verification = action.verification
        else:
            self._complete(action, VerificationLabel.HUMAN_CONFIRMED, task.completion_evidence_ref or "")
        self.reconcile(session, action.case, actor=actor)

    def _on_task_transition(self, session: Session, task: HumanTask, old: TaskStatus, new: TaskStatus, actor: Actor) -> None:
        if new == TaskStatus.COMPLETED:
            return
        action = self._action_for(session, task)
        if action is None or action.status in FINISHED:
            return
        if new == TaskStatus.BLOCKED:
            self._block(action, "TASK_BLOCKED", task.blocker_detail or "assigned human reported a blocker", action.owner)
        elif old == TaskStatus.BLOCKED and action.blocker_code == "TASK_BLOCKED":
            self._unblock(action)
        elif new in (TaskStatus.CANCELLED, TaskStatus.FAILED) and action.task_id == task.id:
            self._unblock(action)
            self.reconcile(session, action.case, actor=actor)


def action_platform(session: Session, action: OffboardingAction):
    assignment = session.get(AccountAssignment, action.target_ref.split(":", 1)[1])
    return assignment.platform if assignment is not None else None
