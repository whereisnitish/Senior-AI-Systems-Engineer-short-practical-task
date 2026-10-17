"""Persistent data model.

Secrets are never stored here. Columns ending in ``_vault_ref`` hold *references*
to entries in the company vault; ``*_hint`` columns hold masked display values
(e.g. ``b***@company.example``); raw email addresses and phone numbers used for
the Instagram account are not persisted.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.clock import utcnow
from app.database import Base, UTCDateTime
from app.enums import (
    AssignmentStatus,
    AuditRunStatus,
    AuditTrigger,
    BackupCodesStatus,
    BusinessAccountStatus,
    ControlStatus,
    CredentialAccessStatus,
    CredentialKind,
    DeliveryStatus,
    FindingStatus,
    HandleStatus,
    MetaLinkStatus,
    NotificationKind,
    OffboardingActionStatus,
    OffboardingActionType,
    OffboardingCaseStatus,
    OperatorRole,
    PersonStatus,
    Platform,
    ProvisioningStatus,
    ProvisioningStep,
    ProxyHealth,
    ProxySessionStatus,
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

ID_LEN = 40


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _enum(enum_cls: type) -> SAEnum:
    return SAEnum(
        enum_cls,
        native_enum=False,
        validate_strings=True,
        length=40,
        values_callable=lambda members: [m.value for m in members],
    )


def _ts(nullable: bool = True) -> Any:
    return mapped_column(UTCDateTime(), nullable=nullable)


# ---------------------------------------------------------------------------
# People and application access
# ---------------------------------------------------------------------------


class Person(Base):
    __tablename__ = "people"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("per"))
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254), unique=True)
    supervisor_id: Mapped[str | None] = mapped_column(ForeignKey("people.id"), nullable=True)
    status: Mapped[PersonStatus] = mapped_column(_enum(PersonStatus), default=PersonStatus.ACTIVE, index=True)
    responsibilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    last_access_review_at: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    supervisor: Mapped[Person | None] = relationship(remote_side=[id])


class ApiCredential(Base):
    """An operator's API token. Only an HMAC of the token is stored."""

    __tablename__ = "api_credentials"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("crd"))
    person_id: Mapped[str] = mapped_column(ForeignKey("people.id"), index=True)
    label: Mapped[str] = mapped_column(String(80))
    token_prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[OperatorRole] = mapped_column(_enum(OperatorRole))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_used_at: Mapped[datetime | None] = _ts()
    revoked_at: Mapped[datetime | None] = _ts()
    revoked_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)

    person: Mapped[Person] = relationship()


class UiSession(Base):
    """Dashboard login session. The cookie carries a random token; only its HMAC is stored."""

    __tablename__ = "ui_sessions"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("uis"))
    credential_id: Mapped[str] = mapped_column(ForeignKey("api_credentials.id"), index=True)
    session_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = _ts()

    credential: Mapped[ApiCredential] = relationship()


# ---------------------------------------------------------------------------
# Account register
# ---------------------------------------------------------------------------


class InstagramAccount(Base):
    __tablename__ = "instagram_accounts"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("acc"))
    brand_name: Mapped[str] = mapped_column(String(80))
    # Normalised brand name; the unique constraint is what prevents duplicate account records.
    brand_key: Mapped[str] = mapped_column(String(80), unique=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    environment: Mapped[str] = mapped_column(String(40), default="company_test_environment")

    suggested_handles: Mapped[list[str]] = mapped_column(JSON, default=list)
    selected_handle: Mapped[str | None] = mapped_column(String(30), unique=True, nullable=True)
    handle_status: Mapped[HandleStatus] = mapped_column(_enum(HandleStatus), default=HandleStatus.NOT_CHECKED)

    owner_id: Mapped[str] = mapped_column(ForeignKey("people.id"), index=True)

    company_email_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    company_email_hint: Mapped[str | None] = mapped_column(String(120), nullable=True)
    company_email_domain: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Who controls the assigned mailbox (a personal-provider substitute is recorded as non_company, never hidden).
    company_email_control: Mapped[ControlStatus] = mapped_column(
        _enum(ControlStatus), default=ControlStatus.UNKNOWN, server_default=ControlStatus.UNKNOWN.value
    )
    company_phone_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    company_phone_hint: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Who controls the assigned number (a personal substitute is recorded as non_company, never hidden).
    company_phone_control: Mapped[ControlStatus] = mapped_column(
        _enum(ControlStatus), default=ControlStatus.UNKNOWN, server_default=ControlStatus.UNKNOWN.value
    )

    recovery_email_control: Mapped[ControlStatus] = mapped_column(_enum(ControlStatus), default=ControlStatus.UNKNOWN)
    recovery_email_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )
    recovery_phone_control: Mapped[ControlStatus] = mapped_column(_enum(ControlStatus), default=ControlStatus.UNKNOWN)
    recovery_phone_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )
    recovery_last_verified_at: Mapped[datetime | None] = _ts()

    two_factor_status: Mapped[TwoFactorStatus] = mapped_column(_enum(TwoFactorStatus), default=TwoFactorStatus.UNKNOWN)
    two_factor_method: Mapped[TwoFactorMethod] = mapped_column(_enum(TwoFactorMethod), default=TwoFactorMethod.UNKNOWN)
    two_factor_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )

    backup_codes_vault_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    backup_codes_status: Mapped[BackupCodesStatus] = mapped_column(
        _enum(BackupCodesStatus), default=BackupCodesStatus.UNKNOWN
    )
    backup_codes_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )

    password_vault_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    password_ref_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )
    other_vault_refs: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)

    profile_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bio: Mapped[str | None] = mapped_column(String(150), nullable=True)
    bio_char_count: Mapped[int] = mapped_column(Integer, default=0)
    profile_link: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    category: Mapped[str | None] = mapped_column(String(60), nullable=True)
    profile_image_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)

    business_account_status: Mapped[BusinessAccountStatus] = mapped_column(
        _enum(BusinessAccountStatus), default=BusinessAccountStatus.NOT_STARTED
    )
    meta_link_status: Mapped[MetaLinkStatus] = mapped_column(_enum(MetaLinkStatus), default=MetaLinkStatus.NOT_STARTED)
    meta_business_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    meta_link_verification: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )

    provisioning_status: Mapped[ProvisioningStatus] = mapped_column(
        _enum(ProvisioningStatus), default=ProvisioningStatus.DRAFT, index=True
    )
    status_before_block: Mapped[ProvisioningStatus | None] = mapped_column(_enum(ProvisioningStatus), nullable=True)
    blocker_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    blocker_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    blocker_task_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    blocked_at: Mapped[datetime | None] = _ts()
    provisioned_at: Mapped[datetime | None] = _ts()
    # Incremented only after a human reconciliation confirms no account exists on the platform.
    signup_attempt: Mapped[int] = mapped_column(Integer, default=1)

    last_verified_at: Mapped[datetime | None] = _ts()
    verification_source: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )
    evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    version_id: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __mapper_args__ = {"version_id_col": version_id}

    owner: Mapped[Person] = relationship(foreign_keys=[owner_id])
    steps: Mapped[list[AccountStep]] = relationship(
        back_populates="account", cascade="all, delete-orphan", order_by="AccountStep.id"
    )
    assignments: Mapped[list[AccountAssignment]] = relationship(back_populates="account", cascade="all, delete-orphan")


class AccountStep(Base):
    """Per-step completion evidence for the provisioning workflow."""

    __tablename__ = "account_steps"
    __table_args__ = (UniqueConstraint("account_id", "step"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("instagram_accounts.id"), index=True)
    step: Mapped[ProvisioningStep] = mapped_column(_enum(ProvisioningStep))
    state: Mapped[StepState] = mapped_column(_enum(StepState), default=StepState.PENDING)
    verification: Mapped[VerificationLabel] = mapped_column(_enum(VerificationLabel), default=VerificationLabel.UNVERIFIED)
    evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    completed_at: Mapped[datetime | None] = _ts()
    completed_by_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    account: Mapped[InstagramAccount] = relationship(back_populates="steps")


class AccountAssignment(Base):
    """A person's approved role on the account (Meta Business / Instagram)."""

    __tablename__ = "account_assignments"
    __table_args__ = (UniqueConstraint("account_id", "person_id", "platform", "role"),)

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("asg"))
    account_id: Mapped[str] = mapped_column(ForeignKey("instagram_accounts.id"), index=True)
    person_id: Mapped[str] = mapped_column(ForeignKey("people.id"), index=True)
    platform: Mapped[Platform] = mapped_column(_enum(Platform))
    role: Mapped[RoleName] = mapped_column(_enum(RoleName))
    role_description: Mapped[str] = mapped_column(String(300))
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[AssignmentStatus] = mapped_column(_enum(AssignmentStatus), default=AssignmentStatus.REQUESTED)
    is_temporary_test_role: Mapped[bool] = mapped_column(Boolean, default=False)
    verification: Mapped[VerificationLabel] = mapped_column(_enum(VerificationLabel), default=VerificationLabel.UNVERIFIED)
    evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    last_verified_at: Mapped[datetime | None] = _ts()
    granted_at: Mapped[datetime | None] = _ts()
    removed_at: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    account: Mapped[InstagramAccount] = relationship(back_populates="assignments")
    person: Mapped[Person] = relationship()


class CredentialAccess(Base):
    """Which vault entries a person could access (drives offboarding rotation)."""

    __tablename__ = "credential_access"
    __table_args__ = (UniqueConstraint("person_id", "vault_ref"),)

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("cra"))
    person_id: Mapped[str] = mapped_column(ForeignKey("people.id"), index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("instagram_accounts.id"), nullable=True)
    vault_ref: Mapped[str] = mapped_column(String(240))
    credential_kind: Mapped[CredentialKind] = mapped_column(_enum(CredentialKind))
    status: Mapped[CredentialAccessStatus] = mapped_column(
        _enum(CredentialAccessStatus), default=CredentialAccessStatus.ACTIVE
    )
    verification: Mapped[VerificationLabel] = mapped_column(_enum(VerificationLabel), default=VerificationLabel.UNVERIFIED)
    granted_at: Mapped[datetime | None] = _ts()
    revoked_at: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    person: Mapped[Person] = relationship()


# ---------------------------------------------------------------------------
# Human tasks
# ---------------------------------------------------------------------------


class HumanTask(Base):
    __tablename__ = "human_tasks"
    __table_args__ = (
        Index("ix_human_tasks_status_due", "status", "due_at"),
        Index("ix_human_tasks_owner_status", "owner_id", "status"),
        Index("ix_human_tasks_account_type", "account_id", "task_type"),
    )

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("tsk"))
    task_type: Mapped[TaskType] = mapped_column(_enum(TaskType))
    origin: Mapped[TaskOrigin] = mapped_column(_enum(TaskOrigin), default=TaskOrigin.PROVISIONING)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("instagram_accounts.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str] = mapped_column(ForeignKey("people.id"))
    supervisor_id: Mapped[str | None] = mapped_column(ForeignKey("people.id"), nullable=True)
    due_at: Mapped[datetime] = mapped_column(UTCDateTime())
    priority: Mapped[TaskPriority] = mapped_column(_enum(TaskPriority), default=TaskPriority.NORMAL)
    status: Mapped[TaskStatus] = mapped_column(_enum(TaskStatus), default=TaskStatus.PENDING)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1)
    reminder_count: Mapped[int] = mapped_column(Integer, default=0)
    last_reminder_at: Mapped[datetime | None] = _ts()
    escalation_count: Mapped[int] = mapped_column(Integer, default=0)
    escalated_at: Mapped[datetime | None] = _ts()
    completed_at: Mapped[datetime | None] = _ts()
    completed_by_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    completion_evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    completion_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_source: Mapped[VerificationLabel] = mapped_column(
        _enum(VerificationLabel), default=VerificationLabel.UNVERIFIED
    )
    outcome: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(200), unique=True)
    blocker_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_id: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __mapper_args__ = {"version_id_col": version_id}

    owner: Mapped[Person] = relationship(foreign_keys=[owner_id])
    supervisor: Mapped[Person | None] = relationship(foreign_keys=[supervisor_id])
    account: Mapped[InstagramAccount | None] = relationship()
    events: Mapped[list[TaskEvent]] = relationship(
        back_populates="task", order_by="TaskEvent.id", cascade="all, delete-orphan"
    )


class TaskEvent(Base):
    """Append-only history for every task (creation, transitions, reminders, escalations)."""

    __tablename__ = "task_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("human_tasks.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    from_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    task: Mapped[HumanTask] = relationship(back_populates="events")


class Notification(Base):
    """Notification outbox. The dedupe key makes reminders/escalations exactly-once per level."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_status_next", "delivery_status", "next_attempt_at"),)

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("ntf"))
    task_id: Mapped[str | None] = mapped_column(ForeignKey("human_tasks.id"), nullable=True, index=True)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("people.id"))
    kind: Mapped[NotificationKind] = mapped_column(_enum(NotificationKind))
    channel: Mapped[str] = mapped_column(String(40), default="email")
    subject: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    delivery_status: Mapped[DeliveryStatus] = mapped_column(_enum(DeliveryStatus), default=DeliveryStatus.PENDING)
    dedupe_key: Mapped[str] = mapped_column(String(200), unique=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = _ts()
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    sent_at: Mapped[datetime | None] = _ts()

    recipient: Mapped[Person] = relationship()


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("aud"))
    trigger: Mapped[AuditTrigger] = mapped_column(_enum(AuditTrigger))
    # e.g. "weekly:2026-W42" - guarantees one scheduled run per ISO week across restarts.
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True, nullable=True)
    status: Mapped[AuditRunStatus] = mapped_column(_enum(AuditRunStatus), default=AuditRunStatus.RUNNING)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = _ts()
    attempt_count: Mapped[int] = mapped_column(Integer, default=1)
    triggered_by_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_json_path: Mapped[str | None] = mapped_column(String(400), nullable=True)
    report_md_path: Mapped[str | None] = mapped_column(String(400), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditFinding(Base):
    __tablename__ = "audit_findings"
    __table_args__ = (
        # At most one OPEN finding per (account, fingerprint): repeated audits reuse it.
        Index(
            "uq_audit_findings_open_fingerprint",
            "account_id",
            "fingerprint",
            unique=True,
            sqlite_where=text("status = 'open'"),
            postgresql_where=text("status = 'open'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("fnd"))
    account_id: Mapped[str] = mapped_column(ForeignKey("instagram_accounts.id"), index=True)
    check_name: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(_enum(Severity))
    description: Mapped[str] = mapped_column(Text)
    verification: Mapped[VerificationLabel] = mapped_column(_enum(VerificationLabel))
    evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_detected_at: Mapped[datetime] = mapped_column(UTCDateTime())
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    last_run_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    remediation_task_id: Mapped[str | None] = mapped_column(ForeignKey("human_tasks.id"), nullable=True)
    remediation_generation: Mapped[int] = mapped_column(Integer, default=0)
    remediation_blocker: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus), default=FindingStatus.OPEN)
    resolved_at: Mapped[datetime | None] = _ts()
    resolution_note: Mapped[str | None] = mapped_column(String(300), nullable=True)

    remediation_task: Mapped[HumanTask | None] = relationship()


# ---------------------------------------------------------------------------
# Offboarding
# ---------------------------------------------------------------------------


class OffboardingCase(Base):
    __tablename__ = "offboarding_cases"
    __table_args__ = (
        Index(
            "uq_offboarding_cases_open_person",
            "person_id",
            unique=True,
            sqlite_where=text("status = 'open'"),
            postgresql_where=text("status = 'open'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("off"))
    person_id: Mapped[str] = mapped_column(ForeignKey("people.id"))
    status: Mapped[OffboardingCaseStatus] = mapped_column(_enum(OffboardingCaseStatus), default=OffboardingCaseStatus.OPEN)
    reason: Mapped[str] = mapped_column(String(300))
    requested_by_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    replacement_admin_id: Mapped[str | None] = mapped_column(ForeignKey("people.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
    closed_at: Mapped[datetime | None] = _ts()
    reconcile_count: Mapped[int] = mapped_column(Integer, default=0)

    person: Mapped[Person] = relationship(foreign_keys=[person_id])
    replacement_admin: Mapped[Person | None] = relationship(foreign_keys=[replacement_admin_id])
    actions: Mapped[list[OffboardingAction]] = relationship(
        back_populates="case", order_by="OffboardingAction.created_at", cascade="all, delete-orphan"
    )


class OffboardingAction(Base):
    __tablename__ = "offboarding_actions"

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("ofa"))
    case_id: Mapped[str] = mapped_column(ForeignKey("offboarding_cases.id"), index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("instagram_accounts.id"), nullable=True)
    action_type: Mapped[OffboardingActionType] = mapped_column(_enum(OffboardingActionType))
    target_ref: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("people.id"), nullable=True)
    status: Mapped[OffboardingActionStatus] = mapped_column(
        _enum(OffboardingActionStatus), default=OffboardingActionStatus.PENDING
    )
    verification: Mapped[VerificationLabel] = mapped_column(_enum(VerificationLabel), default=VerificationLabel.UNVERIFIED)
    evidence_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    blocker_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    blocker_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("human_tasks.id"), nullable=True)
    task_generation: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(300), unique=True)
    completed_at: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())

    case: Mapped[OffboardingCase] = relationship(back_populates="actions")
    owner: Mapped[Person | None] = relationship()
    task: Mapped[HumanTask | None] = relationship()


# ---------------------------------------------------------------------------
# Proxies
# ---------------------------------------------------------------------------


class ProxyEndpoint(Base):
    """Approved proxy. Credentials live in the vault; only the reference is stored."""

    __tablename__ = "proxy_endpoints"

    id: Mapped[str] = mapped_column(String(60), primary_key=True)
    scheme: Mapped[str] = mapped_column(String(10))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    credential_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    health_status: Mapped[ProxyHealth] = mapped_column(_enum(ProxyHealth), default=ProxyHealth.UNKNOWN)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    total_failures: Mapped[int] = mapped_column(Integer, default=0)
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    last_check_at: Mapped[datetime | None] = _ts()
    last_success_at: Mapped[datetime | None] = _ts()
    last_failure_at: Mapped[datetime | None] = _ts()
    last_failure_kind: Mapped[str | None] = mapped_column(String(60), nullable=True)
    last_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_until: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class ProxySession(Base):
    """Session affinity: a test workflow keeps one proxy unless controlled failover is needed."""

    __tablename__ = "proxy_sessions"
    __table_args__ = (
        Index(
            "uq_proxy_sessions_live_account_purpose",
            "account_id",
            "purpose",
            unique=True,
            sqlite_where=text("status != 'ended'"),
            postgresql_where=text("status != 'ended'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(ID_LEN), primary_key=True, default=lambda: new_id("pxs"))
    account_id: Mapped[str | None] = mapped_column(ForeignKey("instagram_accounts.id"), nullable=True)
    purpose: Mapped[str] = mapped_column(String(80))
    proxy_id: Mapped[str] = mapped_column(ForeignKey("proxy_endpoints.id"))
    status: Mapped[ProxySessionStatus] = mapped_column(_enum(ProxySessionStatus), default=ProxySessionStatus.ACTIVE)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_used_at: Mapped[datetime | None] = _ts()
    ended_at: Mapped[datetime | None] = _ts()
    failover_count: Mapped[int] = mapped_column(Integer, default=0)
    rate_limited_until: Mapped[datetime | None] = _ts()
    pause_reason: Mapped[str | None] = mapped_column(String(300), nullable=True)
    review_task_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True)
    end_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)

    proxy: Mapped[ProxyEndpoint] = relationship()


class ProxyEvent(Base):
    __tablename__ = "proxy_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    proxy_id: Mapped[str | None] = mapped_column(String(60), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(ID_LEN), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(String(60))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
