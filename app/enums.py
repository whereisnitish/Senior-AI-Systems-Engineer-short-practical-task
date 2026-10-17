"""Domain enumerations. Values are stored as lowercase strings in the database."""

from __future__ import annotations

from enum import StrEnum


class VerificationLabel(StrEnum):
    """How a fact or finding was verified.

    integration_verified: read directly from the authoritative system (a configured
        integration such as the vault or Meta Graph API, or this application's own
        records when this application *is* the system of record).
    human_confirmed: a named, authorised human attested to it with an evidence reference.
    unverified: no adequate evidence either way. Absence of data is never treated as
        proof that something is wrong (or right).
    """

    INTEGRATION_VERIFIED = "integration_verified"
    HUMAN_CONFIRMED = "human_confirmed"
    UNVERIFIED = "unverified"


class ProvisioningStatus(StrEnum):
    DRAFT = "draft"
    AWAITING_HANDLE_CHECK = "awaiting_handle_check"
    AWAITING_CONTACT_ASSIGNMENT = "awaiting_contact_assignment"
    AWAITING_SIGNUP = "awaiting_signup"
    AWAITING_RECONCILIATION = "awaiting_reconciliation"
    AWAITING_VERIFICATION = "awaiting_verification"
    AWAITING_SECURITY_SETUP = "awaiting_security_setup"
    AWAITING_PROFILE_SETUP = "awaiting_profile_setup"
    AWAITING_META_LINK = "awaiting_meta_link"
    BLOCKED = "blocked"
    PROVISIONED = "provisioned"


class ProvisioningStep(StrEnum):
    HANDLE_SELECTED = "handle_selected"
    COMPANY_EMAIL = "company_email"
    COMPANY_PHONE = "company_phone"
    SIGNUP = "signup"
    PLATFORM_VERIFICATION = "platform_verification"
    TWO_FACTOR = "two_factor"
    PROFILE = "profile"
    BUSINESS_CONVERSION = "business_conversion"
    META_LINK = "meta_link"
    ROLES_ASSIGNED = "roles_assigned"


class StepState(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class HandleStatus(StrEnum):
    NOT_CHECKED = "not_checked"
    AVAILABLE_HUMAN_CONFIRMED = "available_human_confirmed"
    CLAIMED_ON_PLATFORM = "claimed_on_platform"


class ControlStatus(StrEnum):
    UNKNOWN = "unknown"
    COMPANY_CONTROLLED = "company_controlled"
    NON_COMPANY = "non_company"


class TwoFactorStatus(StrEnum):
    UNKNOWN = "unknown"
    ENABLED = "enabled"
    DISABLED = "disabled"


class TwoFactorMethod(StrEnum):
    UNKNOWN = "unknown"
    AUTHENTICATOR_APP = "authenticator_app"
    SECURITY_KEY = "security_key"
    SMS = "sms"


class BackupCodesStatus(StrEnum):
    UNKNOWN = "unknown"
    PRESENT_IN_VAULT = "present_in_vault"
    MISSING = "missing"
    REPLACEMENT_REQUIRED = "replacement_required"


class BusinessAccountStatus(StrEnum):
    NOT_STARTED = "not_started"
    PENDING_HUMAN = "pending_human"
    CONVERTED = "converted"


class MetaLinkStatus(StrEnum):
    NOT_STARTED = "not_started"
    PENDING_HUMAN = "pending_human"
    LINKED = "linked"
    MISMATCH = "mismatch"


class PersonStatus(StrEnum):
    ACTIVE = "active"
    DEPARTING = "departing"
    OFFBOARDED = "offboarded"


class Responsibility(StrEnum):
    SECURITY_OWNER = "security_owner"
    VAULT_ADMIN = "vault_admin"
    PROXY_PROVIDER_ADMIN = "proxy_provider_admin"
    ESCALATION_DEFAULT = "escalation_default"


class OperatorRole(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Platform(StrEnum):
    META_BUSINESS = "meta_business"
    INSTAGRAM = "instagram"


class RoleName(StrEnum):
    BUSINESS_ADMIN = "business_admin"
    CONTENT_PUBLISHER = "content_publisher"
    COMMUNITY_MANAGER = "community_manager"
    INSIGHTS_ANALYST = "insights_analyst"
    TEMPORARY_TEST_ROLE = "temporary_test_role"


class AssignmentStatus(StrEnum):
    REQUESTED = "requested"
    ACTIVE = "active"
    PENDING_REMOVAL = "pending_removal"
    REMOVED = "removed"


class CredentialKind(StrEnum):
    INSTAGRAM_PASSWORD = "instagram_password"
    BACKUP_CODES = "backup_codes"
    TOTP_SEED = "totp_seed"
    PROXY_CREDENTIAL = "proxy_credential"
    META_TOKEN = "meta_token"
    OTHER = "other"


class CredentialAccessStatus(StrEnum):
    ACTIVE = "active"
    REVOCATION_PENDING = "revocation_pending"
    REVOKED = "revoked"


class TaskType(StrEnum):
    HANDLE_AVAILABILITY_CHECK = "handle_availability_check"
    ASSIGN_COMPANY_EMAIL = "assign_company_email"
    ASSIGN_COMPANY_PHONE = "assign_company_phone"
    ACCOUNT_SIGNUP = "account_signup"
    SIGNUP_RECONCILIATION = "signup_reconciliation"
    ACCOUNT_VERIFICATION = "account_verification"
    ENABLE_TWO_FACTOR = "enable_two_factor"
    COMPLETE_PROFILE = "complete_profile"
    CONVERT_TO_BUSINESS = "convert_to_business"
    LINK_META_BUSINESS = "link_meta_business"
    ASSIGN_PEOPLE_ROLES = "assign_people_roles"
    CONFIRM_RECOVERY_CONTACTS = "confirm_recovery_contacts"
    STORE_BACKUP_CODES = "store_backup_codes"
    STORE_PASSWORD_IN_VAULT = "store_password_in_vault"
    REVIEW_ACCESS = "review_access"
    OFFBOARDING_ACTION = "offboarding_action"
    PROXY_SECURITY_REVIEW = "proxy_security_review"
    PROXY_MAINTENANCE = "proxy_maintenance"
    MANUAL = "manual"


class TaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_FOR_HUMAN = "waiting_for_human"
    COMPLETED = "completed"
    OVERDUE = "overdue"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TaskPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class TaskOrigin(StrEnum):
    PROVISIONING = "provisioning"
    AUDIT = "audit"
    OFFBOARDING = "offboarding"
    PROXY = "proxy"
    MANUAL = "manual"


class NotificationKind(StrEnum):
    ASSIGNMENT = "assignment"
    REMINDER = "reminder"
    ESCALATION = "escalation"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    NOT_DELIVERED_NO_PROVIDER = "not_delivered_no_provider"
    SUPERSEDED = "superseded"  # not sent: its task was already closed, so the message would mislead


class AuditTrigger(StrEnum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    CLI = "cli"


class AuditRunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class OffboardingCaseStatus(StrEnum):
    OPEN = "open"
    COMPLETED = "completed"


class OffboardingActionType(StrEnum):
    IDENTIFY_ROLES = "identify_roles"
    REVOKE_APP_ACCESS = "revoke_app_access"
    REMOVE_ACCOUNT_ROLE = "remove_account_role"
    GRANT_REPLACEMENT_ADMIN = "grant_replacement_admin"
    IDENTIFY_CREDENTIALS = "identify_credentials"
    REMOVE_VAULT_ACCESS = "remove_vault_access"
    ROTATE_CREDENTIAL = "rotate_credential"
    REPLACE_BACKUP_CODES = "replace_backup_codes"
    VERIFY_ACCESS_STATE = "verify_access_state"
    UPDATE_REGISTER = "update_register"


class OffboardingActionStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ProxyHealth(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    QUARANTINED = "quarantined"


class ProxySessionStatus(StrEnum):
    ACTIVE = "active"
    PAUSED_SECURITY_REVIEW = "paused_security_review"
    ENDED = "ended"
