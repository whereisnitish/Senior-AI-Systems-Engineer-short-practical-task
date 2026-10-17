"""Registry of human task types: instructions, required completion outcome, defaults.

Completion outcomes are typed and validated here. Humans confirm facts with
checklist confirmations and *references* (ticket IDs, vault references); they
are never asked for passwords, codes or screenshots of secrets.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.enums import TaskPriority, TaskType
from app.errors import ValidationFailed
from app.security.secret_handling import (
    find_secret_material,
    mask_email,
    mask_phone,
    validate_vault_ref,
)
from app.services.handles import handle_problems, normalize_handle

SAFETY_FOOTER = (
    "\n\nSAFETY RULES\n"
    "- Never paste passwords, verification codes, backup codes, cookies or tokens into this system, chat, "
    "tickets or screenshots. Store secrets only in the company vault and record the vault reference.\n"
    "- Evidence is a reference (ticket ID, vault reference, or a short description of what you observed), "
    "never an image of a secret.\n"
    "- If Instagram shows a CAPTCHA, checkpoint or verification you cannot complete normally, STOP, mark this "
    "task BLOCKED with a short description and wait for review. Do not retry repeatedly, switch networks, "
    "or use any workaround.\n"
    "- Do not use automation, bots or unofficial tools against Instagram."
)

_REFERENCE_RE = re.compile(r"^[A-Za-z0-9 _.:/#@+\-()]{2,200}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")


@dataclass(frozen=True)
class OutcomeField:
    name: str
    kind: str  # confirm | choice | handle | vault_ref | reference | text | email | phone
    label: str
    required: bool = True
    choices: tuple[str, ...] = ()
    # False: used only to derive masked metadata; the raw value is never persisted.
    persist: bool = True


@dataclass(frozen=True)
class TaskTypeSpec:
    task_type: TaskType
    title: str
    instructions: str
    outcome_fields: tuple[OutcomeField, ...]
    due_hours: float
    priority: TaskPriority
    evidence_hint: str = "Reference to what you observed, e.g. 'observed in Instagram settings 2026-10-16 (alice)'"


@dataclass
class ValidatedOutcome:
    stored: dict[str, Any] = field(default_factory=dict)
    derived: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.stored:
            return self.stored[key]
        return self.derived.get(key, default)


def _confirm(name: str, label: str) -> OutcomeField:
    return OutcomeField(name, "confirm", label)


SPECS: dict[TaskType, TaskTypeSpec] = {}


def _register(spec: TaskTypeSpec) -> None:
    SPECS[spec.task_type] = spec


_register(
    TaskTypeSpec(
        TaskType.HANDLE_AVAILABILITY_CHECK,
        "Check handle availability for {brand}",
        "Suggested handles (format-checked only - a suggestion is NOT proof of availability):\n{suggestions}\n\n"
        "1. On an approved company device, use the official Instagram app or instagram.com to check whether the "
        "candidates are available (for example by searching the handle or reaching the username step of the "
        "official signup screen). Do not use scraping tools, bulk checkers or unofficial APIs.\n"
        "2. Pick the best available candidate, or another valid handle approved by the account owner.\n"
        "3. Do NOT create the account yet. Signup is a separate task once the company email and phone are assigned.",
        (
            OutcomeField("selected_handle", "handle", "Selected handle (without @)"),
            OutcomeField("checked_via", "choice", "Checked via", choices=("instagram_app", "instagram_web")),
        ),
        24,
        TaskPriority.NORMAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.ASSIGN_COMPANY_EMAIL,
        "Assign a company email alias for {brand}",
        "No email-provisioning integration is configured, so this is a tracked human task.\n"
        "1. Request or create a company-controlled alias on an approved company domain ({company_domains}). "
        "Never use a personal mailbox.\n"
        "2. Make sure the account owner and a backup admin can read the alias.\n"
        "3. Complete with the assignment/ticket reference, the alias address (used only to check the domain and "
        "build a masked hint; it is not stored in full) and say truthfully who controls the mailbox. If only a "
        "personal-provider mailbox (e.g. a new Gmail address) is available, choose personal_provider_substitute: "
        "work continues, and the audit reports the non-company recovery email.",
        (
            OutcomeField("email_assignment_ref", "reference", "Assignment / ticket reference"),
            OutcomeField("email_address", "email", "Alias address (not stored)", persist=False),
            OutcomeField(
                "mailbox_control",
                "choice",
                "Who controls this mailbox (personal_provider_substitute: the step completes, but the audit flags a "
                "non-company recovery email until a company alias replaces it)",
                choices=("company_controlled", "dedicated_test_mailbox", "personal_provider_substitute"),
            ),
        ),
        24,
        TaskPriority.NORMAL,
        "Ticket or assignment ID, e.g. 'IT-REQ-1234'",
    )
)
_register(
    TaskTypeSpec(
        TaskType.ASSIGN_COMPANY_PHONE,
        "Reserve and assign a company-controlled phone number for {brand}",
        "No phone-inventory or SMS integration is configured, so this is a tracked human task.\n"
        "1. Reserve a company-controlled number (company SIM or company virtual number) from the provided test "
        "environment. Never use a personal number.\n"
        "2. Record who administers the number.\n"
        "3. Complete with the assignment reference, the number in E.164 format (used only to build a masked "
        "hint; not stored in full) and say truthfully who controls it. If only a personal number is available, "
        "choose personal_number_substitute: work continues, and the audit reports the non-company recovery phone.",
        (
            OutcomeField("phone_assignment_ref", "reference", "Assignment / inventory reference"),
            OutcomeField("phone_number", "phone", "Number in E.164 format (not stored)", persist=False),
            OutcomeField(
                "number_control",
                "choice",
                "Who controls this number (personal_number_substitute: the step completes, but the audit flags a "
                "non-company recovery phone until a company number replaces it)",
                choices=("company_controlled", "dedicated_test_number", "personal_number_substitute"),
            ),
        ),
        24,
        TaskPriority.NORMAL,
        "Inventory or ticket ID, e.g. 'TEL-0042'",
    )
)
_register(
    TaskTypeSpec(
        TaskType.ACCOUNT_SIGNUP,
        "Sign up @{handle} for {brand} on Instagram (attempt {attempt})",
        "Manual signup - this system never automates Instagram signup.\n"
        "1. On an approved company device and network, open the official Instagram app or instagram.com and "
        "choose 'Create new account'.\n"
        "2. Use the company email alias from assignment {email_ref} ({email_hint}). Do not use a personal email "
        "or phone.\n"
        "3. Use the handle @{handle}. If it is no longer available, STOP and mark this task BLOCKED - do not pick "
        "a different handle on your own.\n"
        "4. Generate the password with the company vault's generator and save it directly into the vault. Record "
        "only the vault reference here.\n"
        "5. Complete any confirmation Instagram requests yourself; never relay codes through this system.\n"
        "6. Sign up once. If you are interrupted and unsure whether the account was created, mark this task "
        "FAILED with 'outcome uncertain' - the system will ask for reconciliation instead of creating a second "
        "account.",
        (
            OutcomeField("platform_handle", "handle", "Handle as created on Instagram"),
            OutcomeField("password_vault_ref", "vault_ref", "Vault reference of the password"),
        ),
        48,
        TaskPriority.HIGH,
        "What you observed, e.g. 'profile instagram.com/<handle> visible while logged in as company alias'",
    )
)
_register(
    TaskTypeSpec(
        TaskType.SIGNUP_RECONCILIATION,
        "Reconcile signup attempt {attempt} for @{handle} before anything is retried",
        "The previous signup task ended without a confirmed result ({reason}). Nobody may sign up again until "
        "this is resolved.\n"
        "1. Check whether the profile instagram.com/{handle} exists (logged out is fine).\n"
        "2. Check the company alias inbox ({email_hint}) for Instagram welcome/confirmation emails, and whether a "
        "password for this account was saved in the vault.\n"
        "3. Record exactly one outcome:\n"
        "   - exists_controlled: the account exists and is controlled via the company alias (give the password "
        "vault reference);\n"
        "   - does_not_exist: no account exists - a fresh signup task (next attempt) will be created;\n"
        "   - exists_not_controlled: the handle exists but is NOT company-controlled - the workflow blocks for "
        "escalation. Do not attempt any recovery workaround.",
        (
            OutcomeField(
                "external_account_state",
                "choice",
                "What exists on Instagram",
                choices=("exists_controlled", "does_not_exist", "exists_not_controlled"),
            ),
            OutcomeField("password_vault_ref", "vault_ref", "Password vault reference (if it exists)", required=False),
        ),
        24,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.ACCOUNT_VERIFICATION,
        "Confirm platform verification and recovery details for @{handle}",
        "1. Complete any email or SMS confirmation Instagram requests, yourself, on the company device. Never "
        "enter codes into this system.\n"
        "2. In Instagram > Accounts Center > Personal details, confirm the contact email is the company alias "
        "({email_hint}) and the phone is the company number ({phone_hint}).\n"
        "3. If anything does not match, fix it on the platform first.",
        (
            _confirm("email_confirmed_on_platform", "Email confirmation completed on Instagram"),
            _confirm("phone_confirmed_on_platform", "Phone confirmation completed on Instagram"),
            _confirm("recovery_email_is_company_alias", "Recovery email is the address assigned in the email task"),
            _confirm("recovery_phone_is_company_number", "Recovery phone is the number assigned in the phone task"),
        ),
        24,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.ENABLE_TWO_FACTOR,
        "Enable two-factor authentication on @{handle} and vault the backup codes",
        "1. Accounts Center > Password and security > Two-factor authentication. Prefer an authenticator app "
        "(store the setup key in the vault) or a security key; use SMS only if nothing else is possible.\n"
        "2. Generate backup codes and save them straight into the company vault. Never paste them anywhere else.\n"
        "3. Complete with the method and the vault references - not the codes.",
        (
            OutcomeField(
                "two_factor_method", "choice", "2FA method", choices=("authenticator_app", "security_key", "sms")
            ),
            OutcomeField("backup_codes_vault_ref", "vault_ref", "Vault reference of the backup codes"),
            OutcomeField("totp_seed_vault_ref", "vault_ref", "Vault reference of the authenticator setup key", required=False),
            _confirm("two_factor_enabled", "Two-factor authentication is enabled on Instagram"),
        ),
        24,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.COMPLETE_PROFILE,
        "Apply the approved profile to @{handle}",
        "Apply exactly these approved values in the Instagram app (bio length is validated here, max 150 "
        "characters):\n{profile_block}\n\nComplete when the live profile matches.",
        (_confirm("profile_matches_spec", "The live profile matches the approved values"),),
        48,
        TaskPriority.NORMAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.CONVERT_TO_BUSINESS,
        "Convert @{handle} to a business account",
        "Settings > Account type and tools > Switch to professional account > Business. Choose the approved "
        "category ({category}). Do not connect any personal Facebook profile or Page here; Meta linking is a "
        "separate task.",
        (
            OutcomeField("account_type", "choice", "Account type now shown", choices=("business", "creator")),
            _confirm("category_set", "The approved category is set"),
        ),
        48,
        TaskPriority.NORMAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.LINK_META_BUSINESS,
        "Link @{handle} to the designated Meta test business",
        "1. In Meta Business Suite for the separate company test business ({business_ref}), add the Instagram "
        "account (Settings > Accounts > Instagram accounts > Add) and complete Instagram's own login prompt "
        "yourself.\n"
        "2. Confirm it appears in Business Manager / business settings for the same business.\n"
        "3. Never link it to a live brand's business portfolio.",
        (
            OutcomeField("meta_business_ref", "reference", "Business ID / reference linked to"),
            _confirm("linked_in_business_suite", "Visible in Meta Business Suite"),
            _confirm("linked_in_business_manager", "Visible in Business Manager / business settings"),
        ),
        48,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.ASSIGN_PEOPLE_ROLES,
        "Grant approved people least-privilege access to @{handle}",
        "Grant exactly the access below in the test business (Business settings > People / Instagram accounts). "
        "Grant nothing beyond it; keep full control limited to the listed business admins.\n{roles_block}\n\n"
        "Complete when every listed person has exactly the listed access.",
        (_confirm("roles_granted_as_listed", "Access granted exactly as listed"),),
        48,
        TaskPriority.NORMAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.CONFIRM_RECOVERY_CONTACTS,
        "Confirm recovery email and phone on @{handle} are company-controlled",
        "Audit finding: {finding_description}\nCheck Accounts Center > Personal details. Replace any non-company "
        "contact with the company alias ({email_hint}) / number ({phone_hint}), then confirm.",
        (
            _confirm("recovery_email_is_company_alias", "Recovery email is the address assigned in the email task"),
            _confirm("recovery_phone_is_company_number", "Recovery phone is the number assigned in the phone task"),
        ),
        72,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.STORE_BACKUP_CODES,
        "Store (or replace) backup codes for @{handle} in the vault",
        "{finding_description}\nGenerate a fresh set of backup codes in Instagram (this invalidates the old set), "
        "store them straight into the vault and record only the vault reference.",
        (
            OutcomeField("backup_codes_vault_ref", "vault_ref", "Vault reference of the new backup codes"),
            _confirm("codes_regenerated", "A new set was generated and the old set invalidated"),
        ),
        72,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.STORE_PASSWORD_IN_VAULT,
        "Record the vault reference for the @{handle} password",
        "{finding_description}\nMake sure the current password is stored in the company vault and record the "
        "vault reference only.",
        (
            OutcomeField("password_vault_ref", "vault_ref", "Vault reference of the password"),
            _confirm("password_in_vault", "The current password is stored in the vault"),
        ),
        72,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.REVIEW_ACCESS,
        "Review people and roles on @{handle}",
        "{finding_description}\nCompare the access actually granted in Meta Business Suite with the approved "
        "register below and fix any difference on the platform.\n{roles_block}",
        (
            _confirm("access_matches_register", "Platform access now matches the approved register"),
            OutcomeField("notes", "text", "Notes", required=False),
        ),
        168,
        TaskPriority.NORMAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.OFFBOARDING_ACTION,
        "{action_title}",
        "{action_instructions}",
        (
            _confirm("action_completed", "The action has been completed on the relevant system"),
            OutcomeField("notes", "text", "Notes", required=False),
        ),
        24,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.PROXY_SECURITY_REVIEW,
        "Human review: security challenge on proxy session {session_id}",
        "The neutral test endpoint returned a security challenge via proxy {proxy_id}. The session is PAUSED and "
        "no proxy rotation was attempted - rotating to get around a challenge is not allowed.\n"
        "Review the event, confirm no workflow is trying to automate around a challenge, then decide whether "
        "to resume or end the session.",
        (
            OutcomeField("decision", "choice", "Decision", choices=("resume_session", "end_session")),
            _confirm("reviewed", "I reviewed the challenge event"),
        ),
        4,
        TaskPriority.CRITICAL,
    )
)
_register(
    TaskTypeSpec(
        TaskType.PROXY_MAINTENANCE,
        "Proxy {proxy_id} rejected its credential",
        "The proxy returned an authentication failure (HTTP 407). It is quarantined and will not be used. Verify "
        "or rotate the credential with the proxy provider, update vault entry {credential_ref}, then confirm. The "
        "proxy returns to service only after a successful health check.",
        (_confirm("credential_updated_in_vault", "Credential verified/rotated and the vault entry updated"),),
        24,
        TaskPriority.HIGH,
    )
)
_register(
    TaskTypeSpec(
        TaskType.MANUAL,
        "{title}",
        "{description}",
        (_confirm("done", "Done"), OutcomeField("notes", "text", "Notes", required=False)),
        72,
        TaskPriority.NORMAL,
    )
)


def get_spec(task_type: TaskType) -> TaskTypeSpec:
    return SPECS[task_type]


class _Defaulting(dict):
    def __missing__(self, key: str) -> str:
        return "(not yet recorded)"


def render(template: str, context: Mapping[str, Any]) -> str:
    return string.Formatter().vformat(template, (), _Defaulting(context))


def render_task_text(task_type: TaskType, context: Mapping[str, Any]) -> tuple[str, str]:
    spec = get_spec(task_type)
    title = render(spec.title, context)[:200]
    return title, render(spec.instructions, context) + SAFETY_FOOTER


_TRUE = {True, "true", "on", "yes", "1"}


def validate_outcome(
    task_type: TaskType, raw: Mapping[str, Any] | None, *, allowed_vault_schemes: Iterable[str]
) -> ValidatedOutcome:
    """Validate a completion outcome. Errors name fields and problems, never values."""
    spec = get_spec(task_type)
    raw = dict(raw or {})
    errors: list[dict[str, str]] = []
    known = {f.name for f in spec.outcome_fields}
    for unknown in sorted(set(raw) - known):
        errors.append({"field": unknown, "problem": "unexpected field"})
    result = ValidatedOutcome()
    schemes = list(allowed_vault_schemes)

    for spec_field in spec.outcome_fields:
        value = raw.get(spec_field.name)
        if isinstance(value, str):
            value = value.strip()
        missing = value is None or value == "" or value is False and spec_field.kind != "confirm"
        if spec_field.kind == "confirm":
            if value not in _TRUE:
                errors.append({"field": spec_field.name, "problem": "must be explicitly confirmed (true)"})
            else:
                result.stored[spec_field.name] = True
            continue
        if missing:
            if spec_field.required:
                errors.append({"field": spec_field.name, "problem": "required"})
            continue
        if not isinstance(value, str):
            errors.append({"field": spec_field.name, "problem": "must be a string"})
            continue
        try:
            if spec_field.kind == "choice":
                if value not in spec_field.choices:
                    raise ValidationFailed(f"must be one of: {', '.join(spec_field.choices)}")
                result.stored[spec_field.name] = value
            elif spec_field.kind == "handle":
                handle = normalize_handle(value)
                problems = handle_problems(handle)
                if problems:
                    raise ValidationFailed("; ".join(problems))
                result.stored[spec_field.name] = handle
            elif spec_field.kind == "vault_ref":
                result.stored[spec_field.name] = validate_vault_ref(value, schemes, field=spec_field.name)
            elif spec_field.kind == "reference":
                if not _REFERENCE_RE.match(value) or find_secret_material(value):
                    raise ValidationFailed("must be a short reference (letters, digits, . _ : / # @ + -), not a secret")
                result.stored[spec_field.name] = value
            elif spec_field.kind == "text":
                if len(value) > 500 or find_secret_material(value):
                    raise ValidationFailed("must be at most 500 characters and contain no secret material")
                result.stored[spec_field.name] = value
            elif spec_field.kind == "email":
                if not _EMAIL_RE.match(value):
                    raise ValidationFailed("must be an email address")
                result.derived["email_hint"] = mask_email(value)
                result.derived["email_domain"] = value.rsplit("@", 1)[1].lower()
            elif spec_field.kind == "phone":
                compact = re.sub(r"[\s().\-]", "", value)
                if not _E164_RE.match(compact):
                    raise ValidationFailed("must be an E.164 number such as +447700900123")
                result.derived["phone_hint"] = mask_phone(compact)
        except ValidationFailed as exc:
            errors.append({"field": spec_field.name, "problem": exc.message})
    if errors:
        raise ValidationFailed("Task outcome is invalid", details=errors)
    return result
