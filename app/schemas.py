"""Request schemas. ``extra='forbid'`` everywhere: unknown fields (for example a
stray ``password``) are rejected rather than silently accepted, and validation
errors never echo submitted values (see the handler in ``app.main``)."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from app.enums import (
    CredentialKind,
    OperatorRole,
    Platform,
    Responsibility,
    RoleName,
    TaskPriority,
)
from app.security.secret_handling import pydantic_secret_guard
from app.services.proxy_manager import ROTATION_REASONS

SafeText = Annotated[str, AfterValidator(pydantic_secret_guard)]
Identifier = Annotated[str, Field(min_length=3, max_length=40, pattern=r"^[a-z]{3}_[0-9a-f]{32}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProfileSpec(StrictModel):
    profile_name: Annotated[SafeText, Field(min_length=1, max_length=64)] | None = None
    bio: Annotated[SafeText, Field(max_length=150, description="Instagram bio, maximum 150 characters")] | None = None
    profile_link: Annotated[str, Field(max_length=2048)] | None = None
    category: Annotated[SafeText, Field(min_length=1, max_length=60)] | None = None
    profile_image_ref: Annotated[str, Field(min_length=3, max_length=240, pattern=r"^[A-Za-z0-9._~:/#\-]+$")] | None = None

    @field_validator("profile_link")
    @classmethod
    def _https_only(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("profile_link must be an absolute https URL")
        if parts.username or parts.password:
            raise ValueError("profile_link must not contain credentials")
        return value


class AccountCreate(StrictModel):
    brand_name: Annotated[SafeText, Field(min_length=2, max_length=80)]
    owner_id: Identifier
    handle_keywords: Annotated[list[Annotated[str, Field(pattern=r"^[A-Za-z0-9]{1,20}$")]], Field(max_length=5)] = []
    profile: ProfileSpec | None = None
    is_synthetic: bool = False


class PersonCreate(StrictModel):
    full_name: Annotated[SafeText, Field(min_length=2, max_length=120)]
    email: Annotated[str, Field(max_length=254, pattern=r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")]
    supervisor_id: Identifier | None = None
    responsibilities: list[Responsibility] = []
    is_synthetic: bool = False


class CredentialCreate(StrictModel):
    role: OperatorRole
    label: Annotated[SafeText, Field(min_length=2, max_length=80)]


class CredentialAccessCreate(StrictModel):
    vault_ref: Annotated[str, Field(min_length=6, max_length=240)]
    credential_kind: CredentialKind
    account_id: Identifier | None = None


class AssignmentCreate(StrictModel):
    person_id: Identifier
    platform: Platform = Platform.META_BUSINESS
    role: RoleName


class ReasonRequest(StrictModel):
    reason: Annotated[SafeText, Field(min_length=3, max_length=500)]


class BlockerRequest(StrictModel):
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_:]{2,79}$")]
    detail: Annotated[SafeText, Field(min_length=3, max_length=1000)]


class StepEvidenceRequest(StrictModel):
    evidence_ref: Annotated[str, Field(min_length=3, max_length=300)]


class TaskCreate(StrictModel):
    title: Annotated[SafeText, Field(min_length=3, max_length=200)]
    description: Annotated[SafeText, Field(min_length=3, max_length=4000)]
    owner_id: Identifier
    due_at: AwareDatetime
    priority: TaskPriority = TaskPriority.NORMAL
    account_id: Identifier | None = None
    idempotency_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9:_\-.]{8,120}$")]


class TaskAssign(StrictModel):
    owner_id: Identifier
    supervisor_id: Identifier | None = None


class TaskComplete(StrictModel):
    outcome: dict[str, str | bool] = {}
    evidence_ref: Annotated[str, Field(min_length=1, max_length=300)]
    note: Annotated[str, Field(max_length=2000)] | None = None


class TaskFail(StrictModel):
    reason: Annotated[str, Field(min_length=3, max_length=1000)]
    outcome_uncertain: bool = False


class TaskReason(StrictModel):
    reason: Annotated[str, Field(min_length=3, max_length=1000)]


class TaskUnblock(StrictModel):
    note: Annotated[str, Field(max_length=1000)] | None = None


class OffboardingStart(StrictModel):
    person_id: Identifier
    reason: Annotated[SafeText, Field(min_length=3, max_length=300)]
    replacement_admin_id: Identifier | None = None


class ProxyCheck(StrictModel):
    url: Annotated[str, Field(max_length=2048)] | None = None


class ProxySessionCreate(StrictModel):
    account_id: Identifier | None = None
    purpose: Annotated[str, Field(pattern=r"^[a-z0-9_\-]{3,80}$")]


class ProxyRotate(StrictModel):
    reason: Literal[ROTATION_REASONS]  # type: ignore[valid-type]
    url: Annotated[str, Field(max_length=2048)] | None = None


class ProxyEnd(StrictModel):
    reason: Annotated[SafeText, Field(min_length=3, max_length=200)]
