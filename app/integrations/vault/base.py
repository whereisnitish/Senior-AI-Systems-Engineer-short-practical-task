"""Vault abstraction: secrets are addressed by reference and returned wrapped.

Implementations must never put secret values into exception messages, and must
register every resolved value with the redactor.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.enums import VerificationLabel
from app.security.secret_handling import SecretValue


class VaultError(Exception):
    """Base class. Messages contain references and status codes only."""


class VaultUnavailable(VaultError):
    def __init__(self, message: str, *, outcome_uncertain: bool = False):
        super().__init__(message)
        self.outcome_uncertain = outcome_uncertain


class VaultSecretNotFound(VaultError):
    pass


class VaultPermissionDenied(VaultError):
    pass


class VaultConflict(VaultError):
    pass


class VaultOperationUnsupported(VaultError):
    pass


@dataclass(frozen=True)
class VaultMetadata:
    ref: str
    exists: bool
    version: int | None = None
    updated_at: datetime | None = None


class VaultAdapter(ABC):
    name: str = "abstract"
    production_grade: bool = False
    description: str = ""
    capabilities: frozenset[str] = frozenset()

    def handles(self, ref: str) -> bool:
        return True

    @abstractmethod
    def read_fields(self, ref: str) -> dict[str, SecretValue]: ...

    def read(self, ref: str) -> SecretValue:
        field = ref.partition("#")[2] or "value"
        fields = self.read_fields(ref)
        if field not in fields:
            raise VaultSecretNotFound(f"field '{field}' not present at {ref.partition('#')[0]}")
        return fields[field]

    @abstractmethod
    def write_fields(self, ref: str, fields: dict[str, SecretValue], *, cas: int | None = None) -> VaultMetadata: ...

    @abstractmethod
    def metadata(self, ref: str) -> VaultMetadata: ...

    @abstractmethod
    def health(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class RefInspection:
    """Result of asking the vault whether a reference exists (metadata only, never the value)."""

    exists: bool | None  # None = could not be determined
    label: VerificationLabel | None  # None = vault gives no machine evidence (reference-only mode)
    version: int | None
    detail: str

    @property
    def evidence_ref(self) -> str | None:
        if self.exists and self.version is not None:
            return f"vault-metadata:v{self.version}"
        return None


def inspect_ref(vault: VaultAdapter, ref: str) -> RefInspection:
    """Never raises: every outcome maps to exists/label so callers can label facts honestly."""
    if "metadata" not in vault.capabilities:
        return RefInspection(None, None, None, f"{vault.name}: presence cannot be machine-verified")
    if not vault.handles(ref):
        # A reference into a different vault product than the configured adapter: record it, but
        # it can only be human-confirmed.
        return RefInspection(None, None, None, f"{vault.name} cannot inspect this reference scheme; presence is human-confirmed")
    try:
        meta = vault.metadata(ref.partition("#")[0])
    except VaultUnavailable as exc:
        return RefInspection(None, VerificationLabel.UNVERIFIED, None, f"vault unavailable: {exc}")
    except VaultPermissionDenied:
        return RefInspection(None, VerificationLabel.UNVERIFIED, None, "vault denied metadata access")
    except VaultOperationUnsupported:
        return RefInspection(None, None, None, f"{vault.name}: presence cannot be machine-verified")
    except VaultError as exc:
        return RefInspection(None, VerificationLabel.UNVERIFIED, None, f"vault error: {exc}")
    if meta.exists:
        return RefInspection(True, VerificationLabel.INTEGRATION_VERIFIED, meta.version, "vault entry exists")
    return RefInspection(False, VerificationLabel.INTEGRATION_VERIFIED, None, "vault entry not found (or its current version is deleted)")
