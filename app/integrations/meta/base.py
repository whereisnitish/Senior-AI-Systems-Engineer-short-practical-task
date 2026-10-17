"""Meta Business integration interface.

Deliberately read-only: the only machine operation is *verifying* that the
Instagram account appears under the designated test business. Linking accounts,
adding people and removing roles stay guided human tasks because those mutations
are security-sensitive and their API support/permissions were not confirmed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal

from app.enums import VerificationLabel


@dataclass(frozen=True)
class MetaLinkCheck:
    status: Literal["linked", "not_linked", "unknown"]
    verification: VerificationLabel
    evidence_ref: str | None
    detail: str


class MetaIntegration(ABC):
    name: str = "abstract"
    configured: bool = False

    @abstractmethod
    def check_instagram_link(self, business_id: str, handle: str) -> MetaLinkCheck: ...

    @abstractmethod
    def health(self) -> dict[str, Any]: ...


class MetaNotConfigured(MetaIntegration):
    name = "disabled"
    configured = False

    def check_instagram_link(self, business_id: str, handle: str) -> MetaLinkCheck:
        return MetaLinkCheck(
            status="unknown",
            verification=VerificationLabel.UNVERIFIED,
            evidence_ref=None,
            detail="Meta integration not configured: business association can only be human-confirmed",
        )

    def health(self) -> dict[str, Any]:
        return {"status": "not_configured", "fallback": "guided human task"}
