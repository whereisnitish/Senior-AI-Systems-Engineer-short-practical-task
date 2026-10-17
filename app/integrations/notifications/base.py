"""Notification delivery interface.

Without a configured provider nothing is claimed as delivered: notifications are
marked ``not_delivered_no_provider`` and surfaced on the dashboard instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class SendResult:
    # sent: provider accepted the message. failed: definitely not sent (safe to retry later).
    # uncertain: the provider may have accepted it; do not resend automatically.
    status: Literal["sent", "failed", "uncertain"]
    detail: str = ""
    retryable: bool = False


class Notifier(ABC):
    name: str = "abstract"
    configured: bool = False

    @abstractmethod
    def send(self, *, to_email: str, subject: str, body: str) -> SendResult: ...


class NoProviderNotifier(Notifier):
    name = "none"
    configured = False

    def send(self, *, to_email: str, subject: str, body: str) -> SendResult:  # pragma: no cover - never called
        raise RuntimeError("no notification provider configured")
