"""Injectable clock so reminder, escalation and audit timing is testable."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return utcnow()


class FrozenClock:
    """Deterministic clock for tests and the synthetic demo. Only moves when told to."""

    def __init__(self, start: datetime):
        if start.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime")
        self._now = start.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta: float) -> datetime:
        self._now = self._now + timedelta(**delta)
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime")
        self._now = value.astimezone(timezone.utc)
