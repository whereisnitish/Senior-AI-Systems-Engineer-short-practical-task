"""Throttle on failed authentication attempts (bearer tokens and dashboard sign-in).

Operator tokens carry 256 bits of randomness, so guessing is already infeasible; this
throttle bounds the noise and makes repeated failures visible in the run log. It is a
fixed window per client address, kept in memory (one process, like the scheduler). While
a client is over the limit every attempt is refused before any token is checked; a
successful sign-in clears the client's count.
"""

from __future__ import annotations

import logging
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.clock import Clock
from app.errors import TooManyAttempts
from app.logging_setup import log_event

logger = logging.getLogger("app.auth")
_MAX_TRACKED_CLIENTS = 10_000


@dataclass
class _Window:
    ends_at: datetime
    failures: int = 0


class FailedAuthThrottle:
    def __init__(self, *, max_failures: int, window_seconds: int, clock: Clock):
        self.max_failures = max_failures
        self.window = timedelta(seconds=window_seconds)
        self.clock = clock
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> None:
        now = self.clock.now()
        with self._lock:
            window = self._windows.get(client)
            if window is None or now >= window.ends_at or window.failures < self.max_failures:
                return
            retry_after = max(1, math.ceil((window.ends_at - now).total_seconds()))
        log_event(logger, "auth.throttled", level=logging.WARNING, action="authenticate", outcome="throttled", client=client)
        raise TooManyAttempts(f"Too many failed sign-in attempts. Try again in {retry_after} seconds.", retry_after=retry_after)

    def record_failure(self, client: str) -> None:
        now = self.clock.now()
        with self._lock:
            window = self._windows.get(client)
            if window is None or now >= window.ends_at:
                window = self._windows[client] = _Window(ends_at=now + self.window)
            window.failures += 1
            failures = window.failures
            if len(self._windows) > _MAX_TRACKED_CLIENTS:
                self._windows = {k: w for k, w in self._windows.items() if w.ends_at > now}
        log_event(
            logger, "auth.failed_attempt", level=logging.WARNING, action="authenticate", outcome="rejected",
            client=client, failures_in_window=failures,
        )

    def record_success(self, client: str) -> None:
        with self._lock:
            self._windows.pop(client, None)
