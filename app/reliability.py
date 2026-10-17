"""Bounded retries with exponential backoff and jitter.

Retries are only used for operations that are safe to repeat (reads, health
checks, requests that provably never reached the server). Anything that may have
taken effect externally is reported as *uncertain* and handed to reconciliation
instead of being retried blindly.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")

    def delay_for(self, attempt: int, rng: random.Random) -> float:
        """Delay after failed attempt ``attempt`` (1-based): equal jitter on a capped exponential."""
        capped = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        return capped / 2 + rng.uniform(0, capped / 2)


def call_with_retries(
    fn: Callable[[int], T],
    *,
    policy: RetryPolicy,
    is_retryable: Callable[[Exception], bool],
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
    on_retry: Callable[[int, Exception, float], None] | None = None,
) -> T:
    rng = rng or random.Random()
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn(attempt)
        except Exception as exc:  # noqa: BLE001 - classification is delegated
            if attempt >= policy.max_attempts or not is_retryable(exc):
                raise
            delay = policy.delay_for(attempt, rng)
            if on_retry:
                on_retry(attempt, exc, delay)
            sleep(delay)
    raise RuntimeError("unreachable")  # pragma: no cover
