"""Integration reads (vault metadata, Meta verification) made outside database transactions.

Inside a unit of work run by ``run_outside_transaction``, ``vault_inspection`` and
``meta_link_check`` answer only from a per-unit cache. A miss raises ``ReadNeeded``, which
propagates through ``session_scope`` (so the transaction rolls back), the read is made
with no transaction open, and the unit is re-run from the start on fresh database state.
Network latency therefore never holds the SQLite write lock, and no decision is taken on
a half-applied transaction. Log events from an aborted pass are discarded, so the run log
never records work that was rolled back.

Outside a runner (seed scripts, tests calling services directly) both functions read
directly, exactly as before.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from contextvars import ContextVar
from typing import Any, TypeVar

from app.integrations.meta.base import MetaIntegration, MetaLinkCheck
from app.integrations.vault.base import RefInspection, VaultAdapter, inspect_ref
from app.logging_setup import hold_events, release_events

T = TypeVar("T")

# A unit needs one pass per distinct read; this bounds a runaway unit (an audit reads a handful).
MAX_READS_PER_UNIT = 25

_cache: ContextVar[dict[Hashable, Any] | None] = ContextVar("integration_read_cache", default=None)


class ReadNeeded(BaseException):
    """Raised inside a unit for an uncached read.

    A BaseException on purpose: it must pass through ``except Exception`` handlers (which
    record per-account failures) up to the runner, like ``KeyboardInterrupt`` would.
    """

    def __init__(self, key: Hashable, fetch: Callable[[], Any]):
        super().__init__(key)
        self.key = key
        self.fetch = fetch


def _cached(key: Hashable, fetch: Callable[[], T]) -> T:
    cache = _cache.get()
    if cache is None:
        return fetch()
    if key not in cache:
        raise ReadNeeded(key, fetch)
    return cache[key]


def vault_inspection(vault: VaultAdapter, ref: str) -> RefInspection:
    return _cached(("vault", id(vault), ref), lambda: inspect_ref(vault, ref))


def meta_link_check(meta: MetaIntegration, business_id: str, handle: str) -> MetaLinkCheck:
    return _cached(("meta", id(meta), business_id, handle.lower()), lambda: meta.check_instagram_link(business_id, handle))


def run_outside_transaction(unit: Callable[[], T]) -> T:
    """Run ``unit`` (which opens and commits its own transaction) with integration reads kept outside it."""
    if _cache.get() is not None:
        return unit()  # nested: the outermost runner owns the cache and re-runs the whole unit
    cache: dict[Hashable, Any] = {}
    token = _cache.set(cache)
    try:
        for _ in range(MAX_READS_PER_UNIT + 1):
            held = hold_events()
            try:
                result = unit()
            except ReadNeeded as need:
                release_events(held, emit=False)  # the pass was rolled back: so are its events
                _cache.set(None)
                try:
                    cache[need.key] = need.fetch()  # no transaction is open here
                finally:
                    _cache.set(cache)
                continue
            except BaseException:
                release_events(held, emit=True)
                raise
            release_events(held, emit=True)
            return result
        raise RuntimeError(f"unit of work needed more than {MAX_READS_PER_UNIT} integration reads")
    finally:
        _cache.reset(token)
