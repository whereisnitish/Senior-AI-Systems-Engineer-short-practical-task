"""Approved-proxy management: health checks, bounded retries, session affinity and
controlled failover against a neutral, explicitly approved test endpoint.

Rotate vs preserve (the policy implemented here):

* PRESERVE by default. A session keeps its proxy for its whole life
  (``ProxySession``) so the connection identity stays consistent.
* FAIL OVER only for infrastructure failure of the proxy itself: connection
  refused/timeout to the proxy, protocol errors, a rejected proxy credential
  (407). A candidate is health-checked before the session is moved, failovers per
  session are capped, and every move is logged with its reason.
* NEVER rotate because of what the destination says about us: a rate limit (429)
  means back off on the same proxy; a security challenge/checkpoint means PAUSE the
  session and create a human review task. Rotating in those cases would be evasion.
* If the endpoint itself is failing (5xx, or every proxy times out), moving the
  session would not help: keep the proxy and report an endpoint failure.

Credentials are resolved from the vault per check, registered with the redactor
(raw and URL-encoded forms), used only in memory and never logged or stored.
Requests may only target URLs on ``PROXY_HEALTHCHECK_ALLOWED_URLS``; social
platform domains are rejected unconditionally.
"""

from __future__ import annotations

import json
import logging
import random
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote

import certifi
import httpx
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.clock import Clock
from app.config import Settings, is_forbidden_target
from app.database import session_scope
from app.enums import (
    ProxyHealth,
    ProxySessionStatus,
    Responsibility,
    TaskOrigin,
    TaskStatus,
    TaskType,
)
from app.errors import (
    Conflict,
    DestinationNotApproved,
    IntegrationUnavailable,
    NotFound,
    SessionPaused,
    ValidationFailed,
)
from app.integrations.vault.base import VaultAdapter, VaultError
from app.logging_setup import log_event
from app.models import (
    HumanTask,
    InstagramAccount,
    ProxyEndpoint,
    ProxyEvent,
    ProxySession,
    new_id,
)
from app.reliability import RetryPolicy
from app.security.authorization import Actor
from app.security.redaction import Redactor
from app.security.secret_handling import validate_vault_ref
from app.services.reminder_service import find_responsible
from app.services.task_manager import ACTIVE_STATUSES, TaskManager
from app.services.task_types import ValidatedOutcome

logger = logging.getLogger("app.proxy")


class FailureKind(StrEnum):
    NONE = "none"
    PROXY_UNREACHABLE = "proxy_unreachable"
    PROXY_TIMEOUT = "proxy_connect_timeout"
    PROXY_AUTH_FAILED = "proxy_auth_failed"
    PROXY_PROTOCOL_ERROR = "proxy_protocol_error"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    READ_TIMEOUT = "read_timeout"
    UPSTREAM_UNREACHABLE = "upstream_unreachable"
    ENDPOINT_ERROR = "endpoint_error"
    RATE_LIMITED = "rate_limited"
    SECURITY_CHALLENGE = "security_challenge"
    UNEXPECTED_STATUS = "unexpected_status"


PROXY_SIDE = frozenset(
    {
        FailureKind.PROXY_UNREACHABLE,
        FailureKind.PROXY_TIMEOUT,
        FailureKind.PROXY_AUTH_FAILED,
        FailureKind.PROXY_PROTOCOL_ERROR,
        FailureKind.CREDENTIAL_UNAVAILABLE,
    }
)
ENDPOINT_SIDE = frozenset({FailureKind.UPSTREAM_UNREACHABLE, FailureKind.ENDPOINT_ERROR})
AMBIGUOUS = frozenset({FailureKind.READ_TIMEOUT})
RETRYABLE = frozenset(
    {
        FailureKind.PROXY_UNREACHABLE,
        FailureKind.PROXY_TIMEOUT,
        FailureKind.PROXY_PROTOCOL_ERROR,
        FailureKind.READ_TIMEOUT,
        FailureKind.UPSTREAM_UNREACHABLE,
        FailureKind.ENDPOINT_ERROR,
    }
)
STOP_KINDS = frozenset({FailureKind.RATE_LIMITED, FailureKind.SECURITY_CHALLENGE})
ROTATION_REASONS = ("scheduled_maintenance", "proxy_degraded", "credential_rotation", "provider_request")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,58}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


@dataclass(frozen=True)
class ProxyConfig:
    id: str
    scheme: str
    host: str
    port: int
    credential_ref: str | None
    priority: int = 100
    approved: bool = True

    @property
    def display(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class ProbeAttempt:
    attempt: int
    kind: FailureKind
    status_code: int | None
    latency_ms: float
    error: str | None = None
    backoff_seconds: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "kind": self.kind.value,
            "status_code": self.status_code,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "backoff_seconds": round(self.backoff_seconds, 3) if self.backoff_seconds is not None else None,
        }


@dataclass
class ProbeResult:
    proxy_id: str
    url: str
    kind: FailureKind
    attempts: list[ProbeAttempt] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.kind == FailureKind.NONE

    @property
    def classification(self) -> str:
        if self.ok:
            return "ok"
        if self.kind == FailureKind.SECURITY_CHALLENGE:
            return "security_challenge"
        if self.kind == FailureKind.RATE_LIMITED:
            return "rate_limited"
        if self.kind in PROXY_SIDE:
            return "proxy_failure"
        if self.kind in ENDPOINT_SIDE:
            return "endpoint_failure"
        if self.kind in AMBIGUOUS:
            return "ambiguous"
        return "unexpected_response"

    def as_dict(self) -> dict[str, Any]:
        return {
            "proxy_id": self.proxy_id,
            "url": self.url,
            "ok": self.ok,
            "failure_kind": self.kind.value,
            "classification": self.classification,
            "attempt_count": len(self.attempts),
            "attempts": [a.as_dict() for a in self.attempts],
        }


ClientFactory = Callable[[ProxyConfig, str, httpx.Timeout], httpx.Client]


@lru_cache(maxsize=1)
def _tls_context() -> ssl.SSLContext:
    # Built once: loading the CA bundle per attempt costs ~1s on some platforms and would skew latency.
    return ssl.create_default_context(cafile=certifi.where())


def default_client_factory(proxy: ProxyConfig, proxy_url: str, timeout: httpx.Timeout) -> httpx.Client:
    # A fresh client per attempt guarantees a fresh connection (no reuse of a broken socket).
    return httpx.Client(proxy=proxy_url, timeout=timeout, trust_env=False, follow_redirects=False, verify=_tls_context())


def load_proxy_config(path: Path, settings: Settings) -> list[ProxyConfig]:
    """Load and validate approved proxies. Inline credentials are rejected."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("proxies") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValidationFailed("proxy config must be an object with a 'proxies' list")
    allowed_keys = {"id", "scheme", "host", "port", "credential_ref", "priority", "approved", "description"}
    out: list[ProxyConfig] = []
    for index, entry in enumerate(entries):
        where = f"proxies[{index}]"
        if not isinstance(entry, dict):
            raise ValidationFailed(f"{where} must be an object")
        unexpected = set(entry) - allowed_keys
        if unexpected:
            raise ValidationFailed(
                f"{where} has unsupported keys {sorted(unexpected)}; credentials must be stored in the vault and "
                "referenced via credential_ref"
            )
        pid, scheme, host, port = entry.get("id"), entry.get("scheme", "http"), entry.get("host"), entry.get("port")
        if not isinstance(pid, str) or not _ID_RE.match(pid):
            raise ValidationFailed(f"{where}.id must be lowercase letters, digits and dashes")
        if scheme not in ("http", "https"):
            raise ValidationFailed(f"{where}.scheme must be http or https")
        if not isinstance(host, str) or not _HOST_RE.match(host) or "@" in host:
            raise ValidationFailed(f"{where}.host must be a bare hostname or IP (no credentials, scheme or path)")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValidationFailed(f"{where}.port must be an integer between 1 and 65535")
        credential_ref = entry.get("credential_ref")
        if credential_ref is not None:
            validate_vault_ref(credential_ref, settings.allowed_vault_schemes, field=f"{where}.credential_ref")
        out.append(
            ProxyConfig(pid, scheme, host, port, credential_ref, int(entry.get("priority", 100)), bool(entry.get("approved", True)))
        )
    if len({p.id for p in out}) != len(out):
        raise ValidationFailed("proxy ids must be unique")
    return out


def _attribution(result: ProbeResult) -> str:
    """Single-probe attribution: who gets the blame for this result."""
    return {"ok": "ok", "proxy_failure": "proxy", "ambiguous": "proxy", "endpoint_failure": "endpoint"}.get(result.classification, "none")


def _snapshot(proxy: ProxyEndpoint) -> ProxyConfig:
    return ProxyConfig(proxy.id, proxy.scheme, proxy.host, proxy.port, proxy.credential_ref, proxy.priority, proxy.approved)


class ProxyManager:
    def __init__(
        self,
        *,
        settings: Settings,
        clock: Clock,
        vault: VaultAdapter,
        redactor: Redactor,
        tasks: TaskManager,
        client_factory: ClientFactory | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ):
        self.settings = settings
        self.clock = clock
        self.vault = vault
        self.redactor = redactor
        self.tasks = tasks
        self.client_factory = client_factory or default_client_factory
        self.sleep = sleep
        self.rng = rng or random.Random()
        self.policy = RetryPolicy(
            max_attempts=settings.proxy_max_attempts,
            base_delay=settings.proxy_backoff_base_seconds,
            max_delay=settings.proxy_backoff_max_seconds,
        )
        self.timeout = httpx.Timeout(
            connect=settings.proxy_connect_timeout_seconds,
            read=settings.proxy_read_timeout_seconds,
            write=settings.proxy_read_timeout_seconds,
            pool=settings.proxy_connect_timeout_seconds,
        )

    def register(self) -> None:
        self.tasks.register_completion_handler(TaskType.PROXY_SECURITY_REVIEW, self._on_review_completed)
        self.tasks.register_completion_handler(TaskType.PROXY_MAINTENANCE, self._on_maintenance_completed)

    # ------------------------------------------------------------------ configuration
    def sync_config(self, session: Session, configs: list[ProxyConfig] | None = None) -> list[ProxyEndpoint]:
        if configs is None:
            if not self.settings.proxy_config_file:
                return []
            configs = load_proxy_config(self.settings.proxy_config_file, self.settings)
        now = self.clock.now()
        seen = set()
        out = []
        for cfg in configs:
            seen.add(cfg.id)
            proxy = session.get(ProxyEndpoint, cfg.id)
            if proxy is None:
                proxy = ProxyEndpoint(id=cfg.id, created_at=now, health_status=ProxyHealth.UNKNOWN)
                session.add(proxy)
            proxy.scheme, proxy.host, proxy.port = cfg.scheme, cfg.host, cfg.port
            proxy.credential_ref, proxy.priority, proxy.approved = cfg.credential_ref, cfg.priority, cfg.approved
            proxy.updated_at = now
            out.append(proxy)
        for proxy in session.scalars(select(ProxyEndpoint)):
            if proxy.id not in seen and proxy.approved:
                proxy.approved = False  # de-listed from config: never used again
        session.flush()
        log_event(logger, "proxy.config_synced", action="sync_config", outcome="synced", proxy_count=len(out))
        return out

    def approved_url(self, url: str | None) -> str:
        url = url or self.settings.proxy_healthcheck_default_url
        if not url:
            raise ValidationFailed("no health-check URL given and PROXY_HEALTHCHECK_DEFAULT_URL is not configured")
        if is_forbidden_target(url):
            raise DestinationNotApproved("social-platform destinations are never valid proxy test targets")
        if url not in self.settings.proxy_healthcheck_allowed_urls:
            raise DestinationNotApproved("URL is not on PROXY_HEALTHCHECK_ALLOWED_URLS (approved neutral endpoints only)")
        return url

    # ------------------------------------------------------------------ probing (no DB access)
    def _proxy_url(self, cfg: ProxyConfig) -> str:
        if not cfg.credential_ref:
            return cfg.display
        fields = self.vault.read_fields(cfg.credential_ref)
        user, password = fields.get("username"), fields.get("password")
        if user is None or password is None:
            raise VaultError("proxy credential entry must contain 'username' and 'password' fields")
        raw_user, raw_password = user.reveal(), password.reveal()
        quoted_user, quoted_password = quote(raw_user, safe=""), quote(raw_password, safe="")
        for value in (raw_user, raw_password, quoted_user, quoted_password):
            self.redactor.register_secret(value)
        return f"{cfg.scheme}://{quoted_user}:{quoted_password}@{cfg.host}:{cfg.port}"

    @staticmethod
    def _classify_exception(exc: Exception) -> FailureKind:
        if isinstance(exc, httpx.ProxyError):
            return FailureKind.PROXY_AUTH_FAILED if "407" in str(exc) else FailureKind.PROXY_PROTOCOL_ERROR
        if isinstance(exc, httpx.ConnectTimeout):
            return FailureKind.PROXY_TIMEOUT
        if isinstance(exc, httpx.ConnectError):
            return FailureKind.PROXY_UNREACHABLE
        if isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
            return FailureKind.READ_TIMEOUT
        return FailureKind.PROXY_PROTOCOL_ERROR

    def _classify_response(self, response: httpx.Response) -> FailureKind:
        status = response.status_code
        if status == 407:
            return FailureKind.PROXY_AUTH_FAILED
        body = ""
        if status >= 400:
            try:
                body = response.text[:2048].lower()
            except Exception:  # noqa: BLE001
                body = ""
        if response.headers.get(self.settings.proxy_challenge_header) or any(
            marker.lower() in body for marker in self.settings.proxy_challenge_markers
        ):
            return FailureKind.SECURITY_CHALLENGE
        if status == 429:
            return FailureKind.RATE_LIMITED
        if status in (502, 504):
            return FailureKind.UPSTREAM_UNREACHABLE
        if status >= 500:
            return FailureKind.ENDPOINT_ERROR
        if 200 <= status < 300:
            return FailureKind.NONE
        return FailureKind.UNEXPECTED_STATUS

    def probe(self, cfg: ProxyConfig, url: str) -> ProbeResult:
        """Bounded, backed-off health probe of ``url`` through ``cfg``. Never raises for network errors."""
        result = ProbeResult(cfg.id, url, FailureKind.NONE)
        try:
            proxy_url = self._proxy_url(cfg)
        except VaultError as exc:
            result.kind = FailureKind.CREDENTIAL_UNAVAILABLE
            result.attempts.append(
                ProbeAttempt(1, FailureKind.CREDENTIAL_UNAVAILABLE, None, 0.0, self.redactor.redact_text(f"{type(exc).__name__}: {exc}"))
            )
            return result
        for attempt in range(1, self.policy.max_attempts + 1):
            started = time.perf_counter()
            status: int | None = None
            error: str | None = None
            try:
                with self.client_factory(cfg, proxy_url, self.timeout) as client:
                    response = client.get(url, headers={"User-Agent": "instagram-ops-healthcheck/1.0", "Cache-Control": "no-cache"})
                status = response.status_code
                kind = self._classify_response(response)
            except Exception as exc:  # noqa: BLE001 - every failure is classified, none escapes
                kind = self._classify_exception(exc)
                error = self.redactor.redact_text(f"{type(exc).__name__}: {exc}")[:300]
            record = ProbeAttempt(attempt, kind, status, (time.perf_counter() - started) * 1000, error)
            result.attempts.append(record)
            result.kind = kind
            if kind == FailureKind.NONE or kind not in RETRYABLE or attempt == self.policy.max_attempts:
                break
            delay = self.policy.delay_for(attempt, self.rng)
            record.backoff_seconds = delay
            self.sleep(delay)
        log_event(
            logger,
            "proxy.probe",
            level=logging.INFO if result.ok else logging.WARNING,
            action="health_check",
            outcome=result.classification,
            proxy_id=cfg.id,
            proxy_endpoint=cfg.display,
            failure_kind=result.kind.value,
            retry_count=len(result.attempts) - 1,
            attempts=[a.as_dict() for a in result.attempts],
        )
        return result

    # ------------------------------------------------------------------ recording (short transactions)
    def _event(self, session: Session, event_type: str, outcome: str, *, proxy_id: str | None, session_id: str | None, detail: dict[str, Any]) -> None:
        session.add(
            ProxyEvent(
                proxy_id=proxy_id,
                session_id=session_id,
                event_type=event_type,
                outcome=outcome,
                detail=self.redactor.redact(detail),
                created_at=self.clock.now(),
            )
        )

    def record_result(self, session: Session, result: ProbeResult, *, attribution: str, session_id: str | None = None) -> ProxyEndpoint:
        """attribution: ok | proxy | endpoint | none (stop kinds never count against the proxy)."""
        proxy = session.get(ProxyEndpoint, result.proxy_id)
        if proxy is None:
            raise NotFound("proxy not found")
        now = self.clock.now()
        proxy.total_checks += 1
        proxy.last_check_at = now
        proxy.last_latency_ms = result.attempts[-1].latency_ms if result.attempts else None
        if result.ok:
            proxy.health_status = ProxyHealth.HEALTHY
            proxy.consecutive_failures = 0
            proxy.last_success_at = now
            proxy.cooldown_until = None
        elif attribution == "proxy":
            proxy.consecutive_failures += 1
            proxy.total_failures += 1
            proxy.last_failure_at = now
            proxy.last_failure_kind = result.kind.value
            if result.kind == FailureKind.PROXY_AUTH_FAILED:
                proxy.health_status = ProxyHealth.QUARANTINED
                self._ensure_maintenance_task(session, proxy)
            elif proxy.consecutive_failures >= self.settings.proxy_unhealthy_after_failed_checks:
                proxy.health_status = ProxyHealth.UNHEALTHY
                proxy.cooldown_until = now + timedelta(seconds=self.settings.proxy_cooldown_seconds)
        else:
            proxy.last_failure_kind = result.kind.value
        proxy.updated_at = now
        self._event(
            session, "health_check", result.classification, proxy_id=proxy.id, session_id=session_id,
            detail={**result.as_dict(), "attribution": attribution, "health_after": proxy.health_status.value},
        )
        return proxy

    def _ensure_maintenance_task(self, session: Session, proxy: ProxyEndpoint) -> None:
        prefix = f"proxy-maintenance:{proxy.id}:g"
        existing = session.scalars(select(HumanTask).where(HumanTask.idempotency_key.like(prefix + "%"))).all()
        if any(t.status in ACTIVE_STATUSES for t in existing):
            return
        owner = find_responsible(session, Responsibility.PROXY_PROVIDER_ADMIN) or find_responsible(session, Responsibility.SECURITY_OWNER)
        if owner is None:
            log_event(logger, "proxy.maintenance_owner_missing", level=logging.WARNING, action="quarantine", outcome="no_owner", proxy_id=proxy.id)
            return
        self.tasks.create_task(
            session,
            task_type=TaskType.PROXY_MAINTENANCE,
            owner_id=owner.id,
            idempotency_key=f"{prefix}{len(existing) + 1}",
            context={"proxy_id": proxy.id, "credential_ref": proxy.credential_ref or "(none)"},
            payload={"proxy_id": proxy.id},
            origin=TaskOrigin.PROXY,
        )

    # ------------------------------------------------------------------ health checks
    def _candidates(self, session: Session, *, exclude: set[str]) -> list[ProxyEndpoint]:
        now = self.clock.now()
        proxies = session.scalars(
            select(ProxyEndpoint).where(
                ProxyEndpoint.approved.is_(True),
                ProxyEndpoint.health_status != ProxyHealth.QUARANTINED,
                or_(ProxyEndpoint.cooldown_until.is_(None), ProxyEndpoint.cooldown_until <= now),
            )
        ).all()
        rank = {ProxyHealth.HEALTHY: 0, ProxyHealth.UNKNOWN: 1, ProxyHealth.UNHEALTHY: 2}
        return sorted(
            (p for p in proxies if p.id not in exclude),
            key=lambda p: (rank.get(p.health_status, 3), p.priority, p.consecutive_failures, p.id),
        )

    def check_proxy(self, factory: sessionmaker[Session], proxy_id: str, url: str | None = None) -> dict[str, Any]:
        url = self.approved_url(url)
        with session_scope(factory) as session:
            proxy = session.get(ProxyEndpoint, proxy_id)
            if proxy is None or not proxy.approved:
                raise NotFound("approved proxy not found")
            cfg = _snapshot(proxy)
        result = self.probe(cfg, url)
        attribution = _attribution(result)
        with session_scope(factory) as session:
            proxy = self.record_result(session, result, attribution=attribution)
            health = proxy.health_status.value
        return {**result.as_dict(), "attribution": attribution, "health_after": health}

    def check_all(self, factory: sessionmaker[Session], url: str | None = None) -> dict[str, Any]:
        """Check every approved proxy; use cross-evidence to tell endpoint failure from proxy failure."""
        url = self.approved_url(url)
        with session_scope(factory) as session:
            configs = [_snapshot(p) for p in session.scalars(select(ProxyEndpoint).where(ProxyEndpoint.approved.is_(True)))]
        results = [self.probe(cfg, url) for cfg in configs]
        any_ok = any(r.ok for r in results)
        rows: list[dict[str, Any]] = []
        with session_scope(factory) as session:
            for result in results:
                if result.ok:
                    attribution = "ok"
                elif result.classification == "proxy_failure":
                    attribution = "proxy"
                elif result.kind == FailureKind.UPSTREAM_UNREACHABLE or result.classification == "ambiguous":
                    # Other proxies reach the endpoint fine -> this proxy's path is at fault.
                    attribution = "proxy" if any_ok else "endpoint"
                elif result.classification == "endpoint_failure":
                    attribution = "endpoint"
                else:
                    attribution = "none"
                proxy = self.record_result(session, result, attribution=attribution)
                rows.append({**result.as_dict(), "attribution": attribution, "health_after": proxy.health_status.value})
        failures = [r for r in results if not r.ok]
        if not results:
            diagnosis = "no_approved_proxies"
        elif any_ok:
            diagnosis = "endpoint_reachable"
        elif all(r.classification in ("endpoint_failure", "ambiguous") for r in failures):
            diagnosis = "endpoint_failure_suspected"
        else:
            diagnosis = "no_healthy_proxy"
        log_event(logger, "proxy.check_all", action="health_check_all", outcome=diagnosis, proxy_count=len(results))
        return {"url": url, "diagnosis": diagnosis, "results": rows}

    # ------------------------------------------------------------------ sessions
    def _live_session(self, session: Session, account_id: str | None, purpose: str) -> ProxySession | None:
        query = select(ProxySession).where(ProxySession.purpose == purpose, ProxySession.status != ProxySessionStatus.ENDED)
        query = query.where(ProxySession.account_id.is_(None) if account_id is None else ProxySession.account_id == account_id)
        return session.scalar(query)

    def acquire_session(
        self, session: Session, *, account_id: str | None, purpose: str, actor: Actor
    ) -> tuple[ProxySession, bool]:
        """Session affinity: the same (account, purpose) always gets its existing live session back."""
        if account_id is not None and session.get(InstagramAccount, account_id) is None:
            raise NotFound("account not found")
        existing = self._live_session(session, account_id, purpose)
        if existing is not None:
            return existing, False
        candidates = self._candidates(session, exclude=set())
        if not candidates:
            raise IntegrationUnavailable("No approved proxy is currently available (all unhealthy, quarantined or unconfigured)")
        now = self.clock.now()
        proxy_session = ProxySession(
            id=new_id("pxs"),
            account_id=account_id,
            purpose=purpose[:80],
            proxy_id=candidates[0].id,
            status=ProxySessionStatus.ACTIVE,
            started_at=now,
        )
        try:
            with session.begin_nested():
                session.add(proxy_session)
                session.flush()
        except IntegrityError:
            existing = self._live_session(session, account_id, purpose)
            assert existing is not None
            return existing, False
        self._event(session, "session_started", "bound", proxy_id=proxy_session.proxy_id, session_id=proxy_session.id, detail={"purpose": purpose})
        log_event(logger, "proxy.session_started", account_id=account_id, action="acquire_session", outcome="bound", proxy_id=proxy_session.proxy_id, session_id=proxy_session.id)
        return proxy_session, True

    def _pause(self, session: Session, proxy_session: ProxySession, reason: str, detail: dict[str, Any]) -> None:
        proxy_session.status = ProxySessionStatus.PAUSED_SECURITY_REVIEW
        proxy_session.pause_reason = reason[:300]
        owner = find_responsible(session, Responsibility.SECURITY_OWNER)
        if owner is None and proxy_session.account_id:
            account = session.get(InstagramAccount, proxy_session.account_id)
            owner = account.owner if account and account.owner.status.value == "active" else None
        owner = owner or find_responsible(session, Responsibility.ESCALATION_DEFAULT)
        if owner is None:
            log_event(
                logger, "proxy.review_owner_missing", level=logging.ERROR, action="pause_session", outcome="no_reviewer",
                session_id=proxy_session.id, error="session paused but nobody holds security_owner/escalation_default",
            )
        if owner is not None:
            prefix = f"proxy-review:{proxy_session.id}:"
            count = len(session.scalars(select(HumanTask.id).where(HumanTask.idempotency_key.like(prefix + "%"))).all())
            task, _ = self.tasks.create_task(
                session,
                task_type=TaskType.PROXY_SECURITY_REVIEW,
                owner_id=owner.id,
                idempotency_key=f"{prefix}{count + 1}",
                account_id=proxy_session.account_id,
                context={"session_id": proxy_session.id, "proxy_id": proxy_session.proxy_id},
                payload={"proxy_session_id": proxy_session.id, "reason": reason},
                origin=TaskOrigin.PROXY,
                initial_status=TaskStatus.WAITING_FOR_HUMAN,
            )
            proxy_session.review_task_id = task.id
        self._event(session, "session_paused", "paused_security_review", proxy_id=proxy_session.proxy_id, session_id=proxy_session.id, detail={"reason": reason, **detail})
        log_event(
            logger, "proxy.session_paused", level=logging.WARNING, account_id=proxy_session.account_id,
            task_id=proxy_session.review_task_id, action="pause_session", outcome="paused_security_review",
            session_id=proxy_session.id, reason=reason,
        )

    def _load_session(self, session: Session, session_id: str) -> ProxySession:
        proxy_session = session.get(ProxySession, session_id)
        if proxy_session is None:
            raise NotFound("proxy session not found")
        if proxy_session.status == ProxySessionStatus.ENDED:
            raise Conflict("proxy session has ended")
        return proxy_session

    def request_via_session(self, factory: sessionmaker[Session], session_id: str, *, url: str | None = None) -> dict[str, Any]:
        """Send one neutral test request through the session's proxy, applying the rotate/preserve policy."""
        url = self.approved_url(url)
        now = self.clock.now()
        with session_scope(factory) as session:
            proxy_session = self._load_session(session, session_id)
            if proxy_session.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW:
                raise SessionPaused(
                    f"Session is paused pending human review ({proxy_session.pause_reason}); no traffic is sent until reviewed"
                )
            if proxy_session.rate_limited_until and proxy_session.rate_limited_until > now:
                return {
                    "session_id": session_id, "proxy_id": proxy_session.proxy_id, "outcome": "rate_limit_backoff",
                    "decision": "Still inside the rate-limit back-off window: no request sent, proxy unchanged.",
                }
            proxy = session.get(ProxyEndpoint, proxy_session.proxy_id)
            assert proxy is not None
            cfg, health = _snapshot(proxy), proxy.health_status
        if health in (ProxyHealth.UNHEALTHY, ProxyHealth.QUARANTINED) or not cfg.approved:
            return self._failover(factory, session_id, cfg, url, f"session proxy already {health.value}", None)

        result = self.probe(cfg, url)
        if result.ok:
            with session_scope(factory) as session:
                self.record_result(session, result, attribution="ok", session_id=session_id)
                proxy_session = session.get(ProxySession, session_id)
                proxy_session.last_used_at = self.clock.now()
            return self._decision(session_id, cfg.id, "ok", "Proxy healthy: connection preserved (session affinity).", result)
        if result.kind == FailureKind.SECURITY_CHALLENGE:
            with session_scope(factory) as session:
                self.record_result(session, result, attribution="none", session_id=session_id)
                proxy_session = session.get(ProxySession, session_id)
                self._pause(session, proxy_session, "security challenge returned by the test endpoint", result.as_dict())
                task_id = proxy_session.review_task_id
            out = self._decision(
                session_id, cfg.id, "paused_security_review",
                "Security challenge: session PAUSED for human review. No retry and no proxy rotation - rotating to get "
                "past a challenge would be evasion.", result,
            )
            out["review_task_id"] = task_id
            return out
        if result.kind == FailureKind.RATE_LIMITED:
            with session_scope(factory) as session:
                self.record_result(session, result, attribution="none", session_id=session_id)
                proxy_session = session.get(ProxySession, session_id)
                proxy_session.rate_limited_until = self.clock.now() + timedelta(seconds=self.settings.proxy_cooldown_seconds)
                self._event(session, "rate_limited", "backoff", proxy_id=cfg.id, session_id=session_id, detail={"until": proxy_session.rate_limited_until.isoformat()})
            return self._decision(
                session_id, cfg.id, "rate_limited",
                "Rate limited: backing off on the SAME proxy. Rotating proxies to escape a rate limit is not allowed.",
                result,
            )
        if result.classification == "endpoint_failure":
            with session_scope(factory) as session:
                self.record_result(session, result, attribution="endpoint", session_id=session_id)
            return self._decision(
                session_id, cfg.id, "endpoint_failure",
                "The endpoint is failing (the proxy relayed an error). Proxy preserved: failover would not help.", result,
            )
        if result.classification == "unexpected_response":
            with session_scope(factory) as session:
                self.record_result(session, result, attribution="none", session_id=session_id)
            return self._decision(session_id, cfg.id, "unexpected_response", "Unexpected response; proxy preserved, no retry.", result)
        return self._failover(factory, session_id, cfg, url, f"{result.kind.value} after {len(result.attempts)} attempt(s)", result)

    def _decision(self, session_id: str, proxy_id: str, outcome: str, decision: str, result: ProbeResult | None, **extra: Any) -> dict[str, Any]:
        out = {"session_id": session_id, "proxy_id": proxy_id, "outcome": outcome, "decision": decision}
        if result is not None:
            out["probe"] = result.as_dict()
        out.update(extra)
        log_event(logger, "proxy.session_decision", action="request_via_session", outcome=outcome, session_id=session_id, proxy_id=proxy_id, decision=decision)
        return out

    def _failover(
        self,
        factory: sessionmaker[Session],
        session_id: str,
        failed: ProxyConfig,
        url: str,
        reason: str,
        original: ProbeResult | None,
    ) -> dict[str, Any]:
        with session_scope(factory) as session:
            proxy_session = self._load_session(session, session_id)
            if original is not None and original.classification == "proxy_failure":
                self.record_result(session, original, attribution="proxy", session_id=session_id)
            if proxy_session.failover_count >= self.settings.proxy_max_failovers_per_session:
                self._pause(
                    session, proxy_session,
                    f"failover budget exhausted ({proxy_session.failover_count}); repeated proxy failure needs human review",
                    {"reason": reason},
                )
                return self._decision(
                    session_id, failed.id, "paused_failover_budget_exhausted",
                    "Too many failovers for one session: paused for human review instead of churning connections.",
                    original,
                )
            candidates = [_snapshot(p) for p in self._candidates(session, exclude={failed.id})]
        checked: list[dict[str, Any]] = []
        for candidate in candidates:
            probe = self.probe(candidate, url)
            checked.append(probe.as_dict())
            ambiguous_original = original is not None and original.classification == "ambiguous"
            if probe.ok or (probe.classification == "endpoint_failure" and not ambiguous_original):
                with session_scope(factory) as session:
                    if ambiguous_original:
                        self.record_result(session, original, attribution="proxy", session_id=session_id)
                    self.record_result(session, probe, attribution="ok" if probe.ok else "endpoint", session_id=session_id)
                    proxy_session = session.get(ProxySession, session_id)
                    proxy_session.proxy_id = candidate.id
                    proxy_session.failover_count += 1
                    proxy_session.last_used_at = self.clock.now()
                    self._event(
                        session, "failover", "rebound", proxy_id=candidate.id, session_id=session_id,
                        detail={"from_proxy": failed.id, "to_proxy": candidate.id, "reason": reason, "candidate_verified": probe.ok},
                    )
                log_event(
                    logger, "proxy.failover", level=logging.WARNING, action="controlled_failover", outcome="rebound",
                    session_id=session_id, from_proxy=failed.id, to_proxy=candidate.id, reason=reason,
                    retry_count=(len(original.attempts) - 1) if original else 0,
                )
                note = "" if probe.ok else " (endpoint is also failing; reported separately)"
                return self._decision(
                    session_id, candidate.id, "failover",
                    f"Controlled failover {failed.id} -> {candidate.id}: {reason}. Candidate health-checked before the "
                    f"session moved{note}.", original, candidates_checked=checked,
                )
            if ambiguous_original and probe.classification in ("endpoint_failure", "ambiguous"):
                with session_scope(factory) as session:
                    self.record_result(session, original, attribution="endpoint", session_id=session_id)
                    self.record_result(session, probe, attribution="endpoint", session_id=session_id)
                return self._decision(
                    session_id, failed.id, "endpoint_failure",
                    "Both the session proxy and a healthy candidate time out or error against the endpoint: the "
                    "endpoint is the likely fault. Proxy preserved; no rotation.", original, candidates_checked=checked,
                )
            if probe.kind in STOP_KINDS:
                with session_scope(factory) as session:
                    self.record_result(session, probe, attribution="none", session_id=session_id)
                    proxy_session = session.get(ProxySession, session_id)
                    self._pause(session, proxy_session, f"{probe.kind.value} seen while verifying failover candidate", probe.as_dict())
                return self._decision(
                    session_id, failed.id, "paused_security_review",
                    "Challenge/rate limit seen during failover verification: paused for human review.", original,
                    candidates_checked=checked,
                )
            with session_scope(factory) as session:
                self.record_result(session, probe, attribution="proxy", session_id=session_id)
        with session_scope(factory) as session:
            if original is not None and original.classification == "ambiguous":
                self.record_result(session, original, attribution="proxy", session_id=session_id)
            self._event(session, "failover", "no_healthy_candidate", proxy_id=failed.id, session_id=session_id, detail={"reason": reason})
        return self._decision(
            session_id, failed.id, "no_healthy_proxy",
            "No approved proxy passed a health check; the session was not moved. Human attention required.",
            original, candidates_checked=checked,
        )

    def rotate_session(self, factory: sessionmaker[Session], session_id: str, *, reason: str, url: str | None = None) -> dict[str, Any]:
        """Planned, controlled rotation for an operational reason (never to evade the destination)."""
        if reason not in ROTATION_REASONS:
            raise ValidationFailed(f"rotation reason must be one of {', '.join(ROTATION_REASONS)}")
        url = self.approved_url(url)
        with session_scope(factory) as session:
            proxy_session = self._load_session(session, session_id)
            if proxy_session.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW:
                raise SessionPaused("session is paused for human review; resolve the review before any rotation")
            if proxy_session.rate_limited_until and proxy_session.rate_limited_until > self.clock.now():
                raise Conflict("session is in rate-limit back-off; rotating now would be evasion, so it is refused")
            current = proxy_session.proxy_id
            candidates = [_snapshot(p) for p in self._candidates(session, exclude={current})]
        for candidate in candidates:
            probe = self.probe(candidate, url)
            if probe.kind in STOP_KINDS:
                # The destination pushed back (challenge or rate limit): stop - never rotate past it.
                with session_scope(factory) as session:
                    self.record_result(session, probe, attribution="none", session_id=session_id)
                    if probe.kind == FailureKind.SECURITY_CHALLENGE:
                        self._pause(session, session.get(ProxySession, session_id), "security challenge seen while verifying a rotation candidate", probe.as_dict())
                raise Conflict(f"rotation aborted: candidate returned {probe.kind.value}; the session was not moved")
            with session_scope(factory) as session:
                self.record_result(session, probe, attribution=_attribution(probe), session_id=session_id)
                if probe.ok:
                    proxy_session = session.get(ProxySession, session_id)
                    proxy_session.proxy_id = candidate.id
                    proxy_session.last_used_at = self.clock.now()
                    self._event(session, "rotation", "rebound", proxy_id=candidate.id, session_id=session_id, detail={"from_proxy": current, "to_proxy": candidate.id, "reason": reason})
            if probe.ok:
                log_event(logger, "proxy.rotation", action="controlled_rotation", outcome="rebound", session_id=session_id, from_proxy=current, to_proxy=candidate.id, reason=reason)
                return {"session_id": session_id, "outcome": "rotated", "from_proxy": current, "to_proxy": candidate.id, "reason": reason}
        raise Conflict("no healthy alternative proxy passed a health check; session left unchanged")

    def end_session(self, session: Session, session_id: str, *, reason: str) -> ProxySession:
        proxy_session = self._load_session(session, session_id)
        proxy_session.status = ProxySessionStatus.ENDED
        proxy_session.ended_at = self.clock.now()
        proxy_session.end_reason = reason[:200]
        self._event(session, "session_ended", "ended", proxy_id=proxy_session.proxy_id, session_id=session_id, detail={"reason": reason})
        return proxy_session

    # ------------------------------------------------------------------ task handlers
    def _on_review_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        proxy_session = session.get(ProxySession, (task.payload or {}).get("proxy_session_id", ""))
        if proxy_session is None or proxy_session.status == ProxySessionStatus.ENDED:
            return
        if outcome.get("decision") == "resume_session":
            proxy_session.status = ProxySessionStatus.ACTIVE
            proxy_session.pause_reason = None
            self._event(session, "session_resumed", "active", proxy_id=proxy_session.proxy_id, session_id=proxy_session.id, detail={"review_task_id": task.id})
        else:
            self.end_session(session, proxy_session.id, reason=f"ended after human review {task.id}")

    def _on_maintenance_completed(self, session: Session, task: HumanTask, outcome: ValidatedOutcome, actor: Actor) -> None:
        proxy = session.get(ProxyEndpoint, (task.payload or {}).get("proxy_id", ""))
        if proxy is not None and proxy.health_status == ProxyHealth.QUARANTINED:
            # Back to 'unknown': it must pass a health check before it is preferred again.
            proxy.health_status = ProxyHealth.UNKNOWN
            proxy.consecutive_failures = 0
            proxy.cooldown_until = None
            self._event(session, "maintenance_completed", "unknown", proxy_id=proxy.id, session_id=None, detail={"task_id": task.id})
