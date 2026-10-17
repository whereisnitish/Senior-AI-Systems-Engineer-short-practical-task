"""Proxy health checks, bounded retries, session affinity and controlled failover.

Unit tests use a deterministic fake transport (httpx.MockTransport). One
integration test uses real sockets against LOCAL simulated proxies and a local
neutral endpoint. No real proxy, platform or third-party endpoint is contacted.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.enums import (
    OperatorRole,
    ProxyHealth,
    ProxySessionStatus,
    TaskStatus,
    TaskType,
)
from app.errors import Conflict, DestinationNotApproved, SessionPaused, ValidationFailed
from app.models import ProxyEndpoint, ProxyEvent, ProxySession
from app.services.proxy_manager import ProxyConfig, load_proxy_config
from tests.conftest import Env, make_settings

URL = "http://neutral.test.invalid/health"
A_PASS = "SYNTHETIC-proxy-a-pass-7Qz"
B_PASS = "SYNTHETIC-proxy-b-pass-9Lm"

Behaviour = Callable[[httpx.Request], httpx.Response]


def ok(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok"})


def status(code: int, headers: dict[str, str] | None = None, body: dict | None = None) -> Behaviour:
    return lambda _req: httpx.Response(code, headers=headers, json=body or {"status": code})


def raises(exc_type: type[Exception], message: str = "simulated") -> Behaviour:
    def handler(req: httpx.Request) -> httpx.Response:
        raise exc_type(message, request=req)

    return handler


def sequence(*behaviours: Behaviour) -> Behaviour:
    items = list(behaviours)

    def handler(req: httpx.Request) -> httpx.Response:
        current = items.pop(0) if len(items) > 1 else items[0]
        return current(req)

    return handler


class FakeNetwork:
    def __init__(self):
        self.behaviour: dict[str, Behaviour] = {}
        self.calls: list[str] = []
        self.proxy_urls: list[str] = []

    def factory(self, cfg: ProxyConfig, proxy_url: str, timeout: httpx.Timeout) -> httpx.Client:
        self.proxy_urls.append(proxy_url)

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(cfg.id)
            return self.behaviour[cfg.id](request)

        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)


class ProxyEnv(Env):
    def __init__(self, tmp_path: Path, **overrides):
        self.net = FakeNetwork()
        self.sleeps: list[float] = []
        super().__init__(
            tmp_path,
            proxy_healthcheck_allowed_urls=URL,
            proxy_healthcheck_default_url=URL,
            **overrides,
        )
        self.container.proxies.client_factory = self.net.factory
        self.container.proxies.sleep = self.sleeps.append
        self.vault_put("devvault://proxies/a", username="SYNTHETIC-user-a", password=A_PASS)
        self.vault_put("devvault://proxies/b", username="SYNTHETIC-user-b", password=B_PASS)
        with self.container.uow() as s:
            self.container.proxies.sync_config(
                s,
                [
                    ProxyConfig("proxy-a", "http", "proxy-a.test.invalid", 3128, "devvault://proxies/a", 1),
                    ProxyConfig("proxy-b", "http", "proxy-b.test.invalid", 3128, "devvault://proxies/b", 2),
                ],
            )
        self.security = self.person("Morgan Lee", responsibilities=("security_owner",))

    def proxy(self, proxy_id: str) -> ProxyEndpoint:
        with self.container.uow() as s:
            return s.get(ProxyEndpoint, proxy_id)

    def session(self, session_id: str) -> ProxySession:
        with self.container.uow() as s:
            return s.get(ProxySession, session_id)

    def acquire(self, purpose: str = "neutral-endpoint-test") -> str:
        with self.container.uow() as s:
            ps, _ = self.container.proxies.acquire_session(s, account_id=None, purpose=purpose, actor=self.actor(self.security, OperatorRole.ADMIN))
            return ps.id

    def probe(self, session_id: str) -> dict:
        return self.container.proxies.request_via_session(self.container.session_factory, session_id)


@pytest.fixture
def penv(tmp_path):
    environment = ProxyEnv(tmp_path)
    yield environment
    environment.container.engine.dispose()


def test_successful_health_check(penv):
    penv.net.behaviour["proxy-a"] = ok
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert result["ok"] and result["attempt_count"] == 1
    proxy = penv.proxy("proxy-a")
    assert proxy.health_status == ProxyHealth.HEALTHY and proxy.last_success_at is not None and proxy.consecutive_failures == 0


def test_connect_timeout_is_retried_a_bounded_number_of_times_with_backoff(penv):
    penv.net.behaviour["proxy-a"] = raises(httpx.ConnectTimeout)
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert not result["ok"] and result["failure_kind"] == "proxy_connect_timeout" and result["classification"] == "proxy_failure"
    assert result["attempt_count"] == 3 and penv.net.calls.count("proxy-a") == 3
    assert len(penv.sleeps) == 2  # between attempts only, never after the last
    base = penv.settings.proxy_backoff_base_seconds
    assert base / 2 <= penv.sleeps[0] <= base and base <= penv.sleeps[1] <= 2 * base  # exponential with equal jitter
    proxy = penv.proxy("proxy-a")
    assert proxy.health_status == ProxyHealth.UNHEALTHY and proxy.cooldown_until is not None and proxy.total_failures == 1


def test_transient_failure_recovers_within_retry_budget(penv):
    penv.net.behaviour["proxy-a"] = sequence(raises(httpx.ConnectError), ok)
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert result["ok"] and result["attempt_count"] == 2
    assert penv.proxy("proxy-a").health_status == ProxyHealth.HEALTHY


def test_read_timeout_is_ambiguous_and_retried(penv):
    penv.net.behaviour["proxy-a"] = raises(httpx.ReadTimeout)
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert result["classification"] == "ambiguous" and result["attempt_count"] == 3


def test_auth_failure_quarantines_without_retry_and_opens_maintenance_task(penv):
    penv.net.behaviour["proxy-a"] = status(407)
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert result["failure_kind"] == "proxy_auth_failed" and result["attempt_count"] == 1
    assert penv.proxy("proxy-a").health_status == ProxyHealth.QUARANTINED
    maintenance = penv.tasks(task_type=TaskType.PROXY_MAINTENANCE)
    assert len(maintenance) == 1 and maintenance[0].owner_id == penv.security
    penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert len(penv.tasks(task_type=TaskType.PROXY_MAINTENANCE)) == 1  # no duplicate maintenance task
    penv.complete(maintenance[0].id, penv.actor(penv.security), {"credential_updated_in_vault": True}, evidence="provider rotated credential (test)")
    assert penv.proxy("proxy-a").health_status == ProxyHealth.UNKNOWN  # must pass a check before preferred again


def test_challenge_and_rate_limit_are_never_retried(penv):
    penv.net.behaviour["proxy-a"] = status(403, {"X-Security-Challenge": "required"})
    assert penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")["attempt_count"] == 1
    penv.net.behaviour["proxy-a"] = status(429)
    rate = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert rate["attempt_count"] == 1 and rate["classification"] == "rate_limited"
    assert penv.proxy("proxy-a").health_status != ProxyHealth.UNHEALTHY


def test_only_approved_neutral_destinations(penv):
    with pytest.raises(DestinationNotApproved):
        penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a", "https://example.org/")
    with pytest.raises(DestinationNotApproved):
        penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a", "https://www.instagram.com/accounts/login/")
    assert penv.net.calls == []


def test_social_platforms_cannot_be_allowlisted(tmp_path):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, proxy_healthcheck_allowed_urls="https://www.instagram.com/")
    with pytest.raises(ValidationError):
        make_settings(tmp_path, proxy_healthcheck_allowed_urls="http://user:pw@neutral.example/health")


def test_session_affinity_returns_the_same_session(penv):
    penv.net.behaviour["proxy-a"] = ok
    first = penv.acquire()
    assert penv.acquire() == first
    assert penv.session(first).proxy_id == "proxy-a"
    assert penv.probe(first)["outcome"] == "ok"
    assert penv.probe(first)["proxy_id"] == "proxy-a"


def test_failover_moves_session_only_after_candidate_verified(penv):
    penv.net.behaviour["proxy-a"] = raises(httpx.ConnectError)
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "failover" and decision["proxy_id"] == "proxy-b"
    assert decision["probe"]["attempt_count"] == 3 and decision["candidates_checked"][0]["ok"]
    session = penv.session(sid)
    assert session.proxy_id == "proxy-b" and session.failover_count == 1
    assert penv.proxy("proxy-a").health_status == ProxyHealth.UNHEALTHY
    # proxy-a recovers, but the session keeps its proxy: no flapping back.
    penv.net.behaviour["proxy-a"] = ok
    assert penv.probe(sid)["proxy_id"] == "proxy-b"
    with penv.container.uow() as s:
        failovers = s.scalars(select(ProxyEvent).where(ProxyEvent.event_type == "failover")).all()
        assert len(failovers) == 1 and failovers[0].detail["from_proxy"] == "proxy-a"


def test_endpoint_failure_preserves_proxy(penv):
    penv.net.behaviour["proxy-a"] = status(503)
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "endpoint_failure" and penv.session(sid).proxy_id == "proxy-a"
    assert penv.proxy("proxy-a").health_status != ProxyHealth.UNHEALTHY
    assert "failover would not help" in decision["decision"]


def test_rate_limit_backs_off_without_rotation(penv):
    penv.net.behaviour["proxy-a"] = status(429)
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "rate_limited" and "not allowed" in decision["decision"]
    assert penv.session(sid).proxy_id == "proxy-a" and "proxy-b" not in penv.net.calls
    assert penv.probe(sid)["outcome"] == "rate_limit_backoff"  # no request during the back-off window
    with pytest.raises(Conflict):
        penv.container.proxies.rotate_session(penv.container.session_factory, sid, reason="proxy_degraded")


def test_security_challenge_pauses_session_for_human_review(penv):
    penv.net.behaviour["proxy-a"] = status(403, body={"error": "checkpoint_required"})
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "paused_security_review" and "proxy-b" not in penv.net.calls
    session = penv.session(sid)
    assert session.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW
    review = penv.tasks(task_type=TaskType.PROXY_SECURITY_REVIEW)[0]
    assert review.status == TaskStatus.WAITING_FOR_HUMAN and review.priority.value == "critical"
    with pytest.raises(SessionPaused):
        penv.probe(sid)
    with pytest.raises(SessionPaused):
        penv.container.proxies.rotate_session(penv.container.session_factory, sid, reason="scheduled_maintenance")
    penv.complete(review.id, penv.actor(penv.security), {"decision": "resume_session", "reviewed": True}, evidence="challenge was a test fixture (test)")
    assert penv.session(sid).status == ProxySessionStatus.ACTIVE


def test_failover_budget_is_bounded(tmp_path):
    penv = ProxyEnv(tmp_path, proxy_max_failovers_per_session=1)
    penv.net.behaviour["proxy-a"] = raises(httpx.ConnectError)
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    assert penv.probe(sid)["outcome"] == "failover"
    penv.net.behaviour["proxy-b"] = raises(httpx.ConnectError)
    decision = penv.probe(sid)
    assert decision["outcome"] == "paused_failover_budget_exhausted"
    assert penv.session(sid).status == ProxySessionStatus.PAUSED_SECURITY_REVIEW
    penv.container.engine.dispose()


def test_no_healthy_proxy_leaves_session_unmoved(penv):
    penv.net.behaviour["proxy-a"] = raises(httpx.ConnectError)
    penv.net.behaviour["proxy-b"] = raises(httpx.ConnectError)
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "no_healthy_proxy" and penv.session(sid).proxy_id == "proxy-a"


def test_ambiguous_timeouts_everywhere_point_to_endpoint(penv):
    penv.net.behaviour["proxy-a"] = raises(httpx.ReadTimeout)
    penv.net.behaviour["proxy-b"] = raises(httpx.ReadTimeout)
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert decision["outcome"] == "endpoint_failure" and penv.session(sid).proxy_id == "proxy-a"
    assert penv.proxy("proxy-a").health_status != ProxyHealth.UNHEALTHY


def test_check_all_distinguishes_endpoint_outage_from_proxy_failure(penv):
    penv.net.behaviour["proxy-a"] = status(502)
    penv.net.behaviour["proxy-b"] = status(502)
    outage = penv.container.proxies.check_all(penv.container.session_factory)
    assert outage["diagnosis"] == "endpoint_failure_suspected"
    assert all(r["attribution"] == "endpoint" for r in outage["results"])
    assert penv.proxy("proxy-a").health_status != ProxyHealth.UNHEALTHY
    penv.net.behaviour["proxy-b"] = ok
    mixed = penv.container.proxies.check_all(penv.container.session_factory)
    assert mixed["diagnosis"] == "endpoint_reachable"
    assert {r["proxy_id"]: r["attribution"] for r in mixed["results"]} == {"proxy-a": "proxy", "proxy-b": "ok"}


def test_controlled_rotation_needs_allowed_reason_and_healthy_candidate(penv):
    penv.net.behaviour["proxy-a"] = ok
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    with pytest.raises(ValidationFailed):
        penv.container.proxies.rotate_session(penv.container.session_factory, sid, reason="avoid_detection")
    rotated = penv.container.proxies.rotate_session(penv.container.session_factory, sid, reason="scheduled_maintenance")
    assert rotated["from_proxy"] == "proxy-a" and rotated["to_proxy"] == "proxy-b"


def test_unavailable_credential_is_classified_without_any_request(penv):
    with penv.container.uow() as s:
        s.get(ProxyEndpoint, "proxy-a").credential_ref = "devvault://proxies/missing"
    result = penv.container.proxies.check_proxy(penv.container.session_factory, "proxy-a")
    assert result["failure_kind"] == "credential_unavailable" and penv.net.calls == []


def test_proxy_credentials_never_reach_logs_events_or_responses(penv):
    penv.net.behaviour["proxy-a"] = lambda req: (_ for _ in ()).throw(
        httpx.ConnectError(f"cannot reach {penv.net.proxy_urls[-1]}", request=req)
    )
    penv.net.behaviour["proxy-b"] = ok
    sid = penv.acquire()
    decision = penv.probe(sid)
    assert A_PASS in penv.net.proxy_urls[0]  # credentials were used in memory...
    blob = json.dumps(decision) + penv.read_logs()
    with penv.container.uow() as s:
        blob += json.dumps([e.detail for e in s.scalars(select(ProxyEvent))])
    for secret in (A_PASS, B_PASS, "SYNTHETIC-user-a"):
        assert secret not in blob  # ...but never written anywhere
    assert "[REDACTED]" in blob


def test_proxy_api_endpoints(penv):
    penv.net.behaviour["proxy-a"] = ok
    penv.net.behaviour["proxy-b"] = ok
    client = penv.client()
    admin = penv.headers(penv.security, OperatorRole.ADMIN)
    viewer = penv.headers(penv.security, OperatorRole.VIEWER)
    assert client.post("/api/v1/proxies/health-check", headers=viewer).status_code == 403
    assert client.post("/api/v1/proxies/health-check", headers=admin).json()["diagnosis"] == "endpoint_reachable"
    created = client.post("/api/v1/proxies/sessions", json={"purpose": "neutral-check"}, headers=admin)
    again = client.post("/api/v1/proxies/sessions", json={"purpose": "neutral-check"}, headers=admin)
    assert created.status_code == 201 and again.status_code == 200
    sid = created.json()["session"]["id"]
    assert client.post(f"/api/v1/proxies/sessions/{sid}/probe", headers=admin).json()["outcome"] == "ok"
    bad = client.post(f"/api/v1/proxies/sessions/{sid}/failover", json={"reason": "evade_rate_limit"}, headers=admin)
    assert bad.status_code == 422
    listing = client.get("/api/v1/proxies", headers=viewer).json()
    assert {p["id"] for p in listing["proxies"]} == {"proxy-a", "proxy-b"}
    assert all("pass" not in json.dumps(p) for p in listing["proxies"])


def test_proxy_config_rejects_inline_credentials(tmp_path):
    settings = make_settings(tmp_path)
    bad = tmp_path / "proxies.json"
    bad.write_text(json.dumps({"proxies": [{"id": "p1", "host": "h.example", "port": 8080, "password": "x"}]}), encoding="utf-8")
    with pytest.raises(ValidationFailed):
        load_proxy_config(bad, settings)
    bad.write_text(json.dumps({"proxies": [{"id": "p1", "host": "user:pw@h.example", "port": 8080}]}), encoding="utf-8")
    with pytest.raises(ValidationFailed):
        load_proxy_config(bad, settings)
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"proxies": [{"id": "p1", "host": "h.example", "port": 8080, "credential_ref": "devvault://proxies/p1"}]}), encoding="utf-8")
    assert load_proxy_config(good, settings)[0].credential_ref == "devvault://proxies/p1"


@pytest.mark.integration
def test_real_socket_failover_with_local_simulated_network(tmp_path):
    """SIMULATED: local neutral endpoint + two local authenticated forward proxies on 127.0.0.1."""
    from app.simulation.local_network import LocalForwardProxy, NeutralEndpoint

    endpoint = NeutralEndpoint()
    endpoint.start()
    proxy_a = LocalForwardProxy("a", "SYNTHETIC-user-a", A_PASS)
    proxy_b = LocalForwardProxy("b", "SYNTHETIC-user-b", B_PASS)
    proxy_a.start()
    proxy_b.start()
    env = Env(
        tmp_path,
        proxy_healthcheck_allowed_urls=endpoint.health_url,
        proxy_healthcheck_default_url=endpoint.health_url,
        proxy_connect_timeout_seconds=1.0,
        proxy_read_timeout_seconds=2.0,
    )
    try:
        env.vault_put("devvault://proxies/a", username="SYNTHETIC-user-a", password=A_PASS)
        env.vault_put("devvault://proxies/b", username="SYNTHETIC-user-b", password=B_PASS)
        with env.container.uow() as s:
            env.container.proxies.sync_config(
                s,
                [
                    ProxyConfig("local-a", "http", "127.0.0.1", proxy_a.port, "devvault://proxies/a", 1),
                    ProxyConfig("local-b", "http", "127.0.0.1", proxy_b.port, "devvault://proxies/b", 2),
                ],
            )
        admin = env.person("Admin", responsibilities=("security_owner",))
        with env.container.uow() as s:
            ps, _ = env.container.proxies.acquire_session(s, account_id=None, purpose="local-sim", actor=env.actor(admin, OperatorRole.ADMIN))
            sid = ps.id
        assert env.container.proxies.request_via_session(env.container.session_factory, sid)["outcome"] == "ok"
        assert proxy_a.requests == 1 and endpoint.hits == 1
        proxy_a.stop()
        decision = env.container.proxies.request_via_session(env.container.session_factory, sid)
        assert decision["outcome"] == "failover" and decision["proxy_id"] == "local-b"
        assert decision["probe"]["failure_kind"] in ("proxy_unreachable", "proxy_connect_timeout")
        endpoint.mode = "challenge"
        assert env.container.proxies.request_via_session(env.container.session_factory, sid)["outcome"] == "paused_security_review"
        assert A_PASS not in env.read_logs() and B_PASS not in env.read_logs()
    finally:
        endpoint.stop()
        proxy_b.stop()
        env.container.engine.dispose()
