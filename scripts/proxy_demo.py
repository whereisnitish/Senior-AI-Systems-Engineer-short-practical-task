"""SIMULATED proxy health / bounded retry / controlled failover demonstration.

No company proxies were provided, so this runs the real ProxyManager against LOCAL
stand-ins on 127.0.0.1: a neutral HTTP test endpoint and three authenticated
forward proxies (one is given a wrong credential on purpose). Real sockets, real
timeouts, real retries - but the result is labelled SIMULATED and must not be
presented as a test of company proxies.

    python -m scripts.proxy_demo

Writes reports/proxy_demo/proxy_failover_demo.{json,md}; transitions are also in the
redacted run log (LOG_DIR/run_log.jsonl) under the printed correlation id.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.container import build_container
from app.database import Base
from app.enums import OperatorRole
from app.errors import DomainError
from app.logging_setup import (
    RUN_LOG_FILENAME,
    configure_logging,
    correlation_id_var,
    new_correlation_id,
)
from app.models import Person, new_id
from app.security.authorization import Actor
from app.security.secret_handling import SecretValue
from app.services.proxy_manager import ProxyConfig
from app.simulation.local_network import LocalForwardProxy, NeutralEndpoint


def main() -> None:
    base = get_settings()
    if base.app_env == "production":
        raise SystemExit("proxy_demo is a local simulation and refuses to run in production")
    endpoint = NeutralEndpoint()
    endpoint.start()
    creds = {name: (f"SYNTHETIC-user-{name}", f"SYNTHETIC-pass-{secrets.token_urlsafe(10)}") for name in ("a", "b", "c")}
    proxies = {name: LocalForwardProxy(name, *creds[name]) for name in creds}
    for proxy in proxies.values():
        proxy.start()
    demo_db = Path("data") / "proxy_demo.db"
    for leftover in Path("data").glob("proxy_demo.db*"):
        leftover.unlink()
    settings = Settings(
        _env_file=None,
        app_env="development",
        app_secret_key=base.app_secret_key,
        database_url=f"sqlite:///{demo_db.as_posix()}",
        vault_backend="dev_memory",
        log_dir=base.log_dir,
        reports_dir=base.reports_dir,
        log_to_stdout=False,
        proxy_healthcheck_allowed_urls=endpoint.health_url,
        proxy_healthcheck_default_url=endpoint.health_url,
        proxy_connect_timeout_seconds=1.0,
        proxy_read_timeout_seconds=2.0,
        proxy_max_attempts=3,
        proxy_backoff_base_seconds=0.2,
        proxy_backoff_max_seconds=1.0,
    )
    container = build_container(settings)
    Base.metadata.create_all(container.engine)
    configure_logging(settings.log_dir, level="INFO", to_stdout=False, redactor=container.redactor)
    correlation_id = new_correlation_id("proxy-demo")
    correlation_id_var.set(correlation_id)
    pm, factory = container.proxies, container.session_factory
    scenes: list[dict[str, Any]] = []

    def scene(name: str, expectation: str, result: dict[str, Any]) -> None:
        scenes.append({"scene": name, "expectation": expectation, "result": result})
        outcome = result.get("outcome") or result.get("diagnosis") or ("ok" if result.get("ok") else result.get("classification"))
        print(f"[{len(scenes)}] {name}: {outcome}")
        if result.get("decision"):
            print(f"     decision: {result['decision']}")

    try:
        for name, (user, password) in creds.items():
            stored = password if name != "c" else f"SYNTHETIC-wrong-{secrets.token_urlsafe(6)}"  # c: deliberately wrong
            container.vault.write_fields(f"devvault://proxies/{name}", {"username": SecretValue(user), "password": SecretValue(stored)})
        with container.uow() as s:
            pm.sync_config(
                s,
                [ProxyConfig(f"local-sim-{n}", "http", "127.0.0.1", proxies[n].port, f"devvault://proxies/{n}", i + 1) for i, n in enumerate(creds)],
            )
            reviewer = Person(
                id=new_id("per"), full_name="Morgan Lee (SYNTHETIC security lead)", email="security.synthetic@testco.example",
                responsibilities=["security_owner", "proxy_provider_admin"], is_synthetic=True,
                created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
            )
            s.add(reviewer)
            s.flush()
            actor = Actor(person_id=reviewer.id, role=OperatorRole.ADMIN.value)

        print(f"SIMULATED proxy demo - correlation id {correlation_id}")
        scene("1. Health check all approved proxies", "a and b healthy; c rejects its credential (407) -> quarantined + maintenance task, no retry", pm.check_all(factory))
        with container.uow() as s:
            session, _ = pm.acquire_session(s, account_id=None, purpose="neutral-endpoint-demo", actor=actor)
            sid = session.id
        scene("2. Acquire session (affinity)", "bound to the highest-priority healthy proxy (a)", {"outcome": "bound", "proxy_id": session.proxy_id, "session_id": sid})
        scene("3. Request via session", "proxy a healthy -> connection preserved", pm.request_via_session(factory, sid))
        proxies["a"].stop()
        scene("4. Proxy a goes down", "3 bounded attempts with backoff, then controlled failover to b after b passes a health check", pm.request_via_session(factory, sid))
        restarted = LocalForwardProxy("a", *creds["a"], port=proxies["a"].port)
        try:
            restarted.start()
            proxies["a"] = restarted
            scene("5a. Proxy a recovers", "a passes a fresh health check", pm.check_proxy(factory, "local-sim-a"))
        except OSError as exc:
            scenes.append({"scene": "5a. Proxy a recovers", "expectation": "restart a", "result": {"skipped": f"port reuse failed: {type(exc).__name__}"}})
        scene("5b. Request via session again", "session stays on b - no flapping back once a recovers", pm.request_via_session(factory, sid))
        endpoint.mode = "error"
        scene("6. Endpoint returns 503", "endpoint failure, not proxy failure -> proxy preserved, no failover", pm.request_via_session(factory, sid))
        endpoint.mode = "ratelimit"
        scene("7. Endpoint rate-limits (429)", "back off on the SAME proxy; rotating to escape a rate limit is refused", pm.request_via_session(factory, sid))
        try:
            pm.rotate_session(factory, sid, reason="proxy_degraded")
            refused = {"outcome": "rotated (unexpected)"}
        except DomainError as exc:
            refused = {"outcome": "rotation_refused", "decision": exc.message}
        scene("7b. Attempt rotation during back-off", "refused", refused)
        with container.uow() as s:
            pm.end_session(s, sid, reason="demo: start a fresh session for the challenge scene")
            session2, _ = pm.acquire_session(s, account_id=None, purpose="neutral-endpoint-demo-2", actor=actor)
            sid2 = session2.id
        endpoint.mode = "challenge"
        scene("8. Endpoint presents a security challenge", "session PAUSED + human review task; no retry, no rotation", pm.request_via_session(factory, sid2))
        try:
            pm.request_via_session(factory, sid2)
            paused = {"outcome": "request sent (unexpected)"}
        except DomainError as exc:
            paused = {"outcome": "request_refused_while_paused", "decision": exc.message}
        scene("8b. Further traffic while paused", "refused until a human reviews", paused)

        log_lines = [
            json.loads(line)
            for line in (settings.log_dir / RUN_LOG_FILENAME).read_text(encoding="utf-8").splitlines()
            if correlation_id in line
        ]
        all_text = json.dumps(scenes) + json.dumps(log_lines)
        leaked = [n for n, (user, password) in creds.items() if user in all_text or password in all_text]
        transitions = [
            {k: line.get(k) for k in ("ts", "event", "outcome", "proxy_id", "from_proxy", "to_proxy", "reason", "retry_count", "decision")}
            for line in log_lines
            if line.get("event") in ("proxy.failover", "proxy.session_paused", "proxy.session_decision", "proxy.probe")
        ]
        report = {
            "report_meta": {
                "title": "Proxy health and controlled failover demonstration",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "data_classification": "SIMULATED_LOCAL_NETWORK",
                "notes": [
                    "Proxies and the neutral endpoint are local stand-ins on 127.0.0.1 (app/simulation/local_network.py).",
                    "No company-approved proxy was available; this is not a test of real proxies.",
                    "Credentials were synthetic, generated for this run, resolved from the dev-only vault and never logged.",
                ],
                "correlation_id": correlation_id,
                "credential_leak_check": "passed" if not leaked else f"FAILED for {leaked}",
            },
            "scenes": scenes,
            "redacted_transition_log": transitions,
        }
        out = settings.reports_dir / "proxy_demo"
        out.mkdir(parents=True, exist_ok=True)
        (out / "proxy_failover_demo.json").write_text(json.dumps(container.redactor.redact(report), indent=2), encoding="utf-8")
        md = [
            "# Proxy health and controlled failover - SIMULATED",
            "",
            f"Generated {report['report_meta']['generated_at']} | correlation id `{correlation_id}` | credential leak check: **{report['report_meta']['credential_leak_check']}**",
            "",
            *[f"> {n}" for n in report["report_meta"]["notes"]],
            "",
            "| # | Scene | Expected | Outcome | Decision / attempts |",
            "|---|---|---|---|---|",
        ]
        for i, item in enumerate(scenes, 1):
            r = item["result"]
            attempts = (r.get("probe") or {}).get("attempts") or r.get("attempts") or []
            detail = r.get("decision") or ""
            if attempts:
                detail += " | attempts: " + ", ".join(f"{a['kind']}({a['latency_ms']}ms)" for a in attempts)
            if r.get("results"):
                detail += " | " + ", ".join(f"{x['proxy_id']}: {x['classification']}/{x['health_after']}" for x in r["results"])
            outcome = r.get("outcome") or r.get("diagnosis") or r.get("classification") or r.get("skipped")
            md.append(f"| {i} | {item['scene']} | {item['expectation']} | {outcome} | {detail.replace('|', '/')} |")
        md += ["", "## Redacted transition log (excerpt)", "", "```json", *[json.dumps(t) for t in transitions if t["event"] != "proxy.probe"], "```", ""]
        (out / "proxy_failover_demo.md").write_text(container.redactor.redact_text("\n".join(md)), encoding="utf-8")
        print(f"credential leak check: {report['report_meta']['credential_leak_check']}")
        print(f"report: {out / 'proxy_failover_demo.md'}")
    finally:
        endpoint.stop()
        for proxy in proxies.values():
            if proxy.running:
                proxy.stop()
        container.engine.dispose()


if __name__ == "__main__":
    main()
