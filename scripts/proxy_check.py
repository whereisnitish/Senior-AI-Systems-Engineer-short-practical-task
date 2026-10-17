"""Live proxy check: real ProxyManager, configured proxies, approved neutral endpoint only.

Health-checks every approved proxy, binds (or reuses) a sticky session for the live
account, and sends one neutral request through it, applying the rotate-vs-preserve
policy. Writes a timestamped report to REPORTS_DIR/proxy/.

    python -m scripts.proxy_check                  # check + request via the sticky session
    python -m scripts.proxy_check --new-session    # end the current session first
    python -m scripts.proxy_check --rotate scheduled_maintenance   # planned, verified rotation

Demo: run it, stop proxy A (Ctrl+C in its terminal), run it again -> bounded retries,
then controlled failover to B. Start A again and run it again -> the session stays on B.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from sqlalchemy import select

from app.enums import ProxySessionStatus
from app.errors import DomainError
from app.models import InstagramAccount, ProxySession
from app.security.authorization import SYSTEM_ACTOR
from scripts._common import cli_container

PURPOSE = "neutral-endpoint-check"


def _source_note(path) -> str:
    try:
        return json.loads(open(path, encoding="utf-8").read()).get("source", "")
    except (OSError, ValueError):
        return ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--new-session", action="store_true", help="end the current sticky session before checking")
    parser.add_argument("--rotate", choices=["scheduled_maintenance", "proxy_degraded", "credential_rotation", "provider_request"])
    args = parser.parse_args()
    container = cli_container("proxy-check")
    settings, pm, factory = container.settings, container.proxies, container.session_factory
    if not settings.proxy_config_file:
        raise SystemExit("PROXY_CONFIG_FILE is not set; see README section 15")
    with container.uow() as s:
        synced = [p.id for p in pm.sync_config(s)]
        accounts = list(s.scalars(select(InstagramAccount).where(InstagramAccount.is_synthetic.is_(False))))
        account_id = accounts[0].id if len(accounts) == 1 else None
        if args.new_session:
            for live in s.scalars(select(ProxySession).where(ProxySession.purpose == PURPOSE, ProxySession.status != ProxySessionStatus.ENDED)):
                pm.end_session(s, live.id, reason="operator requested a new session (--new-session)")

    print(f"Approved proxies: {', '.join(synced)} | neutral endpoint: {settings.proxy_healthcheck_default_url}")
    steps: list[dict[str, Any]] = []
    # 1) The workflow's own request through its sticky session (retries / failover happen here).
    try:
        with container.uow() as s:
            session, created = pm.acquire_session(s, account_id=account_id, purpose=PURPOSE, actor=SYSTEM_ACTOR)
            session_id, bound = session.id, session.proxy_id
        print(f"Session {session_id} ({'new' if created else 'existing, affinity kept'}) bound to {bound}")
        if args.rotate:
            result = pm.rotate_session(factory, session_id, reason=args.rotate)
            print(f"  rotation: {result['from_proxy']} -> {result['to_proxy']} ({args.rotate})")
            steps.append({"step": "controlled_rotation", "result": result})
        decision = pm.request_via_session(factory, session_id)
        attempts = ", ".join(f"{a['kind']}({a['latency_ms']}ms)" for a in (decision.get("probe") or {}).get("attempts", []))
        print(f"  request via session: {decision['outcome']} on {decision['proxy_id']} [{attempts}]")
        print(f"  decision: {decision['decision']}")
        steps.append({"step": "request_via_session", "result": decision})
    except DomainError as exc:
        print(f"  refused: {exc.message}")
        steps.append({"step": "refused", "result": {"code": exc.code, "message": exc.message}})

    # 2) Health of every approved proxy (what the scheduler runs every few minutes).
    health = pm.check_all(factory)
    for row in health["results"]:
        attempts = ", ".join(f"{a['kind']}({a['latency_ms']}ms)" for a in row["attempts"])
        print(f"  health {row['proxy_id']}: {row['classification']} -> {row['health_after']} [{attempts}]")
    print(f"  diagnosis: {health['diagnosis']}")
    steps.append({"step": "health_check_all", "result": health})

    with container.uow() as s:
        meta = container.reports.report_meta(s, "Live proxy check")
    meta["proxy_source"] = _source_note(settings.proxy_config_file)
    meta["neutral_endpoint"] = settings.proxy_healthcheck_default_url
    stamp = container.clock.now().strftime("%Y%m%dT%H%M%SZ")
    out = settings.reports_dir / "proxy" / f"proxy_check_{stamp}.json"
    container.reports.write_json_report(out, {"report_meta": meta, "steps": steps})
    print(f"Report: {out}")


if __name__ == "__main__":
    main()
