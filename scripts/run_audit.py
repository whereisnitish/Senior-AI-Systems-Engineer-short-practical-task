"""Run the security audit from the command line (cron-friendly).

    python -m scripts.run_audit            # manual run (findings are deduplicated)
    python -m scripts.run_audit --weekly   # idempotent weekly run keyed by ISO week
"""

from __future__ import annotations

import argparse
import json

from app.enums import AuditTrigger
from app.security.authorization import SYSTEM_ACTOR
from scripts._common import cli_container


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--weekly", action="store_true", help="use the ISO-week idempotency key (safe to run repeatedly)")
    args = parser.parse_args()
    container = cli_container("audit")
    audits = container.audits
    key = audits.weekly_key(container.clock.now()) if args.weekly else None
    trigger = AuditTrigger.SCHEDULED if args.weekly else AuditTrigger.CLI
    run = audits.run(container.session_factory, trigger=trigger, actor=SYSTEM_ACTOR, idempotency_key=key)
    print(json.dumps(
        {
            "audit_run_id": run.id,
            "status": run.status.value,
            "idempotency_key": run.idempotency_key,
            "totals": (run.summary or {}).get("totals"),
            "report_json": run.report_json_path,
            "report_md": run.report_md_path,
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()
