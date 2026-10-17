"""Run one reminder/overdue/escalation cycle and dispatch the outbox (cron-friendly).

Safe to run as often as you like: reminders are throttled by persisted state and
every notification has a dedupe key.

    python -m scripts.run_reminders
"""

from __future__ import annotations

import json

from scripts._common import cli_container


def main() -> None:
    container = cli_container("reminders")
    with container.uow() as session:
        result = container.reminders.run_cycle(session).as_dict()
    dispatch = container.notifications.dispatch_pending(container.session_factory)
    result["dispatch"] = {
        "sent": dispatch.sent,
        "not_delivered_no_provider": dispatch.not_delivered_no_provider,
        "retry_scheduled": dispatch.retry_scheduled,
        "failed": dispatch.failed,
        "uncertain": dispatch.uncertain,
        "superseded": dispatch.superseded,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
