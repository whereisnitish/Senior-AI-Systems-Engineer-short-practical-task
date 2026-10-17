"""Startup recovery after an interruption.

What it does (all idempotent):
* audit runs left ``running`` by a dead process -> ``interrupted`` (safe to re-run;
  findings are deduplicated and the weekly key lets the scheduler resume it);
* notifications left ``sending`` -> ``uncertain`` (never auto-resent: the provider
  may already have accepted them);
* proxy configuration re-synced from the config file;
* working tasks past their deadline -> ``overdue``;
* every non-provisioned account is re-``advance``d, which only creates *missing*
  human tasks with stable keys - it never repeats a human/external action;
* open offboarding cases are reconciled.

What it deliberately does NOT do: treat a pending task as failed, retry signup, or
assume an external action did or did not happen.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from app.enums import (
    AuditRunStatus,
    DeliveryStatus,
    OffboardingCaseStatus,
    TaskStatus,
)
from app.errors import DomainError
from app.logging_setup import log_event
from app.models import (
    AuditRun,
    HumanTask,
    InstagramAccount,
    Notification,
    OffboardingCase,
)
from app.security.authorization import SYSTEM_ACTOR
from app.services.task_manager import ACTIVE_STATUSES, WORKING_STATUSES

if TYPE_CHECKING:
    from app.container import Container

logger = logging.getLogger("app.recovery")


def run_startup_recovery(container: Container) -> dict[str, Any]:
    now = container.clock.now()
    summary: dict[str, Any] = {}
    with container.uow() as session:
        interrupted = session.scalars(select(AuditRun).where(AuditRun.status == AuditRunStatus.RUNNING)).all()
        for run in interrupted:
            run.status = AuditRunStatus.INTERRUPTED
            run.error_detail = "Process stopped before the run finished; safe to re-run (findings are deduplicated)"
        summary["audit_runs_marked_interrupted"] = len(interrupted)

        sending = session.scalars(select(Notification).where(Notification.delivery_status == DeliveryStatus.SENDING)).all()
        for notification in sending:
            notification.delivery_status = DeliveryStatus.UNCERTAIN
            notification.last_error = "Process stopped while sending; delivery outcome unknown - not resent automatically"
        summary["notifications_marked_uncertain"] = len(sending)

        try:
            summary["proxies_synced"] = len(container.proxies.sync_config(session))
        except (DomainError, OSError, ValueError) as exc:
            summary["proxies_synced"] = 0
            summary["proxy_config_error"] = container.redactor.redact_text(str(exc))
            log_event(logger, "recovery.proxy_config_invalid", level=logging.ERROR, action="sync_config", outcome="failed", error=summary["proxy_config_error"])

        overdue = 0
        for task in session.scalars(select(HumanTask).where(HumanTask.status.in_(list(WORKING_STATUSES)), HumanTask.due_at < now)):
            container.tasks.transition(session, task, TaskStatus.OVERDUE, actor=None, event_type="marked_overdue")
            overdue += 1
        summary["tasks_marked_overdue"] = overdue

    # Each account / case in its own transaction: one bad record must never stop the app from starting.
    with container.uow() as session:
        account_ids = list(session.scalars(select(InstagramAccount.id)))
        case_ids = list(session.scalars(select(OffboardingCase.id).where(OffboardingCase.status == OffboardingCaseStatus.OPEN)))
    failures: list[str] = []
    advanced = 0
    for account_id in account_ids:  # provisioned accounts too: a step reset after provisioning needs its task back
        try:
            with container.uow() as session:
                container.provisioning.advance(session, session.get(InstagramAccount, account_id), actor=SYSTEM_ACTOR)
            advanced += 1
        except Exception:  # noqa: BLE001
            failures.append(account_id)
            logger.exception("recovery could not re-evaluate account", extra={"event": "recovery.account_failed", "fields": {"account_id": account_id}})
    reconciled = 0
    for case_id in case_ids:
        try:
            container.run(lambda session, case_id=case_id: container.offboarding.reconcile(
                session, container.offboarding.get_case(session, case_id), actor=SYSTEM_ACTOR
            ))
            reconciled += 1
        except Exception:  # noqa: BLE001
            failures.append(case_id)
            logger.exception("recovery could not reconcile case", extra={"event": "recovery.case_failed", "fields": {"case_id": case_id}})
    summary["accounts_re_evaluated"] = advanced
    summary["offboarding_cases_reconciled"] = reconciled
    summary["recovery_failures"] = failures
    with container.uow() as session:
        open_tasks = Counter(
            t.value for t in session.scalars(select(HumanTask.status).where(HumanTask.status.in_(list(ACTIVE_STATUSES))))
        )
        summary["open_tasks_resumed_by_status"] = dict(open_tasks)

    log_event(logger, "recovery.completed", action="startup_recovery", outcome="completed", **summary)
    return summary
