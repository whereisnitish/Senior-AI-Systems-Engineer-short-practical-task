"""In-process scheduler (APScheduler) for reminders, notification dispatch, proxy
health checks and the weekly audit.

Durability does not depend on the scheduler: every job is idempotent and driven by
persisted state (reminder counters + dedupe keys, the ISO-week audit key), so a
missed or doubled invocation is harmless. An hourly catch-up job runs the weekly
audit if the process was down at the scheduled time. The same jobs are available
as CLI scripts for cron-based deployments (scripts/run_reminders.py,
scripts/run_audit.py).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta, timezone
from typing import TYPE_CHECKING, Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.logging_setup import correlation_id_var, log_event, new_correlation_id
from app.security.authorization import SYSTEM_ACTOR

if TYPE_CHECKING:
    from app.container import Container

logger = logging.getLogger("app.scheduler")


class OpsScheduler:
    def __init__(self, container: Container):
        self.container = container
        self._scheduler = BackgroundScheduler(
            timezone=timezone.utc,
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600},
        )

    def _wrap(self, name: str, fn: Callable[[], Any]) -> Callable[[], None]:
        def runner() -> None:
            token = correlation_id_var.set(new_correlation_id(f"job-{name}"))
            try:
                fn()
            except Exception:  # noqa: BLE001 - a failing job must never kill the scheduler
                logger.exception("scheduled job failed", extra={"event": "scheduler.job_failed", "fields": {"job": name}})
            finally:
                correlation_id_var.reset(token)

        return runner

    def run_reminders(self) -> None:
        c = self.container
        with c.uow() as session:
            c.reminders.run_cycle(session)
        c.notifications.dispatch_pending(c.session_factory)

    def dispatch_notifications(self) -> None:
        self.container.notifications.dispatch_pending(self.container.session_factory)

    def check_proxies(self) -> None:
        if self.container.settings.proxy_healthcheck_default_url:
            self.container.proxies.check_all(self.container.session_factory)

    def weekly_audit(self) -> None:
        self.container.audits.run_weekly_if_due(self.container.session_factory, actor=SYSTEM_ACTOR)

    def start(self) -> None:
        s = self.container.settings
        now = self.container.clock.now()
        self._scheduler.add_job(self._wrap("reminders", self.run_reminders), "interval", minutes=s.reminder_job_minutes, id="reminders", next_run_time=now + timedelta(seconds=20))
        self._scheduler.add_job(self._wrap("notifications", self.dispatch_notifications), "interval", minutes=s.notification_job_minutes, id="notifications")
        if s.proxy_healthcheck_default_url:
            self._scheduler.add_job(self._wrap("proxy_health", self.check_proxies), "interval", minutes=s.proxy_healthcheck_interval_minutes, id="proxy_health")
        self._scheduler.add_job(
            self._wrap("weekly_audit", self.weekly_audit),
            CronTrigger(day_of_week=s.audit_weekly_day, hour=s.audit_weekly_hour_utc, minute=0, timezone=timezone.utc),
            id="weekly_audit",
        )
        self._scheduler.add_job(self._wrap("weekly_audit_catchup", self.weekly_audit), "interval", hours=1, id="weekly_audit_catchup", next_run_time=now + timedelta(seconds=30))
        self._scheduler.start()
        log_event(logger, "scheduler.started", action="start_scheduler", outcome="running", jobs=[j.id for j in self._scheduler.get_jobs()])

    def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def status(self) -> dict[str, Any]:
        return {
            "running": self._scheduler.running,
            "jobs": [
                {"id": j.id, "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None}
                for j in self._scheduler.get_jobs()
            ],
        }
