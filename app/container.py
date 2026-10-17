"""Explicit dependency wiring. Tests build a container with fakes (clock, vault,
proxy transport, notifier) instead of patching globals."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.clock import Clock, SystemClock
from app.config import Settings
from app.database import create_db_engine, make_session_factory, session_scope
from app.integrations.meta import MetaIntegration, build_meta
from app.integrations.notifications import Notifier, build_notifier
from app.integrations.reads import run_outside_transaction
from app.integrations.vault import VaultAdapter, build_vault
from app.security.redaction import Redactor, set_redactor
from app.security.throttle import FailedAuthThrottle
from app.services.audit_service import AuditService
from app.services.notification_service import NotificationService
from app.services.offboarding_service import OffboardingService
from app.services.provisioning import ProvisioningService
from app.services.proxy_manager import ClientFactory, ProxyManager
from app.services.reminder_service import ReminderService
from app.services.report_service import ReportService
from app.services.task_manager import TaskManager

T = TypeVar("T")

@dataclass
class Container:
    settings: Settings
    clock: Clock
    redactor: Redactor
    engine: Engine
    session_factory: sessionmaker[Session]
    vault: VaultAdapter
    meta: MetaIntegration
    notifier: Notifier
    notifications: NotificationService
    tasks: TaskManager
    reminders: ReminderService
    provisioning: ProvisioningService
    audits: AuditService
    offboarding: OffboardingService
    proxies: ProxyManager
    reports: ReportService
    auth_throttle: FailedAuthThrottle
    scheduler: object | None = None

    def uow(self) -> AbstractContextManager[Session]:
        return session_scope(self.session_factory)

    def run(self, fn: Callable[[Session], T]) -> T:
        """One unit of work whose vault/Meta reads happen outside the transaction (see integrations.reads)."""

        def unit() -> T:
            with self.uow() as session:
                return fn(session)

        return run_outside_transaction(unit)


def build_container(
    settings: Settings,
    *,
    clock: Clock | None = None,
    vault: VaultAdapter | None = None,
    meta: MetaIntegration | None = None,
    notifier: Notifier | None = None,
    proxy_client_factory: ClientFactory | None = None,
    proxy_sleep: Callable[[float], None] | None = None,
    rng: random.Random | None = None,
) -> Container:
    clock = clock or SystemClock()
    redactor = Redactor(
        redact_emails=settings.redact_emails,
        redact_phones=settings.redact_phones,
        extra_sensitive_keys=settings.extra_sensitive_keys,
    )
    set_redactor(redactor)
    engine = create_db_engine(settings.database_url)
    factory = make_session_factory(engine)
    vault = vault or build_vault(settings, redactor=redactor, clock=clock)
    meta = meta or build_meta(settings, vault=vault, redactor=redactor)
    notifier = notifier or build_notifier(settings, vault=vault, redactor=redactor)
    notifications = NotificationService(settings=settings, clock=clock, notifier=notifier, redactor=redactor)
    tasks = TaskManager(settings=settings, clock=clock, redactor=redactor, notifications=notifications)
    reminders = ReminderService(settings=settings, clock=clock, tasks=tasks, notifications=notifications)
    provisioning = ProvisioningService(settings=settings, clock=clock, tasks=tasks, vault=vault, meta=meta, redactor=redactor)
    provisioning.register()
    audits = AuditService(
        settings=settings, clock=clock, tasks=tasks, provisioning=provisioning, vault=vault, meta=meta, redactor=redactor
    )
    audits.register()
    offboarding = OffboardingService(
        settings=settings, clock=clock, tasks=tasks, provisioning=provisioning, vault=vault, redactor=redactor
    )
    offboarding.register()
    proxies = ProxyManager(
        settings=settings,
        clock=clock,
        vault=vault,
        redactor=redactor,
        tasks=tasks,
        client_factory=proxy_client_factory,
        sleep=proxy_sleep or time.sleep,
        rng=rng,
    )
    proxies.register()
    reports = ReportService(
        settings=settings, clock=clock, redactor=redactor, vault=vault, meta=meta, notifier=notifier, provisioning=provisioning
    )
    audits.report_writer = reports.write_audit_report
    return Container(
        settings=settings,
        clock=clock,
        redactor=redactor,
        engine=engine,
        session_factory=factory,
        vault=vault,
        meta=meta,
        notifier=notifier,
        notifications=notifications,
        tasks=tasks,
        reminders=reminders,
        provisioning=provisioning,
        audits=audits,
        offboarding=offboarding,
        proxies=proxies,
        reports=reports,
        auth_throttle=FailedAuthThrottle(
            max_failures=settings.auth_max_failed_attempts, window_seconds=settings.auth_failure_window_seconds, clock=clock
        ),
    )
