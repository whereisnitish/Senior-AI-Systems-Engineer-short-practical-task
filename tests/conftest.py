"""Shared fixtures. Every test gets its own file-backed SQLite database, a frozen
clock, a development-only synthetic vault and no network access to anything but
local simulated servers. Nothing here touches Instagram, Meta or a real vault."""

from __future__ import annotations

import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.clock import FrozenClock
from app.config import Settings
from app.container import Container, build_container
from app.database import Base
from app.enums import OperatorRole, Platform, RoleName, TaskStatus, TaskType
from app.logging_setup import configure_logging
from app.main import create_app
from app.models import HumanTask, Person, new_id
from app.security.authentication import issue_api_credential
from app.security.authorization import Actor
from app.security.secret_handling import SecretValue
from app.services.task_manager import ACTIVE_STATUSES

T0 = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)  # a Monday, 09:00 UTC
TEST_SECRET_KEY = "unit-test-signing-key-" + "q" * 40
HANDLE = "lumenlabtestbrand"
PASSWORD_REF = "devvault://instagram/lumenlab/password"
BACKUP_REF = "devvault://instagram/lumenlab/backup-codes"
TOTP_REF = "devvault://instagram/lumenlab/totp"
PROFILE = {
    "profile_name": "Lumen Lab Test Brand",
    "bio": "Synthetic test brand used to exercise the operations workflow. Not a real business.",
    "profile_link": "https://brand.testco.example/lumen",
    "category": "Product/service",
    "profile_image_ref": "brandkit://lumen-lab/logo-v1.png",
}

OUTCOMES: dict[TaskType, dict[str, Any]] = {
    TaskType.HANDLE_AVAILABILITY_CHECK: {"selected_handle": HANDLE, "checked_via": "instagram_web"},
    TaskType.ASSIGN_COMPANY_EMAIL: {"email_assignment_ref": "IT-REQ-4821", "email_address": "ig-lumenlab@testco.example", "mailbox_control": "company_controlled"},
    TaskType.ASSIGN_COMPANY_PHONE: {
        "phone_assignment_ref": "TEL-0042",
        "phone_number": "+447700900123",
        "number_control": "company_controlled",
    },
    TaskType.ACCOUNT_SIGNUP: {"platform_handle": HANDLE, "password_vault_ref": PASSWORD_REF},
    TaskType.ACCOUNT_VERIFICATION: {
        "email_confirmed_on_platform": True,
        "phone_confirmed_on_platform": True,
        "recovery_email_is_company_alias": True,
        "recovery_phone_is_company_number": True,
    },
    TaskType.ENABLE_TWO_FACTOR: {
        "two_factor_method": "authenticator_app",
        "backup_codes_vault_ref": BACKUP_REF,
        "totp_seed_vault_ref": TOTP_REF,
        "two_factor_enabled": True,
    },
    TaskType.COMPLETE_PROFILE: {"profile_matches_spec": True},
    TaskType.CONVERT_TO_BUSINESS: {"account_type": "business", "category_set": True},
    TaskType.LINK_META_BUSINESS: {
        "meta_business_ref": "biz-test-0001",
        "linked_in_business_suite": True,
        "linked_in_business_manager": True,
    },
    TaskType.ASSIGN_PEOPLE_ROLES: {"roles_granted_as_listed": True},
}


class Env:
    def __init__(self, tmp_path: Path, **overrides: Any):
        self.tmp_path = tmp_path
        self.clock = FrozenClock(T0)
        self.settings = make_settings(tmp_path, **overrides)
        self.container: Container = build_container(
            self.settings, clock=self.clock, proxy_sleep=lambda _s: None, rng=random.Random(7)
        )
        Base.metadata.create_all(self.container.engine)
        configure_logging(self.settings.log_dir, level="DEBUG", to_stdout=False, redactor=self.container.redactor)
        self._client: TestClient | None = None

    # -- people & credentials ---------------------------------------------------
    def person(self, name: str, *, supervisor: str | None = None, responsibilities: tuple[str, ...] = ()) -> str:
        with self.container.uow() as s:
            person = Person(
                id=new_id("per"),
                full_name=name,
                email=f"{name.lower().replace(' ', '.')}@testco.example",
                supervisor_id=supervisor,
                responsibilities=list(responsibilities),
                is_synthetic=True,
                created_at=self.clock.now(),
                updated_at=self.clock.now(),
            )
            s.add(person)
            return person.id

    def token(self, person_id: str, role: OperatorRole) -> str:
        with self.container.uow() as s:
            person = s.get(Person, person_id)
            _, raw = issue_api_credential(
                s, person=person, role=role, label="test", secret_key=self.settings.secret_key_bytes, now=self.clock.now()
            )
            return raw

    def headers(self, person_id: str, role: OperatorRole = OperatorRole.ADMIN) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(person_id, role)}"}

    @staticmethod
    def actor(person_id: str, role: OperatorRole = OperatorRole.OPERATOR) -> Actor:
        return Actor(person_id=person_id, role=role.value, display_name="test")

    # -- vault --------------------------------------------------------------------
    def vault_put(self, ref: str, **fields: str) -> None:
        self.container.vault.write_fields(ref, {k: SecretValue(v) for k, v in (fields or {"value": "SYNTHETIC-x"}).items()})

    def seed_vault(self) -> None:
        self.vault_put(PASSWORD_REF, value="SYNTHETIC-password-lumenlab-1")
        self.vault_put(BACKUP_REF, value="SYNTHETIC-backup-codes-set-1")
        self.vault_put(TOTP_REF, value="SYNTHETIC-totp-seed-1")

    # -- tasks ---------------------------------------------------------------------
    def open_task(self, account_id: str, task_type: TaskType) -> HumanTask:
        with self.container.uow() as s:
            task = s.scalar(
                select(HumanTask).where(
                    HumanTask.account_id == account_id,
                    HumanTask.task_type == task_type,
                    HumanTask.status.in_(list(ACTIVE_STATUSES)),
                )
            )
            assert task is not None, f"no open {task_type.value} task"
            return task

    def tasks(self, account_id: str | None = None, task_type: TaskType | None = None) -> list[HumanTask]:
        with self.container.uow() as s:
            query = select(HumanTask).order_by(HumanTask.created_at, HumanTask.id)
            if account_id:
                query = query.where(HumanTask.account_id == account_id)
            if task_type:
                query = query.where(HumanTask.task_type == task_type)
            return list(s.scalars(query))

    def complete(self, task_id: str, actor: Actor, outcome: dict[str, Any] | None = None, evidence: str = "observed in Instagram settings (test)"):
        with self.container.uow() as s:
            return self.container.tasks.complete(s, task_id, actor=actor, outcome=outcome or {}, evidence_ref=evidence)

    def complete_type(self, account_id: str, task_type: TaskType, actor: Actor, outcome: dict[str, Any] | None = None):
        task = self.open_task(account_id, task_type)
        return self.complete(task.id, actor, outcome if outcome is not None else OUTCOMES[task_type])

    # -- workflow --------------------------------------------------------------------
    def create_account(self, owner_id: str, *, brand: str = "Lumen Lab Test Brand", profile: dict | None = None) -> str:
        with self.container.uow() as s:
            account, _ = self.container.provisioning.create_account(
                s, brand_name=brand, owner_id=owner_id, actor=self.actor(owner_id, OperatorRole.ADMIN),
                profile=profile if profile is not None else PROFILE, is_synthetic=True,
            )
            return account.id

    def add_role(self, account_id: str, person_id: str, role: RoleName, admin_id: str) -> str:
        with self.container.uow() as s:
            assignment = self.container.provisioning.add_assignment(
                s, account_id, person_id=person_id, platform=Platform.META_BUSINESS, role=role,
                actor=self.actor(admin_id, OperatorRole.ADMIN),
            )
            return assignment.id

    def provision(self, account_id: str, owner_id: str, *, stop_before: TaskType | None = None) -> None:
        """Drive the account through every human step with synthetic confirmations."""
        self.seed_vault()
        actor = self.actor(owner_id, OperatorRole.ADMIN)
        self.add_role(account_id, owner_id, RoleName.BUSINESS_ADMIN, owner_id)
        order = [
            TaskType.HANDLE_AVAILABILITY_CHECK,
            TaskType.ASSIGN_COMPANY_EMAIL,
            TaskType.ASSIGN_COMPANY_PHONE,
            TaskType.ACCOUNT_SIGNUP,
            TaskType.ACCOUNT_VERIFICATION,
            TaskType.ENABLE_TWO_FACTOR,
            TaskType.COMPLETE_PROFILE,
            TaskType.CONVERT_TO_BUSINESS,
            TaskType.LINK_META_BUSINESS,
            TaskType.ASSIGN_PEOPLE_ROLES,
        ]
        for task_type in order:
            if task_type == stop_before:
                return
            self.complete_type(account_id, task_type, actor)

    def client(self) -> TestClient:
        if self._client is None:
            self._client = TestClient(create_app(self.settings, self.container, run_recovery=False))
        return self._client

    def read_logs(self) -> str:
        for handler in __import__("logging").getLogger().handlers:
            handler.flush()
        path = self.settings.log_dir / "run_log.jsonl"
        return path.read_text(encoding="utf-8") if path.exists() else ""


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "_env_file": None,
        "app_env": "test",
        "app_secret_key": TEST_SECRET_KEY,
        "database_url": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        "vault_backend": "dev_memory",
        "log_dir": tmp_path / "logs",
        "reports_dir": tmp_path / "reports",
        "log_to_stdout": False,
        "scheduler_enabled": False,
        "company_email_domains": "testco.example",
        "public_base_url": "http://testserver",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    environment = Env(tmp_path)
    yield environment
    environment.container.engine.dispose()


@pytest.fixture
def team(env: Env) -> dict[str, str]:
    """Synthetic team: supervisor/security owner, account owner, operator, departing tester."""
    security = env.person("Morgan Lee", responsibilities=("security_owner", "escalation_default", "vault_admin"))
    owner = env.person("Sam Rivera", supervisor=security)
    operator = env.person("Alex Chen", supervisor=owner)
    departing = env.person("Jordan Patel", supervisor=owner)
    return {"security": security, "owner": owner, "operator": operator, "departing": departing}


@pytest.fixture
def account(env: Env, team: dict[str, str]) -> str:
    return env.create_account(team["owner"])


def statuses(tasks: list[HumanTask]) -> list[TaskStatus]:
    return [t.status for t in tasks]
