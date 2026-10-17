"""Role-based authorisation (least privilege).

viewer   - read-only access to the register, tasks, findings and reports.
operator - creates accounts, records profile specs, works and completes human tasks.
auditor  - read access plus running audits and exporting reports.
admin    - everything, including the access register, offboarding, proxy control
           and operator management.

Task actions are additionally restricted to the task owner, their supervisor or
an admin (see ``TaskManager.ensure_can_act``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.enums import OperatorRole
from app.errors import PermissionDenied


class Permission(StrEnum):
    READ = "read"
    ACCOUNTS_WRITE = "accounts:write"
    ACCESS_REGISTER_WRITE = "access_register:write"
    TASKS_WRITE = "tasks:write"
    TASKS_RUN_REMINDERS = "tasks:run_reminders"
    AUDITS_RUN = "audits:run"
    OFFBOARDING_WRITE = "offboarding:write"
    PROXIES_CHECK = "proxies:check"
    PROXIES_CONTROL = "proxies:control"
    REPORTS_EXPORT = "reports:export"
    PEOPLE_MANAGE = "people:manage"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    OperatorRole.VIEWER: frozenset({Permission.READ}),
    OperatorRole.OPERATOR: frozenset(
        {
            Permission.READ,
            Permission.ACCOUNTS_WRITE,
            Permission.TASKS_WRITE,
            Permission.TASKS_RUN_REMINDERS,
            Permission.PROXIES_CHECK,
        }
    ),
    OperatorRole.AUDITOR: frozenset(
        {Permission.READ, Permission.AUDITS_RUN, Permission.REPORTS_EXPORT, Permission.PROXIES_CHECK}
    ),
    OperatorRole.ADMIN: frozenset(Permission),
    "system": frozenset(Permission),
}


@dataclass(frozen=True)
class Actor:
    person_id: str | None
    role: str
    credential_id: str | None = None
    display_name: str = ""

    def has(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())

    @property
    def is_admin(self) -> bool:
        return self.role in (OperatorRole.ADMIN, "system")

    @property
    def is_system(self) -> bool:
        return self.role == "system"

    @property
    def audit_id(self) -> str:
        return self.person_id or "system"


SYSTEM_ACTOR = Actor(person_id=None, role="system", display_name="system")


def require_permission(actor: Actor, permission: Permission) -> None:
    if not actor.has(permission):
        raise PermissionDenied(f"Role '{actor.role}' lacks permission '{permission.value}'")
