"""Liveness, readiness and integration status."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import func, inspect, select

from app.container import Container
from app.database import ping
from app.dependencies import current_actor, get_container, require
from app.enums import DeliveryStatus
from app.models import Notification, ProxyEndpoint
from app.security.authorization import Actor, Permission

router = APIRouter()
REQUIRED_TABLES = {"people", "instagram_accounts", "human_tasks", "audit_findings", "offboarding_actions", "proxy_endpoints"}


@router.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", tags=["health"])
def ready(container: Container = Depends(get_container)) -> JSONResponse:
    checks: dict[str, Any] = {}
    ok = True
    try:
        ping(container.engine)
        missing = REQUIRED_TABLES - set(inspect(container.engine).get_table_names())
        checks["database"] = "ok" if not missing else "schema_missing (run: alembic upgrade head)"
        ok = ok and not missing
    except Exception:  # noqa: BLE001
        checks["database"] = "unavailable"
        ok = False
    vault_health = container.vault.health()
    checks["vault"] = vault_health.get("status")
    if vault_health.get("status") in ("unavailable", "sealed"):
        ok = False
    scheduler = container.scheduler
    checks["scheduler"] = scheduler.status()["running"] if scheduler is not None else "disabled"
    return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503)


@router.get("/api/v1/me", tags=["health"])
def me(actor: Actor = Depends(current_actor)) -> dict[str, Any]:
    return {"person_id": actor.person_id, "role": actor.role, "name": actor.display_name}


@router.get("/api/v1/integrations", tags=["health"])
def integrations(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        undelivered = session.scalar(
            select(func.count(Notification.id)).where(Notification.delivery_status == DeliveryStatus.NOT_DELIVERED_NO_PROVIDER)
        )
        proxies = session.scalars(select(ProxyEndpoint)).all()
    s = container.settings
    return {
        "instagram": {
            "status": "no_automation_by_design",
            "detail": "Signup, verification, security settings, profile edits and business conversion are guided human tasks.",
        },
        "vault": {
            "backend": container.vault.name,
            "production_grade": container.vault.production_grade,
            "capabilities": sorted(container.vault.capabilities),
            "description": container.vault.description,
            "health": container.vault.health(),
        },
        "meta": {"mode": container.meta.name, "configured": container.meta.configured, "health": container.meta.health()},
        "notifications": {
            "backend": container.notifier.name,
            "configured": container.notifier.configured,
            "not_delivered_no_provider": undelivered,
        },
        "email_alias_provisioning": {"status": "not_integrated", "fallback": "human task assign_company_email"},
        "phone_number_inventory": {"status": "not_integrated", "fallback": "human task assign_company_phone"},
        "proxies": {
            "config_file": str(s.proxy_config_file) if s.proxy_config_file else None,
            "approved": sum(p.approved for p in proxies),
            "healthy": sum(p.health_status.value == "healthy" for p in proxies),
            "allowed_healthcheck_urls": len(s.proxy_healthcheck_allowed_urls),
        },
        "company_email_domains_configured": bool(s.company_email_domains),
        "scheduler": container.scheduler.status() if container.scheduler is not None else {"running": False, "detail": "SCHEDULER_ENABLED=false"},
    }
