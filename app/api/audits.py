"""Security audit endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response, status
from sqlalchemy import select

from app.container import Container
from app.dependencies import get_container, require
from app.enums import AuditTrigger, FindingStatus
from app.errors import NotFound, ValidationFailed
from app.models import AuditFinding, AuditRun
from app.security.authorization import Actor, Permission
from app.views import finding_view, iso

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])


def _run_view(run: AuditRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "trigger": run.trigger.value,
        "idempotency_key": run.idempotency_key,
        "status": run.status.value,
        "started_at": iso(run.started_at),
        "finished_at": iso(run.finished_at),
        "attempt_count": run.attempt_count,
        "totals": (run.summary or {}).get("totals", {}),
        "report_json_path": run.report_json_path,
        "report_md_path": run.report_md_path,
    }


@router.post("/run", status_code=status.HTTP_201_CREATED)
def run_audit(
    response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=100),
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.AUDITS_RUN)),
) -> dict[str, Any]:
    key = None
    if idempotency_key:
        if not idempotency_key.replace("-", "").replace("_", "").replace(":", "").isalnum():
            raise ValidationFailed("Idempotency-Key may contain letters, digits, '-', '_' and ':' only")
        key = f"manual:{idempotency_key}"
    with container.uow() as session:
        existed = key is not None and session.scalar(select(AuditRun.id).where(AuditRun.idempotency_key == key)) is not None
    run = container.audits.run(container.session_factory, trigger=AuditTrigger.MANUAL, actor=actor, idempotency_key=key)
    if existed:
        response.status_code = status.HTTP_200_OK
    return _run_view(run)


@router.get("")
def list_runs(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        return [_run_view(r) for r in session.scalars(select(AuditRun).order_by(AuditRun.started_at.desc()).limit(100))]


@router.get("/findings")
def list_findings(
    finding_status: FindingStatus | None = Query(FindingStatus.OPEN, alias="status"),
    account_id: str | None = None,
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> list[dict[str, Any]]:
    query = select(AuditFinding).order_by(AuditFinding.last_detected_at.desc())
    if finding_status:
        query = query.where(AuditFinding.status == finding_status)
    if account_id:
        query = query.where(AuditFinding.account_id == account_id)
    with container.uow() as session:
        return [finding_view(f) for f in session.scalars(query)]


@router.get("/{run_id}")
def get_run(run_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        run = session.get(AuditRun, run_id)
        if run is None:
            raise NotFound("audit run not found")
        return container.reports.audit_report(session, run)
