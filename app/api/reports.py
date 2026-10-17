"""Report export endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from app.container import Container
from app.dependencies import get_container, require
from app.logging_setup import RUN_LOG_FILENAME
from app.security.authorization import Actor, Permission

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/account-register", response_model=None)
def account_register(
    fmt: str = Query("json", alias="format", pattern="^(json|md|csv)$"),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> dict[str, Any] | PlainTextResponse:
    with container.uow() as session:
        data = container.reports.account_register(session)
    if fmt == "md":
        return PlainTextResponse(container.redactor.redact_text(container.reports.account_register_markdown(data)), media_type="text/markdown")
    if fmt == "csv":
        return PlainTextResponse(container.redactor.redact_text(container.reports.account_register_csv(data)), media_type="text/csv")
    return container.redactor.redact(data)


@router.post("/export")
def export_reports(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.REPORTS_EXPORT))) -> dict[str, Any]:
    with container.uow() as session:
        return container.reports.export_all(session)


@router.get("/run-log")
def run_log(
    limit: int = Query(200, ge=1, le=2000),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.REPORTS_EXPORT)),
) -> list[dict[str, Any]]:
    path = container.settings.log_dir / RUN_LOG_FILENAME
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(container.redactor.redact(json.loads(line)))
        except json.JSONDecodeError:
            continue
    return out
