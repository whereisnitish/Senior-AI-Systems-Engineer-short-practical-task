"""Offboarding endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select

from app.container import Container
from app.dependencies import get_container, require
from app.models import OffboardingCase
from app.schemas import OffboardingStart
from app.security.authorization import Actor, Permission
from app.views import case_view

router = APIRouter(prefix="/api/v1/offboarding", tags=["offboarding"])


@router.post("", status_code=status.HTTP_201_CREATED)
def start_offboarding(
    body: OffboardingStart,
    response: Response,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.OFFBOARDING_WRITE)),
) -> dict[str, Any]:
    def op(session) -> dict[str, Any]:
        case, created = container.offboarding.start(
            session, person_id=body.person_id, actor=actor, reason=body.reason, replacement_admin_id=body.replacement_admin_id
        )
        return {"created": created, "case": case_view(case)}

    result = container.run(op)  # rotation baselines read vault metadata: kept outside the transaction
    if not result["created"]:
        response.status_code = status.HTTP_200_OK
    return result


@router.get("")
def list_cases(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        return [case_view(c) for c in session.scalars(select(OffboardingCase).order_by(OffboardingCase.created_at.desc()))]


@router.get("/{case_id}")
def get_case(case_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        return case_view(container.offboarding.get_case(session, case_id))


@router.post("/{case_id}/reconcile")
def reconcile_case(
    case_id: str, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.OFFBOARDING_WRITE))
) -> dict[str, Any]:
    return container.run(
        lambda session: case_view(container.offboarding.reconcile(session, container.offboarding.get_case(session, case_id), actor=actor))
    )


@router.get("/{case_id}/report", response_model=None)
def case_report(
    case_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|md)$"),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> dict[str, Any] | PlainTextResponse:
    with container.uow() as session:
        data = container.reports.offboarding_report(session, container.offboarding.get_case(session, case_id))
    if fmt == "md":
        return PlainTextResponse(container.reports.offboarding_report_markdown(data), media_type="text/markdown")
    return data
