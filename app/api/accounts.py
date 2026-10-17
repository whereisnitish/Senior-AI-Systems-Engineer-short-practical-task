"""Account register and provisioning workflow endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import select

from app.container import Container
from app.dependencies import get_container, require
from app.enums import ProvisioningStep
from app.models import InstagramAccount
from app.schemas import (
    AccountCreate,
    AssignmentCreate,
    BlockerRequest,
    ProfileSpec,
    ReasonRequest,
    StepEvidenceRequest,
)
from app.security.authorization import Actor, Permission
from app.services.handles import (
    AVAILABILITY_NOTE,
    handle_problems,
    normalize_handle,
    suggest_handles,
)
from app.views import account_view, task_view

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


def _view(container: Container, session, account: InstagramAccount) -> dict[str, Any]:
    return account_view(session, account, container.clock.now(), container.provisioning.provisioning_gaps(account))


@router.post("", status_code=status.HTTP_201_CREATED)
def create_account(
    body: AccountCreate,
    response: Response,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        account, created = container.provisioning.create_account(
            session,
            brand_name=body.brand_name,
            owner_id=body.owner_id,
            actor=actor,
            keywords=body.handle_keywords,
            profile=body.profile.model_dump(exclude_none=True) if body.profile else None,
            is_synthetic=body.is_synthetic,
        )
        if not created:
            response.status_code = status.HTTP_200_OK
        return {"created": created, "account": _view(container, session, account)}


@router.get("")
def list_accounts(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        accounts = session.scalars(select(InstagramAccount).order_by(InstagramAccount.created_at)).all()
        return [_view(container, session, a) for a in accounts]


@router.get("/{account_id}")
def get_account(account_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        return _view(container, session, container.provisioning.get_account(session, account_id))


@router.get("/{account_id}/handle-suggestions")
def handle_suggestions(
    account_id: str,
    keywords: str = Query("", max_length=120),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> dict[str, Any]:
    with container.uow() as session:
        account = container.provisioning.get_account(session, account_id)
        words = [w for w in keywords.split(",") if w.strip()][:5]
        suggestions = suggest_handles(account.brand_name, words)
    return {
        "brand_name": account.brand_name,
        "suggestions": [{"handle": h, "format_valid": not handle_problems(h), "availability": "unknown"} for h in suggestions],
        "note": AVAILABILITY_NOTE,
    }


@router.get("/handle-format/{handle}")
def check_handle_format(handle: str, _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    normalised = normalize_handle(handle)
    problems = handle_problems(normalised)
    return {"handle": normalised, "format_valid": not problems, "problems": problems, "availability": "unknown", "note": AVAILABILITY_NOTE}


@router.put("/{account_id}/profile")
def set_profile(
    account_id: str,
    body: ProfileSpec,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        account = container.provisioning.set_profile_spec(session, account_id, body.model_dump(exclude_none=True), actor=actor)
        return _view(container, session, account)


@router.post("/{account_id}/assignments", status_code=status.HTTP_201_CREATED)
def add_assignment(
    account_id: str,
    body: AssignmentCreate,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCESS_REGISTER_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        container.provisioning.add_assignment(
            session, account_id, person_id=body.person_id, platform=body.platform, role=body.role, actor=actor
        )
        return _view(container, session, container.provisioning.get_account(session, account_id))


@router.post("/{account_id}/reconcile")
def request_reconciliation(
    account_id: str,
    body: ReasonRequest,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        task = container.provisioning.request_reconciliation(session, account_id, actor=actor, reason=body.reason)
        return {"reconciliation_task": task_view(task, container.clock.now(), detail=True)}


@router.post("/{account_id}/steps/{step}/evidence")
def record_step_evidence(
    account_id: str,
    step: ProvisioningStep,
    body: StepEvidenceRequest,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        record = container.provisioning.record_step_evidence(session, account_id, step=step, evidence_ref=body.evidence_ref, actor=actor)
        return {"step": record.step.value, "verification": record.verification.value, "evidence_ref": record.evidence_ref}


@router.post("/{account_id}/steps/{step}/reset")
def reset_step(
    account_id: str,
    step: ProvisioningStep,
    body: ReasonRequest,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCESS_REGISTER_WRITE)),  # admin: withdraws a confirmed fact
) -> dict[str, Any]:
    with container.uow() as session:
        task = container.provisioning.reset_step(session, account_id, step=step, reason=body.reason, actor=actor)
        return {"step": step.value, "state": "pending", "new_task": task_view(task, container.clock.now(), detail=True) if task else None}


@router.post("/{account_id}/verify-integrations")
def verify_integrations(
    account_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.ACCOUNTS_WRITE))
) -> dict[str, Any]:
    return container.run(lambda session: {"results": container.provisioning.verify_integrations(session, account_id)})


@router.post("/{account_id}/blocker")
def set_blocker(
    account_id: str,
    body: BlockerRequest,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE)),
) -> dict[str, Any]:
    with container.uow() as session:
        account = container.provisioning.set_blocker(session, account_id, code=body.code, detail=body.detail, actor=actor)
        return _view(container, session, account)


@router.delete("/{account_id}/blocker")
def clear_blocker(
    account_id: str, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.ACCOUNTS_WRITE))
) -> dict[str, Any]:
    with container.uow() as session:
        account = container.provisioning.clear_blocker(session, account_id, actor=actor)
        return _view(container, session, account)
