"""Human task endpoints, reminders/escalation trigger and the notification outbox."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm.exc import StaleDataError

from app.container import Container
from app.dependencies import get_container, require
from app.enums import DeliveryStatus, TaskOrigin, TaskStatus, TaskType
from app.errors import Conflict
from app.models import HumanTask, Notification
from app.schemas import (
    TaskAssign,
    TaskComplete,
    TaskCreate,
    TaskFail,
    TaskReason,
    TaskUnblock,
)
from app.security.authorization import Actor, Permission
from app.services.task_manager import ACTIVE_STATUSES
from app.views import notification_view, task_view

router = APIRouter(prefix="/api/v1", tags=["tasks"])


@router.get("/tasks")
def list_tasks(
    status_filter: TaskStatus | None = Query(None, alias="status"),
    owner_id: str | None = None,
    account_id: str | None = None,
    task_type: TaskType | None = None,
    open_only: bool = False,
    limit: int = Query(200, ge=1, le=1000),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> list[dict[str, Any]]:
    query = select(HumanTask).order_by(HumanTask.due_at).limit(limit)
    if status_filter:
        query = query.where(HumanTask.status == status_filter)
    if open_only:
        query = query.where(HumanTask.status.in_(list(ACTIVE_STATUSES)))
    if owner_id:
        query = query.where(HumanTask.owner_id == owner_id)
    if account_id:
        query = query.where(HumanTask.account_id == account_id)
    if task_type:
        query = query.where(HumanTask.task_type == task_type)
    with container.uow() as session:
        now = container.clock.now()
        return [task_view(t, now) for t in session.scalars(query)]


@router.get("/tasks/overdue")
def overdue_tasks(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        now = container.clock.now()
        rows = session.scalars(
            select(HumanTask).where(HumanTask.status.in_(list(ACTIVE_STATUSES)), HumanTask.due_at < now).order_by(HumanTask.due_at)
        )
        return [task_view(t, now) for t in rows]


@router.post("/tasks/reminders/run")
def run_reminders(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.TASKS_RUN_REMINDERS))) -> dict[str, Any]:
    with container.uow() as session:
        result = container.reminders.run_cycle(session).as_dict()
    dispatch = container.notifications.dispatch_pending(container.session_factory)
    result["dispatch"] = {
        "sent": dispatch.sent,
        "not_delivered_no_provider": dispatch.not_delivered_no_provider,
        "retry_scheduled": dispatch.retry_scheduled,
        "failed": dispatch.failed,
        "uncertain": dispatch.uncertain,
        "superseded": dispatch.superseded,
    }
    return result


@router.post("/tasks", status_code=status.HTTP_201_CREATED)
def create_task(
    body: TaskCreate, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    with container.uow() as session:
        task, created = container.tasks.create_task(
            session,
            task_type=TaskType.MANUAL,
            owner_id=body.owner_id,
            idempotency_key=f"manual:{body.idempotency_key}",
            account_id=body.account_id,
            context={"title": body.title, "description": body.description},
            due_at=body.due_at,
            priority=body.priority,
            origin=TaskOrigin.MANUAL,
            actor=actor,
        )
        return {"created": created, "task": task_view(task, container.clock.now(), detail=True)}


@router.get("/tasks/{task_id}")
def get_task(task_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        return task_view(container.tasks.get(session, task_id), container.clock.now(), detail=True)


def _run(container: Container, fn) -> dict[str, Any]:
    """Run a task mutation; on a concurrent-update collision retry once on fresh state.

    Completion handlers may consult the vault or Meta; ``container.run`` keeps those reads outside the transaction.
    """
    for attempt in range(2):
        try:
            return container.run(fn)
        except (StaleDataError, OperationalError):
            if attempt == 1:
                raise Conflict("the task was changed concurrently; reload and retry") from None
    raise AssertionError("unreachable")


@router.post("/tasks/{task_id}/complete")
def complete_task(
    task_id: str, body: TaskComplete, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    def op(session) -> dict[str, Any]:
        result = container.tasks.complete(
            session, task_id, actor=actor, outcome=body.outcome, evidence_ref=body.evidence_ref, note=body.note
        )
        return {"already_completed": result.already_completed, "task": task_view(result.task, container.clock.now(), detail=True)}

    return _run(container, op)


@router.post("/tasks/{task_id}/start")
def start_task(task_id: str, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))) -> dict[str, Any]:
    return _run(container, lambda s: task_view(container.tasks.start(s, task_id, actor=actor), container.clock.now()))


@router.post("/tasks/{task_id}/assign")
def assign_task(
    task_id: str, body: TaskAssign, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    return _run(
        container,
        lambda s: task_view(
            container.tasks.assign(s, task_id, actor=actor, owner_id=body.owner_id, supervisor_id=body.supervisor_id), container.clock.now()
        ),
    )


@router.post("/tasks/{task_id}/block")
def block_task(
    task_id: str, body: TaskReason, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    return _run(container, lambda s: task_view(container.tasks.block(s, task_id, actor=actor, reason=body.reason), container.clock.now()))


@router.post("/tasks/{task_id}/unblock")
def unblock_task(
    task_id: str, body: TaskUnblock, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    return _run(container, lambda s: task_view(container.tasks.unblock(s, task_id, actor=actor, note=body.note), container.clock.now()))


@router.post("/tasks/{task_id}/fail")
def fail_task(
    task_id: str, body: TaskFail, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    return _run(
        container,
        lambda s: task_view(
            container.tasks.fail(s, task_id, actor=actor, reason=body.reason, outcome_uncertain=body.outcome_uncertain),
            container.clock.now(),
        ),
    )


@router.post("/tasks/{task_id}/cancel")
def cancel_task(
    task_id: str, body: TaskReason, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.TASKS_WRITE))
) -> dict[str, Any]:
    return _run(container, lambda s: task_view(container.tasks.cancel(s, task_id, actor=actor, reason=body.reason), container.clock.now()))


@router.get("/notifications")
def list_notifications(
    delivery_status: DeliveryStatus | None = None,
    limit: int = Query(200, ge=1, le=1000),
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.READ)),
) -> list[dict[str, Any]]:
    query = select(Notification).order_by(Notification.created_at.desc()).limit(limit)
    if delivery_status:
        query = query.where(Notification.delivery_status == delivery_status)
    with container.uow() as session:
        return [notification_view(n) for n in session.scalars(query)]


@router.post("/notifications/dispatch")
def dispatch_notifications(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.TASKS_RUN_REMINDERS))) -> dict[str, Any]:
    summary = container.notifications.dispatch_pending(container.session_factory)
    return {
        "sent": summary.sent,
        "not_delivered_no_provider": summary.not_delivered_no_provider,
        "retry_scheduled": summary.retry_scheduled,
        "failed": summary.failed,
        "uncertain": summary.uncertain,
        "superseded": summary.superseded,
    }


@router.post("/notifications/{notification_id}/requeue")
def requeue_notification(
    notification_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.PEOPLE_MANAGE))
) -> dict[str, Any]:
    with container.uow() as session:
        return notification_view(container.notifications.requeue(session, notification_id))
