"""Server-rendered operations dashboard (no JavaScript, strict CSP).

Sign-in exchanges an operator API token for a server-side session cookie
(HttpOnly, SameSite=Strict, Secure in production). Every form carries an
HMAC-derived CSRF token. Pages call the same services as the API.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from app.container import Container
from app.dependencies import get_container
from app.enums import (
    AuditTrigger,
    DeliveryStatus,
    FindingStatus,
    OffboardingActionStatus,
    OffboardingCaseStatus,
    ProxySessionStatus,
    Severity,
    TaskStatus,
)
from app.errors import AuthenticationRequired, DomainError, PermissionDenied, TooManyAttempts
from app.models import (
    AuditFinding,
    AuditRun,
    HumanTask,
    InstagramAccount,
    Notification,
    OffboardingAction,
    OffboardingCase,
    ProxyEndpoint,
    ProxyEvent,
    ProxySession,
)
from app.security.authentication import (
    authenticate_token,
    authenticate_ui_session,
    create_ui_session,
    csrf_token,
    revoke_ui_session,
    verify_csrf,
)
from app.security.authorization import Actor, Permission, require_permission
from app.services.report_service import LABEL_LEGEND
from app.services.task_manager import ACTIVE_STATUSES
from app.services.task_types import get_spec
from app.views import (
    account_view,
    case_view,
    finding_view,
    iso,
    notification_view,
    proxy_event_view,
    proxy_session_view,
    proxy_view,
    task_view,
)

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
COOKIE = "iom_session"
NOTICES = {
    "completed": "Task completed and the workflow advanced.",
    "already_completed": "That task was already completed - nothing was changed (idempotent).",
    "started": "Task marked in progress.",
    "blocked": "Task marked blocked. The supervisor has been notified and the blocker is visible here.",
    "reminders": "Reminder and escalation cycle ran. Delivery status is on the Notifications page.",
    "audit": "Audit finished. Findings are deduplicated against earlier runs.",
    "proxies": "Proxy health check finished.",
    "reconciled": "Offboarding case reconciled.",
}
ERRORS = {
    "forbidden": "Your role does not allow that action.",
    "validation_failed": "That action could not run because its configuration is incomplete (see the README).",
    "destination_not_approved": "No approved neutral health-check endpoint is configured.",
    "integration_unavailable": "An integration needed for that action is unavailable right now.",
    "not_found": "That record no longer exists.",
    "default": "That action could not be completed. Details are in the run log (search by correlation id).",
}
TONES = {
    "completed": "ok", "provisioned": "ok", "healthy": "ok", "active": "ok", "sent": "ok", "pass": "ok", "linked": "ok",
    "enabled": "ok", "present_in_vault": "ok", "company_controlled": "ok", "converted": "ok", "removed": "",
    "in_progress": "info", "waiting_for_human": "info", "open": "info", "running": "info", "requested": "info",
    "pending": "", "unknown": "", "cancelled": "", "ended": "", "not_started": "", "superseded": "",
    "overdue": "bad", "blocked": "bad", "failed": "bad", "unhealthy": "bad", "quarantined": "bad", "non_company": "bad",
    "disabled": "bad", "missing": "bad", "mismatch": "bad",
    "paused_security_review": "warn", "not_delivered_no_provider": "warn", "uncertain": "warn",
    "replacement_required": "warn", "completed_with_errors": "warn", "interrupted": "warn", "pending_removal": "warn",
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------- template helpers
def _short_dt(value: Any) -> str:
    """'2026-10-16T13:37:26+00:00' -> '2026-10-16 13:37 UTC' (all stored times are UTC)."""
    if not value:
        return "-"
    text = value.isoformat() if hasattr(value, "isoformat") else str(value)
    return text[:16].replace("T", " ") + " UTC"


def _relative(value: Any, now: datetime | None) -> str:
    if not value or now is None:
        return "-"
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    seconds = int((moment - now).total_seconds())
    future, seconds = seconds > 0, abs(seconds)
    if seconds < 60:
        return "just now"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = [f"{days}d"] if days else []
    if hours and len(parts) < 2:
        parts.append(f"{hours}h")
    if not days and minutes and len(parts) < 2:
        parts.append(f"{minutes}m")
    span = " ".join(parts)
    return f"in {span}" if future else f"{span} ago"


def _tone(value: Any) -> str:
    text = str(value or "")
    if text in TONES:
        return TONES[text]
    return "info" if text.startswith("awaiting") else ""


templates.env.filters["dt"] = _short_dt
templates.env.filters["rel"] = _relative
templates.env.filters["human"] = lambda value: str(value).replace("_", " ")
templates.env.globals.update(tone=_tone, LABEL_HELP=LABEL_LEGEND)


class UiLoginRequired(Exception):
    pass


def _ui_actor(request: Request, container: Container) -> tuple[Actor, str]:
    raw = request.cookies.get(COOKIE)
    try:
        with container.uow() as session:
            actor = authenticate_ui_session(session, raw, secret_key=container.settings.secret_key_bytes, now=container.clock.now())
    except AuthenticationRequired:
        raise UiLoginRequired() from None
    request.state.actor_id = actor.person_id
    return actor, raw or ""


def _page(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def _counts(session, now: datetime) -> dict[str, int]:
    active = session.execute(
        select(HumanTask.status, HumanTask.due_at).where(HumanTask.status.in_(list(ACTIVE_STATUSES)))
    ).all()
    open_cases = select(OffboardingCase.id).where(OffboardingCase.status == OffboardingCaseStatus.OPEN)
    actions = session.execute(
        select(OffboardingAction.status).where(OffboardingAction.case_id.in_(open_cases))
    ).scalars().all()
    findings = session.execute(select(AuditFinding.severity).where(AuditFinding.status == FindingStatus.OPEN)).scalars().all()
    proxies = session.execute(select(ProxyEndpoint.health_status).where(ProxyEndpoint.approved.is_(True))).scalars().all()
    return {
        "accounts": session.scalar(select(func.count(InstagramAccount.id))) or 0,
        "provisioned": session.scalar(
            select(func.count(InstagramAccount.id)).where(InstagramAccount.provisioning_status == "provisioned")
        ) or 0,
        "open_tasks": len(active),
        "overdue": sum(1 for st, due in active if st == TaskStatus.OVERDUE or (st != TaskStatus.BLOCKED and due < now)),
        "blocked": sum(1 for st, _ in active if st == TaskStatus.BLOCKED),
        "findings": len(findings),
        "findings_high": sum(1 for s in findings if s in (Severity.HIGH, Severity.CRITICAL)),
        "offboarding_open": sum(1 for s in actions if s in (OffboardingActionStatus.PENDING, OffboardingActionStatus.IN_PROGRESS)),
        "offboarding_blocked": sum(1 for s in actions if s == OffboardingActionStatus.BLOCKED),
        "undelivered": session.scalar(
            select(func.count(Notification.id)).where(Notification.delivery_status == DeliveryStatus.NOT_DELIVERED_NO_PROVIDER)
        ) or 0,
        "proxies": len(proxies),
        "proxies_healthy": sum(1 for h in proxies if h.value == "healthy"),
        "paused_sessions": session.scalar(
            select(func.count(ProxySession.id)).where(ProxySession.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW)
        ) or 0,
    }


def _base(container: Container, actor: Actor, raw: str, active: str) -> dict[str, Any]:
    now = container.clock.now()
    with container.uow() as session:
        synthetic = list(session.scalars(select(InstagramAccount.is_synthetic)))
        counts = _counts(session, now)
    nav = [
        ("overview", "Overview", "/dashboard", 0, False),
        ("accounts", "Accounts", "/dashboard/accounts", counts["accounts"], False),
        ("tasks", "Tasks", "/dashboard/tasks", counts["open_tasks"], counts["overdue"] + counts["blocked"] > 0),
        ("audit", "Audit", "/dashboard/audit", counts["findings"], counts["findings_high"] > 0),
        ("offboarding", "Offboarding", "/dashboard/offboarding", counts["offboarding_open"] + counts["offboarding_blocked"], counts["offboarding_blocked"] > 0),
        ("proxies", "Proxies", "/dashboard/proxies", counts["proxies"], counts["proxies_healthy"] < counts["proxies"] or counts["paused_sessions"] > 0),
        ("notifications", "Notifications", "/dashboard/notifications", counts["undelivered"], counts["undelivered"] > 0),
    ]
    name = actor.display_name or "?"
    initials = "".join(part[0] for part in name.replace("(", " ").split()[:2]).upper() or "?"
    return {
        "actor": actor,
        "initials": initials,
        "csrf": csrf_token(container.settings.secret_key_bytes, raw),
        "app_env": container.settings.app_env,
        "environment_label": container.settings.environment_label,
        "synthetic_data": any(synthetic),
        "vault_name": container.vault.name,
        "vault_production": container.vault.production_grade,
        "meta_configured": container.meta.configured,
        "notifier_configured": container.notifier.configured,
        "counts": counts,
        "nav": nav,
        "active": active,
        "now_dt": now,
        "scheduler": container.scheduler.status() if container.scheduler is not None else None,
    }


def _check_csrf(form: dict[str, Any], container: Container, raw: str) -> None:
    if not verify_csrf(container.settings.secret_key_bytes, raw, str(form.get("csrf_token", ""))):
        raise PermissionDenied("CSRF token missing or invalid; reload the page and try again")


def _safe_next(value: Any, default: str) -> str:
    """Only same-site dashboard paths are allowed as redirect targets (no open redirect)."""
    text = str(value or "")
    if text.startswith("/dashboard") and "//" not in text and "\\" not in text:
        return text.split("?", 1)[0]
    return default


async def _render(request: Request, container: Container, name: str, active: str, loader, *args) -> HTMLResponse:
    actor, raw = await run_in_threadpool(_ui_actor, request, container)
    data = await run_in_threadpool(loader, container, *args) if loader else {}
    base = await run_in_threadpool(_base, container, actor, raw, active)
    notice = NOTICES.get(request.query_params.get("notice", ""))
    error_code = request.query_params.get("error")
    page_error = ERRORS.get(error_code, ERRORS["default"]) if error_code else None  # fixed strings only, never reflected
    return _page(request, name, {**base, **data, "notice": notice, "page_error": page_error})


# ---------------------------------------------------------------- auth pages
@router.get("/")
def root() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login")
def login_form(request: Request) -> HTMLResponse:
    return _page(request, "login.html", {"error": None})


@router.post("/login")
async def login(request: Request, container: Container = Depends(get_container)) -> Response:
    form = await request.form()
    token = str(form.get("token", "")).strip()
    client = request.client.host if request.client else "unknown"

    def do_login() -> str | None:
        container.auth_throttle.check(client)
        try:
            with container.uow() as session:
                actor = authenticate_token(session, token, secret_key=container.settings.secret_key_bytes, now=container.clock.now())
                raw_session = create_ui_session(
                    session, actor.credential_id or "", secret_key=container.settings.secret_key_bytes,
                    now=container.clock.now(), hours=container.settings.ui_session_hours,
                )
        except AuthenticationRequired:
            container.auth_throttle.record_failure(client)
            return None
        container.auth_throttle.record_success(client)
        return raw_session

    try:
        raw = await run_in_threadpool(do_login)
    except TooManyAttempts as exc:
        page = _page(request, "login.html", {"error": exc.message}, status_code=429)
        page.headers["Retry-After"] = str(exc.retry_after)
        return page
    if raw is None:
        return _page(request, "login.html", {"error": "Invalid or revoked token."}, status_code=401)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        COOKIE, raw, httponly=True, samesite="strict", secure=container.settings.cookie_secure,
        max_age=container.settings.ui_session_hours * 3600, path="/",
    )
    return response


@router.post("/logout")
async def logout(request: Request, container: Container = Depends(get_container)) -> Response:
    form = dict(await request.form())
    raw = request.cookies.get(COOKIE, "")
    if verify_csrf(container.settings.secret_key_bytes, raw, str(form.get("csrf_token", ""))):
        def do_logout() -> None:
            with container.uow() as session:
                revoke_ui_session(session, raw, secret_key=container.settings.secret_key_bytes, now=container.clock.now())

        await run_in_threadpool(do_logout)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE, path="/")
    return response


# ---------------------------------------------------------------- loaders
def _attention(session, now: datetime) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for task in session.scalars(
        select(HumanTask).where(HumanTask.status.in_(list(ACTIVE_STATUSES))).order_by(HumanTask.due_at)
    ):
        if task.status == TaskStatus.BLOCKED:
            items.append({"tone": "bad", "tag": "Blocked task", "what": task.title, "why": task.blocker_detail or "", "href": f"/dashboard/tasks/{task.id}"})
        elif task.status == TaskStatus.OVERDUE or task.due_at < now:
            owner = task.owner.full_name if task.owner else "-"
            items.append({"tone": "bad", "tag": "Overdue", "what": task.title, "why": f"Owner {owner}; due {_short_dt(task.due_at)}", "href": f"/dashboard/tasks/{task.id}"})
    for finding in session.scalars(select(AuditFinding).where(AuditFinding.status == FindingStatus.OPEN)):
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            items.append({"tone": "bad" if finding.severity == Severity.CRITICAL else "warn", "tag": f"{finding.severity.value} finding", "what": finding.check_name.replace("_", " "), "why": finding.description, "href": "/dashboard/audit"})
    for action in session.scalars(select(OffboardingAction).where(OffboardingAction.status == OffboardingActionStatus.BLOCKED)):
        items.append({"tone": "bad", "tag": "Offboarding blocked", "what": action.description, "why": f"{action.blocker_code}: {action.blocker_detail}", "href": "/dashboard/offboarding"})
    for proxy_session in session.scalars(select(ProxySession).where(ProxySession.status == ProxySessionStatus.PAUSED_SECURITY_REVIEW)):
        items.append({"tone": "warn", "tag": "Proxy session paused", "what": proxy_session.purpose, "why": proxy_session.pause_reason or "", "href": "/dashboard/proxies"})
    return items


def _overview(container: Container) -> dict[str, Any]:
    now = container.clock.now()
    with container.uow() as session:
        accounts = session.scalars(select(InstagramAccount).order_by(InstagramAccount.created_at)).all()
        latest_run = session.scalar(select(AuditRun).order_by(AuditRun.started_at.desc()).limit(1))
        return {
            "accounts": [account_view(session, a, now, container.provisioning.provisioning_gaps(a)) for a in accounts],
            "attention": _attention(session, now),
            "notifications": [notification_view(n) for n in session.scalars(select(Notification).order_by(Notification.created_at.desc()).limit(5))],
            "latest_run": {"id": latest_run.id, "status": latest_run.status.value, "trigger": latest_run.trigger.value, "at": iso(latest_run.started_at), "totals": (latest_run.summary or {}).get("totals", {})} if latest_run else None,
        }


def _accounts(container: Container) -> dict[str, Any]:
    now = container.clock.now()
    with container.uow() as session:
        accounts = session.scalars(select(InstagramAccount).order_by(InstagramAccount.created_at)).all()
        return {"accounts": [account_view(session, a, now, container.provisioning.provisioning_gaps(a)) for a in accounts]}


def _account(container: Container, account_id: str) -> dict[str, Any]:
    with container.uow() as session:
        account = container.provisioning.get_account(session, account_id)
        return {"account": account_view(session, account, container.clock.now(), container.provisioning.provisioning_gaps(account))}


TASK_VIEWS = {
    "open": "Open", "overdue": "Overdue", "blocked": "Blocked", "completed": "Completed", "all": "All",
}


def _tasks(container: Container, view: str) -> dict[str, Any]:
    now = container.clock.now()
    query = select(HumanTask)
    if view == "open":
        query = query.where(HumanTask.status.in_(list(ACTIVE_STATUSES))).order_by(HumanTask.due_at)
    elif view == "overdue":
        query = query.where(HumanTask.status.in_(list(ACTIVE_STATUSES)), HumanTask.status != TaskStatus.BLOCKED, HumanTask.due_at < now).order_by(HumanTask.due_at)
    elif view == "blocked":
        query = query.where(HumanTask.status == TaskStatus.BLOCKED).order_by(HumanTask.due_at)
    elif view == "completed":
        query = query.where(HumanTask.status == TaskStatus.COMPLETED).order_by(HumanTask.completed_at.desc())
    else:
        query = query.order_by(HumanTask.created_at.desc())
    with container.uow() as session:
        return {"tasks": [task_view(t, now) for t in session.scalars(query.limit(300))], "view": view, "views": TASK_VIEWS}


def _task(container: Container, task_id: str) -> dict[str, Any]:
    with container.uow() as session:
        task = container.tasks.get(session, task_id)
        spec = get_spec(task.task_type)
        account = session.get(InstagramAccount, task.account_id) if task.account_id else None
        return {
            "task": task_view(task, container.clock.now(), detail=True),
            "fields": spec.outcome_fields,
            "evidence_hint": spec.evidence_hint,
            "account_name": account.brand_name if account else None,
        }


def _audit(container: Container) -> dict[str, Any]:
    with container.uow() as session:
        findings = sorted(
            (finding_view(f) for f in session.scalars(select(AuditFinding).where(AuditFinding.status == FindingStatus.OPEN))),
            key=lambda f: (_SEVERITY_RANK[f["severity"]], f["check_name"]),
        )
        resolved = [finding_view(f) for f in session.scalars(
            select(AuditFinding).where(AuditFinding.status == FindingStatus.RESOLVED).order_by(AuditFinding.resolved_at.desc()).limit(10)
        )]
        runs = [
            {"id": r.id, "trigger": r.trigger.value, "status": r.status.value, "key": r.idempotency_key, "started_at": iso(r.started_at),
             "attempts": r.attempt_count, "totals": (r.summary or {}).get("totals", {}), "checks": (r.summary or {}).get("accounts", [])}
            for r in session.scalars(select(AuditRun).order_by(AuditRun.started_at.desc()).limit(10))
        ]
    return {"findings": findings, "resolved": resolved, "runs": runs, "latest": runs[0] if runs else None, "legend": LABEL_LEGEND}


def _offboarding(container: Container) -> dict[str, Any]:
    with container.uow() as session:
        return {"cases": [case_view(c) for c in session.scalars(select(OffboardingCase).order_by(OffboardingCase.created_at.desc()))]}


def _proxies(container: Container) -> dict[str, Any]:
    with container.uow() as session:
        return {
            "proxies": [proxy_view(p) for p in session.scalars(select(ProxyEndpoint).order_by(ProxyEndpoint.priority, ProxyEndpoint.id))],
            "sessions": [proxy_session_view(s) for s in session.scalars(select(ProxySession).order_by(ProxySession.started_at.desc()).limit(20))],
            "events": [proxy_event_view(e) for e in session.scalars(select(ProxyEvent).order_by(ProxyEvent.id.desc()).limit(25))],
            "healthcheck_url": container.settings.proxy_healthcheck_default_url,
        }


def _notifications(container: Container) -> dict[str, Any]:
    with container.uow() as session:
        return {"notifications": [notification_view(n) for n in session.scalars(select(Notification).order_by(Notification.created_at.desc()).limit(200))]}


# ---------------------------------------------------------------- pages
@router.get("/dashboard")
async def dashboard(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "dashboard.html", "overview", _overview)


@router.get("/dashboard/accounts")
async def accounts_page(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "accounts.html", "accounts", _accounts)


@router.get("/dashboard/accounts/{account_id}")
async def account_page(account_id: str, request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "account.html", "accounts", _account, account_id)


@router.get("/dashboard/tasks")
async def tasks_page(request: Request, view: str = Query("open"), container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "tasks.html", "tasks", _tasks, view if view in TASK_VIEWS else "open")


@router.get("/dashboard/tasks/{task_id}")
async def task_page(task_id: str, request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "task.html", "tasks", _task, task_id)


@router.get("/dashboard/audit")
async def audit_page(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "audit.html", "audit", _audit)


@router.get("/dashboard/offboarding")
async def offboarding_page(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "offboarding.html", "offboarding", _offboarding)


@router.get("/dashboard/proxies")
async def proxies_page(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "proxies.html", "proxies", _proxies)


@router.get("/dashboard/notifications")
async def notifications_page(request: Request, container: Container = Depends(get_container)) -> HTMLResponse:
    return await _render(request, container, "notifications.html", "notifications", _notifications)


# ---------------------------------------------------------------- actions
@router.post("/dashboard/tasks/{task_id}/{action}")
async def task_action(task_id: str, action: str, request: Request, container: Container = Depends(get_container)) -> Response:
    actor, raw = await run_in_threadpool(_ui_actor, request, container)
    form = dict(await request.form())

    def act(session) -> str:
        if action == "complete":
            outcome = {k[len("outcome."):]: v for k, v in form.items() if k.startswith("outcome.") and v != ""}
            result = container.tasks.complete(
                session, task_id, actor=actor, outcome=outcome,
                evidence_ref=str(form.get("evidence_ref", "")), note=str(form.get("note", "")) or None,
            )
            return "already_completed" if result.already_completed else "completed"
        if action == "start":
            container.tasks.start(session, task_id, actor=actor)
            return "started"
        if action == "block":
            container.tasks.block(session, task_id, actor=actor, reason=str(form.get("reason", "")))
            return "blocked"
        raise PermissionDenied("unknown action")

    def run() -> str:
        _check_csrf(form, container, raw)
        require_permission(actor, Permission.TASKS_WRITE)
        return container.run(act)  # vault/Meta reads in completion handlers stay outside the transaction

    try:
        notice = await run_in_threadpool(run)
    except DomainError as exc:
        ctx = await run_in_threadpool(_task, container, task_id)
        base = await run_in_threadpool(_base, container, actor, raw, "tasks")
        problems = exc.details if isinstance(exc.details, list) else None
        return _page(request, "task.html", {**base, **ctx, "error": exc.message, "problems": problems, "notice": None}, status_code=exc.status_code)
    return RedirectResponse(f"/dashboard/tasks/{task_id}?notice={notice}", status_code=303)


@router.post("/dashboard/run/{job}")
async def run_job(job: str, request: Request, container: Container = Depends(get_container)) -> Response:
    actor, raw = await run_in_threadpool(_ui_actor, request, container)
    form = dict(await request.form())

    await run_in_threadpool(_check_csrf, form, container, raw)  # forged requests get a hard 403

    def run() -> tuple[str, str]:
        if job == "reminders":
            require_permission(actor, Permission.TASKS_RUN_REMINDERS)
            with container.uow() as session:
                container.reminders.run_cycle(session)
            container.notifications.dispatch_pending(container.session_factory)
            return "reminders", "/dashboard/notifications"
        if job == "audit":
            require_permission(actor, Permission.AUDITS_RUN)
            container.audits.run(container.session_factory, trigger=AuditTrigger.MANUAL, actor=actor)
            return "audit", "/dashboard/audit"
        if job == "proxies":
            require_permission(actor, Permission.PROXIES_CHECK)
            container.proxies.check_all(container.session_factory)
            return "proxies", "/dashboard/proxies"
        if job.startswith("offboarding-"):
            require_permission(actor, Permission.OFFBOARDING_WRITE)
            case_id = job[len("offboarding-"):]
            container.run(lambda session: container.offboarding.reconcile(session, container.offboarding.get_case(session, case_id), actor=actor))
            return "reconciled", "/dashboard/offboarding"
        raise PermissionDenied("unknown job")

    try:
        notice, default = await run_in_threadpool(run)
    except DomainError as exc:
        return RedirectResponse(f"{_safe_next(form.get('next'), '/dashboard')}?error={exc.code}", status_code=303)
    return RedirectResponse(f"{_safe_next(form.get('next'), default)}?notice={notice}", status_code=303)
