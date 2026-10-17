"""FastAPI application factory."""

from __future__ import annotations

import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api import (
    accounts,
    audits,
    dashboard,
    health,
    offboarding,
    people,
    proxies,
    reports,
    tasks,
)
from app.config import Settings, get_settings
from app.container import Container, build_container
from app.errors import DomainError, TooManyAttempts
from app.logging_setup import (
    configure_logging,
    correlation_id_var,
    log_event,
    new_correlation_id,
)
from app.services.recovery import run_startup_recovery
from app.services.scheduler import OpsScheduler

logger = logging.getLogger("app.http")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._\-]{8,64}$")
_DOCS_PATHS = ("/docs", "/openapi.json", "/redoc")
_CSP = (
    "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'none'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
)


def _error(status_code: int, code: str, message: str, details=None, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message, "details": details, "correlation_id": correlation_id_var.get()}},
        status_code=status_code,
        headers=headers,
    )


def create_app(settings: Settings | None = None, container: Container | None = None, *, run_recovery: bool = True) -> FastAPI:
    settings = settings or (container.settings if container else get_settings())
    container = container or build_container(settings)
    configure_logging(settings.log_dir, level=settings.log_level, to_stdout=settings.log_to_stdout, redactor=container.redactor)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        token = correlation_id_var.set(new_correlation_id("startup"))
        try:
            if run_recovery:
                run_startup_recovery(container)
            if settings.scheduler_enabled:
                scheduler = OpsScheduler(container)
                scheduler.start()
                container.scheduler = scheduler
            log_event(logger, "app.started", action="startup", outcome="ready", version=__version__, app_env=settings.app_env, vault=container.vault.name)
        finally:
            correlation_id_var.reset(token)
        yield
        if isinstance(container.scheduler, OpsScheduler):
            container.scheduler.shutdown()
        log_event(logger, "app.stopped", action="shutdown", outcome="stopped")

    docs = settings.docs_are_enabled
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Coordinates human tasks, verification, audits, offboarding and proxy health for one company-authorised Instagram account. No Instagram automation.",
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    app.state.container = container

    if settings.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID", "Idempotency-Key"],
        )

    @app.middleware("http")
    async def correlation_and_security(request: Request, call_next):
        incoming = request.headers.get("x-correlation-id", "")
        cid = incoming if _CORRELATION_RE.match(incoming) else new_correlation_id()
        token = correlation_id_var.set(cid)
        started = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:  # noqa: BLE001 - convert to a safe, redacted 500
                logger.exception("unhandled error", extra={"event": "http.unhandled_error", "fields": {"path": request.url.path}})
                response = _error(500, "internal_error", "An internal error occurred. Quote the correlation_id when reporting it.")
            response.headers["X-Correlation-ID"] = cid
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers.setdefault("Cache-Control", "no-store")
            if not request.url.path.startswith(_DOCS_PATHS):
                response.headers["Content-Security-Policy"] = _CSP
            if settings.app_env == "production":
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            # Never log bodies or query strings; path + status + timing only.
            log_event(
                logger,
                "http.request",
                action=f"{request.method} {request.url.path}",
                outcome=str(response.status_code),
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
                actor_id=getattr(request.state, "actor_id", None),
            )
            return response
        finally:
            correlation_id_var.reset(token)

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        if isinstance(exc, TooManyAttempts):
            headers = {"Retry-After": str(exc.retry_after)}
        if exc.status_code >= 500:
            log_event(logger, "http.integration_error", level=logging.WARNING, outcome=exc.code, error=exc.message)
        return _error(exc.status_code, exc.code, exc.message, exc.details, headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Submitted values are never echoed back (they could be secrets pasted by mistake).
        details = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        return _error(422, "validation_failed", "Request validation failed", details)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error(exc.status_code, "http_error", str(exc.detail) if exc.status_code < 500 else "error")

    @app.exception_handler(dashboard.UiLoginRequired)
    async def ui_login_required(request: Request, exc: dashboard.UiLoginRequired) -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    for module in (health, people, accounts, tasks, audits, offboarding, proxies, reports, dashboard):
        app.include_router(module.router)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")
    return app
