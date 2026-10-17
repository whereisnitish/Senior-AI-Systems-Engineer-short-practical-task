"""Proxy health, session affinity and controlled failover endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select

from app.container import Container
from app.dependencies import get_container, require
from app.models import ProxyEndpoint, ProxyEvent, ProxySession
from app.schemas import ProxyCheck, ProxyEnd, ProxyRotate, ProxySessionCreate
from app.security.authorization import Actor, Permission
from app.views import proxy_event_view, proxy_session_view, proxy_view

router = APIRouter(prefix="/api/v1/proxies", tags=["proxies"])


@router.get("")
def list_proxies(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> dict[str, Any]:
    with container.uow() as session:
        return {
            "proxies": [proxy_view(p) for p in session.scalars(select(ProxyEndpoint).order_by(ProxyEndpoint.priority, ProxyEndpoint.id))],
            "sessions": [proxy_session_view(s) for s in session.scalars(select(ProxySession).order_by(ProxySession.started_at.desc()).limit(50))],
            "recent_events": [proxy_event_view(e) for e in session.scalars(select(ProxyEvent).order_by(ProxyEvent.id.desc()).limit(50))],
            "allowed_healthcheck_urls": container.settings.proxy_healthcheck_allowed_urls,
        }


@router.post("/health-check")
def check_all(
    body: ProxyCheck | None = None, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.PROXIES_CHECK))
) -> dict[str, Any]:
    return container.proxies.check_all(container.session_factory, (body.url if body else None))


@router.post("/{proxy_id}/health-check")
def check_one(
    proxy_id: str,
    body: ProxyCheck | None = None,
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.PROXIES_CHECK)),
) -> dict[str, Any]:
    return container.proxies.check_proxy(container.session_factory, proxy_id, (body.url if body else None))


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def acquire_session(
    body: ProxySessionCreate,
    response: Response,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.PROXIES_CONTROL)),
) -> dict[str, Any]:
    with container.uow() as session:
        proxy_session, created = container.proxies.acquire_session(session, account_id=body.account_id, purpose=body.purpose, actor=actor)
        if not created:
            response.status_code = status.HTTP_200_OK
        return {"created": created, "session": proxy_session_view(proxy_session)}


@router.get("/sessions")
def list_sessions(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        return [proxy_session_view(s) for s in session.scalars(select(ProxySession).order_by(ProxySession.started_at.desc()))]


@router.post("/sessions/{session_id}/probe")
def probe_session(
    session_id: str,
    body: ProxyCheck | None = None,
    container: Container = Depends(get_container),
    _: Actor = Depends(require(Permission.PROXIES_CONTROL)),
) -> dict[str, Any]:
    return container.proxies.request_via_session(container.session_factory, session_id, url=(body.url if body else None))


@router.post("/sessions/{session_id}/failover")
def controlled_failover(
    session_id: str, body: ProxyRotate, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.PROXIES_CONTROL))
) -> dict[str, Any]:
    return container.proxies.rotate_session(container.session_factory, session_id, reason=body.reason, url=body.url)


@router.post("/sessions/{session_id}/end")
def end_session(
    session_id: str, body: ProxyEnd, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.PROXIES_CONTROL))
) -> dict[str, Any]:
    with container.uow() as session:
        return proxy_session_view(container.proxies.end_session(session, session_id, reason=body.reason))
