"""FastAPI dependencies: container access, bearer authentication, permissions."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request

from app.container import Container
from app.errors import AuthenticationRequired
from app.security.authentication import authenticate_token
from app.security.authorization import Actor, Permission, require_permission


def get_container(request: Request) -> Container:
    return request.app.state.container


def current_actor(request: Request, container: Container = Depends(get_container)) -> Actor:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationRequired("Missing bearer token")
    client = request.client.host if request.client else "unknown"
    container.auth_throttle.check(client)  # over the limit: refused before any token is checked
    try:
        with container.uow() as session:
            actor = authenticate_token(
                session, token.strip(), secret_key=container.settings.secret_key_bytes, now=container.clock.now()
            )
    except AuthenticationRequired:
        container.auth_throttle.record_failure(client)
        raise
    container.auth_throttle.record_success(client)
    request.state.actor_id = actor.person_id
    return actor


def require(permission: Permission) -> Callable[..., Actor]:
    def dependency(actor: Actor = Depends(current_actor)) -> Actor:
        require_permission(actor, permission)
        return actor

    dependency.__name__ = f"require_{permission.value.replace(':', '_')}"
    return dependency
