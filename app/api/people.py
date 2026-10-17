"""Personnel records, operator credentials and the credential-access register."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.container import Container
from app.dependencies import get_container, require
from app.enums import OffboardingCaseStatus
from app.errors import Conflict, NotFound
from app.logging_setup import log_event
from app.models import CredentialAccess, OffboardingCase, Person, new_id
from app.schemas import CredentialAccessCreate, CredentialCreate, PersonCreate
from app.security.authentication import issue_api_credential
from app.security.authorization import Actor, Permission
from app.views import iso, person_view

router = APIRouter(prefix="/api/v1/people", tags=["people"])
logger = logging.getLogger("app.api.people")


@router.get("")
def list_people(container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))) -> list[dict[str, Any]]:
    with container.uow() as session:
        return [person_view(p) for p in session.scalars(select(Person).order_by(Person.created_at))]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_person(
    body: PersonCreate, container: Container = Depends(get_container), actor: Actor = Depends(require(Permission.PEOPLE_MANAGE))
) -> dict[str, Any]:
    with container.uow() as session:
        if session.scalar(select(Person).where(Person.email == body.email.lower())):
            raise Conflict("a person with that email already exists")
        if body.supervisor_id and session.get(Person, body.supervisor_id) is None:
            raise NotFound("supervisor not found")
        now = container.clock.now()
        person = Person(
            id=new_id("per"),
            full_name=body.full_name,
            email=body.email.lower(),
            supervisor_id=body.supervisor_id,
            responsibilities=[r.value for r in body.responsibilities],
            is_synthetic=body.is_synthetic,
            created_at=now,
            updated_at=now,
        )
        session.add(person)
        session.flush()
        log_event(logger, "person.created", action="create_person", outcome="created", person_id=person.id, actor_id=actor.audit_id)
        return person_view(person)


@router.post("/{person_id}/credentials", status_code=status.HTTP_201_CREATED)
def issue_credential(
    person_id: str,
    body: CredentialCreate,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.PEOPLE_MANAGE)),
) -> JSONResponse:
    with container.uow() as session:
        person = session.get(Person, person_id)
        if person is None or person.status.value != "active":
            raise NotFound("active person not found")
        credential, raw = issue_api_credential(
            session, person=person, role=body.role, label=body.label,
            secret_key=container.settings.secret_key_bytes, now=container.clock.now(),
        )
        log_event(logger, "credential.issued", action="issue_credential", outcome="issued", person_id=person.id, role=body.role.value, actor_id=actor.audit_id)
        payload = {
            "credential_id": credential.id,
            "role": credential.role.value,
            "token": raw,
            "warning": "This token is shown exactly once. Store it in your password manager; it cannot be recovered.",
        }
    return JSONResponse(payload, status_code=201, headers={"Cache-Control": "no-store"})


@router.post("/{person_id}/credential-access", status_code=status.HTTP_201_CREATED)
def record_credential_access(
    person_id: str,
    body: CredentialAccessCreate,
    container: Container = Depends(get_container),
    actor: Actor = Depends(require(Permission.ACCESS_REGISTER_WRITE)),
) -> dict[str, Any]:
    def op(session) -> dict[str, Any]:
        access = container.provisioning.add_credential_access(
            session, person_id=person_id, vault_ref=body.vault_ref, credential_kind=body.credential_kind,
            account_id=body.account_id, actor=actor,
        )
        case = session.scalar(
            select(OffboardingCase).where(OffboardingCase.person_id == person_id, OffboardingCase.status == OffboardingCaseStatus.OPEN)
        )
        if case is not None:
            # Access found during offboarding must be removed and rotated before the case can close.
            container.offboarding.reconcile(session, case, actor=actor)
        return _access_view(access)

    return container.run(op)


@router.get("/{person_id}/credential-access")
def list_credential_access(
    person_id: str, container: Container = Depends(get_container), _: Actor = Depends(require(Permission.READ))
) -> list[dict[str, Any]]:
    with container.uow() as session:
        rows = session.scalars(select(CredentialAccess).where(CredentialAccess.person_id == person_id)).all()
        return [_access_view(a) for a in rows]


def _access_view(access: CredentialAccess) -> dict[str, Any]:
    return {
        "id": access.id,
        "person_id": access.person_id,
        "account_id": access.account_id,
        "vault_ref": access.vault_ref,
        "credential_kind": access.credential_kind.value,
        "status": access.status.value,
        "granted_at": iso(access.granted_at),
        "revoked_at": iso(access.revoked_at),
    }
