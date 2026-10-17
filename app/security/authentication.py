"""Operator authentication.

API clients use ``Authorization: Bearer iom_...`` tokens. The dashboard uses a
server-side session (``ius_...`` cookie, HttpOnly, SameSite=Strict, Secure in
production) plus an HMAC-derived CSRF token on every form.

Only HMAC-SHA256 digests (keyed with APP_SECRET_KEY) of tokens are stored, so a
database leak does not leak usable credentials. There is no default admin and no
hard-coded password: the first admin is bootstrapped explicitly with
``python -m scripts.create_operator``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.enums import OperatorRole, PersonStatus
from app.errors import AuthenticationRequired
from app.models import ApiCredential, Person, UiSession, new_id
from app.security.authorization import Actor

API_TOKEN_PREFIX = "iom_"
UI_SESSION_PREFIX = "ius_"
_MAX_TOKEN_LEN = 100
_LAST_USED_RESOLUTION = timedelta(minutes=5)


def generate_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def hmac_hex(secret_key: bytes, value: str) -> str:
    return hmac.new(secret_key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_api_credential(
    session: Session,
    *,
    person: Person,
    role: OperatorRole,
    label: str,
    secret_key: bytes,
    now: datetime,
) -> tuple[ApiCredential, str]:
    """Create a credential and return the raw token. The raw token is shown once and never stored."""
    raw = generate_token(API_TOKEN_PREFIX)
    credential = ApiCredential(
        id=new_id("crd"),
        person_id=person.id,
        label=label[:80],
        token_prefix=raw[:10],
        token_hash=hmac_hex(secret_key, raw),
        role=role,
        active=True,
        created_at=now,
    )
    session.add(credential)
    session.flush()
    return credential, raw


def _actor_for(credential: ApiCredential) -> Actor:
    return Actor(
        person_id=credential.person_id,
        role=credential.role.value,
        credential_id=credential.id,
        display_name=credential.person.full_name if credential.person else "",
    )


def authenticate_token(session: Session, raw_token: str, *, secret_key: bytes, now: datetime) -> Actor:
    if not raw_token or len(raw_token) > _MAX_TOKEN_LEN or not raw_token.startswith(API_TOKEN_PREFIX):
        raise AuthenticationRequired("Invalid or missing credentials")
    credential = session.scalar(select(ApiCredential).where(ApiCredential.token_hash == hmac_hex(secret_key, raw_token)))
    if credential is None or not credential.active or credential.revoked_at is not None:
        raise AuthenticationRequired("Invalid or missing credentials")
    if credential.person is None or credential.person.status == PersonStatus.OFFBOARDED:
        raise AuthenticationRequired("Invalid or missing credentials")
    if credential.last_used_at is None or now - credential.last_used_at > _LAST_USED_RESOLUTION:
        credential.last_used_at = now
    return _actor_for(credential)


def revoke_person_credentials(session: Session, person_id: str, *, now: datetime, reason: str) -> int:
    """Deactivate every API credential and dashboard session of a person. Idempotent."""
    credentials = session.scalars(
        select(ApiCredential).where(ApiCredential.person_id == person_id, ApiCredential.active.is_(True))
    ).all()
    for credential in credentials:
        credential.active = False
        credential.revoked_at = now
        credential.revoked_reason = reason[:200]
    credential_ids = select(ApiCredential.id).where(ApiCredential.person_id == person_id)
    session.execute(
        update(UiSession)
        .where(UiSession.credential_id.in_(credential_ids), UiSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    return len(credentials)


def revoke_other_credentials(session: Session, person_id: str, *, keep_credential_id: str, now: datetime, reason: str) -> int:
    """Deactivate every active credential of a person except one (token rotation), with their dashboard sessions."""
    others = session.scalars(
        select(ApiCredential).where(
            ApiCredential.person_id == person_id, ApiCredential.active.is_(True), ApiCredential.id != keep_credential_id
        )
    ).all()
    for credential in others:
        credential.active = False
        credential.revoked_at = now
        credential.revoked_reason = reason[:200]
    if others:
        session.execute(
            update(UiSession)
            .where(UiSession.credential_id.in_([c.id for c in others]), UiSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
    return len(others)


def active_credential_count(session: Session, person_id: str) -> int:
    return len(
        session.scalars(
            select(ApiCredential.id).where(ApiCredential.person_id == person_id, ApiCredential.active.is_(True))
        ).all()
    )


# -- dashboard sessions ---------------------------------------------------------


def create_ui_session(
    session: Session, credential_id: str, *, secret_key: bytes, now: datetime, hours: int
) -> str:
    raw = generate_token(UI_SESSION_PREFIX)
    session.add(
        UiSession(
            id=new_id("uis"),
            credential_id=credential_id,
            session_hash=hmac_hex(secret_key, raw),
            created_at=now,
            expires_at=now + timedelta(hours=hours),
        )
    )
    session.flush()
    return raw


def authenticate_ui_session(session: Session, raw: str | None, *, secret_key: bytes, now: datetime) -> Actor:
    if not raw or len(raw) > _MAX_TOKEN_LEN or not raw.startswith(UI_SESSION_PREFIX):
        raise AuthenticationRequired("Please sign in")
    record = session.scalar(select(UiSession).where(UiSession.session_hash == hmac_hex(secret_key, raw)))
    if record is None or record.revoked_at is not None or record.expires_at <= now:
        raise AuthenticationRequired("Session expired; please sign in again")
    credential = record.credential
    if not credential.active or credential.person.status == PersonStatus.OFFBOARDED:
        raise AuthenticationRequired("Session expired; please sign in again")
    return _actor_for(credential)


def revoke_ui_session(session: Session, raw: str | None, *, secret_key: bytes, now: datetime) -> None:
    if not raw:
        return
    record = session.scalar(select(UiSession).where(UiSession.session_hash == hmac_hex(secret_key, raw)))
    if record is not None and record.revoked_at is None:
        record.revoked_at = now


def csrf_token(secret_key: bytes, raw_session: str) -> str:
    return hmac_hex(secret_key, "csrf:" + raw_session)


def verify_csrf(secret_key: bytes, raw_session: str | None, submitted: str | None) -> bool:
    if not raw_session or not submitted:
        return False
    return hmac.compare_digest(csrf_token(secret_key, raw_session), submitted)
