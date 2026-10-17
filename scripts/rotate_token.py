"""Rotate a person's API token: issue a new one, then revoke every other token and dashboard session they hold.

    python -m scripts.rotate_token --email owner@company.example --token-file data/live_owner_token.local.txt

The new token is written to --token-file only (never printed). Use this whenever a token may have been
exposed, e.g. pasted into a chat or a ticket. Move it into your password manager and delete the file.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from sqlalchemy import select

from app.enums import OperatorRole
from app.logging_setup import log_event
from app.models import ApiCredential, Person
from app.security.authentication import issue_api_credential, revoke_other_credentials
from scripts._common import cli_container

logger = logging.getLogger("app.auth")
_RANK = {OperatorRole.VIEWER: 0, OperatorRole.AUDITOR: 1, OperatorRole.OPERATOR: 2, OperatorRole.ADMIN: 3}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--email", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    container = cli_container("rotate-token")
    with container.uow() as session:
        person = session.scalar(select(Person).where(Person.email == args.email.strip().lower()))
        if person is None:
            raise SystemExit("no person has that email address")
        active = list(session.scalars(select(ApiCredential).where(ApiCredential.person_id == person.id, ApiCredential.active.is_(True))))
        if not active:
            raise SystemExit("this person has no active token to rotate; issue one with scripts.create_operator")
        role = max((c.role for c in active), key=lambda r: _RANK[r])
        now = container.clock.now()
        credential, token = issue_api_credential(
            session, person=person, role=role, label="rotated", secret_key=container.settings.secret_key_bytes, now=now
        )
        revoked = revoke_other_credentials(
            session, person.id, keep_credential_id=credential.id, now=now, reason="rotated: the previous token may have been exposed"
        )
        log_event(logger, "auth.token_rotated", action="rotate_token", outcome="rotated", person_id=person.id, revoked_count=revoked)
        person_id = person.id
    args.token_file.parent.mkdir(parents=True, exist_ok=True)
    args.token_file.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(args.token_file, 0o600)
    except OSError:
        pass
    print(f"Token rotated for {person_id} ({role.value}): {revoked} old token(s) and their dashboard sessions revoked.")
    print(f"The new token is in {args.token_file} (not shown). Store it in your password manager, then delete the file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
