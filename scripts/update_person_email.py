"""Change the email address a person receives notifications at (admin, from a shell on the host).

    python -m scripts.update_person_email --from-email owner@old.example --to-email owner@company.example

Notifications already queued use the new address when they are sent. The change is logged with masked
addresses only.
"""

from __future__ import annotations

import argparse
import logging
import re

from sqlalchemy import select

from app.logging_setup import log_event
from app.models import Person
from app.security.secret_handling import mask_email
from scripts._common import cli_container

logger = logging.getLogger("app.people")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from-email", required=True)
    parser.add_argument("--to-email", required=True)
    args = parser.parse_args()
    old, new = args.from_email.strip().lower(), args.to_email.strip().lower()
    if not _EMAIL_RE.match(new) or new.endswith(".invalid"):
        raise SystemExit("--to-email must be a deliverable email address")
    container = cli_container("update-person-email")
    with container.uow() as session:
        person = session.scalar(select(Person).where(Person.email == old))
        if person is None:
            raise SystemExit("no person has that email address")
        if session.scalar(select(Person.id).where(Person.email == new, Person.id != person.id)):
            raise SystemExit("another person already uses that address")
        person.email = new
        person.updated_at = container.clock.now()
        person_id = person.id
        log_event(
            logger, "person.email_changed", action="update_person_email",
            outcome="updated", person_id=person_id, from_hint=mask_email(old), to_hint=mask_email(new),
        )
    print(f"Person {person_id}: notification address changed from {mask_email(old)} to {mask_email(new)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
