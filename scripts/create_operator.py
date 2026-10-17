"""Bootstrap an operator (person + API token) - the only way to create the first admin.

There is no default administrator and no default password. The token is printed
once (or written to --token-file) and only its HMAC is stored.

    python -m scripts.create_operator --name "Sam Rivera" --email sam@company.example --role admin
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from sqlalchemy import select

from app.enums import OperatorRole, Responsibility
from app.models import Person, new_id
from app.security.authentication import issue_api_credential
from scripts._common import cli_container


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--role", required=True, choices=[r.value for r in OperatorRole])
    parser.add_argument("--label", default="cli-bootstrap")
    parser.add_argument("--supervisor-email")
    parser.add_argument("--responsibility", action="append", default=[], choices=[r.value for r in Responsibility])
    parser.add_argument("--token-file", type=Path, help="write the token to this file instead of printing it")
    args = parser.parse_args()

    container = cli_container("create-operator")
    with container.uow() as session:
        person = session.scalar(select(Person).where(Person.email == args.email.lower()))
        supervisor_id = None
        if args.supervisor_email:
            supervisor = session.scalar(select(Person).where(Person.email == args.supervisor_email.lower()))
            if supervisor is None:
                raise SystemExit("supervisor not found - create them first")
            supervisor_id = supervisor.id
        now = container.clock.now()
        if person is None:
            person = Person(
                id=new_id("per"), full_name=args.name, email=args.email.lower(), supervisor_id=supervisor_id,
                responsibilities=sorted(set(args.responsibility)), created_at=now, updated_at=now,
            )
            session.add(person)
            session.flush()
        else:
            person.responsibilities = sorted(set(person.responsibilities or []) | set(args.responsibility))
        _, token = issue_api_credential(
            session, person=person, role=OperatorRole(args.role), label=args.label,
            secret_key=container.settings.secret_key_bytes, now=now,
        )
        person_id = person.id

    if args.token_file:
        args.token_file.parent.mkdir(parents=True, exist_ok=True)
        args.token_file.write_text(token + "\n", encoding="utf-8")
        try:
            os.chmod(args.token_file, 0o600)
        except OSError:
            pass
        print(f"Operator {person_id} ({args.role}) created. Token written to {args.token_file}.")
        print("Move it into your password manager and delete the file.")
    else:
        print(f"Operator {person_id} ({args.role}) created.")
        print("API token (shown once - store it in your password manager now):")
        print(token)


if __name__ == "__main__":
    main()
