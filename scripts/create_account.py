"""Create (or update) the account record, its approved profile spec and its access register.

Idempotent: running it again returns the same account and only adds what is missing.
No secrets are accepted - only names, emails of operators, roles and vault *references*.

    python -m scripts.create_account --brand "Demo Brand" --owner-email you@example.com \
        --profile-name "Demo Brand" --bio "Max 150 characters" --link https://example.com \
        --category "Product/service" --image-ref brandkit://demo/logo.png \
        --assign you@example.com:business_admin --assign friend@example.com:temporary_test_role \
        --access friend@example.com:backup_codes:bw://Instagram/demo/backup-codes
"""

from __future__ import annotations

import argparse
import json

from sqlalchemy import select

from app.enums import CredentialKind, Platform, RoleName
from app.models import Person
from app.security.authorization import SYSTEM_ACTOR
from app.services.provisioning import BIO_MAX_CHARS
from scripts._common import cli_container


def _person(session, email: str) -> Person:
    person = session.scalar(select(Person).where(Person.email == email.lower()))
    if person is None:
        raise SystemExit(f"No person with email {email}. Create them first: python -m scripts.create_operator ...")
    return person


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--brand", required=True)
    parser.add_argument("--owner-email", required=True)
    parser.add_argument("--keyword", action="append", default=[], help="extra handle-suggestion keyword")
    parser.add_argument("--profile-name")
    parser.add_argument("--bio")
    parser.add_argument("--link")
    parser.add_argument("--category")
    parser.add_argument("--image-ref")
    parser.add_argument("--assign", action="append", default=[], metavar="EMAIL:ROLE", help=f"roles: {', '.join(r.value for r in RoleName)}")
    parser.add_argument("--access", action="append", default=[], metavar="EMAIL:KIND:VAULT_REF", help=f"kinds: {', '.join(k.value for k in CredentialKind)}")
    args = parser.parse_args()
    if args.bio is not None and len(args.bio) > BIO_MAX_CHARS:
        raise SystemExit(f"--bio is {len(args.bio)} characters; Instagram allows at most {BIO_MAX_CHARS}")

    container = cli_container("create-account")
    profile = {
        k: v
        for k, v in {
            "profile_name": args.profile_name, "bio": args.bio, "profile_link": args.link,
            "category": args.category, "profile_image_ref": args.image_ref,
        }.items()
        if v
    }
    with container.uow() as session:
        owner = _person(session, args.owner_email)
        account, created = container.provisioning.create_account(
            session, brand_name=args.brand, owner_id=owner.id, actor=SYSTEM_ACTOR, keywords=args.keyword, profile=None, is_synthetic=False
        )
        account_id = account.id
    if profile:
        with container.uow() as session:
            container.provisioning.set_profile_spec(session, account_id, profile, actor=SYSTEM_ACTOR)
    for item in args.assign:
        email, _, role = item.rpartition(":")
        with container.uow() as session:
            container.provisioning.add_assignment(
                session, account_id, person_id=_person(session, email).id, platform=Platform.META_BUSINESS, role=RoleName(role), actor=SYSTEM_ACTOR
            )
    for item in args.access:
        email, kind, ref = item.split(":", 2)
        with container.uow() as session:
            container.provisioning.add_credential_access(
                session, person_id=_person(session, email).id, vault_ref=ref, credential_kind=CredentialKind(kind), account_id=account_id, actor=SYSTEM_ACTOR
            )
    with container.uow() as session:
        account = container.provisioning.get_account(session, account_id)
        print(json.dumps(
            {
                "created": created,
                "account_id": account.id,
                "status": account.provisioning_status.value,
                "handle_suggestions": account.suggested_handles,
                "profile_gaps": [g for g in container.provisioning.provisioning_gaps(account) if "profile" in g],
                "roles": [f"{a.person.full_name}: {a.role.value} ({a.status.value})" for a in account.assignments],
                "next": "open the dashboard and work the open tasks in order",
            },
            indent=2,
        ))


if __name__ == "__main__":
    main()
