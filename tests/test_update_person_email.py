"""scripts/update_person_email.py: change where a person's notifications go."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import Person


@pytest.fixture
def run_cli(env, monkeypatch):
    import scripts.update_person_email as cli

    monkeypatch.setattr(cli, "cli_container", lambda _name: env.container)

    def run(*argv: str) -> None:
        monkeypatch.setattr("sys.argv", ["update_person_email", *argv])
        cli.main()

    return run


def test_email_is_changed_and_logged_masked(env, run_cli):
    person_id = env.person("Sam Rivera")
    run_cli("--from-email", "sam.rivera@testco.example", "--to-email", "Sam.Real@Mail.Example")
    with env.container.uow() as s:
        assert s.get(Person, person_id).email == "sam.real@mail.example"
    logs = env.read_logs()
    assert "person.email_changed" in logs and "sam.real@mail.example" not in logs


def test_undeliverable_duplicate_or_unknown_addresses_are_refused(env, run_cli):
    env.person("Sam Rivera")
    env.person("Alex Chen")
    with pytest.raises(SystemExit, match="deliverable"):
        run_cli("--from-email", "sam.rivera@testco.example", "--to-email", "owner@brand.invalid")
    with pytest.raises(SystemExit, match="already uses"):
        run_cli("--from-email", "sam.rivera@testco.example", "--to-email", "alex.chen@testco.example")
    with pytest.raises(SystemExit, match="no person"):
        run_cli("--from-email", "nobody@testco.example", "--to-email", "x@mail.example")
    with env.container.uow() as s:
        assert s.scalar(select(Person.email).where(Person.full_name == "Sam Rivera")) == "sam.rivera@testco.example"
