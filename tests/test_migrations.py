"""The Alembic migration builds exactly the schema the models describe."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app.database import Base

ROOT = Path(__file__).resolve().parent.parent


def _config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.attributes["database_url"] = url
    config.attributes["configure_logger"] = False
    return config


def test_migrations_apply_match_models_and_downgrade(tmp_path):
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    config = _config(url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []
        indexes = {i["name"] for i in inspect(connection).get_indexes("audit_findings")}
        assert "uq_audit_findings_open_fingerprint" in indexes
    command.downgrade(config, "base")
    with engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
    engine.dispose()
