"""Apply database migrations: ``python -m scripts.init_db`` (equivalent to ``alembic upgrade head``)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

from app.config import DatabaseSettings

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    url = DatabaseSettings().database_url
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.attributes["database_url"] = url
    config.attributes["configure_logger"] = False
    command.upgrade(config, "head")
    print(f"Database migrated to head: {make_url(url).render_as_string(hide_password=True)}")


if __name__ == "__main__":
    main()
