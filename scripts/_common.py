"""Shared CLI bootstrap: settings, container, redacted file logging, schema check."""

from __future__ import annotations

import sys

from sqlalchemy import inspect

from app.clock import Clock
from app.config import Settings, get_settings
from app.container import Container, build_container
from app.logging_setup import configure_logging, correlation_id_var, new_correlation_id

REQUIRED_TABLES = {"people", "instagram_accounts", "human_tasks", "audit_runs", "offboarding_cases", "proxy_endpoints"}


def cli_container(name: str, settings: Settings | None = None, clock: Clock | None = None, *, check_schema: bool = True) -> Container:
    settings = settings or get_settings()
    container = build_container(settings, clock=clock)
    # CLI output stays human-readable; the structured, redacted log goes to LOG_DIR/run_log.jsonl.
    configure_logging(settings.log_dir, level=settings.log_level, to_stdout=False, redactor=container.redactor)
    correlation_id_var.set(new_correlation_id(f"cli-{name}"))
    if check_schema:
        missing = REQUIRED_TABLES - set(inspect(container.engine).get_table_names())
        if missing:
            print("Database schema is missing. Run:  python -m scripts.init_db", file=sys.stderr)
            sys.exit(2)
    return container
