"""Structured JSON-lines logging with mandatory redaction.

Every record (ours and third-party) passes through the redactor before it is
written. Request bodies are never logged. The run log lives at
``<LOG_DIR>/run_log.jsonl`` and is the source for the exported redacted run log.

Standard event fields: ts, level, correlation_id, event, account_id, task_id,
action, outcome, retry_count, verification_source, error.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security.redaction import Redactor, get_redactor

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

RUN_LOG_FILENAME = "run_log.jsonl"

_STANDARD_ATTRS = set(vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", (), None)).keys()) | {
    "message",
    "asctime",
    "taskName",
}


def new_correlation_id(prefix: str = "req") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class RedactingJsonFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor | None = None):
        super().__init__()
        self._redactor = redactor

    @property
    def redactor(self) -> Redactor:
        return self._redactor or get_redactor()

    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed third-party log call
            message = str(record.msg)
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", None) or correlation_id_var.get(),
            "event": getattr(record, "event", None) or "log",
            "message": message,
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in ("event", "fields", "correlation_id", "color_message"):
                continue
            payload.setdefault(key, value)
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            payload["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": self.formatException(record.exc_info)[-4000:],
            }
        return json.dumps(self.redactor.redact(payload), default=str, ensure_ascii=False)


_held_events: ContextVar[list[tuple[logging.Logger, int, str, dict[str, Any]]] | None] = ContextVar("held_log_events", default=None)


def log_event(logger: logging.Logger, event: str, *, level: int = logging.INFO, message: str | None = None, **fields: Any) -> None:
    """Emit one structured run-log event. ``fields`` are redacted by the formatter."""
    held = _held_events.get()
    if held is not None:
        held.append((logger, level, message or event, {"event": event, "fields": fields}))
        return
    logger.log(level, message or event, extra={"event": event, "fields": fields})


def hold_events() -> tuple[Any, list[tuple[logging.Logger, int, str, dict[str, Any]]]]:
    """Start holding ``log_event`` calls (used while a unit of work might still be rolled back)."""
    events: list[tuple[logging.Logger, int, str, dict[str, Any]]] = []
    return _held_events.set(events), events


def release_events(held: tuple[Any, list[tuple[logging.Logger, int, str, dict[str, Any]]]], *, emit: bool) -> None:
    token, events = held
    _held_events.reset(token)
    if emit:
        for logger, level, message, extra in events:
            log_event(logger, extra["event"], level=level, message=message, **extra["fields"])


def close_logging() -> None:
    """Detach and close all root handlers (releases the run-log file, e.g. before archiving it)."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()


def configure_logging(log_dir: Path, *, level: str = "INFO", to_stdout: bool = True, redactor: Redactor | None = None) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = RedactingJsonFormatter(redactor)
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(level.upper())

    log_path = log_dir / RUN_LOG_FILENAME
    file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    if to_stdout:
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(formatter)
        root.addHandler(stream)

    # Third-party loggers: keep them quiet and route through the redacting handlers.
    for name in ("httpx", "httpcore", "apscheduler", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False
    access.disabled = True  # our middleware logs a redacted access line instead
    return log_path
