"""Deterministic handle suggestions and format validation.

A suggestion only means the string satisfies Instagram's documented username
format (letters, digits, periods, underscores; max 30 characters). It says
nothing about availability: availability is checked by a human in the official
Instagram interface. Nothing here contacts Instagram.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

HANDLE_MAX_LEN = 30
_ALLOWED = re.compile(r"^[a-z0-9._]+$")
_LEGAL_SUFFIXES = {"inc", "ltd", "llc", "plc", "gmbh", "limited", "corp"}
AVAILABILITY_NOTE = "format-checked only; availability unknown until a human checks in the official Instagram interface"


def normalize_handle(handle: str) -> str:
    return (handle or "").strip().lstrip("@").lower()


def handle_problems(handle: str) -> list[str]:
    problems: list[str] = []
    if not handle:
        return ["handle is empty"]
    if len(handle) > HANDLE_MAX_LEN:
        problems.append(f"longer than {HANDLE_MAX_LEN} characters")
    if not _ALLOWED.match(handle):
        problems.append("only lowercase letters, digits, periods and underscores are allowed")
    if handle.startswith(".") or handle.endswith("."):
        problems.append("cannot start or end with a period")
    if ".." in handle:
        problems.append("cannot contain consecutive periods")
    if handle.replace(".", "").replace("_", "").isdigit():
        problems.append("cannot consist only of digits")
    return problems


def brand_tokens(brand_name: str) -> list[str]:
    folded = unicodedata.normalize("NFKD", brand_name or "").encode("ascii", "ignore").decode("ascii")
    tokens = [t for t in re.findall(r"[a-z0-9]+", folded.lower()) if t not in _LEGAL_SUFFIXES]
    return tokens or ["brand"]


def brand_key(brand_name: str) -> str:
    return "-".join(brand_tokens(brand_name))[:80]


def suggest_handles(brand_name: str, keywords: Iterable[str] = (), limit: int = 8) -> list[str]:
    tokens = brand_tokens(brand_name)
    joined = "".join(tokens)
    initials = "".join(t[0] for t in tokens)
    extra = [re.sub(r"[^a-z0-9]", "", normalize_handle(k)) for k in keywords]
    candidates = [
        joined,
        "_".join(tokens),
        ".".join(tokens),
        *(f"{joined}_{k}" for k in extra if k),  # operator-supplied keywords rank early
        f"{joined}official",
        f"{joined}_hq",
        f"the{joined}",
        f"{joined}.team",
        f"{joined}_studio",
        f"{initials}_{tokens[-1]}" if len(tokens) > 1 else f"{joined}_app",
    ]
    out: list[str] = []
    for index, candidate in enumerate(candidates):
        if len(candidate) > HANDLE_MAX_LEN:
            if index:  # variants that do not fit are dropped rather than cut mid-word
                continue
            candidate = candidate[:HANDLE_MAX_LEN].rstrip("._")
        if candidate and not handle_problems(candidate) and candidate not in out:
            out.append(candidate)
    return out[:limit]
