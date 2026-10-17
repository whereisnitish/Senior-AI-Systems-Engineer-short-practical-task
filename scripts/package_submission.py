"""Build the submission zip without local secrets or runtime state.

This folder is not necessarily a git repository, so ``.gitignore`` protects nothing
when it is zipped by hand. This script applies the same exclusions explicitly, then
scans every included file for the secrets that exist on this machine (APP_SECRET_KEY
values from the env files, operator tokens in local token files) and for token
formats. Any hit aborts the build; nothing is written.

    python -m scripts.package_submission [--out ../instagram-ops-submission.zip]

Secrets are never printed: findings name the file and the kind of secret only.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "data", "logs", "secrets", "vault-data", ".git"}
EXCLUDED_FILES = (
    ".env", ".env.*", "*.local.json", "*.synthetic.json", "*token*.txt", "vault-token*", "*.pem", "*.key", "*.p12",
    "*.db", "*.db-wal", "*.db-shm", "*.bak", "*.tmp", "*.pyc", "*proxy-list*.json", "*.exe", "*.dll",
)
KEPT_DESPITE_PATTERNS = {".env.example"}
EXCLUDED_PATHS = {"config/proxies.json"}

TOKEN_PATTERNS = {
    "operator token": re.compile(r"\biom_[A-Za-z0-9_\-]{16,}"),
    "dashboard session": re.compile(r"\bius_[A-Za-z0-9_\-]{16,}"),
    "vault token": re.compile(r"\bhv[sbr]\.[A-Za-z0-9_\-]{16,}"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
# Test modules deliberately contain fake token-shaped strings to exercise the redactor.
PATTERN_SCAN_EXEMPT_DIRS = ("tests/",)


def _excluded(rel: str) -> bool:
    parts = rel.split("/")
    if any(part in EXCLUDED_DIRS for part in parts[:-1]) or rel in EXCLUDED_PATHS:
        return True
    name = parts[-1]
    return name not in KEPT_DESPITE_PATTERNS and any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED_FILES)


def _known_secrets(root: Path) -> dict[str, str]:
    """kind -> value, for every secret this machine holds locally. Values never leave this function's callers."""
    found: dict[str, str] = {}
    for env_file in sorted(root.glob(".env*")):
        if env_file.name == ".env.example":
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "APP_SECRET_KEY" and len(value.strip()) >= 16:
                found[f"APP_SECRET_KEY from {env_file.name}"] = value.strip()
    data = root / "data"
    for path in sorted(data.glob("*token*")) + sorted(data.glob("*.local.json")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for index, match in enumerate(TOKEN_PATTERNS["operator token"].findall(text)):
            found[f"operator token #{index + 1} from data/{path.name}"] = match
    return found


def _scan(rel: str, text: str, secrets: dict[str, str]) -> list[str]:
    problems = [f"{rel}: contains {kind}" for kind, value in secrets.items() if value in text]
    if not rel.startswith(PATTERN_SCAN_EXEMPT_DIRS):
        problems += [f"{rel}: contains a {kind}-shaped string" for kind, pattern in TOKEN_PATTERNS.items() if pattern.search(text)]
    return problems


def build(out: Path) -> int:
    secrets = _known_secrets(ROOT)
    included: list[tuple[Path, str]] = []
    excluded = 0
    for path in sorted(p for p in ROOT.rglob("*") if p.is_file()):
        rel = path.relative_to(ROOT).as_posix()
        if _excluded(rel):
            excluded += 1
        else:
            included.append((path, rel))
    problems: list[str] = []
    for path, rel in included:
        problems += _scan(rel, path.read_bytes().decode("utf-8", errors="replace"), secrets)
    if problems:
        print("REFUSED: secret material found in files that would be shipped (nothing was written):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, rel in included:
            archive.write(path, f"{ROOT.name}/{rel}")
    print(json.dumps(
        {
            "written": str(out),
            "files_included": len(included),
            "files_excluded": excluded,
            "known_local_secrets_checked": len(secrets),
            "secret_scan": "clean",
            "reports_included": sorted({rel.split("/")[1] for _, rel in included if rel.startswith("reports/") and rel.count("/") > 1}),
        },
        indent=2,
    ))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT.parent / f"{ROOT.name}-submission.zip")
    args = parser.parse_args()
    if args.out.resolve().is_relative_to(ROOT):
        parser.error("--out must be outside the project folder (the zip would include itself next time)")
    return build(args.out.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
