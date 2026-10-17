"""Check the configured HashiCorp Vault from this application's own token.

    python -m scripts.vault_check

Statuses only: no secret value is ever printed or written.
1. Vault is reachable and unsealed.
2. Least privilege: the token may read the metadata (existence, version) of Instagram entries
   but is DENIED their values.
3. Every runtime secret the application is configured to use (SMTP password, Meta token, proxy
   credentials) is readable.
Writes ``<REPORTS_DIR>/vault/vault_check_<timestamp>.json`` through the report leak guard.
"""

from __future__ import annotations

import sys
from typing import Any

from sqlalchemy import select

from app.config import Settings
from app.integrations.vault import VaultAdapter, inspect_ref
from app.integrations.vault.base import VaultError, VaultPermissionDenied, VaultSecretNotFound
from app.models import InstagramAccount
from app.services.proxy_manager import load_proxy_config
from scripts._common import cli_container


def run_checks(vault: VaultAdapter, settings: Settings, *, handle: str, proxy_refs: list[tuple[str, str]]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool | None, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    health = vault.health().get("status")
    add("vault reachable and unsealed", health == "ok", f"sys/health: {health}")
    prefix = f"vault://instagram/{handle}"
    for label, ref in (("password", f"{prefix}/password"), ("backup codes", f"{prefix}/backup-codes")):
        inspection = inspect_ref(vault, ref)
        if inspection.exists:
            add(f"metadata readable: Instagram {label}", True, f"entry exists, version {inspection.version}")
        elif inspection.exists is False:
            add(f"metadata readable: Instagram {label}", True, "metadata answered: no entry stored yet")
        else:
            add(f"metadata readable: Instagram {label}", False, inspection.detail)
    try:
        vault.read_fields(f"{prefix}/password")
        add("value denied: Instagram password", False, "the token CAN read Instagram secret values: the policy is too broad")
    except VaultPermissionDenied:
        add("value denied: Instagram password", True, "Vault answered 403, as the policy intends")
    except VaultSecretNotFound:
        add("value denied: Instagram password", False, "Vault answered 404, so the token may read values here: the policy is too broad")
    except VaultError as exc:
        add("value denied: Instagram password", False, f"could not be checked: {exc}")

    runtime = [("SMTP password", settings.smtp_password_vault_ref), ("Meta token", settings.meta_access_token_vault_ref)]
    for label, ref in runtime:
        if not ref:
            add(f"runtime secret: {label}", None, "not configured")
            continue
        try:
            vault.read(ref)
            add(f"runtime secret: {label}", True, f"readable at {ref}")
        except VaultError as exc:
            add(f"runtime secret: {label}", False, str(exc))
    for label, ref in proxy_refs:
        try:
            fields = vault.read_fields(ref)
            missing = {"username", "password"} - set(fields)
            add(f"runtime secret: {label}", not missing, f"readable at {ref}" + (f"; missing fields {sorted(missing)}" if missing else ""))
        except VaultError as exc:
            add(f"runtime secret: {label}", False, str(exc))
    return {
        "vault": {"backend": vault.name, "address": settings.vault_addr, "mount": settings.vault_kv_mount},
        "checks": checks,
        "ok": all(c["ok"] for c in checks if c["ok"] is not None),
    }


def main() -> int:
    container = cli_container("vault-check")
    settings = container.settings
    if container.vault.name != "hashicorp_kv2":
        print(f"VAULT_BACKEND is '{container.vault.name}'. Set VAULT_BACKEND=hashicorp_kv2 (README section 14) and re-run.")
        return 2
    with container.uow() as session:
        handle = session.scalar(
            select(InstagramAccount.selected_handle).where(InstagramAccount.is_synthetic.is_(False), InstagramAccount.selected_handle.is_not(None))
        )
    proxy_refs: list[tuple[str, str]] = []
    if settings.proxy_config_file:
        proxy_refs = [(f"proxy {p.id} credential", p.credential_ref) for p in load_proxy_config(settings.proxy_config_file, settings) if p.credential_ref]
    result = run_checks(container.vault, settings, handle=handle or "example-handle", proxy_refs=proxy_refs)
    for check in result["checks"]:
        mark = {True: "PASS", False: "FAIL", None: "skip"}[check["ok"]]
        print(f"  [{mark}] {check['check']}: {check['detail']}")
    stamp = container.clock.now().strftime("%Y%m%dT%H%M%SZ")
    out = settings.reports_dir / "vault" / f"vault_check_{stamp}.json"
    with container.uow() as session:
        result["report_meta"] = container.reports.report_meta(session, "Vault check")
    container.reports.write_json_report(out, result)
    print(f"{'All checks passed' if result['ok'] else 'Some checks FAILED'}. Report: {out}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
