"""Vault adapters.

* ``ReferenceOnlyVault`` (default, safe for live use): the application never reads
  or writes secrets. Humans store secrets directly in the company vault and the
  application records references; presence is human-confirmed, not machine-verified.
* ``DevMemoryVault``: development/test only. Refuses to start in production, only
  accepts ``devvault://`` references, and only stores values that start with
  ``SYNTHETIC-`` so a real secret can never be put into it by mistake.
* ``HashiCorpKV2Vault``: HashiCorp Vault KV v2 over its documented HTTP API.
  Implemented and unit-tested against a simulated transport; it has NOT been
  connected to the company vault (the vault product and access were not provided).
"""

from __future__ import annotations

import codecs
import json
import logging
import os
import random
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.clock import Clock
from app.config import Settings
from app.integrations.vault.base import (
    VaultAdapter,
    VaultConflict,
    VaultError,
    VaultMetadata,
    VaultOperationUnsupported,
    VaultPermissionDenied,
    VaultSecretNotFound,
    VaultUnavailable,
)
from app.logging_setup import log_event
from app.reliability import RetryPolicy, call_with_retries
from app.security.redaction import Redactor
from app.security.secret_handling import SecretValue

logger = logging.getLogger("app.vault")


class ReferenceOnlyVault(VaultAdapter):
    name = "reference_only"
    production_grade = True
    description = (
        "Reference-only mode: this application never reads or writes secrets. Secrets are stored by "
        "humans directly in the company vault; only references are recorded and presence is human-confirmed."
    )
    capabilities: frozenset[str] = frozenset()

    def _unsupported(self) -> VaultOperationUnsupported:
        return VaultOperationUnsupported("reference-only vault mode: secret access is not available to this application")

    def read_fields(self, ref: str) -> dict[str, SecretValue]:
        raise self._unsupported()

    def write_fields(self, ref: str, fields: dict[str, SecretValue], *, cas: int | None = None) -> VaultMetadata:
        raise self._unsupported()

    def metadata(self, ref: str) -> VaultMetadata:
        raise self._unsupported()

    def health(self) -> dict[str, Any]:
        return {"status": "reference_only", "machine_verifiable": False}


class DevMemoryVault(VaultAdapter):
    """Development/test vault for SYNTHETIC secrets only.

    Optionally mirrored to a git-ignored JSON file (``DEV_VAULT_FILE``) so the demo
    seed script and the server process see the same synthetic entries. Every value
    must start with ``SYNTHETIC-``; it refuses to exist in production.
    """

    name = "dev_memory"
    production_grade = False
    description = "DEVELOPMENT-ONLY SYNTHETIC VAULT - synthetic secrets only. NOT a production vault."
    capabilities = frozenset({"read", "write", "metadata"})
    REF_PREFIX = "devvault://"
    VALUE_PREFIX = "SYNTHETIC-"

    def __init__(self, *, app_env: str, redactor: Redactor, clock: Clock, persist_path: Path | None = None):
        if app_env not in ("development", "test"):
            raise RuntimeError("DevMemoryVault is refused outside development/test environments")
        self._redactor = redactor
        self._clock = clock
        self._persist_path = Path(persist_path) if persist_path else None
        self._data: dict[str, list[tuple[dict[str, str], datetime]]] = {}
        self._reload()
        log_event(logger, "vault.dev_memory_enabled", level=logging.WARNING, message=self.description)

    def _reload(self) -> None:
        if self._persist_path is None or not self._persist_path.exists():
            return
        raw = json.loads(self._persist_path.read_text(encoding="utf-8"))
        data: dict[str, list[tuple[dict[str, str], datetime]]] = {}
        for ref, versions in (raw.get("entries") or {}).items():
            loaded = []
            for version in versions:
                fields = {k: str(v) for k, v in version["fields"].items()}
                if not all(v.startswith(self.VALUE_PREFIX) for v in fields.values()):
                    raise VaultError("dev vault file contains a non-synthetic value; refusing to load it")
                for value in fields.values():
                    self._redactor.register_secret(value)
                loaded.append((fields, datetime.fromisoformat(version["updated_at"])))
            data[ref] = loaded
        self._data = data

    def _save(self) -> None:
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "_warning": "DEVELOPMENT-ONLY SYNTHETIC VAULT MIRROR. Synthetic values only. Never commit. Not a vault.",
            "entries": {
                ref: [{"fields": fields, "updated_at": ts.isoformat()} for fields, ts in versions]
                for ref, versions in self._data.items()
            },
        }
        tmp = self._persist_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self._persist_path)

    def handles(self, ref: str) -> bool:
        return ref.startswith(self.REF_PREFIX)

    def _key(self, ref: str) -> str:
        base = ref.partition("#")[0]
        if not base.startswith(self.REF_PREFIX):
            raise VaultError("dev vault only accepts devvault:// references")
        return base

    def read_fields(self, ref: str) -> dict[str, SecretValue]:
        self._reload()
        versions = self._data.get(self._key(ref))
        if not versions:
            raise VaultSecretNotFound(f"no entry at {self._key(ref)}")
        fields, _ = versions[-1]
        for value in fields.values():
            self._redactor.register_secret(value)
        return {k: SecretValue(v) for k, v in fields.items()}

    def write_fields(self, ref: str, fields: dict[str, SecretValue], *, cas: int | None = None) -> VaultMetadata:
        key = self._key(ref)
        raw = {k: v.reveal() for k, v in fields.items()}
        if not raw or not all(v.startswith(self.VALUE_PREFIX) for v in raw.values()):
            raise VaultError("dev vault only stores synthetic values prefixed with 'SYNTHETIC-'")
        self._reload()
        versions = self._data.setdefault(key, [])
        if cas is not None and cas != len(versions):
            raise VaultConflict(f"check-and-set mismatch at {key}")
        now = self._clock.now()
        versions.append((raw, now))
        for value in raw.values():
            self._redactor.register_secret(value)
        self._save()
        return VaultMetadata(key, True, len(versions), now)

    def metadata(self, ref: str) -> VaultMetadata:
        self._reload()
        key = self._key(ref)
        versions = self._data.get(key)
        if not versions:
            return VaultMetadata(key, False)
        return VaultMetadata(key, True, len(versions), versions[-1][1])

    def delete(self, ref: str) -> None:
        """Demo/test helper: simulate an entry that has gone missing."""
        self._reload()
        self._data.pop(self._key(ref), None)
        self._save()

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "synthetic": True, "entries": len(self._data), "warning": self.description}


class HashiCorpKV2Vault(VaultAdapter):
    """HashiCorp Vault KV v2. References look like ``vault://<path>[#field]`` within VAULT_KV_MOUNT."""

    name = "hashicorp_kv2"
    production_grade = True
    description = "HashiCorp Vault KV v2 (implemented against the public HTTP API; not yet connected to the company vault)"
    capabilities = frozenset({"read", "write", "metadata"})
    REF_PREFIX = "vault://"

    def __init__(
        self,
        *,
        settings: Settings,
        redactor: Redactor,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        rng: random.Random | None = None,
    ):
        self._addr = (settings.vault_addr or "").rstrip("/")
        self._mount = settings.vault_kv_mount.strip("/")
        self._redactor = redactor
        token_path = Path(settings.vault_token_file) if settings.vault_token_file else None
        if token_path is None or not token_path.is_file():
            raise VaultError("VAULT_TOKEN_FILE does not exist")
        token = _read_token_file(token_path)
        if not token:
            raise VaultError("VAULT_TOKEN_FILE is empty")
        if any(ch.isspace() for ch in token):
            raise VaultError("VAULT_TOKEN_FILE must contain only the token")
        redactor.register_secret(token)
        self._token = SecretValue(token)
        self._namespace = settings.vault_namespace
        self._policy = RetryPolicy(max_attempts=settings.vault_max_attempts, base_delay=0.25, max_delay=2.0)
        self._client = client or httpx.Client(timeout=httpx.Timeout(settings.vault_timeout_seconds), trust_env=False)
        self._sleep = sleep
        self._rng = rng

    def handles(self, ref: str) -> bool:
        return ref.startswith(self.REF_PREFIX)

    def _path(self, ref: str) -> str:
        base = ref.partition("#")[0]
        if not base.startswith(self.REF_PREFIX):
            raise VaultError("hashicorp_kv2 adapter only accepts vault:// references")
        path = base[len(self.REF_PREFIX) :].strip("/")
        if not path or ".." in path:
            raise VaultError("invalid vault reference path")
        return path

    def _headers(self) -> dict[str, str]:
        headers = {"X-Vault-Token": self._token.reveal()}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        return headers

    def _request(self, method: str, url: str, *, json: Any = None, retry: bool) -> httpx.Response:
        def attempt(_n: int) -> httpx.Response:
            try:
                response = self._client.request(method, url, headers=self._headers(), json=json)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                raise VaultUnavailable(f"vault connection failed ({type(exc).__name__})") from None
            except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.RemoteProtocolError, httpx.ReadError) as exc:
                # The request may have reached the vault: writes become "uncertain".
                raise VaultUnavailable(
                    f"vault request interrupted ({type(exc).__name__})", outcome_uncertain=(method != "GET")
                ) from None
            if response.status_code >= 500 or response.status_code == 429:
                raise VaultUnavailable(f"vault returned HTTP {response.status_code}", outcome_uncertain=(method != "GET"))
            return response

        def retryable(exc: Exception) -> bool:
            return retry and isinstance(exc, VaultUnavailable) and not exc.outcome_uncertain

        kwargs: dict[str, Any] = {"policy": self._policy, "is_retryable": retryable}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        if self._rng is not None:
            kwargs["rng"] = self._rng
        return call_with_retries(attempt, **kwargs)

    @staticmethod
    def _raise_for(response: httpx.Response, ref_path: str) -> None:
        if response.status_code == 404:
            raise VaultSecretNotFound(f"no entry at vault://{ref_path}")
        if response.status_code in (401, 403):
            raise VaultPermissionDenied(f"vault denied access to vault://{ref_path} (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise VaultError(f"vault returned HTTP {response.status_code} for vault://{ref_path}")

    def read_fields(self, ref: str) -> dict[str, SecretValue]:
        path = self._path(ref)
        response = self._request("GET", f"{self._addr}/v1/{self._mount}/data/{path}", retry=True)
        self._raise_for(response, path)
        data = (response.json().get("data") or {}).get("data") or {}
        out: dict[str, SecretValue] = {}
        for key, value in data.items():
            text = value if isinstance(value, str) else str(value)
            self._redactor.register_secret(text)
            out[key] = SecretValue(text)
        return out

    def write_fields(self, ref: str, fields: dict[str, SecretValue], *, cas: int | None = None) -> VaultMetadata:
        path = self._path(ref)
        body: dict[str, Any] = {"data": {k: v.reveal() for k, v in fields.items()}}
        if cas is not None:
            body["options"] = {"cas": cas}
        # Writes are never retried automatically: a timeout may mean the write happened.
        response = self._request("POST", f"{self._addr}/v1/{self._mount}/data/{path}", json=body, retry=False)
        if response.status_code == 400 and "check-and-set" in response.text:
            raise VaultConflict(f"check-and-set mismatch at vault://{path}")
        self._raise_for(response, path)
        data = response.json().get("data") or {}
        return VaultMetadata(f"vault://{path}", True, data.get("version"), _parse_time(data.get("created_time")))

    def metadata(self, ref: str) -> VaultMetadata:
        path = self._path(ref)
        response = self._request("GET", f"{self._addr}/v1/{self._mount}/metadata/{path}", retry=True)
        if response.status_code == 404:
            return VaultMetadata(f"vault://{path}", False)
        self._raise_for(response, path)
        data = response.json().get("data") or {}
        current = data.get("current_version")
        # KV v2 keeps metadata after a soft delete or destroy: only a readable current version counts as present.
        version_info = (data.get("versions") or {}).get(str(current)) or {}
        exists = bool(current) and not _version_unreadable(version_info)
        return VaultMetadata(f"vault://{path}", exists, current, _parse_time(data.get("updated_time")))

    def health(self) -> dict[str, Any]:
        try:
            response = self._client.get(f"{self._addr}/v1/sys/health")
        except httpx.HTTPError as exc:
            return {"status": "unavailable", "detail": type(exc).__name__}
        status = {200: "ok", 429: "standby", 473: "performance_standby", 501: "not_initialised", 503: "sealed"}
        return {"status": status.get(response.status_code, f"http_{response.status_code}")}


def _read_token_file(path: Path) -> str:
    """UTF-8, UTF-8 with BOM, or UTF-16 (what Windows PowerShell 5.1 writes with '>')."""
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16").strip()
    return raw.decode("utf-8-sig").strip()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _version_unreadable(info: dict[str, Any]) -> bool:
    """True when a KV v2 version is destroyed or its deletion time has passed (unparseable counts as deleted)."""
    if info.get("destroyed"):
        return True
    deletion = info.get("deletion_time")
    if not deletion:
        return False
    when = _parse_time(deletion)
    return when is None or when <= datetime.now(timezone.utc)


def build_vault(settings: Settings, *, redactor: Redactor, clock: Clock, client: httpx.Client | None = None) -> VaultAdapter:
    if settings.vault_backend == "dev_memory":
        return DevMemoryVault(app_env=settings.app_env, redactor=redactor, clock=clock, persist_path=settings.dev_vault_file)
    if settings.vault_backend == "hashicorp_kv2":
        return HashiCorpKV2Vault(settings=settings, redactor=redactor, client=client)
    return ReferenceOnlyVault()
