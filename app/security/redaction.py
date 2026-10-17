"""Redaction of sensitive values from logs, error records and reports.

Three layers, applied recursively to dicts/lists/strings:

1. Key-based: values under sensitive keys (password, token, cookie, authorization,
   backup_codes, ...) are replaced entirely. Keys that are *references or metadata*
   (``*_ref``, ``*_status``, ``*_hint``...) are exempt so vault references stay visible.
2. Pattern-based: credentials embedded in free text (URL userinfo, bearer/basic
   headers, ``password=...``, JWTs, known token formats, backup-code-like digit
   groups) plus email addresses and E.164 phone numbers (masked, not removed).
3. Exact-value: every secret the process resolves from the vault is registered at
   runtime and replaced wherever it appears, whatever the surrounding format.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import SecretStr

REDACTED = "[REDACTED]"

_SAFE_KEY_SUFFIXES = (
    "_ref",
    "_refs",
    "_status",
    "_verification",
    "_hint",
    "_count",
    "_at",
    "_id",
    "_ids",
    "_kind",
    "_method",
    "_prefix",
    "_present",
    "_label",
    "_policy",
)
# Metadata leaves that stay visible even inside a sensitive container, e.g.
# {"backup_codes": {"vault_ref": ..., "status": ..., "verification": ...}}.
_SAFE_EXACT_KEYS = frozenset(
    {"status", "verification", "method", "kind", "count", "id", "ref", "vault_ref", "label", "present", "hint", "version"}
)

_SENSITIVE_KEY_RE = re.compile(
    r"(pass(word|wd|phrase)?|(^|_)pwd($|_)|secret|token|api_?key|authori[sz]ation|cookie|"
    r"session_?(key|token|secret)|backup_?codes?|recovery_?codes?|(^|_)otp($|_)|totp|"
    r"(mfa|2fa|verification|auth|login|security)_?code|private_?key|credentials?|"
    r"proxy_?auth|signature|x_vault_token)",
    re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # scheme://user:pass@host -> scheme://[REDACTED]@host
    (re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,15}://)[^\s/@:]+(?::[^\s/@]*)?@"), r"\1" + REDACTED + "@"),
    (re.compile(r"(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9\-._~+/=]{6,}"), r"\1 " + REDACTED),
    (
        re.compile(
            r"(?i)\b((?:verification|auth|2fa|mfa|login|security|backup|recovery)[ _-]?codes?|otp|pin|"
            r"password|passwd|pwd|passphrase|secret|client[_-]?secret|token|access[_-]?token|"
            r"refresh[_-]?token|api[_-]?key|apikey|cookie|session[_-]?id|sessionid)"
            r"(\s*[:=]\s*|\s+is\s+)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1\2" + REDACTED,
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(iom|ius)_[A-Za-z0-9_\-]{16,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9_\-]{16,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bEAA[A-Za-z0-9]{20,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bSYNTHETIC-SECRET-[A-Za-z0-9\-]+"), "[REDACTED_SYNTHETIC_SECRET]"),
]

_PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d ().\-]{6,18}\d\b")
# Instagram backup codes are 8 digits, often shown as "1234 5678".
_BACKUP_CODE_RE = re.compile(r"(?<![\d.:\-/])\b\d{4}[ \-]?\d{4}\b(?![\d.:\-/])")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)\b")


def _mask_phone_match(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return f"[PHONE ***{digits[-2:]}]"


class Redactor:
    def __init__(
        self,
        *,
        redact_emails: bool = True,
        redact_phones: bool = True,
        extra_sensitive_keys: Iterable[str] = (),
    ):
        self.redact_emails = redact_emails
        self.redact_phones = redact_phones
        self._extra_keys = {k.lower().replace("-", "_") for k in extra_sensitive_keys}
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    # -- runtime secret registry ---------------------------------------------
    def register_secret(self, value: str | None) -> None:
        """Register a resolved secret so it is replaced anywhere it appears."""
        if value and len(value) >= 4:
            with self._lock:
                self._secrets.add(value)

    def registered_secret_count(self) -> int:
        return len(self._secrets)

    def contains_registered_secret(self, text: str) -> bool:
        with self._lock:
            secrets = list(self._secrets)
        return any(secret in text for secret in secrets)

    # -- key classification --------------------------------------------------
    @staticmethod
    def _normalise(key: str) -> str:
        return key.lower().replace("-", "_")

    def is_safe_key(self, key: str) -> bool:
        normalised = self._normalise(key)
        if normalised in self._extra_keys:
            return False
        return normalised in _SAFE_EXACT_KEYS or normalised.endswith(_SAFE_KEY_SUFFIXES)

    def is_sensitive_key(self, key: str) -> bool:
        normalised = self._normalise(key)
        if normalised in self._extra_keys:
            return True
        if self.is_safe_key(key):
            return False
        return bool(_SENSITIVE_KEY_RE.search(normalised))

    # -- redaction -----------------------------------------------------------
    def redact_text(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            secrets = sorted(self._secrets, key=len, reverse=True)
        for secret in secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        if self.redact_phones:
            text = _PHONE_RE.sub(_mask_phone_match, text)
        text = _BACKUP_CODE_RE.sub("[REDACTED_CODE]", text)
        if self.redact_emails:
            text = _EMAIL_RE.sub(r"\1***@\2", text)
        return text

    def redact(self, value: Any, _depth: int = 0, _sensitive: bool = False) -> Any:
        """Recursively redact. Inside a sensitive container only safe metadata leaves survive."""
        if _depth > 20:
            return "[TRUNCATED]"
        if value is None:
            return None
        if isinstance(value, SecretStr) or type(value).__name__ == "SecretValue":
            return REDACTED
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for key, item in value.items():
                skey = str(key)
                safe = self.is_safe_key(skey)
                sensitive = (_sensitive or self.is_sensitive_key(skey)) and not safe
                if isinstance(item, (Mapping, list, tuple, set, frozenset)):
                    out[skey] = self.redact(item, _depth + 1, sensitive)
                elif sensitive and item not in (None, ""):
                    out[skey] = REDACTED
                else:
                    out[skey] = self.redact(item, _depth + 1)
            return out
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self.redact(item, _depth + 1, _sensitive) for item in value]
        if _sensitive:
            return REDACTED
        if isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            return "[BYTES]"
        return self.redact_text(str(value))


_default_redactor = Redactor()


def get_redactor() -> Redactor:
    return _default_redactor


def set_redactor(redactor: Redactor) -> None:
    global _default_redactor
    _default_redactor = redactor
