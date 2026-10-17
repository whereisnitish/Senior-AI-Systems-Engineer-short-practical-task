"""Guards that keep secrets out of the application in the first place.

* ``SecretValue`` wraps anything resolved from the vault so it cannot be printed,
  logged or serialised by accident.
* ``find_secret_material`` / ``reject_secret_material`` stop humans from pasting
  passwords, verification codes or backup codes into task notes or evidence
  fields. The error message names the field, never the value.
* ``validate_vault_ref`` makes sure only *references* are recorded.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app.errors import SecretMaterialRejected, ValidationFailed


class SecretValue:
    """Opaque wrapper for a secret. ``str()``/``repr()`` never reveal the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretValue([REDACTED])"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return self.__repr__()

    def __reduce__(self):  # pragma: no cover - defensive
        raise TypeError("SecretValue cannot be pickled or serialised")

    def __len__(self) -> int:
        return len(self._value)


_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("backup-code-like digit group", re.compile(r"(?<![\d.:\-/])\b\d{4}[ \-]?\d{4}\b(?![\d.:\-/])")),
    ("one-time code", re.compile(r"(?i)\b(code|otp|2fa|mfa|pin)\b\D{0,12}\b\d{6}\b")),
    ("credential assignment", re.compile(r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key)\s*[:=]\s*\S+")),
    ("authorization header", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/=]{8,}")),
    ("URL with embedded credentials", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("known token format", re.compile(r"\b(iom_|ius_|hvs\.|EAA[A-Za-z0-9]{10}|gh[pousr]_|AKIA[0-9A-Z]{8}|xox[abprs]-)")),
    ("session cookie", re.compile(r"(?i)\b(sessionid|csrftoken|ds_user_id|set-cookie)\b\s*[:=]")),
]

# Long unbroken base64-ish runs mixing upper case, lower case and digits look like tokens.
# (This application's own IDs are lowercase hex and therefore never match.)
_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/_\-]{32,}")


def _looks_high_entropy(token: str) -> bool:
    return all(re.search(p, token) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))


def find_secret_material(text: str | None) -> list[str]:
    """Return the *kinds* of secret-looking material found (never the material)."""
    if not text:
        return []
    reasons = [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]
    for match in _HIGH_ENTROPY_RE.finditer(text):
        if _looks_high_entropy(match.group(0)):
            reasons.append("high-entropy token")
            break
    return reasons


def reject_secret_material(field: str, text: str | None) -> None:
    reasons = find_secret_material(text)
    if reasons:
        raise SecretMaterialRejected(
            f"Field '{field}' appears to contain secret material ({', '.join(sorted(set(reasons)))}). "
            "Do not submit passwords, codes, tokens or cookies to this system. Store secrets in the "
            "company vault and record only the vault reference.",
            details={"field": field, "reasons": sorted(set(reasons))},
        )


def pydantic_secret_guard(value: str | None) -> str | None:
    """For use as a Pydantic ``AfterValidator`` on free-text fields."""
    if value is not None and find_secret_material(value):
        raise ValueError(
            "value appears to contain secret material; store secrets in the vault and submit only a reference"
        )
    return value


_VAULT_REF_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.\-]{1,20})://(?P<path>[A-Za-z0-9._~/\-:#]{1,200})$")


def validate_vault_ref(ref: str, allowed_schemes: Iterable[str], *, field: str = "vault_ref") -> str:
    """A vault reference is ``scheme://path``. It must never be the secret itself."""
    ref = (ref or "").strip()
    match = _VAULT_REF_RE.match(ref)
    if not match:
        raise ValidationFailed(
            f"Field '{field}' must be a vault reference such as vault://team/instagram/brand/password",
            details={"field": field},
        )
    if match.group("scheme") not in set(allowed_schemes):
        raise ValidationFailed(
            f"Field '{field}' uses a vault scheme that is not configured (allowed: {', '.join(sorted(allowed_schemes))})",
            details={"field": field},
        )
    if "@" in ref or find_secret_material(match.group("path")):
        raise SecretMaterialRejected(
            f"Field '{field}' looks like it contains a credential rather than a reference",
            details={"field": field},
        )
    return ref


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain.lower()}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    return f"+{'*' * max(len(digits) - 2, 0)}{digits[-2:]}" if digits else "***"
