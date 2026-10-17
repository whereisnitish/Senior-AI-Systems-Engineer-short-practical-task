"""Application configuration.

All configuration comes from environment variables (optionally a local, git-ignored
``.env`` file for development). A ``.env`` file is NOT a vault: it only holds
non-secret settings plus the application's own signing key. Platform secrets
(Instagram passwords, backup codes, proxy credentials, Meta tokens) are only ever
referenced by vault reference.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

CsvList = Annotated[list[str], NoDecode]

# Health checks, demos and tests must never target a social platform.
FORBIDDEN_TARGET_DOMAINS = (
    "instagram.com",
    "cdninstagram.com",
    "facebook.com",
    "fbcdn.net",
    "meta.com",
    "threads.net",
    "tiktok.com",
    "x.com",
    "twitter.com",
    "snapchat.com",
    "linkedin.com",
    "youtube.com",
)

# Free consumer mailbox providers: never a company-controlled domain (COMPANY_EMAIL_DOMAINS refuses them).
CONSUMER_MAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
        "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com",
        "yandex.com", "zoho.com",
    }
)

_PLACEHOLDER_HINTS = ("change-me", "changeme", "replace", "placeholder", "your-secret", "<", "example")
_CSV_FIELDS = (
    "cors_allowed_origins",
    "trusted_hosts",
    "vault_ref_schemes",
    "company_email_domains",
    "proxy_healthcheck_allowed_urls",
    "proxy_challenge_markers",
    "extra_sensitive_keys",
)


# Which settings file to read: ".env" (live run) by default; the synthetic demo uses
# IOM_ENV_FILE=.env.demo so demo and live data never share a database or report folder.
ENV_FILE = os.environ.get("IOM_ENV_FILE", ".env")

ENVIRONMENT_LABELS = {
    "company_test_environment": "Test resources provided by the company (brand kit, email, phone, vault, Meta business, proxies).",
    "candidate_provided_test_environment": (
        "The company test environment was not provided. The candidate created throwaway substitute resources "
        "(test brand, email, Instagram account, Meta business portfolio); they are not company-authorised resources."
    ),
}


def is_forbidden_target(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in FORBIDDEN_TARGET_DOMAINS)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_FILE, env_file_encoding="utf-8", extra="ignore")

    # --- application -------------------------------------------------------
    app_env: Literal["development", "test", "production"] = "development"
    # Where the (non-synthetic) test resources came from; shown on every report and the dashboard.
    environment_label: Literal["company_test_environment", "candidate_provided_test_environment"] = "company_test_environment"
    app_name: str = "Instagram Operations Manager"
    app_secret_key: SecretStr | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    public_base_url: str = "http://127.0.0.1:8000"

    database_url: str = "sqlite:///./data/instagram_ops.db"
    log_dir: Path = Path("logs")
    log_level: str = "INFO"
    log_to_stdout: bool = True
    reports_dir: Path = Path("reports")

    docs_enabled: bool | None = None
    cors_allowed_origins: CsvList = []
    trusted_hosts: CsvList = []
    session_cookie_secure: bool | None = None
    ui_session_hours: int = 8
    # Failed bearer-token / sign-in attempts allowed per client address per window before 429.
    auth_max_failed_attempts: int = 10
    auth_failure_window_seconds: int = 900

    # --- vault ---------------------------------------------------------------
    vault_backend: Literal["reference_only", "dev_memory", "hashicorp_kv2"] = "reference_only"
    vault_ref_schemes: CsvList = ["vault", "op", "bw", "aws-sm", "azure-kv", "gcp-sm"]
    vault_addr: str | None = None
    vault_kv_mount: str = "secret"
    vault_namespace: str | None = None
    vault_token_file: Path | None = None
    vault_timeout_seconds: float = 5.0
    vault_max_attempts: int = 3
    # dev_memory only: git-ignored synthetic mirror so the seed script and server share entries.
    dev_vault_file: Path | None = None

    # --- Meta (read-only verification only) -----------------------------------
    meta_integration: Literal["disabled", "graph_readonly"] = "disabled"
    meta_graph_base_url: str = "https://graph.facebook.com"
    meta_graph_api_version: str | None = None
    meta_business_id: str | None = None
    meta_access_token_vault_ref: str | None = None
    meta_timeout_seconds: float = 10.0
    meta_max_attempts: int = 3

    # --- notifications --------------------------------------------------------
    notification_backend: Literal["none", "smtp"] = "none"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password_vault_ref: str | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True
    smtp_timeout_seconds: float = 10.0
    notification_max_attempts: int = 3

    # --- organisation ---------------------------------------------------------
    company_email_domains: CsvList = []

    # --- human tasks ----------------------------------------------------------
    reminder_interval_hours: float = 24.0
    overdue_reminder_interval_hours: float = 12.0
    max_reminders: int = 6
    escalation_grace_hours: float = 0.0
    escalation_repeat_hours: float = 24.0
    max_escalations: int = 2

    # --- audit & scheduler ----------------------------------------------------
    access_stale_days: int = 30
    audit_weekly_day: Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"] = "mon"
    audit_weekly_hour_utc: int = 9
    scheduler_enabled: bool = False
    reminder_job_minutes: int = 15
    notification_job_minutes: int = 1

    # --- proxies ----------------------------------------------------------------
    proxy_config_file: Path | None = None
    proxy_healthcheck_allowed_urls: CsvList = []
    proxy_healthcheck_default_url: str | None = None
    proxy_connect_timeout_seconds: float = 3.0
    proxy_read_timeout_seconds: float = 5.0
    proxy_max_attempts: int = 3
    proxy_backoff_base_seconds: float = 0.5
    proxy_backoff_max_seconds: float = 8.0
    proxy_unhealthy_after_failed_checks: int = 1
    proxy_cooldown_seconds: int = 300
    proxy_max_failovers_per_session: int = 2
    proxy_healthcheck_interval_minutes: int = 10
    proxy_challenge_header: str = "X-Security-Challenge"
    proxy_challenge_markers: CsvList = ["challenge_required", "checkpoint_required", "captcha"]

    # --- redaction ----------------------------------------------------------------
    redact_emails: bool = True
    redact_phones: bool = True
    extra_sensitive_keys: CsvList = []

    @field_validator(*_CSV_FIELDS, mode="before")
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("company_email_domains")
    @classmethod
    def _lower_domains(cls, value: list[str]) -> list[str]:
        domains = [d.lower().lstrip("@") for d in value]
        consumer = sorted(set(domains) & CONSUMER_MAIL_DOMAINS)
        if consumer:
            raise ValueError(
                f"COMPANY_EMAIL_DOMAINS lists consumer mail domains ({', '.join(consumer)}). They are not company-controlled "
                "and would make the audit report personal mailboxes as company ones. Remove them and record such a mailbox "
                "as personal_provider_substitute in the email task."
            )
        return domains

    @field_validator("proxy_healthcheck_allowed_urls")
    @classmethod
    def _validate_allowed_urls(cls, value: list[str]) -> list[str]:
        for url in value:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError("PROXY_HEALTHCHECK_ALLOWED_URLS entries must be absolute http(s) URLs")
            if parts.username or parts.password:
                raise ValueError("PROXY_HEALTHCHECK_ALLOWED_URLS entries must not contain credentials")
            if is_forbidden_target(url):
                raise ValueError("social-platform domains can never be proxy health-check targets")
        return value

    @model_validator(mode="after")
    def _validate_security(self) -> Settings:
        key = self.app_secret_key.get_secret_value() if self.app_secret_key else ""
        if len(key) < 32 or any(h in key.lower() for h in _PLACEHOLDER_HINTS):
            raise ValueError(
                "APP_SECRET_KEY must be set to a random value of at least 32 characters. Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        if self.app_env == "production":
            if self.vault_backend == "dev_memory":
                raise ValueError("VAULT_BACKEND=dev_memory is development/test only and is refused in production")
            if self.docs_enabled:
                raise ValueError("Interactive API docs must not be exposed in production (unset DOCS_ENABLED)")
            if self.session_cookie_secure is False:
                raise ValueError("SESSION_COOKIE_SECURE cannot be disabled in production")
            if not self.trusted_hosts:
                raise ValueError("TRUSTED_HOSTS must be configured in production")
        if self.vault_backend == "hashicorp_kv2" and not (self.vault_addr and self.vault_token_file):
            raise ValueError("VAULT_BACKEND=hashicorp_kv2 requires VAULT_ADDR and VAULT_TOKEN_FILE")
        if self.meta_integration == "graph_readonly" and not (
            self.meta_graph_api_version and self.meta_business_id and self.meta_access_token_vault_ref
        ):
            raise ValueError(
                "META_INTEGRATION=graph_readonly requires META_GRAPH_API_VERSION, META_BUSINESS_ID "
                "and META_ACCESS_TOKEN_VAULT_REF"
            )
        if self.notification_backend == "smtp" and not (self.smtp_host and self.smtp_from):
            raise ValueError("NOTIFICATION_BACKEND=smtp requires SMTP_HOST and SMTP_FROM")
        if self.proxy_max_attempts < 1 or self.proxy_max_attempts > 10:
            raise ValueError("PROXY_MAX_ATTEMPTS must be between 1 and 10 (retries are always bounded)")
        if self.proxy_healthcheck_default_url and self.proxy_healthcheck_default_url not in self.proxy_healthcheck_allowed_urls:
            raise ValueError("PROXY_HEALTHCHECK_DEFAULT_URL must be one of PROXY_HEALTHCHECK_ALLOWED_URLS")
        return self

    # --- derived ----------------------------------------------------------------
    @property
    def secret_key_bytes(self) -> bytes:
        assert self.app_secret_key is not None
        return self.app_secret_key.get_secret_value().encode("utf-8")

    @property
    def docs_are_enabled(self) -> bool:
        if self.docs_enabled is not None:
            return self.docs_enabled
        return self.app_env != "production"

    @property
    def cookie_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.app_env == "production"

    @property
    def allowed_vault_schemes(self) -> list[str]:
        schemes = list(self.vault_ref_schemes)
        if self.vault_backend == "dev_memory" and "devvault" not in schemes:
            schemes.append("devvault")
        return schemes


class DatabaseSettings(BaseSettings):
    """Minimal settings used by Alembic so migrations do not need the app secret."""

    model_config = SettingsConfigDict(env_file=ENV_FILE, env_file_encoding="utf-8", extra="ignore")
    database_url: str = "sqlite:///./data/instagram_ops.db"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
