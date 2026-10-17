"""Read-only Meta Graph API verification of the business <-> Instagram association.

Status: implemented and unit-tested with a simulated transport only. It has NOT
been run against the live Graph API because no Meta business access or app token
was provided. Before enabling, confirm against the current Graph API reference for
your configured API version that the business ``instagram_accounts`` edge and the
``username`` field are available to your app with the granted permissions.
The access token is resolved from the vault per call and never logged.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Callable
from typing import Any

import httpx

from app.config import Settings
from app.enums import VerificationLabel
from app.integrations.meta.base import MetaIntegration, MetaLinkCheck, MetaNotConfigured
from app.integrations.vault.base import VaultAdapter, VaultError
from app.logging_setup import log_event
from app.reliability import RetryPolicy, call_with_retries
from app.security.redaction import Redactor

logger = logging.getLogger("app.meta")
_MAX_PAGES = 5


class _Transient(Exception):
    pass


class MetaGraphReadOnly(MetaIntegration):
    name = "graph_readonly"
    configured = True

    def __init__(
        self,
        *,
        settings: Settings,
        vault: VaultAdapter,
        redactor: Redactor,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        rng: random.Random | None = None,
    ):
        self._base = settings.meta_graph_base_url.rstrip("/")
        self._version = settings.meta_graph_api_version
        self._token_ref = settings.meta_access_token_vault_ref or ""
        self._vault = vault
        self._redactor = redactor
        self._client = client or httpx.Client(timeout=httpx.Timeout(settings.meta_timeout_seconds), trust_env=False)
        self._policy = RetryPolicy(max_attempts=settings.meta_max_attempts, base_delay=0.5, max_delay=4.0)
        self._sleep = sleep
        self._rng = rng

    def _get(self, url: str, params: dict[str, Any] | None, token: str) -> dict[str, Any]:
        def attempt(_n: int) -> dict[str, Any]:
            try:
                response = self._client.get(url, params=params, headers={"Authorization": f"Bearer {token}"})
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                raise _Transient(type(exc).__name__) from None
            if response.status_code >= 500 or response.status_code == 429:
                raise _Transient(f"HTTP {response.status_code}")
            if response.status_code >= 400:
                raise PermissionError(f"Graph API returned HTTP {response.status_code}")
            return response.json()

        kwargs: dict[str, Any] = {"policy": self._policy, "is_retryable": lambda e: isinstance(e, _Transient)}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        if self._rng is not None:
            kwargs["rng"] = self._rng
        return call_with_retries(attempt, **kwargs)

    def check_instagram_link(self, business_id: str, handle: str) -> MetaLinkCheck:
        try:
            token = self._vault.read(self._token_ref).reveal()
        except VaultError as exc:
            return MetaLinkCheck("unknown", VerificationLabel.UNVERIFIED, None, f"Meta token unavailable from vault: {exc}")
        self._redactor.register_secret(token)
        url: str | None = f"{self._base}/{self._version}/{business_id}/instagram_accounts"
        params: dict[str, Any] | None = {"fields": "id,username", "limit": 100}
        api_host = httpx.URL(self._base).host
        pages = 0
        try:
            while url is not None:
                if pages >= _MAX_PAGES:
                    # Only part of the listing was read: absence there is not a verified negative.
                    return MetaLinkCheck(
                        "unknown", VerificationLabel.UNVERIFIED, None,
                        f"Listing has more than {_MAX_PAGES} pages; the account was not found in the pages read (not a confirmed negative)",
                    )
                if httpx.URL(url).host != api_host:
                    # Never send the access token to a host the paging link names.
                    log_event(logger, "meta.paging_host_rejected", level=logging.WARNING, outcome="not_followed")
                    return MetaLinkCheck("unknown", VerificationLabel.UNVERIFIED, None, "Graph API paging link points to another host; not followed")
                body = self._get(url, params, token)
                pages += 1
                for item in body.get("data", []):
                    if str(item.get("username", "")).lower() == handle.lower():
                        return MetaLinkCheck(
                            "linked",
                            VerificationLabel.INTEGRATION_VERIFIED,
                            f"meta-graph:{business_id}/instagram_accounts#{item.get('id')}",
                            "Instagram account listed under the designated business",
                        )
                url = (body.get("paging") or {}).get("next")
                params = None
        except _Transient as exc:
            log_event(logger, "meta.verification_unavailable", level=logging.WARNING, outcome="unavailable", error=str(exc))
            return MetaLinkCheck("unknown", VerificationLabel.UNVERIFIED, None, f"Graph API unavailable after retries ({exc})")
        except PermissionError as exc:
            return MetaLinkCheck("unknown", VerificationLabel.UNVERIFIED, None, str(exc))
        except (httpx.InvalidURL, ValueError) as exc:  # malformed paging link or non-JSON body
            return MetaLinkCheck("unknown", VerificationLabel.UNVERIFIED, None, f"unexpected Graph API response ({type(exc).__name__})")
        return MetaLinkCheck(
            "not_linked",
            VerificationLabel.INTEGRATION_VERIFIED,
            f"meta-graph:{business_id}/instagram_accounts",
            "Instagram account not listed under the designated business",
        )

    def health(self) -> dict[str, Any]:
        return {"status": "configured", "mode": "read_only", "live_verified": False}


def build_meta(settings: Settings, *, vault: VaultAdapter, redactor: Redactor, client: httpx.Client | None = None) -> MetaIntegration:
    if settings.meta_integration == "graph_readonly":
        return MetaGraphReadOnly(settings=settings, vault=vault, redactor=redactor, client=client)
    return MetaNotConfigured()
