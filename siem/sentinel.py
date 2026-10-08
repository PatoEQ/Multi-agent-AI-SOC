"""
siem/sentinel.py — Microsoft Sentinel (Log Analytics) connector (BETA).

Authenticates with an Entra ID (Azure AD) app registration using the OAuth2
client-credentials flow, then runs a KQL query:

    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
    POST https://api.loganalytics.io/v1/workspaces/{workspace}/query

Required env: SENTINEL_WORKSPACE_ID, SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID,
SENTINEL_CLIENT_SECRET. The app needs the "Log Analytics Reader" role.
Status: unit-tested with mocked HTTP; not yet validated against a live instance.
"""

from __future__ import annotations

import re
import time
from typing import Any

import requests

from .base import SIEMConnector, SIEMError, quote_for_query

_GUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace}/query"
SCOPE = "https://api.loganalytics.io/.default"


class SentinelConnector(SIEMConnector):
    name = "sentinel"
    beta = True

    def __init__(self, workspace_id: str | None, tenant_id: str | None,
                 client_id: str | None, client_secret: str | None,
                 timeout: int = 20, lookback_hours: int = 24, max_events: int = 50) -> None:
        if not all([workspace_id, tenant_id, client_id, client_secret]):
            raise SIEMError(
                "Sentinel backend needs SENTINEL_WORKSPACE_ID, SENTINEL_TENANT_ID, "
                "SENTINEL_CLIENT_ID and SENTINEL_CLIENT_SECRET."
            )
        for label, value in (("workspace", workspace_id), ("tenant", tenant_id)):
            if not _GUID_RE.match(value or ""):
                raise SIEMError(f"SENTINEL {label} id must be a GUID.")
        self.workspace_id = workspace_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.lookback_hours = max(1, lookback_hours)
        self.max_events = max(1, min(max_events, 500))
        self._token: str | None = None
        self._token_expiry = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        try:
            resp = requests.post(
                LOGIN_URL.format(tenant=self.tenant_id),
                data={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self.client_secret, "scope": SCOPE},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SIEMError(f"Entra ID token request failed: {exc!r}") from exc
        if resp.status_code != 200:
            raise SIEMError(f"Entra ID returned HTTP {resp.status_code} for the token request.")
        data = resp.json()
        self._token = data.get("access_token")
        if not self._token:
            raise SIEMError("Entra ID response did not include an access_token.")
        self._token_expiry = time.time() + int(data.get("expires_in", 3600))
        return self._token

    def build_query(self, entity: str, event_type: str) -> str:
        literal = quote_for_query(entity)
        if event_type == "sysmon":
            kql = (f'Event | where Source == "Microsoft-Windows-Sysmon" '
                   f'| search "{literal}"')
        else:
            kql = f'search "{literal}"'
        return f"{kql} | take {self.max_events}"

    def search(self, entity: str, event_type: str = "all") -> dict[str, Any]:
        query = self.build_query(entity, event_type)
        token = self._get_token()
        try:
            resp = requests.post(
                QUERY_URL.format(workspace=self.workspace_id),
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
                json={"query": query, "timespan": f"PT{self.lookback_hours}H"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SIEMError(f"Log Analytics network failure: {exc!r}") from exc
        if resp.status_code in (401, 403):
            raise SIEMError(f"Log Analytics denied access (HTTP {resp.status_code}).")
        if resp.status_code != 200:
            raise SIEMError(f"Log Analytics returned HTTP {resp.status_code}: {resp.text[:200]}")

        events: list[dict[str, Any]] = []
        for table in resp.json().get("tables", []):
            cols = [c.get("name") for c in table.get("columns", [])]
            for row in table.get("rows", []):
                events.append(dict(zip(cols, row, strict=False)))
        return {
            "entity": entity,
            "events": events[: self.max_events],
            "_meta": {"backend": self.name, "query": query, "count": len(events)},
        }
