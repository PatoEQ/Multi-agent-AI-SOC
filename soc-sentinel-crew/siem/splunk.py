"""
siem/splunk.py — Splunk Enterprise / Cloud connector (BETA).

Uses the REST *export* endpoint, which streams results without creating a
persistent search job:

    POST {SPLUNK_URL}/services/search/jobs/export
    Authorization: Bearer {SPLUNK_TOKEN}

Required env: SPLUNK_URL (e.g. https://splunk.example.com:8089), SPLUNK_TOKEN.
Optional: SPLUNK_INDEX (default "*"), SPLUNK_VERIFY_TLS (default true).
Status: unit-tested with mocked HTTP; not yet validated against a live instance.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from .base import SIEMConnector, SIEMError, quote_for_query

_INDEX_RE = re.compile(r"^[A-Za-z0-9_*\-]{1,80}$")
SYSMON_SOURCETYPE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


class SplunkConnector(SIEMConnector):
    name = "splunk"
    beta = True

    def __init__(self, url: str | None, token: str | None, index: str = "*",
                 verify_tls: bool = True, timeout: int = 20,
                 lookback_hours: int = 24, max_events: int = 50) -> None:
        if not url or not token:
            raise SIEMError("Splunk backend needs SPLUNK_URL and SPLUNK_TOKEN.")
        if not _INDEX_RE.match(index):
            raise SIEMError(f"Invalid SPLUNK_INDEX {index!r}.")
        self.url = url.rstrip("/")
        self.token = token
        self.index = index
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.lookback_hours = max(1, lookback_hours)
        self.max_events = max(1, min(max_events, 500))

    def build_query(self, entity: str, event_type: str) -> str:
        spl = f'search index={self.index} "{quote_for_query(entity)}"'
        if event_type == "sysmon":
            spl += f' sourcetype="{SYSMON_SOURCETYPE}"'
        return f"{spl} | head {self.max_events}"

    def search(self, entity: str, event_type: str = "all") -> dict[str, Any]:
        query = self.build_query(entity, event_type)
        try:
            resp = requests.post(
                f"{self.url}/services/search/jobs/export",
                headers={"Authorization": f"Bearer {self.token}"},
                data={
                    "search": query,
                    "output_mode": "json",
                    "earliest_time": f"-{self.lookback_hours}h",
                    "latest_time": "now",
                },
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            raise SIEMError(f"Splunk network failure: {exc!r}") from exc

        if resp.status_code in (401, 403):
            raise SIEMError(f"Splunk rejected the token (HTTP {resp.status_code}).")
        if resp.status_code != 200:
            raise SIEMError(f"Splunk returned HTTP {resp.status_code}: {resp.text[:200]}")

        events: list[dict[str, Any]] = []
        # The export endpoint returns one JSON object per line.
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
                events.append(obj["result"])
        return {
            "entity": entity,
            "events": events[: self.max_events],
            "_meta": {"backend": self.name, "query": query, "count": len(events)},
        }
