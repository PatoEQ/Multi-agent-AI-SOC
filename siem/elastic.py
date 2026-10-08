"""
siem/elastic.py — Elasticsearch / Elastic Security connector (BETA).

    POST {ELASTIC_URL}/{ELASTIC_INDEX}/_search
    Authorization: ApiKey {ELASTIC_API_KEY}

The entity is sent as a JSON value inside a ``multi_match`` query (never
concatenated into a query string), so it cannot alter the query structure.

Required env: ELASTIC_URL, ELASTIC_API_KEY. Optional: ELASTIC_INDEX (logs-*).
Status: unit-tested with mocked HTTP; not yet validated against a live instance.
"""

from __future__ import annotations

import re
from typing import Any

import requests

from .base import SIEMConnector, SIEMError

_INDEX_RE = re.compile(r"^[A-Za-z0-9_.*,\-]{1,120}$")
SYSMON_DATASET = "windows.sysmon_operational"


class ElasticConnector(SIEMConnector):
    name = "elastic"
    beta = True

    def __init__(self, url: str | None, api_key: str | None, index: str = "logs-*",
                 timeout: int = 20, lookback_hours: int = 24, max_events: int = 50) -> None:
        if not url or not api_key:
            raise SIEMError("Elastic backend needs ELASTIC_URL and ELASTIC_API_KEY.")
        if not _INDEX_RE.match(index):
            raise SIEMError(f"Invalid ELASTIC_INDEX {index!r}.")
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.index = index
        self.timeout = timeout
        self.lookback_hours = max(1, lookback_hours)
        self.max_events = max(1, min(max_events, 500))

    def build_body(self, entity: str, event_type: str) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [
            {"range": {"@timestamp": {"gte": f"now-{self.lookback_hours}h"}}}
        ]
        if event_type == "sysmon":
            filters.append({"term": {"event.dataset": SYSMON_DATASET}})
        return {
            "size": self.max_events,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [{"multi_match": {"query": entity, "fields": ["*"],
                                              "lenient": True}}],
                    "filter": filters,
                }
            },
        }

    def search(self, entity: str, event_type: str = "all") -> dict[str, Any]:
        body = self.build_body(entity, event_type)
        try:
            resp = requests.post(
                f"{self.url}/{self.index}/_search",
                headers={"Authorization": f"ApiKey {self.api_key}",
                         "Content-Type": "application/json"},
                json=body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SIEMError(f"Elastic network failure: {exc!r}") from exc

        if resp.status_code in (401, 403):
            raise SIEMError(f"Elastic rejected the API key (HTTP {resp.status_code}).")
        if resp.status_code != 200:
            raise SIEMError(f"Elastic returned HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            hits = resp.json().get("hits", {}).get("hits", [])
        except ValueError as exc:
            raise SIEMError(f"Could not parse Elastic response: {exc!r}") from exc

        events = [h.get("_source", {}) for h in hits if isinstance(h, dict)]
        return {
            "entity": entity,
            "events": events,
            "_meta": {"backend": self.name, "index": self.index, "count": len(events)},
        }
