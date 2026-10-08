"""
tools.py
========
Custom CrewAI tools for the Multi-agent AI SOC, written from scratch on top of
``crewai.tools.BaseTool``.

1. ``SIEMLogSearchTool``   — read-only log search through the configured SIEM
                             connector (Chronicle mock by default; Splunk,
                             Elastic and Sentinel available as beta backends).
2. ``VirusTotalTool``      — VirusTotal API v3 for IPs, hashes and domains,
                             with caching and free-tier rate limiting.
3. ``ThreatCVESearchTool`` — open-source intel search for CVEs / actors /
                             zero-days via EXA (preferred) or DuckDuckGo.

Rules every tool obeys:
* ``_run`` never raises — agents receive a readable error string instead.
* Secrets come only from :mod:`config` (environment variables).
* Tool *output* is untrusted evidence: control tokens are defanged and, when
  ``REDACT_PII`` is on, identities are pseudonymised before the LLM sees it.
* Every tool degrades to deterministic mock data when its key is missing.
"""

from __future__ import annotations

import ipaddress
import json
import re

import requests
from pydantic import BaseModel, Field

import config  # noqa: F401  (sets privacy env vars before crewai loads)
from crewai.tools import BaseTool

import redaction
from cache import RateLimiter, TTLCache
from config import get_settings
from security import defang_control_tokens
from siem import SIEMError, get_connector, validate_entity, validate_event_type

# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}$"
)

# Indicators used by the bundled demo/eval alerts so mock mode tells a story.
MOCK_KNOWN_BAD = {
    "185.220.101.47",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "cdn-telemetry-sync.net",
}


def classify_indicator(indicator: str) -> str:
    """Classify an IoC string as 'ip', 'hash', 'domain' or 'unknown'."""
    ioc = indicator.strip()
    if _IPV4_RE.match(ioc):
        try:
            ipaddress.ip_address(ioc)
            return "ip"
        except ValueError:
            return "unknown"
    if _SHA256_RE.match(ioc) or _SHA1_RE.match(ioc) or _MD5_RE.match(ioc):
        return "hash"
    if _DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


# Backwards-compatible alias (older tests / notebooks imported the private name)
_classify_indicator = classify_indicator


def _is_non_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not addr.is_global


def finalize_output(text: str) -> str:
    """Prepare tool output for the LLM: defang control tokens, then redact."""
    return redaction.to_llm(defang_control_tokens(text))


# Module-level caches / limiters shared by every tool instance.
_vt_cache: TTLCache[str] = TTLCache(ttl_seconds=get_settings().cache_ttl)
_search_cache: TTLCache[str] = TTLCache(ttl_seconds=get_settings().cache_ttl)
_vt_limiter = RateLimiter(min_interval=get_settings().vt_min_interval)


def reset_tool_state() -> None:
    """Clear caches and re-read rate limits (used by tests and the UI)."""
    s = get_settings()
    _vt_cache.ttl = s.cache_ttl
    _search_cache.ttl = s.cache_ttl
    _vt_cache.clear()
    _search_cache.clear()
    _vt_limiter.min_interval = max(0.0, s.vt_min_interval)


# =========================================================================== #
# 1. SIEM log search (Chronicle mock / Splunk / Elastic / Sentinel)
# =========================================================================== #
class SIEMQuery(BaseModel):
    entity: str = Field(
        ...,
        description="Observable to pull logs for: hostname, internal IP, username "
                    "or file SHA256, e.g. 'FIN-WKS-0423' or '10.20.14.57'.",
    )
    event_type: str = Field(
        default="all", description="Telemetry to return: 'udm', 'sysmon' or 'all'."
    )


class SIEMLogSearchTool(BaseTool):
    name: str = "siem_log_search"
    description: str = (
        "Fetch raw SIEM logs (UDM events and Windows Sysmon events) for one entity "
        "(hostname, IP, user or file hash). Use it to see the telemetry behind an "
        "alert and to reconstruct an execution chain. Read-only. Returns JSON."
    )
    args_schema: type[BaseModel] = SIEMQuery

    def _run(self, entity: str, event_type: str = "all") -> str:
        try:
            real_entity = validate_entity(redaction.from_llm(entity or ""))
            etype = validate_event_type(event_type)
        except ValueError as exc:
            return f"ERROR: {exc}"
        try:
            connector = get_connector(get_settings())
            payload = connector.search(real_entity, etype)
        except SIEMError as exc:
            return f"ERROR: SIEM query failed: {exc}"
        except Exception as exc:  # defensive: never bubble up to the agent
            return f"ERROR: unexpected SIEM failure: {exc!r}"
        return finalize_output(json.dumps(payload, indent=2, default=str))


# Backwards-compatible name used in the first release
ChronicleMockTool = SIEMLogSearchTool


# =========================================================================== #
# 2. VirusTotal API v3
# =========================================================================== #
class VirusTotalQuery(BaseModel):
    indicator: str = Field(
        ..., description="One IoC: IPv4 address, file hash (MD5/SHA1/SHA256) or domain."
    )
    indicator_type: str = Field(
        default="auto", description="'ip', 'hash', 'domain' or 'auto' (detect)."
    )


class VirusTotalTool(BaseTool):
    """
    Endpoints (header ``x-apikey``):
        GET /api/v3/ip_addresses/{ip} | /files/{hash} | /domains/{domain}

    Lookups only — nothing is ever uploaded. Internal IPs are refused (no
    reputation exists for them, and sending them out would leak topology).
    """

    name: str = "virustotal_lookup"
    description: str = (
        "Look up the reputation of a public IP, file hash (MD5/SHA1/SHA256) or "
        "domain on VirusTotal. Returns vendor detection counts, reputation score "
        "and, for files, the malware family. Use it to confirm whether an "
        "observable is actually malicious before classifying it."
    )
    args_schema: type[BaseModel] = VirusTotalQuery

    _BASE = "https://www.virustotal.com/api/v3"

    @staticmethod
    def _mock(indicator: str, itype: str) -> dict:
        malicious = indicator.strip().lower() in MOCK_KNOWN_BAD
        payload = {
            "indicator": indicator,
            "type": itype,
            "mode": "MOCK (no VIRUSTOTAL_API_KEY or FORCE_MOCK on)",
            "last_analysis_stats": {
                "malicious": 41 if malicious else 0,
                "suspicious": 3 if malicious else 0,
                "harmless": 2 if malicious else 68,
                "undetected": 18 if malicious else 20,
            },
            "reputation": -84 if malicious else 0,
            "verdict": "MALICIOUS" if malicious else "no detections",
        }
        if malicious and itype == "hash":
            payload["suggested_threat_label"] = "trojan.cobaltstrike/beacon"
        return payload

    @staticmethod
    def _summarize(indicator: str, itype: str, data: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        summary = {
            "indicator": indicator,
            "type": itype,
            "mode": "LIVE VirusTotal v3",
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation"),
            "verdict": "MALICIOUS" if flagged > 0 else "no detections",
        }
        if itype == "hash":
            summary["meaningful_name"] = attrs.get("meaningful_name")
            summary["type_description"] = attrs.get("type_description")
            summary["suggested_threat_label"] = (
                attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
            )
        elif itype == "ip":
            summary["as_owner"] = attrs.get("as_owner")
            summary["country"] = attrs.get("country")
        return summary

    def _lookup(self, indicator: str, itype: str) -> str:
        settings = get_settings()
        if not settings.virustotal_enabled:
            return json.dumps(self._mock(indicator, itype), indent=2)

        path = {"ip": "ip_addresses", "hash": "files", "domain": "domains"}[itype]
        waited = _vt_limiter.wait()  # respect the free-tier quota
        try:
            resp = requests.get(
                f"{self._BASE}/{path}/{indicator}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=settings.http_timeout,
            )
        except requests.RequestException as exc:
            return f"ERROR: VirusTotal network failure: {exc!r}"

        if resp.status_code == 200:
            try:
                summary = self._summarize(indicator, itype, resp.json())
            except (ValueError, KeyError, TypeError) as exc:
                return f"ERROR: could not parse VirusTotal response: {exc!r}"
            if waited:
                summary["rate_limit_wait_seconds"] = round(waited, 1)
            return json.dumps(summary, indent=2)
        if resp.status_code == 404:
            return json.dumps({"indicator": indicator, "type": itype,
                               "verdict": "not found in VirusTotal"}, indent=2)
        if resp.status_code == 401:
            return "ERROR: VirusTotal rejected the API key (401 Unauthorized)."
        if resp.status_code == 429:
            return "ERROR: VirusTotal quota exceeded (429). Increase VT_MIN_INTERVAL_SECONDS."
        return f"ERROR: VirusTotal returned HTTP {resp.status_code}."

    def _run(self, indicator: str, indicator_type: str = "auto") -> str:
        real = redaction.from_llm((indicator or "").strip())
        if not real:
            return "ERROR: 'indicator' is required."
        itype = (indicator_type or "auto").lower().strip()
        if itype == "auto":
            itype = classify_indicator(real)
        if itype not in {"ip", "hash", "domain"}:
            return (f"ERROR: could not classify {indicator!r} as ip/hash/domain. "
                    "Pass indicator_type explicitly.")
        if itype == "ip" and _is_non_public_ip(real):
            return finalize_output(json.dumps({
                "indicator": real, "type": "ip",
                "verdict": "not looked up: internal/non-routable address",
            }, indent=2))

        mode = "live" if get_settings().virustotal_enabled else "mock"
        key = f"{mode}:{itype}:{real.lower()}"
        cached = _vt_cache.get(key)
        if cached is not None:
            return finalize_output(cached)

        result = self._lookup(real, itype)
        if not result.startswith("ERROR"):
            _vt_cache.set(key, result)  # never cache errors
        return finalize_output(result)


# =========================================================================== #
# 3. Threat & CVE search (EXA preferred, DuckDuckGo fallback)
# =========================================================================== #
class ThreatSearchQuery(BaseModel):
    query: str = Field(
        ..., description="What to research, e.g. 'CVE-2024-3400 exploitation' or a "
                         "malware family / threat actor / zero-day name."
    )
    max_results: int = Field(default=5, description="Number of results (1-10).")


class ThreatCVESearchTool(BaseTool):
    name: str = "threat_cve_search"
    description: str = (
        "Search the open web / threat-intel sources for recent context on a CVE, "
        "malware family, threat-actor campaign or zero-day. Returns titles, URLs "
        "and snippets. Use it to enrich IoCs and find patch/mitigation guidance. "
        "Do not put usernames, hostnames or internal IPs in the query."
    )
    args_schema: type[BaseModel] = ThreatSearchQuery

    @staticmethod
    def _mock(query: str, n: int) -> dict:
        return {"query": query, "backend": "mock", "results": [{
            "title": f"[MOCK] Advisory discussing: {query}",
            "url": "https://example.com/advisory",
            "snippet": "Simulated result. Set EXA_API_KEY or install ddgs for live OSINT.",
        }][:n]}

    @staticmethod
    def _search_exa(query: str, n: int, settings) -> str:
        try:
            resp = requests.post(
                "https://api.exa.ai/search",
                headers={"x-api-key": settings.exa_api_key,
                         "Content-Type": "application/json"},
                json={"query": query, "numResults": n, "type": "auto",
                      "contents": {"text": {"maxCharacters": 500}}},
                timeout=settings.http_timeout,
            )
        except requests.RequestException as exc:
            return f"ERROR: EXA network failure: {exc!r}"
        if resp.status_code != 200:
            return f"ERROR: EXA returned HTTP {resp.status_code}."
        try:
            raw = resp.json().get("results", [])
        except ValueError as exc:
            return f"ERROR: could not parse EXA response: {exc!r}"
        results = [{"title": r.get("title"), "url": r.get("url"),
                    "snippet": (r.get("text") or "")[:400]} for r in raw[:n]]
        return json.dumps({"query": query, "backend": "exa", "results": results}, indent=2)

    @staticmethod
    def _search_ddg(query: str, n: int) -> str:
        try:
            from ddgs import DDGS  # package renamed from duckduckgo-search in 2025
        except ImportError:
            try:
                from duckduckgo_search import DDGS  # legacy name
            except ImportError:
                return ("ERROR: no search backend available. Install with "
                        "`pip install ddgs` or set EXA_API_KEY.")
        try:
            with DDGS() as ddgs:
                hits = list(ddgs.text(query, max_results=n))
        except Exception as exc:  # ddgs raises its own ratelimit/timeout errors
            return f"ERROR: DuckDuckGo search failed: {exc!r}"
        results = [{"title": h.get("title"), "url": h.get("href") or h.get("url"),
                    "snippet": (h.get("body") or "")[:400]} for h in hits]
        return json.dumps({"query": query, "backend": "duckduckgo",
                           "results": results}, indent=2)

    def _run(self, query: str, max_results: int = 5) -> str:
        settings = get_settings()
        query = (query or "").strip()
        if not query:
            return "ERROR: 'query' is required."
        try:
            n = max(1, min(int(max_results or 5), 10))
        except (TypeError, ValueError):
            n = 5

        if settings.force_mock:
            return finalize_output(json.dumps(self._mock(query, n), indent=2))

        key = f"{query.lower()}:{n}"
        cached = _search_cache.get(key)
        if cached is not None:
            return finalize_output(cached)

        out = ""
        if settings.exa_enabled:
            out = self._search_exa(query, n, settings)
        if not out or out.startswith("ERROR"):
            out = self._search_ddg(query, n)  # fall back rather than fail
        if not out.startswith("ERROR"):
            _search_cache.set(key, out)
        return finalize_output(out)


# --------------------------------------------------------------------------- #
# Singletons imported by agents.py
# --------------------------------------------------------------------------- #
siem_tool = SIEMLogSearchTool()
virustotal_tool = VirusTotalTool()
threat_search_tool = ThreatCVESearchTool()
chronicle_tool = siem_tool  # backwards-compatible alias

__all__ = [
    "SIEMLogSearchTool", "ChronicleMockTool", "VirusTotalTool", "ThreatCVESearchTool",
    "siem_tool", "chronicle_tool", "virustotal_tool", "threat_search_tool",
    "classify_indicator", "reset_tool_state", "finalize_output", "MOCK_KNOWN_BAD",
]
