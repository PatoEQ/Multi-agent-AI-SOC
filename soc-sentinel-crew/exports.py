"""
exports.py
==========
Machine-readable exports so results plug into existing tooling:

* **STIX 2.1 bundle** of the validated indicators (+ ATT&CK attack-patterns and
  a report object) — importable into MISP, OpenCTI, TIPs and many SIEMs.
* **MITRE ATT&CK Navigator layer** of the observed techniques.

Only indicators the Threat-Intel analyst rated MALICIOUS or SUSPICIOUS and
the Auditor did NOT reject are exported. Exports are skipped when the gate
halted the pipeline.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from gate import find_json_with_key

# Fixed namespace => the same indicator always gets the same STIX id.
_NAMESPACE = uuid.UUID("6f0b3c9e-2d5a-4f8e-9a51-0c7b1d2e3f40")
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EXPORTABLE = {"MALICIOUS", "SUSPICIOUS"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NAMESPACE, f'{kind}:{key}')}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _normalize_type(value: str, declared: str) -> str | None:
    t = (declared or "").lower().replace("-", "").replace("_", "")
    v = value.strip()
    if t in {"ipv4", "ip", "ipaddress", "ipv4addr"}:
        return "ipv4"
    if t in {"ipv6", "ipv6addr"}:
        return "ipv6"
    if t in {"domain", "domainname", "fqdn", "hostname"}:
        return "domain"
    if t == "url":
        return "url"
    if t in {"md5", "sha1", "sha256", "hash", "filehash"}:
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v))
    return None


def _pattern(value: str, itype: str) -> str | None:
    v = _escape(value.strip())
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
    }.get(itype)


# --------------------------------------------------------------------------- #
# Extraction from agent outputs
# --------------------------------------------------------------------------- #
def extract_indicators(intel_text: str, rejected: list[str] | None = None) -> list[dict]:
    """Return validated, exportable indicators from the intel agent's json block."""
    rejected_set = {r.strip().lower() for r in (rejected or [])}
    block = find_json_with_key(intel_text or "", "indicators")
    if not block or not isinstance(block.get("indicators"), list):
        return []
    out, seen = [], set()
    for item in block["indicators"]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        verdict = str(item.get("verdict", "")).strip().upper()
        itype = _normalize_type(value, str(item.get("type", "")))
        if not value or verdict not in _EXPORTABLE or itype is None:
            continue
        if value.lower() in rejected_set or value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append({
            "value": value, "type": itype, "verdict": verdict,
            "evidence": str(item.get("evidence", ""))[:500],
            "attack": [t for t in item.get("attack", []) if _TECHNIQUE_RE.fullmatch(str(t))]
            if isinstance(item.get("attack"), list) else [],
        })
    return out


def extract_techniques(*texts: str) -> list[dict]:
    """Collect ATT&CK techniques: DFIR json block first, regex fallback."""
    found: dict[str, dict] = {}
    for text in texts:
        block = find_json_with_key(text or "", "techniques")
        if block and isinstance(block.get("techniques"), list):
            for t in block["techniques"]:
                if isinstance(t, dict) and _TECHNIQUE_RE.fullmatch(str(t.get("id", ""))):
                    found.setdefault(t["id"], {
                        "id": t["id"], "name": str(t.get("name", "")),
                        "evidence": str(t.get("evidence", ""))[:300],
                    })
    if not found:
        for text in texts:
            for tid in _TECHNIQUE_RE.findall(text or ""):
                found.setdefault(tid, {"id": tid, "name": "", "evidence": ""})
    return sorted(found.values(), key=lambda t: t["id"])


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def build_stix_bundle(indicators: list[dict], techniques: list[dict],
                      title: str = "SOC Sentinel Crew investigation") -> dict[str, Any]:
    now = _now()
    identity_id = _stix_id("identity", "soc-sentinel-crew")
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now, "name": "SOC Sentinel Crew",
        "identity_class": "system",
    }]
    refs: list[str] = []

    for ind in indicators:
        pattern = _pattern(ind["value"], ind["type"])
        if not pattern:
            continue
        sid = _stix_id("indicator", f"{ind['type']}:{ind['value'].lower()}")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": sid,
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"{ind['type']}: {ind['value']}",
            "description": f"{ind['verdict']} — {ind['evidence']}".strip(" —"),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": now,
            "confidence": 85 if ind["verdict"] == "MALICIOUS" else 50,
            "labels": [ind["verdict"].lower()],
        })
        refs.append(sid)

    for tech in techniques:
        aid = _stix_id("attack-pattern", tech["id"])
        url_path = tech["id"].replace(".", "/")
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": aid,
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": tech["name"] or tech["id"],
            "external_references": [{
                "source_name": "mitre-attack", "external_id": tech["id"],
                "url": f"https://attack.mitre.org/techniques/{url_path}/",
            }],
        })
        refs.append(aid)

    if refs:
        objects.append({
            "type": "report", "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}", "created": now, "modified": now,
            "created_by_ref": identity_id, "name": title, "published": now,
            "report_types": ["threat-report"], "object_refs": refs,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def build_navigator_layer(techniques: list[dict],
                          name: str = "SOC Sentinel Crew — observed techniques") -> dict:
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Techniques observed and validated by the SOC Sentinel Crew.",
        "techniques": [{
            "techniqueID": t["id"], "score": 1, "color": "#e4572e",
            "comment": t.get("evidence", ""), "enabled": True,
        } for t in techniques],
        "gradient": {"colors": ["#ffffff", "#e4572e"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Observed in this incident", "color": "#e4572e"}],
    }
