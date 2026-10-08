"""Gate parsing, rule linting and STIX / Navigator exports."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from exports import build_navigator_layer, build_stix_bundle, extract_indicators, extract_techniques
from gate import (
    GateDecision,
    TriageVerdict,
    audit_guardrail,
    parse_gate,
    parse_triage,
    triage_guardrail,
)
from rule_validation import lint_suricata_rule, lint_yaral_rule, validate_report_rules

AUDIT_JSON = """Audit table...
```json
{"gate_decision": "PROCEED_WITH_CORRECTIONS", "approved_findings": ["chain"],
 "rejected_findings": ["APT29 attribution"], "rejected_indicators": ["198.51.100.7"],
 "rationale": "Core proven"}
```
GATE_DECISION: PROCEED_WITH_CORRECTIONS
"""


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #
def test_parse_gate_json():
    g = parse_gate(AUDIT_JSON)
    assert g.decision is GateDecision.PROCEED_WITH_CORRECTIONS and g.parsed
    assert g.source == "json" and g.rejected_indicators == ["198.51.100.7"]


def test_parse_gate_line_only():
    g = parse_gate("blah\n**GATE_DECISION: HALT**")
    assert g.decision is GateDecision.HALT and g.parsed and g.source == "line"


def test_parse_gate_fails_closed():
    g = parse_gate("Looks fine to me, proceed!")
    assert g.decision is GateDecision.HALT and not g.parsed
    assert not g.decision.allows_report


def test_parse_gate_uses_last_line():
    g = parse_gate("GATE_DECISION: PROCEED\n...reconsidered...\nGATE_DECISION: HALT")
    assert g.decision is GateDecision.HALT


@pytest.mark.parametrize("text,expected", [
    ("...\nTRIAGE_VERDICT: INVESTIGATE", TriageVerdict.INVESTIGATE),
    ("TRIAGE_VERDICT: FALSE_POSITIVE", TriageVerdict.FALSE_POSITIVE),
    ("TRIAGE_VERDICT: false positive", TriageVerdict.FALSE_POSITIVE),
    ("no verdict here", TriageVerdict.UNKNOWN),
])
def test_parse_triage(text, expected):
    assert parse_triage(text) is expected


def test_guardrails():
    ok, _ = audit_guardrail(SimpleNamespace(raw=AUDIT_JSON))
    bad, feedback = audit_guardrail(SimpleNamespace(raw="no decision"))
    assert ok and not bad and "GATE_DECISION" in feedback
    assert triage_guardrail(SimpleNamespace(raw="TRIAGE_VERDICT: INVESTIGATE"))[0]
    assert not triage_guardrail(SimpleNamespace(raw="maybe?"))[0]


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
GOOD_SURICATA = ('alert tls $HOME_NET any -> 185.220.101.47 443 (msg:"C2 beacon; test"; '
                 'flow:established,to_server; sid:1000001; rev:1;)')
GOOD_YARAL = """rule powershell_from_office {
  meta:
    author = "Multi-agent AI SOC"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.parent_process.file.full_path = /winword\\.exe$/ nocase
    $e.target.process.file.full_path = /powershell\\.exe$/ nocase
  condition:
    $e
}"""


def test_suricata_good_rule():
    check = lint_suricata_rule(GOOD_SURICATA)
    assert check.ok, check.errors
    assert not check.warnings


@pytest.mark.parametrize("rule,needle", [
    ('alert tcp any any -> any any (msg:"x"; rev:1;)', "sid"),
    ('alert tcp any any -> any any (sid:1000001; rev:1;)', "msg"),
    ('alert tcp any any -> any any (msg:"x"; sid:1000001; rev:1)', "end with ';'"),
    ('banana tcp any any -> any any (msg:"x"; sid:1000001;)', "Unknown action"),
    ("alert tcp any any any any", "Header"),
    ('alert tcp any any -> any any (msg:"x; sid:1000001;)', "quotes"),
])
def test_suricata_bad_rules(rule, needle):
    check = lint_suricata_rule(rule)
    assert not check.ok and any(needle in e for e in check.errors), check.errors


def test_suricata_sid_range_warning():
    check = lint_suricata_rule('alert tcp any any -> any any (msg:"x"; sid:42; rev:1;)')
    assert check.ok and any("local range" in w for w in check.warnings)


def test_yaral_good_rule():
    check = lint_yaral_rule(GOOD_YARAL)
    assert check.ok, check.errors


def test_yaral_missing_sections_and_braces():
    check = lint_yaral_rule("rule broken {\n  meta:\n  condition:\n    $e\n")
    assert not check.ok
    joined = " ".join(check.errors)
    assert "events" in joined and "braces" in joined


def test_validate_report_rules_extracts_blocks():
    report = f"# Report\n```yara-l\n{GOOD_YARAL}\n```\n\n```suricata\n# comment\n{GOOD_SURICATA}\n```"
    checks = validate_report_rules(report, engine_check=False)
    assert [c.language for c in checks] == ["yara-l", "suricata"]
    assert all(c.ok for c in checks)


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
INTEL = """Table...
```json
{"indicators": [
  {"value": "185.220.101.47", "type": "ipv4", "verdict": "MALICIOUS", "evidence": "VT 41", "attack": ["T1071.001"]},
  {"value": "cdn-telemetry-sync.net", "type": "domain", "verdict": "SUSPICIOUS", "evidence": "new domain"},
  {"value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "type": "sha256", "verdict": "MALICIOUS"},
  {"value": "198.51.100.7", "type": "ipv4", "verdict": "MALICIOUS"},
  {"value": "8.8.8.8", "type": "ipv4", "verdict": "BENIGN"}
]}
```"""
DFIR = """```json
{"techniques": [{"id": "T1059.001", "name": "PowerShell", "evidence": "EID 1"},
                {"id": "T1547.001", "name": "Run Keys", "evidence": "EID 13"}]}
```"""


def test_extract_indicators_respects_verdict_and_auditor():
    inds = extract_indicators(INTEL, rejected=["198.51.100.7"])
    values = {i["value"] for i in inds}
    assert values == {"185.220.101.47", "cdn-telemetry-sync.net",
                      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}


def test_extract_techniques_json_and_regex_fallback():
    assert [t["id"] for t in extract_techniques(DFIR)] == ["T1059.001", "T1547.001"]
    assert [t["id"] for t in extract_techniques("seen T1021.002 and T1003")] == ["T1003", "T1021.002"]


def test_stix_bundle_shape():
    bundle = build_stix_bundle(extract_indicators(INTEL), extract_techniques(DFIR))
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("indicator") == 4 and types.count("attack-pattern") == 2
    assert "report" in types and "identity" in types
    patterns = {o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert "[ipv4-addr:value = '185.220.101.47']" in patterns
    assert any("file:hashes.'SHA-256'" in p for p in patterns)
    for obj in bundle["objects"]:
        assert obj["spec_version"] == "2.1" and obj["id"].startswith(obj["type"] + "--")


def test_stix_ids_are_deterministic():
    a = build_stix_bundle(extract_indicators(INTEL), [])
    b = build_stix_bundle(extract_indicators(INTEL), [])
    ids = lambda bun: sorted(o["id"] for o in bun["objects"] if o["type"] == "indicator")  # noqa: E731
    assert ids(a) == ids(b)


def test_stix_pattern_escaping():
    bundle = build_stix_bundle([{"value": "evil'.com", "type": "domain",
                                 "verdict": "MALICIOUS", "evidence": ""}], [])
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[domain-name:value = 'evil\\'.com']"


def test_navigator_layer():
    layer = build_navigator_layer(extract_techniques(DFIR))
    assert layer["domain"] == "enterprise-attack"
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1059.001", "T1547.001"]
