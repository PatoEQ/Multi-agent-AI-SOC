"""
gate.py
=======
Deterministic parsing of the agents' machine-readable decisions.

The Auditor's verdict is **enforced in code**, not just requested in a prompt:

* the audit task carries a CrewAI *guardrail* (``audit_guardrail``) that rejects
  any output lacking a valid decision, forcing the Auditor to retry;
* after the investigation crew finishes, ``parse_gate`` extracts the decision;
* if the decision is ``HALT`` — or cannot be parsed at all — the pipeline stops
  and the Report Writer never runs (**fail closed**).

The same approach is used for the triage verdict (``TRIAGE_VERDICT``).
"""

# NOTE: no `from __future__ import annotations` in this module. CrewAI inspects
# the guardrail functions' return annotation at runtime and requires a real
# `tuple[bool, Any]` type object, not a postponed string annotation.

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GateDecision(str, Enum):
    PROCEED = "PROCEED"
    PROCEED_WITH_CORRECTIONS = "PROCEED_WITH_CORRECTIONS"
    HALT = "HALT"

    @property
    def allows_report(self) -> bool:
        return self is not GateDecision.HALT


class TriageVerdict(str, Enum):
    INVESTIGATE = "INVESTIGATE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNKNOWN = "UNKNOWN"


@dataclass
class GateResult:
    decision: GateDecision
    parsed: bool                     # False => decision defaulted to HALT
    source: str                      # "json" | "line" | "fallback"
    approved_findings: list[str] = field(default_factory=list)
    rejected_findings: list[str] = field(default_factory=list)
    rejected_indicators: list[str] = field(default_factory=list)
    rationale: str = ""


_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)
_GATE_LINE_RE = re.compile(
    r"GATE_DECISION\s*[:=]\s*\**\s*(PROCEED_WITH_CORRECTIONS|PROCEED|HALT)\b",
    re.IGNORECASE,
)
_TRIAGE_LINE_RE = re.compile(
    r"TRIAGE_VERDICT\s*[:=]\s*\**\s*(INVESTIGATE|FALSE[_\s-]?POSITIVE)\b",
    re.IGNORECASE,
)


def extract_json_blocks(text: str) -> list[Any]:
    """Return every fenced JSON block in ``text`` that parses successfully."""
    blocks: list[Any] = []
    for raw in _FENCE_RE.findall(text or ""):
        try:
            blocks.append(json.loads(raw))
        except ValueError:
            continue
    return blocks


def find_json_with_key(text: str, key: str) -> dict | None:
    """Return the LAST fenced JSON object containing ``key`` (agents put it last)."""
    for block in reversed(extract_json_blocks(text)):
        if isinstance(block, dict) and key in block:
            return block
    return None


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None and str(v).strip()]


def parse_gate(text: str) -> GateResult:
    """Parse the Auditor's decision. Unknown or missing => HALT (fail closed)."""
    block = find_json_with_key(text, "gate_decision")
    if block is not None:
        raw = str(block.get("gate_decision", "")).strip().upper().replace(" ", "_")
        try:
            decision = GateDecision(raw)
            return GateResult(
                decision=decision,
                parsed=True,
                source="json",
                approved_findings=_as_str_list(block.get("approved_findings")),
                rejected_findings=_as_str_list(block.get("rejected_findings")),
                rejected_indicators=[
                    s.lower() for s in _as_str_list(block.get("rejected_indicators"))
                ],
                rationale=str(block.get("rationale", "")),
            )
        except ValueError:
            pass  # fall through to the line format

    matches = _GATE_LINE_RE.findall(text or "")
    if matches:
        # Use the last occurrence — the final, considered decision.
        return GateResult(
            decision=GateDecision(matches[-1].upper()), parsed=True, source="line"
        )

    return GateResult(
        decision=GateDecision.HALT,
        parsed=False,
        source="fallback",
        rationale="No valid GATE_DECISION found in the audit output; failing closed.",
    )


def parse_triage(text: str) -> TriageVerdict:
    matches = _TRIAGE_LINE_RE.findall(text or "")
    if not matches:
        return TriageVerdict.UNKNOWN
    value = re.sub(r"[\s-]", "_", matches[-1].upper())
    return TriageVerdict.FALSE_POSITIVE if "FALSE" in value else TriageVerdict.INVESTIGATE


# --------------------------------------------------------------------------- #
# CrewAI guardrails: callable(TaskOutput) -> (bool, result_or_feedback)
# --------------------------------------------------------------------------- #
def _raw(task_output: Any) -> str:
    return str(getattr(task_output, "raw", task_output) or "")


def audit_guardrail(task_output: Any) -> tuple[bool, Any]:
    text = _raw(task_output)
    result = parse_gate(text)
    if result.parsed:
        return True, text
    return False, (
        "Your audit is missing a machine-readable decision. End your answer with a "
        "fenced ```json block containing the keys gate_decision (exactly one of "
        "PROCEED, PROCEED_WITH_CORRECTIONS, HALT), approved_findings, "
        "rejected_findings, rejected_indicators and rationale, followed by the line "
        "GATE_DECISION: <decision>."
    )


def triage_guardrail(task_output: Any) -> tuple[bool, Any]:
    text = _raw(task_output)
    if parse_triage(text) is not TriageVerdict.UNKNOWN:
        return True, text
    return False, (
        "Your triage is missing the required final line. End with exactly one line: "
        "TRIAGE_VERDICT: INVESTIGATE  or  TRIAGE_VERDICT: FALSE_POSITIVE"
    )
