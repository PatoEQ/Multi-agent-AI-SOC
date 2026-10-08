"""
crew.py
=======
Pipeline orchestration. ``run_pipeline`` is the single entry point used by the
CLI, the Streamlit UI and the evaluation harness.

    sanitize + injection pre-scan (+ optional PII redaction)
        │
    Phase 1  Triage crew ──► TRIAGE_VERDICT
        │      FALSE_POSITIVE + no injection markers + early-exit on => close
    Phase 2  Investigation crew (intel, DFIR, IR, Auditor) ──► GATE_DECISION
        │      HALT or unparseable => stop here (fail closed), no report
    Phase 3  Report crew ──► report + YARA-L + Suricata
        │
    rule linting, STIX 2.1 + ATT&CK Navigator exports, usage metrics

Splitting the work into separate crews is what makes the Auditor's gate
*binding*: the report crew is simply never started unless code allows it.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from collections.abc import Callable

import config  # noqa: F401  (sets privacy env vars before crewai loads)
from crewai import Crew, Process

import redaction
from agents import build_all_agents
from config import get_llm, get_settings
from exports import build_navigator_layer, build_stix_bundle, extract_indicators, extract_techniques
from gate import GateDecision, GateResult, TriageVerdict, parse_gate, parse_triage
from rule_validation import RuleCheck, render_checks_markdown, validate_report_rules
from security import (
    InjectionFinding,
    detect_injection,
    injection_notice,
    neutralize_placeholders,
    sanitize_alert,
    wrap_untrusted,
)
from tasks import build_investigation_tasks, build_report_task, build_triage_task

STATUS_COMPLETED = "completed"
STATUS_HALTED = "halted_by_auditor"
STATUS_FALSE_POSITIVE = "closed_false_positive"
STATUS_ERROR = "error"


@dataclass
class StageOutput:
    stage: str
    agent: str
    text: str


@dataclass
class PipelineResult:
    status: str
    report_markdown: str = ""
    triage_verdict: str = TriageVerdict.UNKNOWN.value
    gate: Optional[GateResult] = None
    injection_findings: list[InjectionFinding] = field(default_factory=list)
    stages: list[StageOutput] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    rule_checks: list[RuleCheck] = field(default_factory=list)
    stix_bundle: Optional[dict] = None
    navigator_layer: Optional[dict] = None
    output_files: dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    alert_truncated: bool = False
    redacted_identities: int = 0

    @property
    def ok(self) -> bool:
        return self.status != STATUS_ERROR

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "triage_verdict": self.triage_verdict,
            "gate_decision": self.gate.decision.value if self.gate else None,
            "gate_parsed": self.gate.parsed if self.gate else None,
            "injection_findings": [f.label for f in self.injection_findings],
            "usage": self.usage,
            "rule_checks": [{"language": c.language, "ok": c.ok, "errors": c.errors,
                             "warnings": c.warnings} for c in self.rule_checks],
            "exported_indicators": sum(
                1 for o in (self.stix_bundle or {}).get("objects", [])
                if o.get("type") == "indicator"),
            "duration_seconds": round(self.duration_seconds, 1),
            "alert_truncated": self.alert_truncated,
            "redacted_identities": self.redacted_identities,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
_USAGE_FIELDS = ("total_tokens", "prompt_tokens", "completion_tokens",
                 "cached_prompt_tokens", "successful_requests")


def _add_usage(total: dict[str, int], crew_output: Any) -> None:
    metrics = getattr(crew_output, "token_usage", None)
    if metrics is None:
        return
    data = metrics.model_dump() if hasattr(metrics, "model_dump") else vars(metrics)
    for name in _USAGE_FIELDS:
        try:
            total[name] = total.get(name, 0) + int(data.get(name, 0) or 0)
        except (TypeError, ValueError):
            continue


def _task_texts(crew_output: Any) -> list[str]:
    outputs = getattr(crew_output, "tasks_output", None) or []
    return [str(getattr(o, "raw", "") or "") for o in outputs]


def _make_crew(agents: list, tasks: list, step_callback, task_callback,
               hierarchical: bool = False) -> Crew:
    settings = get_settings()
    kwargs: dict[str, Any] = {
        "agents": agents,
        "tasks": tasks,
        "verbose": settings.verbose,
        "process": Process.hierarchical if hierarchical else Process.sequential,
    }
    if hierarchical:
        kwargs["manager_llm"] = get_llm()  # required for hierarchical mode
    if step_callback is not None:
        kwargs["step_callback"] = step_callback
    if task_callback is not None:
        kwargs["task_callback"] = task_callback
    return Crew(**kwargs)


def _gate_banner(gate: GateResult) -> str:
    icon = {"PROCEED": "✅", "PROCEED_WITH_CORRECTIONS": "⚠️", "HALT": "⛔"}[gate.decision.value]
    lines = [f"> {icon} **Auditor gate: {gate.decision.value}**"]
    if gate.rationale:
        lines.append(f"> {gate.rationale}")
    if gate.rejected_findings:
        lines.append("> Rejected by the Auditor: " + "; ".join(gate.rejected_findings))
    return "\n".join(lines) + "\n\n"


def _injection_banner(findings: list[InjectionFinding]) -> str:
    if not findings:
        return ""
    labels = ", ".join(sorted({f.label for f in findings}))
    return (f"> 🚩 **Prompt-injection markers detected in the alert:** {labels}. "
            "Treated as attacker artefacts; triage early-exit was disabled.\n\n")


def _write(path: str, content: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _finish(result: PipelineResult, started: float, output_dir: str) -> PipelineResult:
    result.duration_seconds = time.monotonic() - started
    if result.report_markdown:
        result.output_files["report"] = _write(
            os.path.join(output_dir, "incident_report.md"), result.report_markdown)
    if result.stix_bundle:
        result.output_files["stix"] = _write(
            os.path.join(output_dir, "iocs.stix.json"), json.dumps(result.stix_bundle, indent=2))
    if result.navigator_layer:
        result.output_files["navigator"] = _write(
            os.path.join(output_dir, "attack_navigator_layer.json"),
            json.dumps(result.navigator_layer, indent=2))
    result.output_files["summary"] = _write(
        os.path.join(output_dir, "run_summary.json"), json.dumps(result.summary(), indent=2))
    return result


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run_pipeline(
    alert_text: str,
    step_callback: Optional[Callable] = None,
    task_callback: Optional[Callable] = None,
    output_dir: str = "output",
    early_exit: Optional[bool] = None,
) -> PipelineResult:
    """Run the full investigation. Never raises for operational problems."""
    started = time.monotonic()
    settings = get_settings()
    early_exit = settings.triage_early_exit if early_exit is None else early_exit

    if not alert_text or not alert_text.strip():
        return PipelineResult(status=STATUS_ERROR,
                              error="Empty alert. Paste a SIEM/UDM alert to investigate.")

    # --- 0. Pre-processing (deterministic, no LLM) ------------------------ #
    findings = detect_injection(alert_text)
    clean_alert, truncated = sanitize_alert(alert_text, settings.max_alert_chars)
    prescan = injection_notice(findings)
    if truncated:
        prescan += "\nNote: the alert was truncated to the configured maximum size."

    redactor = redaction.Redactor() if settings.redact_pii else None
    redaction.activate(redactor)
    llm_alert = redactor.redact(clean_alert) if redactor else clean_alert

    result = PipelineResult(status=STATUS_ERROR, injection_findings=findings,
                            alert_truncated=truncated)
    restore = redaction.from_llm

    def _done() -> PipelineResult:
        if redactor is not None:
            result.redacted_identities = len(redactor.mapping())
        return _finish(result, started, output_dir)

    try:
        agents = build_all_agents()

        # --- Phase 1: triage ------------------------------------------------ #
        triage_crew = _make_crew([agents["triage"]], [build_triage_task(agents["triage"])],
                                 step_callback, task_callback)
        triage_out = triage_crew.kickoff(inputs={"alert": wrap_untrusted(llm_alert),
                                                 "prescan": prescan})
        _add_usage(result.usage, triage_out)
        triage_text = (_task_texts(triage_out) or [str(getattr(triage_out, "raw", ""))])[0]
        result.stages.append(StageOutput("Triage", agents["triage"].role, restore(triage_text)))
        verdict = parse_triage(triage_text)
        result.triage_verdict = verdict.value

        if verdict is TriageVerdict.FALSE_POSITIVE and early_exit and not findings:
            result.status = STATUS_FALSE_POSITIVE
            result.report_markdown = (
                "# Alert closed at triage — FALSE POSITIVE\n\n"
                "The Tier 1 analyst classified this alert as a false positive, so the "
                "full investigation was skipped to save time and cost. Set "
                "`TRIAGE_EARLY_EXIT=0` to always run every agent.\n\n"
                "## Triage analysis\n\n" + restore(triage_text) + "\n"
            )
            return _done()

        # --- Phase 2: investigation + audit gate ---------------------------- #
        phase2_inputs = {"triage_report": neutralize_placeholders(triage_text),
                         "prescan": prescan}
        inv_tasks = build_investigation_tasks(agents)
        inv_crew = _make_crew(
            [agents["intel"], agents["dfir"], agents["ir"], agents["auditor"]], inv_tasks,
            step_callback, task_callback,
            hierarchical=settings.process_type == "hierarchical")
        inv_out = inv_crew.kickoff(inputs=phase2_inputs)
        _add_usage(result.usage, inv_out)

        texts = _task_texts(inv_out)
        texts += [""] * (4 - len(texts))
        intel_text, dfir_text, ir_text, audit_text = texts[:4]
        for name, key, text in (("Threat Intelligence", "intel", intel_text),
                                ("DFIR", "dfir", dfir_text),
                                ("Incident Response", "ir", ir_text),
                                ("Critical Audit (gate)", "auditor", audit_text)):
            result.stages.append(StageOutput(name, agents[key].role, restore(text)))

        gate = parse_gate(audit_text)
        result.gate = gate

        if not gate.decision.allows_report:
            result.status = STATUS_HALTED
            reason = gate.rationale or "The Auditor found the core conclusion unsupported."
            if not gate.parsed:
                reason = ("The Auditor did not return a valid decision, so the pipeline "
                          "failed closed.")
            result.report_markdown = (
                "# ⛔ Investigation halted by the Critical Auditor\n\n"
                + _injection_banner(findings)
                + f"**Reason:** {reason}\n\n"
                "No executive report or detection rules were produced. A human analyst "
                "should review the audit below before acting on any finding.\n\n"
                "## Auditor validation\n\n" + restore(audit_text) + "\n\n"
                "## Unvalidated investigation notes\n\n"
                "### Threat intelligence\n\n" + restore(intel_text) + "\n\n"
                "### DFIR\n\n" + restore(dfir_text) + "\n\n"
                "### Proposed response (NOT approved)\n\n" + restore(ir_text) + "\n"
            )
            return _done()

        # --- Phase 3: report + detection rules ------------------------------ #
        report_crew = _make_crew([agents["writer"]],
                                 [build_report_task(agents["writer"])],
                                 step_callback, task_callback)
        report_out = report_crew.kickoff(inputs={
            "audit_report": neutralize_placeholders(audit_text),
            "triage_report": neutralize_placeholders(triage_text),
            "intel_report": neutralize_placeholders(intel_text),
            "dfir_report": neutralize_placeholders(dfir_text),
            "ir_report": neutralize_placeholders(ir_text),
        })
        _add_usage(result.usage, report_out)
        report_text = restore((_task_texts(report_out) or [str(getattr(report_out, "raw", ""))])[0])
        result.stages.append(StageOutput("Report", agents["writer"].role, report_text))

        # --- Post-processing (deterministic) -------------------------------- #
        result.rule_checks = validate_report_rules(report_text)
        result.report_markdown = (
            _gate_banner(gate) + _injection_banner(findings) + report_text
            + render_checks_markdown(result.rule_checks)
        )

        indicators = extract_indicators(restore(intel_text),
                                        [restore(r) for r in gate.rejected_indicators])
        techniques = extract_techniques(restore(dfir_text), restore(intel_text))
        if indicators or techniques:
            result.stix_bundle = build_stix_bundle(indicators, techniques)
        if techniques:
            result.navigator_layer = build_navigator_layer(techniques)

        result.status = STATUS_COMPLETED
        return _done()

    except Exception as exc:  # surface a clean message instead of a traceback
        result.status = STATUS_ERROR
        result.error = (
            f"The crew failed to complete: {exc!r}\n\nCommon causes: a missing or "
            "invalid LLM API key, a model your account cannot use, or a provider "
            "outage. Check .env, or try FORCE_MOCK=1 to rule out tool problems."
        )
        result.duration_seconds = time.monotonic() - started
        return result
    finally:
        if redactor is not None:
            result.redacted_identities = len(redactor.mapping())
        redaction.activate(None)


def result_to_dict(result: PipelineResult) -> dict[str, Any]:
    """Full JSON-serialisable view (used by the eval harness)."""
    data = result.summary()
    data["stages"] = [asdict(s) for s in result.stages]
    return data


__all__ = ["run_pipeline", "PipelineResult", "StageOutput", "result_to_dict",
           "STATUS_COMPLETED", "STATUS_HALTED", "STATUS_FALSE_POSITIVE", "STATUS_ERROR",
           "GateDecision"]
