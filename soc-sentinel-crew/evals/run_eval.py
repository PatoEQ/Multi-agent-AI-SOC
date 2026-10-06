#!/usr/bin/env python3
"""
evals/run_eval.py — measure how accurately the crew handles labelled alerts.

    python evals/run_eval.py                 # all cases, mock tools, 1 run each
    python evals/run_eval.py --runs 3        # repeat to measure consistency
    python evals/run_eval.py --case prompt-injection-attempt
    python evals/run_eval.py --live-tools    # use real VirusTotal / search
    python evals/run_eval.py --validate-only # no LLM: check files + injection pre-scan (CI)

Needs an LLM key (except --validate-only). Results are written to
evals/results/<timestamp>_<model>.md and .json so you can publish them in the
README and track accuracy across models and prompt changes.

Scoring per case (all must hold for a PASS):
  triage      TRIAGE_VERDICT matches expected_triage
  status      final status is in expected_status
  gate        Auditor decision is in expected_gate (when specified)
  injection   the deterministic pre-scan flagged injection iff expected
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def load_cases(selected: str | None = None) -> list[dict]:
    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]
    if selected:
        cases = [c for c in cases if c["id"] == selected]
        if not cases:
            raise SystemExit(f"No case with id {selected!r}.")
    for case in cases:
        with open(os.path.join(HERE, case["file"]), encoding="utf-8") as fh:
            case["alert"] = fh.read()
        json.loads(case["alert"])  # every alert must be valid JSON
    return cases


def validate_only(cases: list[dict]) -> int:
    """Deterministic checks that need no LLM (safe for CI)."""
    from security import detect_injection

    failures = 0
    for case in cases:
        flagged = bool(detect_injection(case["alert"]))
        ok = flagged == case["expect_injection_flag"]
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {case['id']:<32} injection pre-scan flagged={flagged}")
    print(f"\n{len(cases) - failures}/{len(cases)} cases passed deterministic validation.")
    return 1 if failures else 0


def score(case: dict, result) -> dict:
    gate = result.gate.decision.value if result.gate else None
    checks = {
        "triage": result.triage_verdict == case["expected_triage"],
        "status": result.status in case["expected_status"],
        "gate": case["expected_gate"] is None or gate in case["expected_gate"],
        "injection": bool(result.injection_findings) == case["expect_injection_flag"],
    }
    return {
        "case": case["id"], "label": case["label"], "passed": all(checks.values()),
        "checks": checks, "triage": result.triage_verdict, "status": result.status,
        "gate": gate, "tokens": result.usage.get("total_tokens", 0),
        "seconds": round(result.duration_seconds, 1), "error": result.error,
    }


def render_markdown(rows: list[dict], model: str, mock_tools: bool) -> str:
    passed = sum(r["passed"] for r in rows)
    lines = [
        f"# Evaluation results — {model}",
        "",
        f"- Date (UTC): {datetime.now(timezone.utc):%Y-%m-%d %H:%M}",
        f"- Tools: {'mock' if mock_tools else 'live'}",
        f"- **Score: {passed}/{len(rows)} runs passed ({100 * passed / max(1, len(rows)):.0f}%)**",
        "",
        "| Case | Label | Triage | Status | Gate | Injection flag | Result | Tokens |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        c = r["checks"]
        mark = lambda ok: "✅" if ok else "❌"  # noqa: E731
        lines.append(
            f"| {r['case']} | {r['label']} | {mark(c['triage'])} {r['triage']} | "
            f"{mark(c['status'])} {r['status']} | {mark(c['gate'])} {r['gate'] or '—'} | "
            f"{mark(c['injection'])} | {'PASS' if r['passed'] else 'FAIL'} | {r['tokens']:,} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", help="Run only this case id.")
    parser.add_argument("--runs", type=int, default=1, help="Repetitions per case.")
    parser.add_argument("--live-tools", action="store_true", help="Do not force mock tools.")
    parser.add_argument("--validate-only", action="store_true", help="No LLM; deterministic checks.")
    args = parser.parse_args()

    cases = load_cases(args.case)
    if args.validate_only:
        return validate_only(cases)

    if not args.live_tools:
        os.environ["FORCE_MOCK"] = "1"  # reproducible tool answers
    os.environ.setdefault("CREW_VERBOSE", "0")

    import config
    from crew import run_pipeline

    config.reset_caches()
    model = config.get_settings().llm_model
    rows: list[dict] = []
    for case in cases:
        for run in range(1, args.runs + 1):
            print(f"→ {case['id']} (run {run}/{args.runs}) …", flush=True)
            out_dir = os.path.join(HERE, "results", "runs", f"{case['id']}_{run}")
            result = run_pipeline(case["alert"], output_dir=out_dir)
            row = score(case, result)
            rows.append(row)
            print(f"  {'PASS' if row['passed'] else 'FAIL'}  triage={row['triage']} "
                  f"status={row['status']} gate={row['gate']}"
                  + (f"  error={row['error'][:120]}" if row["error"] else ""))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    safe_model = model.replace("/", "-")
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    base = os.path.join(HERE, "results", f"{stamp}_{safe_model}")
    markdown = render_markdown(rows, model, not args.live_tools)
    with open(base + ".md", "w", encoding="utf-8") as fh:
        fh.write(markdown)
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    print("\n" + markdown)
    print(f"Saved: {base}.md")
    return 0 if all(r["passed"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
