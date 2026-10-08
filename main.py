#!/usr/bin/env python3
"""
main.py — command-line entry point for the Multi-agent AI SOC.

Examples
--------
    python main.py --sample                    # bundled sample alert
    python main.py --file path/to/alert.json   # your own alert
    cat alert.json | python main.py            # stdin
    python main.py --sample --mock             # mock every external tool
    python main.py --sample --full             # never stop early at triage
"""

from __future__ import annotations

import argparse
import os
import sys

import config
from config import preflight
from crew import STATUS_COMPLETED, STATUS_ERROR, run_pipeline

SAMPLE_PATH = os.path.join("sample_alerts", "sample_udm_alert.json")


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        print(f"ERROR: could not read {path}: {exc}", file=sys.stderr)
        return None


def _read_alert(args: argparse.Namespace) -> str | None:
    if args.alert:
        return args.alert
    if args.file:
        return _read(args.file)
    if args.sample:
        return _read(SAMPLE_PATH)
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        return data or None
    return None


def _step_logger(step) -> None:
    text = " ".join(str(getattr(step, "log", None) or step).split())
    if text:
        print(f"  ┊ {text[:300]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Autonomous multi-agent SOC pipeline (CrewAI).")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--alert", help="Raw alert text passed directly.")
    src.add_argument("--file", help="Path to a file containing the alert.")
    src.add_argument("--sample", action="store_true", help="Use the bundled sample alert.")
    parser.add_argument("--output-dir", default="output", help="Where results are written.")
    parser.add_argument("--full", action="store_true",
                        help="Run every agent even if triage says FALSE_POSITIVE.")
    parser.add_argument("--quiet", action="store_true", help="No per-step logging.")
    parser.add_argument("--mock", action="store_true",
                        help="Mock every external tool (same as FORCE_MOCK=1; works on Windows too).")
    args = parser.parse_args()

    if args.mock:
        os.environ["FORCE_MOCK"] = "1"
        config.reset_caches()

    for warning in preflight():
        print(f"[config] {warning}", file=sys.stderr)

    alert = _read_alert(args)
    if not alert:
        parser.print_help()
        print("\nERROR: no alert provided. Use --sample, --file, --alert or stdin.",
              file=sys.stderr)
        return 2

    print("\n=== Multi-agent AI SOC: investigation starting ===\n")
    result = run_pipeline(
        alert,
        step_callback=None if args.quiet else _step_logger,
        output_dir=args.output_dir,
        early_exit=False if args.full else None,
    )

    if result.status == STATUS_ERROR:
        print(f"\nERROR: {result.error}", file=sys.stderr)
        return 1

    for f in result.injection_findings:
        print(f"[!] Prompt-injection marker: {f.label} — “{f.excerpt}”")

    print("\n=== RESULT ===\n")
    print(result.report_markdown)

    print("\n=== SUMMARY ===")
    print(f"Status          : {result.status}")
    print(f"Triage verdict  : {result.triage_verdict}")
    if result.gate:
        print(f"Auditor gate    : {result.gate.decision.value}"
              + ("" if result.gate.parsed else " (fail-closed: no valid decision)"))
    usage = result.usage
    if usage:
        print(f"LLM usage       : {usage.get('total_tokens', 0):,} tokens in "
              f"{usage.get('successful_requests', 0)} requests")
    print(f"Duration        : {result.duration_seconds:.0f}s")
    for kind, path in result.output_files.items():
        print(f"Saved {kind:<10}: {path}")

    return 0 if result.status == STATUS_COMPLETED or result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
