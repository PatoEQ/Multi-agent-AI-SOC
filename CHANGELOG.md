# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-10-06

First public release.

### Added
- Six-agent CrewAI pipeline: Triage, Threat Intel, DFIR, Incident Response,
  Critical Auditor and Report Writer.
- **Binding Auditor gate**: the pipeline runs as three crews, and the report crew
  only starts if code parses `PROCEED` / `PROCEED_WITH_CORRECTIONS`. A missing or
  invalid decision fails closed (`HALT`). Guardrails make the Auditor retry until
  it states a decision.
- **Prompt-injection defences**: deterministic pre-scan, sanitiser, untrusted-data
  delimiters, a standing policy in every agent, and no triage early-exit when
  injection is detected.
- **Optional PII redaction** (`REDACT_PII=1`): identities are pseudonymised before
  reaching the LLM and restored locally.
- Pluggable SIEM connectors: Chronicle mock (default), plus Splunk, Elastic and
  Microsoft Sentinel (beta).
- VirusTotal v3 tool with caching and free-tier rate limiting; EXA / DuckDuckGo
  threat search with caching.
- Detection-rule linting (Suricata + YARA-L 2.0) with optional `suricata -T` check.
- STIX 2.1 bundle and MITRE ATT&CK Navigator layer exports.
- Token-usage metrics in the CLI and UI.
- Streamlit UI with live agent feed, agent-debate view, rule validation and exports.
- Labelled evaluation set and harness (`evals/`).
- Test suite, GitHub Actions CI (ruff, pytest, gitleaks), Dependabot, Docker.
- CrewAI anonymous telemetry disabled by default.
