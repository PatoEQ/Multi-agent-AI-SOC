# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub:
**Security tab → Report a vulnerability**
(<https://github.com/PatoEQ/Multi-agent-AI-SOC/advisories/new>).

Include what you found, how to reproduce it, and the impact you expect. You can
expect an acknowledgement within 7 days. Please allow a reasonable time for a
fix before any public disclosure.

## In scope

- Prompt-injection bypasses that change a verdict, the gate decision, or make an
  agent follow instructions embedded in alert or tool data
- Ways to make the pipeline produce a report when the Auditor halted it
- Query injection into a SIEM connector (SPL, KQL, Elasticsearch)
- Leakage of secrets, or of pseudonymised data when `REDACT_PII=1`
- Unsafe defaults in the Docker setup

## Out of scope

- The LLM simply being wrong about an alert. That is a quality issue; please
  open a normal issue with a sanitised example (it may become an eval case).
- Vulnerabilities in third-party services (OpenAI, VirusTotal, ...).

## Using this project safely

- This is a **decision-support tool**. A human must approve containment actions,
  especially the ones marked `[REQUIRES HUMAN APPROVAL]`.
- Never commit `.env`. Rotate any key you think was exposed: deleting the commit is
  not enough.
- Enable `REDACT_PII=1` or use a local model (`ollama/...`) for real alert data.
- The Streamlit UI has no authentication. Run it only on `localhost` (as the
  Docker setup does), or behind your own access control.
- The Splunk, Elastic and Sentinel connectors only *read*. Give them read-only
  credentials.
