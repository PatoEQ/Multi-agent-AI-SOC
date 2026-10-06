"""
app.py — Streamlit front-end for the SOC Sentinel Crew.

Paste a SIEM/UDM alert, run the crew, and watch six agents triage, enrich,
investigate, plan, audit each other and report — with live reasoning, the
Auditor's binding gate decision, rule validation and STIX / ATT&CK exports.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import json
import os
import queue
import threading

import streamlit as st

import config

st.set_page_config(page_title="SOC Sentinel Crew", page_icon="🛡️", layout="wide")

SAMPLE_DIR = "sample_alerts"
EVAL_DIR = os.path.join("evals", "alerts")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _list_samples() -> dict[str, str]:
    files: dict[str, str] = {}
    for folder in (SAMPLE_DIR, EVAL_DIR):
        if os.path.isdir(folder):
            for name in sorted(os.listdir(folder)):
                if name.endswith(".json"):
                    files[f"{folder}/{name}"] = os.path.join(folder, name)
    return files


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _format_step(step) -> str:
    text = getattr(step, "log", None) or getattr(step, "text", None) or str(step)
    return " ".join(str(text).split())[:600]


def _apply_overrides(model: str, process: str, force_mock: bool, redact: bool,
                     early_exit: bool, keys: dict[str, str]) -> None:
    os.environ["LLM_MODEL"] = model
    os.environ["CREW_PROCESS"] = process
    os.environ["FORCE_MOCK"] = "1" if force_mock else "0"
    os.environ["REDACT_PII"] = "1" if redact else "0"
    os.environ["TRIAGE_EARLY_EXIT"] = "1" if early_exit else "0"
    for name, value in keys.items():
        if value:  # only override keys the user typed; a populated .env still works
            os.environ[name] = value
    config.reset_caches()


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
st.sidebar.title("⚙️ Configuration")
current = config.get_settings()

model_options = ["gpt-4o-mini", "gpt-4o", "anthropic/claude-sonnet-4-5", "ollama/llama3.1"]
if current.llm_model not in model_options:
    model_options.insert(0, current.llm_model)
model = st.sidebar.selectbox("LLM model", model_options,
                             index=model_options.index(current.llm_model),
                             help="LiteLLM-style model string. Needs the matching provider key.")
process = st.sidebar.radio("Investigation orchestration", ["sequential", "hierarchical"],
                           index=0 if current.process_type != "hierarchical" else 1)
force_mock = st.sidebar.toggle("Mock all external tools", value=current.force_mock)
redact = st.sidebar.toggle("Redact PII before sending to the LLM", value=current.redact_pii,
                           help="Usernames, hostnames and internal IPs become USER_1, HOST_1…")
early_exit = st.sidebar.toggle("Stop early on clear false positives",
                               value=current.triage_early_exit)

with st.sidebar.expander("🔑 API keys (this session only)"):
    st.caption("Leave blank to use your local .env. Typed keys stay in memory and are "
               "never written to disk.")
    keys = {name: st.text_input(name, type="password") for name in
            ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "EXA_API_KEY")}

st.sidebar.caption(f"SIEM backend: `{current.siem_backend}` (set SIEM_BACKEND in .env)")

_apply_overrides(model, process, force_mock, redact, early_exit, keys)

# --------------------------------------------------------------------------- #
# Main panel
# --------------------------------------------------------------------------- #
st.title("🛡️ SOC Sentinel Crew")
st.markdown(
    "Six AI specialists triage an alert, enrich IoCs, reconstruct the attack, plan the "
    "response and **audit each other for hallucinations**. The Auditor's decision is "
    "enforced in code: if it says HALT, no report is written."
)

samples = _list_samples()
c1, c2 = st.columns([3, 1])
with c1:
    choice = st.selectbox("Load an example alert", ["—"] + list(samples))
with c2:
    st.write("")
    if st.button("Load", use_container_width=True) and choice in samples:
        st.session_state["alert_text"] = _read(samples[choice])

alert_text = st.text_area("Paste a SIEM / UDM alert", value=st.session_state.get("alert_text", ""),
                          height=240, placeholder="Paste raw JSON or text from your SIEM…")

warnings = config.preflight()
if warnings:
    with st.expander(f"⚠️ Configuration notes ({len(warnings)})"):
        for w in warnings:
            st.write(f"- {w}")

run = st.button("▶️  Run investigation", type="primary")

# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
if run:
    if not alert_text.strip():
        st.error("Paste an alert (or load an example) first.")
        st.stop()

    import tools
    from crew import STATUS_COMPLETED, STATUS_ERROR, STATUS_FALSE_POSITIVE, STATUS_HALTED, run_pipeline

    tools.reset_tool_state()
    log_q: queue.Queue[tuple[str, object]] = queue.Queue()
    holder: dict = {}

    def step_cb(step):
        log_q.put(("step", _format_step(step)))

    def task_cb(task_output):
        agent = getattr(task_output, "agent", "agent")
        log_q.put(("task", str(agent)))

    def worker():
        # This thread never calls st.*; it only pushes to the queue.
        holder["result"] = run_pipeline(alert_text, step_callback=step_cb,
                                        task_callback=task_cb, output_dir="output")
        log_q.put(("done", None))

    thread = threading.Thread(target=worker, daemon=True)
    status = st.status("Agents are investigating…", expanded=True)
    feed = status.empty()
    lines: list[str] = []
    thread.start()
    while True:
        try:
            kind, payload = log_q.get(timeout=0.3)
        except queue.Empty:
            if not thread.is_alive():
                break
            continue
        if kind == "done":
            break
        if kind == "step":
            lines.append(f"• {payload}")
        else:
            lines += ["", f"✅ **{payload} finished** — handing off.", ""]
        feed.markdown("\n\n".join(lines[-40:]))
    thread.join(timeout=2)

    result = holder.get("result")
    if result is None or result.status == STATUS_ERROR:
        status.update(label="Investigation failed", state="error", expanded=False)
        st.error(getattr(result, "error", None) or "No result produced.")
        st.stop()
    status.update(label="Investigation complete", state="complete", expanded=False)

    # --- Outcome banner --------------------------------------------------- #
    if result.status == STATUS_COMPLETED:
        decision = result.gate.decision.value if result.gate else "?"
        (st.success if decision == "PROCEED" else st.warning)(
            f"Report approved by the Auditor — gate decision **{decision}**.")
    elif result.status == STATUS_HALTED:
        st.error("⛔ The Auditor HALTED the pipeline. No report or rules were produced; "
                 "review the audit before acting.")
    elif result.status == STATUS_FALSE_POSITIVE:
        st.info("Closed at triage as a FALSE POSITIVE (early exit).")

    for f in result.injection_findings:
        st.warning(f"🚩 Prompt-injection marker: **{f.label}** — “{f.excerpt}”")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Triage verdict", result.triage_verdict)
    m2.metric("LLM tokens", f"{result.usage.get('total_tokens', 0):,}")
    m3.metric("LLM requests", result.usage.get("successful_requests", 0))
    m4.metric("Duration", f"{result.duration_seconds:.0f}s")
    if result.redacted_identities:
        st.caption(f"🔒 {result.redacted_identities} identities were pseudonymised before "
                   "leaving this machine.")

    tab_report, tab_debate, tab_rules, tab_exports = st.tabs(
        ["📑 Report", "🧠 Agent debate", "🧪 Rule validation", "📦 Exports"])

    with tab_report:
        st.markdown(result.report_markdown)

    with tab_debate:
        st.caption("Each specialist's full output, in order. The Auditor reviews all of them.")
        for stage in result.stages:
            with st.expander(f"{stage.stage} — {stage.agent}",
                             expanded=stage.stage.startswith("Critical")):
                st.markdown(stage.text)

    with tab_rules:
        if not result.rule_checks:
            st.write("No rules to validate for this outcome.")
        for i, check in enumerate(result.rule_checks, 1):
            label = "✅ passes static checks" if check.ok else "❌ needs fixes"
            st.markdown(f"**Rule {i} ({check.language}) — {label}**"
                        + (" · loaded by Suricata -T" if check.engine_checked else ""))
            st.code(check.rule, language="text")
            for e in check.errors:
                st.error(e)
            for w in check.warnings:
                st.warning(w)

    with tab_exports:
        st.download_button("⬇️ Report (Markdown)", result.report_markdown,
                           file_name="incident_report.md", mime="text/markdown")
        if result.stix_bundle:
            st.download_button("⬇️ IoCs (STIX 2.1 bundle)",
                               json.dumps(result.stix_bundle, indent=2),
                               file_name="iocs.stix.json", mime="application/json")
        if result.navigator_layer:
            st.download_button("⬇️ MITRE ATT&CK Navigator layer",
                               json.dumps(result.navigator_layer, indent=2),
                               file_name="attack_navigator_layer.json", mime="application/json")
            st.caption("Open https://mitre-attack.github.io/attack-navigator/ → "
                       "Open Existing Layer → Upload from local.")
        st.json(result.summary(), expanded=False)
