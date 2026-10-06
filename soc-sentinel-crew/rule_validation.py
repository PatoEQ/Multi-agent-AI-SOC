"""
rule_validation.py
==================
Static checks for the detection rules the Report Writer drafts.

LLMs can produce rules that look right but do not load. Every generated rule
is linted here and the results are attached to the report, so an engineer
knows what to fix before deploying. Rules are always labelled DRAFT.

* Suricata — structural lint of header + options. If a ``suricata`` binary is
  on PATH, the rule is also test-loaded with ``suricata -T`` (engine check).
* YARA-L 2.0 — structural lint: rule block, required sections, balanced
  braces, event variables used in the condition are defined.

These checks catch common mistakes; they are not a full grammar.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_\-]*)[^\n]*\n(.*?)```", re.DOTALL)

SURICATA_ACTIONS = {"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
SURICATA_PROTOCOLS = {
    "ip", "tcp", "udp", "icmp", "http", "http1", "http2", "tls", "dns", "smb", "ftp",
    "ssh", "smtp", "dcerpc", "dhcp", "ntp", "nfs", "krb5", "snmp", "sip", "rdp",
    "mqtt", "quic", "tcp-pkt", "tcp-stream", "pkthdr", "ike", "modbus", "dnp3", "enip",
}
_SURICATA_HEADER_RE = re.compile(
    r"^(?P<action>\S+)\s+(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<opts>.*)\)\s*$",
    re.DOTALL,
)


@dataclass
class RuleCheck:
    language: str          # "suricata" | "yara-l"
    rule: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    engine_checked: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict:
        return {"language": self.language, "ok": self.ok, "errors": self.errors,
                "warnings": self.warnings, "engine_checked": self.engine_checked,
                "rule": self.rule}


def extract_rules(markdown: str) -> list[tuple[str, str]]:
    """Return (language, body) for every fenced yara-l / suricata block."""
    rules: list[tuple[str, str]] = []
    for lang, body in _FENCE_RE.findall(markdown or ""):
        tag = lang.lower().replace("_", "-")
        if tag in {"yara-l", "yaral", "yara-l2", "yaral2"}:
            rules.append(("yara-l", body.strip()))
        elif tag in {"suricata", "snort", "rules"}:
            rules.append(("suricata", body.strip()))
    return rules


# --------------------------------------------------------------------------- #
# Suricata
# --------------------------------------------------------------------------- #
def _split_options(opts: str) -> list[str]:
    """Split rule options on ';' while respecting quoted strings and escapes."""
    parts, buf, in_quote, escaped = [], [], False, False
    for ch in opts:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
        if ch == ";" and not in_quote:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def lint_suricata_rule(rule: str) -> RuleCheck:
    check = RuleCheck(language="suricata", rule=rule)
    m = _SURICATA_HEADER_RE.match(rule.strip())
    if not m:
        check.errors.append(
            "Header does not match 'action proto src sport -> dst dport (options)'."
        )
        return check
    if m["action"].lower() not in SURICATA_ACTIONS:
        check.errors.append(f"Unknown action {m['action']!r}.")
    if m["proto"].lower() not in SURICATA_PROTOCOLS:
        check.warnings.append(f"Unrecognised protocol {m['proto']!r}.")

    opts_raw = m["opts"].strip()
    if opts_raw.count('"') % 2:
        check.errors.append("Unbalanced double quotes in options.")
    if opts_raw and not opts_raw.endswith(";"):
        check.errors.append("Options must end with ';' before the closing parenthesis.")

    keys = {}
    for opt in _split_options(opts_raw):
        key, _, value = opt.partition(":")
        keys[key.strip().lower()] = value.strip()
    if "msg" not in keys:
        check.errors.append("Missing required 'msg' option.")
    if "sid" not in keys:
        check.errors.append("Missing required 'sid' option.")
    else:
        try:
            sid = int(keys["sid"])
            if not 1000000 <= sid <= 1999999:
                check.warnings.append(f"sid {sid} is outside the local range 1000000-1999999.")
        except ValueError:
            check.errors.append(f"sid {keys['sid']!r} is not an integer.")
    if "rev" not in keys:
        check.warnings.append("Missing 'rev' option (recommended).")
    return check


def _engine_check_suricata(rule: str, check: RuleCheck) -> None:
    """Load the rule with a real Suricata binary when one is installed."""
    binary = shutil.which("suricata")
    if not binary:
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "draft.rules")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rule + "\n")
        try:
            proc = subprocess.run(
                [binary, "-T", "-S", path, "-l", tmp],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            check.warnings.append(f"Suricata engine check could not run: {exc!r}")
            return
    check.engine_checked = True
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        check.errors.append("Suricata -T rejected the rule: " + " | ".join(tail))


def validate_suricata(block: str, engine_check: bool = True) -> list[RuleCheck]:
    checks = []
    lines = [ln.strip() for ln in block.splitlines()]
    rules = [ln for ln in lines if ln and not ln.startswith("#")]
    for rule in rules:
        check = lint_suricata_rule(rule)
        if engine_check and check.ok:
            _engine_check_suricata(rule, check)
        checks.append(check)
    if not checks:
        checks.append(RuleCheck("suricata", block, errors=["Block contains no rule."]))
    return checks


# --------------------------------------------------------------------------- #
# YARA-L 2.0
# --------------------------------------------------------------------------- #
def _strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def lint_yaral_rule(rule: str) -> RuleCheck:
    check = RuleCheck(language="yara-l", rule=rule)
    code = _strip_comments_and_strings(rule)

    if not re.search(r"^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", code, re.MULTILINE):
        check.errors.append("Missing 'rule <name> {' declaration (name: letters, digits, _).")
    if code.count("{") != code.count("}"):
        check.errors.append("Unbalanced curly braces.")
    for section in ("meta", "events", "condition"):
        if not re.search(rf"^\s*{section}\s*:", code, re.MULTILINE):
            check.errors.append(f"Missing required '{section}:' section.")

    events_match = re.search(r"events\s*:(.*?)(?:\n\s*(?:match|outcome|condition|options)\s*:)",
                             code, re.DOTALL)
    defined = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\.", events_match.group(1))) \
        if events_match else set()
    if events_match and not defined:
        check.errors.append("No event variables (like $e.metadata.event_type) in events.")

    cond_match = re.search(r"condition\s*:(.*?)(?:\n\s*options\s*:|\}\s*$)", code, re.DOTALL)
    if cond_match:
        used = set(re.findall(r"[#$]([A-Za-z_][A-Za-z0-9_]*)", cond_match.group(1)))
        missing = sorted(v for v in used if v not in defined and defined)
        # Outcome/match variables can also appear in conditions; only warn.
        if missing:
            check.warnings.append(
                "Condition references variables not defined in events: "
                + ", ".join("$" + v for v in missing)
            )
        if not used:
            check.errors.append("Condition does not reference any event variable.")
    return check


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def validate_report_rules(markdown: str, engine_check: bool = True) -> list[RuleCheck]:
    checks: list[RuleCheck] = []
    for language, body in extract_rules(markdown):
        if language == "suricata":
            checks.extend(validate_suricata(body, engine_check=engine_check))
        else:
            checks.append(lint_yaral_rule(body))
    return checks


def render_checks_markdown(checks: list[RuleCheck]) -> str:
    """Appendix appended to the report."""
    lines = ["", "---", "", "## Detection rule validation (automated)", ""]
    if not checks:
        lines.append("⚠️ No fenced `yara-l` or `suricata` rule blocks were found in the report.")
        return "\n".join(lines)
    lines.append("All rules are **DRAFTS**. Review and test before deploying.")
    lines.append("")
    for i, c in enumerate(checks, 1):
        status = "✅ passed static checks" if c.ok else "❌ needs fixes"
        engine = " (also loaded by Suricata -T)" if c.engine_checked else ""
        lines.append(f"**Rule {i} — {c.language}: {status}{engine}**")
        lines += [f"- Error: {e}" for e in c.errors]
        lines += [f"- Warning: {w}" for w in c.warnings]
        lines.append("")
    return "\n".join(lines)
