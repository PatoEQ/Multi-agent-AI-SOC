"""
redaction.py
============
Optional PII pseudonymisation (``REDACT_PII=1``).

Before anything reaches the LLM provider, usernames, hostnames, internal
(RFC 1918) IP addresses and e-mail addresses are replaced with stable
pseudonyms such as ``USER_1``, ``HOST_1``, ``INTERNAL_IP_1``. External IPs,
domains and file hashes are kept, because threat-intel enrichment needs them.

The mapping never leaves the machine:

* tools receive pseudonyms from the LLM and ``restore`` them before querying
  the SIEM, then ``redact`` their results before returning them to the LLM;
* the final report and exports are ``restore``-d locally for the analyst.

Limitation: one active redactor per process. Run one investigation at a time
per process when redaction is enabled (the CLI and Streamlit UI already do).
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
from typing import Any

_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Structured keys whose values are identities worth hiding.
_USER_KEYS = {"user", "username", "user_name", "account", "accountname",
              "targetusername", "subjectusername", "userid", "user_id"}
_HOST_KEYS = {"hostname", "host", "computer", "computername", "workstation",
              "device", "devicename", "asset", "src_host", "dst_host"}

_TOKEN_RE = re.compile(r"\b(USER|HOST|INTERNAL_IP|EMAIL)_\d+\b")


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class Redactor:
    """Bidirectional, deterministic pseudonymiser for one investigation."""

    def __init__(self) -> None:
        self._real_to_token: dict[str, str] = {}
        self._token_to_real: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _token_for(self, real: str, kind: str) -> str:
        key = real.lower()
        with self._lock:
            if key not in self._real_to_token:
                self._counters[kind] = self._counters.get(kind, 0) + 1
                token = f"{kind}_{self._counters[kind]}"
                self._real_to_token[key] = token
                self._token_to_real[token] = real
            return self._real_to_token[key]

    def _learn_from_structure(self, obj: Any) -> None:
        """Walk JSON and register identity values found under known keys."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower().replace("-", "").replace(" ", "")
                if isinstance(v, str) and v.strip():
                    if lk in _USER_KEYS:
                        # "CORP\\j.alvarez" -> learn "j.alvarez"
                        name = re.split(r"[\\/]", v.strip())[-1]
                        if len(name) >= 2:
                            self._token_for(name, "USER")
                    elif lk in _HOST_KEYS and not _IPV4_RE.fullmatch(v.strip()):
                        if len(v.strip()) >= 3:
                            self._token_for(v.strip(), "HOST")
                self._learn_from_structure(v)
        elif isinstance(obj, list):
            for item in obj:
                self._learn_from_structure(item)

    def learn(self, text: str) -> None:
        """Register identities from (possibly JSON) text."""
        if not text:
            return
        try:
            self._learn_from_structure(json.loads(text))
        except (ValueError, TypeError):
            pass
        for m in _IPV4_RE.finditer(text):
            if _is_internal_ip(m.group(1)):
                self._token_for(m.group(1), "INTERNAL_IP")
        for m in _EMAIL_RE.finditer(text):
            self._token_for(m.group(0), "EMAIL")

    # ------------------------------------------------------------------ #
    def redact(self, text: str) -> str:
        """Replace every known real value with its pseudonym."""
        if not text:
            return text
        self.learn(text)
        with self._lock:
            pairs = sorted(self._real_to_token.items(), key=lambda kv: -len(kv[0]))
        for real, token in pairs:
            text = re.sub(
                rf"(?<![A-Za-z0-9_.]){re.escape(real)}(?![A-Za-z0-9_])",
                token,
                text,
                flags=re.IGNORECASE,
            )
        return text

    def restore(self, text: str) -> str:
        """Replace pseudonyms with the original values (local use only)."""
        if not text:
            return text
        with self._lock:
            mapping = dict(self._token_to_real)
        return _TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)

    def mapping(self) -> dict[str, str]:
        with self._lock:
            return dict(self._token_to_real)


# ---------------------------------------------------------------------- #
# Process-wide active redactor (None when REDACT_PII is off)
# ---------------------------------------------------------------------- #
_active: Redactor | None = None
_active_lock = threading.Lock()


def activate(redactor: Redactor | None) -> None:
    global _active
    with _active_lock:
        _active = redactor


def active() -> Redactor | None:
    return _active


def to_llm(text: str) -> str:
    """Redact text on its way to the LLM (no-op when redaction is off)."""
    r = _active
    return r.redact(text) if r else text


def from_llm(text: str) -> str:
    """Restore pseudonyms in text coming back from the LLM (no-op when off)."""
    r = _active
    return r.restore(text) if r else text
