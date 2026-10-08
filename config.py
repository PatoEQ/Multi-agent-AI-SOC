"""
config.py
=========
Centralised configuration for the **Multi-agent AI SOC**.

Everything environment-specific (API keys, model selection, SIEM backend,
mock toggles, rate limits, privacy options) is resolved here, so the rest of
the codebase never touches ``os.environ`` directly.

SECURITY NOTE
-------------
No secret is ever hard-coded. Every key is read from the process environment,
which is populated at dev time from a **git-ignored** ``.env`` file. The
committed template is ``.env.example`` and contains placeholders only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import load_dotenv

# Load the local .env exactly once. override=False => real environment
# variables (Docker / CI / Kubernetes) always win over the .env file.
load_dotenv(override=False)

# Privacy by default: CrewAI sends anonymous usage telemetry unless told not to.
# A security tool should not phone home, so opt out unless the user explicitly
# set these variables. Must run before `crewai` is imported anywhere.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")


def _env(name: str, default: str | None = None) -> str | None:
    """Read an env var, treating empty strings as 'not set'."""
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _as_float(value: str | None, default: float) -> float:
    try:
        return float(value) if value is not None else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """An immutable snapshot of all runtime configuration."""

    # --- LLM -------------------------------------------------------------- #
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", "gpt-4o-mini"))
    llm_temperature: float = field(
        default_factory=lambda: _as_float(_env("LLM_TEMPERATURE"), 0.2)
    )
    llm_base_url: str | None = field(default_factory=lambda: _env("LLM_BASE_URL"))
    openai_api_key: str | None = field(default_factory=lambda: _env("OPENAI_API_KEY"))
    anthropic_api_key: str | None = field(
        default_factory=lambda: _env("ANTHROPIC_API_KEY")
    )

    # --- Threat-intel tool keys ------------------------------------------- #
    virustotal_api_key: str | None = field(
        default_factory=lambda: _env("VIRUSTOTAL_API_KEY")
    )
    exa_api_key: str | None = field(default_factory=lambda: _env("EXA_API_KEY"))

    # --- SIEM backend ----------------------------------------------------- #
    # chronicle_mock (default) | splunk | elastic | sentinel
    siem_backend: str = field(
        default_factory=lambda: (_env("SIEM_BACKEND", "chronicle_mock") or "").lower()
    )
    siem_lookback_hours: int = field(
        default_factory=lambda: _as_int(_env("SIEM_LOOKBACK_HOURS"), 24)
    )
    siem_max_events: int = field(
        default_factory=lambda: _as_int(_env("SIEM_MAX_EVENTS"), 50)
    )
    splunk_url: str | None = field(default_factory=lambda: _env("SPLUNK_URL"))
    splunk_token: str | None = field(default_factory=lambda: _env("SPLUNK_TOKEN"))
    splunk_index: str = field(default_factory=lambda: _env("SPLUNK_INDEX", "*"))
    splunk_verify_tls: bool = field(
        default_factory=lambda: _as_bool(_env("SPLUNK_VERIFY_TLS"), True)
    )
    elastic_url: str | None = field(default_factory=lambda: _env("ELASTIC_URL"))
    elastic_api_key: str | None = field(default_factory=lambda: _env("ELASTIC_API_KEY"))
    elastic_index: str = field(
        default_factory=lambda: _env("ELASTIC_INDEX", "logs-*")
    )
    sentinel_workspace_id: str | None = field(
        default_factory=lambda: _env("SENTINEL_WORKSPACE_ID")
    )
    sentinel_tenant_id: str | None = field(
        default_factory=lambda: _env("SENTINEL_TENANT_ID")
    )
    sentinel_client_id: str | None = field(
        default_factory=lambda: _env("SENTINEL_CLIENT_ID")
    )
    sentinel_client_secret: str | None = field(
        default_factory=lambda: _env("SENTINEL_CLIENT_SECRET")
    )

    # --- Behaviour toggles ------------------------------------------------ #
    force_mock: bool = field(default_factory=lambda: _as_bool(_env("FORCE_MOCK")))
    http_timeout: int = field(default_factory=lambda: _as_int(_env("HTTP_TIMEOUT"), 20))
    process_type: str = field(
        default_factory=lambda: (_env("CREW_PROCESS", "sequential") or "").lower()
    )
    verbose: bool = field(default_factory=lambda: _as_bool(_env("CREW_VERBOSE"), True))
    # Stop after triage when it confidently says FALSE_POSITIVE (saves cost).
    # Never applies when prompt-injection markers were detected in the alert.
    triage_early_exit: bool = field(
        default_factory=lambda: _as_bool(_env("TRIAGE_EARLY_EXIT"), True)
    )

    # --- Rate limiting / caching ------------------------------------------ #
    # VirusTotal free tier = 4 requests/minute -> 15 s between live calls.
    vt_min_interval: float = field(
        default_factory=lambda: _as_float(_env("VT_MIN_INTERVAL_SECONDS"), 15.0)
    )
    cache_ttl: int = field(
        default_factory=lambda: _as_int(_env("CACHE_TTL_SECONDS"), 3600)
    )

    # --- Privacy / safety ------------------------------------------------- #
    # Replace usernames, hostnames and internal IPs with pseudonyms before
    # anything is sent to the LLM provider. Restored locally in the report.
    redact_pii: bool = field(default_factory=lambda: _as_bool(_env("REDACT_PII")))
    max_alert_chars: int = field(
        default_factory=lambda: _as_int(_env("MAX_ALERT_CHARS"), 20000)
    )

    # --- Derived helpers -------------------------------------------------- #
    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.virustotal_api_key) and not self.force_mock

    @property
    def exa_enabled(self) -> bool:
        return bool(self.exa_api_key) and not self.force_mock


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached, process-wide settings snapshot."""
    return Settings()


@lru_cache(maxsize=1)
def get_llm():
    """
    Build the shared LLM used by every agent.

    CrewAI's ``LLM`` targets OpenAI, Anthropic, Azure, Bedrock, Ollama, etc.
    Only ``LLM_MODEL`` changes between providers. For a fully local, private
    setup use ``LLM_MODEL=ollama/llama3.1`` and
    ``LLM_BASE_URL=http://localhost:11434``.
    """
    from crewai import LLM  # lazy import keeps `import config` cheap

    s = get_settings()
    kwargs: dict = {"model": s.llm_model, "temperature": s.llm_temperature}
    if s.llm_base_url:
        kwargs["base_url"] = s.llm_base_url

    model_lower = s.llm_model.lower()
    if "claude" in model_lower or model_lower.startswith("anthropic/"):
        if s.anthropic_api_key:
            kwargs["api_key"] = s.anthropic_api_key
    elif not model_lower.startswith("ollama/") and s.openai_api_key:
        kwargs["api_key"] = s.openai_api_key

    return LLM(**kwargs)


def reset_caches() -> None:
    """Clear memoised settings/LLM so env changes (e.g. from the UI) apply."""
    get_settings.cache_clear()
    get_llm.cache_clear()


def preflight() -> list[str]:
    """Return human-readable configuration warnings. Never raises."""
    s = get_settings()
    warnings: list[str] = []
    is_local = s.llm_model.lower().startswith("ollama/")

    if not is_local and not s.openai_api_key and not s.anthropic_api_key:
        warnings.append(
            "No LLM API key found (OPENAI_API_KEY / ANTHROPIC_API_KEY). The agents "
            "cannot reason without one — set one in .env, or use a local Ollama model."
        )
    if not s.virustotal_api_key:
        warnings.append("VIRUSTOTAL_API_KEY not set — VirusTotal runs in MOCK mode.")
    if not s.exa_api_key:
        warnings.append("EXA_API_KEY not set — threat search falls back to DuckDuckGo.")
    if s.force_mock:
        warnings.append("FORCE_MOCK is on — ALL external tools return canned data.")
    if s.siem_backend != "chronicle_mock":
        warnings.append(
            f"SIEM_BACKEND={s.siem_backend} — beta connector: unit-tested with mocked "
            "HTTP, not yet validated against a live instance."
        )
    if not s.redact_pii and not is_local:
        warnings.append(
            "REDACT_PII is off — usernames/hostnames/internal IPs are sent to the "
            "LLM provider. Enable it for real data."
        )
    return warnings
