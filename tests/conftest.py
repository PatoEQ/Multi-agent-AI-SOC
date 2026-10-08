"""
Shared pytest setup.

* Forces a safe, offline configuration BEFORE any project module is imported:
  mock tools, no real keys, no rate-limit sleeps, telemetry off.
* Uses the real `crewai` when installed (CI); otherwise falls back to the
  lightweight stub in tests/stubs so the suite also runs offline.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.update({
    "FORCE_MOCK": "1",
    "OPENAI_API_KEY": "test-dummy-key",  # never a real key; no network calls are made
    "CREW_VERBOSE": "0",
    "VT_MIN_INTERVAL_SECONDS": "0",
    "SIEM_BACKEND": "chronicle_mock",
    "REDACT_PII": "0",
    "TRIAGE_EARLY_EXIT": "1",
    "CREWAI_DISABLE_TELEMETRY": "true",
    "OTEL_SDK_DISABLED": "true",
    "CREWAI_TRACING_ENABLED": "false",
})
for var in ("VIRUSTOTAL_API_KEY", "EXA_API_KEY", "ANTHROPIC_API_KEY"):
    os.environ.pop(var, None)

try:
    import crewai  # noqa: F401
    USING_STUB = False
except ImportError:
    sys.path.insert(0, os.path.join(ROOT, "tests", "stubs"))
    USING_STUB = True


@pytest.fixture(autouse=True)
def _fresh_config(monkeypatch):
    """Reset cached settings/tool state around every test."""
    import config
    import tools

    config.reset_caches()
    tools.reset_tool_state()
    yield
    config.reset_caches()
    tools.reset_tool_state()


def make_output(raw: str):
    return SimpleNamespace(raw=raw, agent="agent", name=None)


class FakeCrew:
    """Stands in for a CrewAI Crew: records inputs and returns scripted outputs."""

    calls: list = []

    def __init__(self, agents, tasks, script: dict[str, str]):
        self.agents, self.tasks, self.script = agents, tasks, script

    def kickoff(self, inputs=None):
        FakeCrew.calls.append({"tasks": [t.name for t in self.tasks], "inputs": inputs})
        outputs = [make_output(self.script.get(t.name, "")) for t in self.tasks]
        usage = SimpleNamespace(model_dump=lambda: {
            "total_tokens": 100 * len(self.tasks), "prompt_tokens": 70 * len(self.tasks),
            "completion_tokens": 30 * len(self.tasks), "successful_requests": len(self.tasks)})
        return SimpleNamespace(raw=outputs[-1].raw if outputs else "",
                               tasks_output=outputs, token_usage=usage)


@pytest.fixture
def scripted_pipeline(monkeypatch):
    """Patch crew._make_crew so run_pipeline uses scripted agent answers."""
    import crew as crew_module

    FakeCrew.calls = []

    def install(script: dict[str, str]):
        def fake_make_crew(agents, tasks, step_callback, task_callback, hierarchical=False):
            return FakeCrew(agents, tasks, script)
        monkeypatch.setattr(crew_module, "_make_crew", fake_make_crew)
        return FakeCrew

    return install
