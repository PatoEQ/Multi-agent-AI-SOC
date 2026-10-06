"""
Minimal offline stand-in for the `crewai` package.

Used ONLY by the test suite, and only when the real `crewai` is not installed
(for example on a machine without internet access). CI installs the real
library, so the same tests also run against genuine CrewAI classes.

It mirrors the constructor surface this project uses and keeps CrewAI's
placeholder-interpolation rule (a missing `{variable}` raises KeyError).
"""

from __future__ import annotations

import inspect
import re
from enum import Enum
from typing import Any, get_args, get_origin
from types import SimpleNamespace

__version__ = "0.0.0-stub"

_VARIABLE_PATTERN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_\-]*)}")


def _interpolate(text: str, inputs: dict) -> str:
    if not text or "{" not in text:
        return text
    variables = _VARIABLE_PATTERN.findall(text)
    missing = [v for v in variables if v not in inputs]
    if missing:
        raise KeyError(f"Template variable '{missing[0]}' not found in inputs dictionary")
    for var in variables:
        text = text.replace("{" + var + "}", str(inputs[var]))
    return text


class Process(str, Enum):
    sequential = "sequential"
    hierarchical = "hierarchical"


class LLM:
    def __init__(self, model: str, **kwargs):
        self.model = model
        self.kwargs = kwargs


class Agent:
    def __init__(self, role: str, goal: str, backstory: str, tools=None, llm=None, **kwargs):
        self.role, self.goal, self.backstory = role, goal, backstory
        self.tools = list(tools or [])
        self.llm = llm
        self.kwargs = kwargs

    def __str__(self) -> str:
        return self.role


def _validate_guardrail(fn) -> None:
    """Same signature rules as crewai.Task.validate_guardrail_function."""
    if fn is None or not callable(fn):
        return
    sig = inspect.signature(fn)
    required = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
    if len(required) != 1:
        raise ValueError("Guardrail function must accept exactly one parameter")
    ann = sig.return_annotation
    if ann is not inspect.Signature.empty:
        args = get_args(ann)
        if not (get_origin(ann) is tuple and len(args) == 2 and args[0] is bool
                and (args[1] is Any or args[1] is str)):
            raise ValueError("If return type is annotated, it must be Tuple[bool, Any]")


class Task:
    def __init__(self, description: str, expected_output: str, agent=None, context=None,
                 name=None, output_file=None, guardrail=None, guardrail_max_retries=3,
                 **kwargs):
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context
        self.name = name
        self.output_file = output_file
        _validate_guardrail(guardrail)
        self.guardrail = guardrail
        self.guardrail_max_retries = guardrail_max_retries
        self.kwargs = kwargs


class Crew:
    """Kickoff is not implemented: tests replace `crew._make_crew` with a fake."""

    def __init__(self, agents, tasks, process=Process.sequential, **kwargs):
        if process == Process.hierarchical and "manager_llm" not in kwargs:
            raise ValueError("manager_llm is required for hierarchical process")
        self.agents, self.tasks, self.process = agents, tasks, process
        self.kwargs = kwargs

    def interpolate(self, inputs: dict) -> None:
        for task in self.tasks:
            task.description = _interpolate(task.description, inputs)
            task.expected_output = _interpolate(task.expected_output, inputs)

    def kickoff(self, inputs=None):  # pragma: no cover - never called by tests
        raise RuntimeError("The crewai test stub cannot run a real crew.")


__all__ = ["Agent", "Task", "Crew", "Process", "LLM", "SimpleNamespace"]
