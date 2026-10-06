"""Offline stand-in for `crewai.tools` (tests only; see the package docstring)."""

from __future__ import annotations

from pydantic import BaseModel


class BaseTool(BaseModel):
    """Pydantic-based like the real BaseTool, so field declarations behave the same."""

    name: str
    description: str
    args_schema: type[BaseModel] | None = None

    model_config = {"arbitrary_types_allowed": True}

    def run(self, *args, **kwargs):
        return self._run(*args, **kwargs)

    def _run(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError


def tool(name=None):  # pragma: no cover
    def decorator(fn):
        return fn
    return decorator
