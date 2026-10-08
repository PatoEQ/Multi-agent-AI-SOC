"""
siem/base.py
============
The contract every SIEM connector implements, plus shared input validation.

To add a new SIEM, subclass :class:`SIEMConnector`, implement ``search`` and
register it in ``siem/__init__.py`` (see docs/CONNECTORS.md).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

EVENT_TYPES = {"all", "udm", "sysmon"}

# Entities are interpolated into SIEM query languages (SPL, KQL, ...). Only a
# conservative character set is accepted, which blocks query injection such as
# `x" | delete` or `x" OR 1==1`. Backslash is allowed for DOMAIN\user and is
# escaped by each connector.
_ENTITY_RE = re.compile(r"^[A-Za-z0-9._:@\\\-]{1,256}$")


class SIEMError(Exception):
    """Raised by connectors for operational failures (network, auth, ...)."""


def validate_entity(entity: str) -> str:
    """Return the stripped entity or raise ValueError if it is unsafe."""
    value = (entity or "").strip()
    if not value:
        raise ValueError("'entity' is required (hostname, IP, user or hash).")
    if not _ENTITY_RE.match(value):
        raise ValueError(
            f"Rejected entity {value[:60]!r}: only letters, digits and . _ : @ \\ - "
            "are allowed (prevents query injection into the SIEM)."
        )
    return value


def validate_event_type(event_type: str) -> str:
    value = (event_type or "all").strip().lower()
    if value not in EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(EVENT_TYPES)}")
    return value


def quote_for_query(entity: str) -> str:
    """Escape for a double-quoted string literal in SPL / KQL."""
    return entity.replace("\\", "\\\\").replace('"', '\\"')


class SIEMConnector(ABC):
    """A read-only log search backend."""

    #: short identifier shown in tool output and the UI
    name: str = "base"
    #: True for connectors not yet validated against a live instance
    beta: bool = False

    @abstractmethod
    def search(self, entity: str, event_type: str = "all") -> dict[str, Any]:
        """
        Return ``{"entity": ..., "events": [...], "_meta": {...}}``.

        ``entity`` and ``event_type`` are already validated by the caller.
        Must raise :class:`SIEMError` (not return) on operational failure.
        """
