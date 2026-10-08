"""
cache.py
========
Tiny thread-safe helpers used by the tools:

* ``TTLCache``    — memoises lookups so the same indicator is queried once per
                    run (the intel agent and the Auditor both check IoCs).
* ``RateLimiter`` — enforces a minimum interval between live API calls
                    (VirusTotal's free tier allows 4 requests per minute).
"""

from __future__ import annotations

import threading
import time
from typing import Generic, TypeVar
from collections.abc import Callable

V = TypeVar("V")


class TTLCache(Generic[V]):
    def __init__(self, ttl_seconds: float, max_items: int = 2048,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._clock = clock
        self._data: dict[str, tuple[float, V]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> V | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                self.misses += 1
                return None
            expires, value = item
            if self._clock() >= expires:
                del self._data[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    def set(self, key: str, value: V) -> None:
        with self._lock:
            if len(self._data) >= self.max_items:
                # Evict the entry closest to expiry.
                oldest = min(self._data, key=lambda k: self._data[k][0])
                del self._data[oldest]
            self._data[key] = (self._clock() + self.ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = self.misses = 0


class RateLimiter:
    """Blocks so that consecutive ``wait()`` calls are >= ``min_interval`` apart."""

    def __init__(self, min_interval: float,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.min_interval = max(0.0, min_interval)
        self._clock = clock
        self._sleep = sleep
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Sleep if needed; return the number of seconds slept."""
        with self._lock:
            now = self._clock()
            delay = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.min_interval
        if delay > 0:
            self._sleep(delay)
        return delay
