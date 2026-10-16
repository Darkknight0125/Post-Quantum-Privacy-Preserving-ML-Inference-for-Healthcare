"""Atomic in-memory replay protection for the local prototype."""

from __future__ import annotations

import threading
import time
from typing import Protocol


class ReplayStore(Protocol):
    def claim(self, request_id: str) -> bool: ...

    def expire_before(self, cutoff_unix_seconds: int) -> int: ...


class InMemoryReplayStore:
    """Thread-safe request-ID claims with bounded-age cleanup.

    The store is process-local and non-persistent. A deployment with multiple
    workers needs a shared atomic store before it can rely on replay blocking.
    """

    def __init__(
        self,
        *,
        retention_seconds: int = 600,
        max_entries: int = 100_000,
        clock=time.time,
    ) -> None:
        if (
            isinstance(retention_seconds, bool)
            or not isinstance(retention_seconds, int)
            or retention_seconds <= 0
        ):
            raise ValueError("retention_seconds must be a positive integer")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        self._retention = retention_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._claims: dict[str, float] = {}

    def claim(self, request_id: str) -> bool:
        if not isinstance(request_id, str) or not request_id:
            return False
        now = self._clock()
        with self._lock:
            self._expire_before_locked(now - self._retention)
            if request_id in self._claims or len(self._claims) >= self._max_entries:
                return False
            self._claims[request_id] = now
            return True

    def expire_before(self, cutoff_unix_seconds: int) -> int:
        if isinstance(cutoff_unix_seconds, bool) or not isinstance(cutoff_unix_seconds, int):
            raise ValueError("cutoff_unix_seconds must be an integer")
        with self._lock:
            return self._expire_before_locked(float(cutoff_unix_seconds))

    def _expire_before_locked(self, cutoff: float) -> int:
        expired = [
            request_id for request_id, claimed_at in self._claims.items() if claimed_at < cutoff
        ]
        for request_id in expired:
            del self._claims[request_id]
        return len(expired)
