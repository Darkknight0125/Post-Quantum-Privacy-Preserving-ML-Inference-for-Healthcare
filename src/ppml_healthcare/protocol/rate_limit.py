"""Sliding-window limiter driven by the selected LRS link operation."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Protocol

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.lrs import LRSAdapter, LRSSignature


class AnonymousRateLimiter(Protocol):
    def accept(self, signature: LRSSignature, scope: bytes, limit: int) -> bool: ...


@dataclass(frozen=True, slots=True)
class _Entry:
    timestamp: float
    scope: bytes
    signature: LRSSignature


class InMemoryLinkabilityRateLimiter:
    """Process-local sliding-window limit based on pairwise LRS link checks.

    This can exercise the workflow with the identity-revealing test mock. It
    does not establish anonymous rate limiting or substitute for a reviewed
    LRS. Every accepted proof is retained for at most ``window_seconds``.
    """

    def __init__(
        self,
        lrs: LRSAdapter,
        *,
        window_seconds: float = 60.0,
        max_entries: int = 100_000,
        clock=time.monotonic,
        settings: Settings | None = None,
    ) -> None:
        if not callable(getattr(lrs, "link", None)):
            raise ValueError("LRS adapter must provide linkability checks")
        if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool):
            raise ValueError("window_seconds must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        selected_settings = settings or Settings()
        if getattr(lrs, "insecure_test_only", False) and (
            selected_settings.environment != "test"
            or selected_settings.crypto_mode != "INSECURE_TEST_MOCK"
        ):
            raise ValueError("insecure mock rate limiting requires explicit test mode")
        self._lrs = lrs
        self._window = float(window_seconds)
        self._max_entries = max_entries
        self._clock = clock
        self._entries: deque[_Entry] = deque()
        self._lock = threading.Lock()

    def accept(self, signature: LRSSignature, scope: bytes, limit: int) -> bool:
        if not isinstance(signature, LRSSignature) or not isinstance(scope, bytes) or not scope:
            return False
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            return False
        now = self._clock()
        with self._lock:
            cutoff = now - self._window
            while self._entries and self._entries[0].timestamp <= cutoff:
                self._entries.popleft()

            linked_count = 0
            try:
                for entry in self._entries:
                    if entry.scope == scope and self._lrs.link(signature, entry.signature):
                        linked_count += 1
            except Exception:
                # An adapter failure must reject the request; do not grant a
                # rate-limit bypass when linkability cannot be evaluated.
                return False

            if linked_count >= limit or len(self._entries) >= self._max_entries:
                return False
            self._entries.append(_Entry(now, scope, signature))
            return True
