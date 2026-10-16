"""Atomic replay-store contract; concrete storage belongs to Step 6."""

from __future__ import annotations

from typing import Protocol


class ReplayStore(Protocol):
    def claim(self, request_id: str) -> bool: ...

    def expire_before(self, cutoff_unix_seconds: int) -> int: ...
