"""Anonymous rate-limit contract; implementation requires a real LRS and belongs to Step 6."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.crypto.lrs import LRSSignature


class AnonymousRateLimiter(Protocol):
    def accept(self, signature: LRSSignature, scope: bytes, limit: int) -> bool: ...
