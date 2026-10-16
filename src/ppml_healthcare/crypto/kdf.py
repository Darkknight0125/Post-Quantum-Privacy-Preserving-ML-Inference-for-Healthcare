"""KDF adapter contract. A vetted library implementation belongs to Step 2."""

from __future__ import annotations

from typing import Protocol


class KDFAdapter(Protocol):
    def derive_key(self, input_key_material: bytes, context: bytes, length: int = 32) -> bytes: ...
