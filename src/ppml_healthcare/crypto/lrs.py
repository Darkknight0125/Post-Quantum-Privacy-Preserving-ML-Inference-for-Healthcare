"""Opaque LRS interface only; no MAYO or mock signing behavior is provided."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LRSSignature:
    proof: bytes
    response_association: bytes | None = None


class LRSAdapter(Protocol):
    """Contract to implement only after an LRS construction is selected."""

    def generate_keypair(self) -> tuple[bytes, bytes]: ...

    def sign(
        self, secret_key: bytes, ring: tuple[bytes, ...], message: bytes, epoch: int, scope: bytes
    ) -> LRSSignature: ...

    def verify(
        self,
        ring: tuple[bytes, ...],
        message: bytes,
        signature: LRSSignature,
        epoch: int,
        scope: bytes,
    ) -> bool: ...

    def link(self, left: LRSSignature, right: LRSSignature) -> bool: ...
