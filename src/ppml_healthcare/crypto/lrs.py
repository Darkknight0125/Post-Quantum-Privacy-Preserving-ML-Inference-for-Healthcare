"""Opaque contract implemented by the MAYO scoped zero-knowledge LRS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LRSSignature:
    proof: bytes
    response_association: bytes | None = None
    link_tag: bytes | None = None
    epoch: int | None = None
    ring_digest: bytes | None = None
    scope: bytes | None = None


class LRSAdapter(Protocol):
    """LRS contract; membership rows and secret credentials are opaque bytes."""

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


class ResponseAssociationAdapter(Protocol):
    """Optional construction-specific request/response association contract."""

    def verify_response_association(
        self, signature: LRSSignature, request_message: bytes, response_material: bytes
    ) -> bool: ...
