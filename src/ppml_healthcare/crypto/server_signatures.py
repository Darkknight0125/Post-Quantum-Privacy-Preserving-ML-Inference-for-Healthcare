"""ML-DSA server-signature adapter contract. Concrete binding belongs to Step 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    public_key: bytes
    private_key: bytes


class ServerSignatureAdapter(Protocol):
    def generate_keypair(self) -> SignatureKeyPair: ...

    def sign(self, private_key: bytes, message: bytes) -> bytes: ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
