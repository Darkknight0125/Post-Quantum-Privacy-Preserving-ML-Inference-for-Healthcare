"""ML-KEM adapter contract. Concrete provider binding belongs to Step 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True, slots=True)
class Encapsulation:
    ciphertext: bytes
    shared_secret: bytes


class KEMAdapter(Protocol):
    """Provider contract for ML-KEM key generation and encapsulation."""

    def generate_keypair(self) -> KEMKeyPair: ...

    def encapsulate(self, public_key: bytes) -> Encapsulation: ...

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes: ...
