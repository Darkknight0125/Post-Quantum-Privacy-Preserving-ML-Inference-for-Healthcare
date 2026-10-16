"""AES-256-GCM adapter contract. Concrete encryption belongs to Step 2."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import EncryptedPayload


class AEADAdapter(Protocol):
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> EncryptedPayload: ...

    def decrypt(self, key: bytes, payload: EncryptedPayload, aad: bytes) -> bytes: ...
