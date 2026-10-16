"""AES-256-GCM adapter backed by ``cryptography``."""

from __future__ import annotations

import secrets
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ppml_healthcare.schemas import EncryptedPayload


class AEADAdapter(Protocol):
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> EncryptedPayload: ...

    def decrypt(self, key: bytes, payload: EncryptedPayload, aad: bytes) -> bytes: ...


class AES256GCMAdapter:
    """Encrypt/decrypt with AES-256-GCM and a fresh random 96-bit nonce."""

    KEY_LENGTH = 32
    NONCE_LENGTH = 12

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        self._validate_inputs(key, plaintext, aad)
        nonce = secrets.token_bytes(self.NONCE_LENGTH)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return EncryptedPayload(nonce=nonce, ciphertext=ciphertext)

    def decrypt(self, key: bytes, payload: EncryptedPayload, aad: bytes) -> bytes:
        if not isinstance(payload, EncryptedPayload):
            raise TypeError("payload must be an EncryptedPayload")
        self._validate_inputs(key, payload.ciphertext, aad)
        return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, aad)

    @classmethod
    def _validate_inputs(cls, key: bytes, data: bytes, aad: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != cls.KEY_LENGTH:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")
        if not isinstance(data, bytes):
            raise TypeError("plaintext/ciphertext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")
