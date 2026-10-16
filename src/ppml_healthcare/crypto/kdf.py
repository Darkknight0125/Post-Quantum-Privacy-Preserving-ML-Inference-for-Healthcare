"""HKDF-SHA-256 adapter backed by ``cryptography``."""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KDFAdapter(Protocol):
    def derive_key(self, input_key_material: bytes, context: bytes, length: int = 32) -> bytes: ...


class HKDFSHA256Adapter:
    """Derive key material with HKDF-SHA-256; ``context`` maps to HKDF info."""

    _MAX_LENGTH = 255 * 32

    def __init__(self, salt: bytes | None = None) -> None:
        if salt is not None and not isinstance(salt, bytes):
            raise TypeError("salt must be bytes or None")
        self._salt = salt

    def derive_key(self, input_key_material: bytes, context: bytes, length: int = 32) -> bytes:
        if not isinstance(input_key_material, bytes) or not input_key_material:
            raise ValueError("input_key_material must be non-empty bytes")
        if not isinstance(context, bytes):
            raise TypeError("context must be bytes")
        if (
            isinstance(length, bool)
            or not isinstance(length, int)
            or not 1 <= length <= self._MAX_LENGTH
        ):
            raise ValueError(f"length must be between 1 and {self._MAX_LENGTH}")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self._salt,
            info=context,
        ).derive(input_key_material)
