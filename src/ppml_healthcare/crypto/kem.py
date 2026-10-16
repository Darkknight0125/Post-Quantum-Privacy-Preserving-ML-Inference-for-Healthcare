"""ML-KEM adapter backed by ``cryptography``'s FIPS 203 implementation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import mlkem


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


class MLKEMParameterSet(StrEnum):
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


_PRIVATE_KEY_TYPES = {
    MLKEMParameterSet.ML_KEM_768: mlkem.MLKEM768PrivateKey,
    MLKEMParameterSet.ML_KEM_1024: mlkem.MLKEM1024PrivateKey,
}
_PUBLIC_KEY_TYPES = {
    MLKEMParameterSet.ML_KEM_768: mlkem.MLKEM768PublicKey,
    MLKEMParameterSet.ML_KEM_1024: mlkem.MLKEM1024PublicKey,
}


class CryptographyMLKEMAdapter:
    """ML-KEM provider adapter.

    Private-key bytes are the provider's raw 64-byte seed serialization, not
    an expanded key. Secure persistence and access control are caller duties.
    The default suite uses ML-KEM-768.
    """

    def __init__(self, parameter_set: MLKEMParameterSet = MLKEMParameterSet.ML_KEM_768) -> None:
        self.parameter_set = MLKEMParameterSet(parameter_set)
        self._private_key_type = _PRIVATE_KEY_TYPES[self.parameter_set]
        self._public_key_type = _PUBLIC_KEY_TYPES[self.parameter_set]

    def generate_keypair(self) -> KEMKeyPair:
        private_key = self._private_key_type.generate()
        public_key = private_key.public_key()
        return KEMKeyPair(public_key.public_bytes_raw(), private_key.private_bytes_raw())

    def encapsulate(self, public_key: bytes) -> Encapsulation:
        public_key_obj = self._public_key_type.from_public_bytes(public_key)
        shared_secret, ciphertext = public_key_obj.encapsulate()
        return Encapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        private_key_obj = self._private_key_type.from_seed_bytes(private_key)
        # FIPS 203 uses implicit rejection for well-sized invalid ciphertexts;
        # this API returns a secret in that case. The caller must not infer
        # ciphertext validity from the return value.
        return private_key_obj.decapsulate(ciphertext)
