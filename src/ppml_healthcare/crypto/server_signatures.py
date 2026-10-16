"""ML-DSA server-signature adapter backed by ``cryptography``."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    public_key: bytes
    private_key: bytes


class ServerSignatureAdapter(Protocol):
    def generate_keypair(self) -> SignatureKeyPair: ...

    def sign(self, private_key: bytes, message: bytes) -> bytes: ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class MLDSAParameterSet(StrEnum):
    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


_PRIVATE_KEY_TYPES = {
    MLDSAParameterSet.ML_DSA_44: mldsa.MLDSA44PrivateKey,
    MLDSAParameterSet.ML_DSA_65: mldsa.MLDSA65PrivateKey,
    MLDSAParameterSet.ML_DSA_87: mldsa.MLDSA87PrivateKey,
}
_PUBLIC_KEY_TYPES = {
    MLDSAParameterSet.ML_DSA_44: mldsa.MLDSA44PublicKey,
    MLDSAParameterSet.ML_DSA_65: mldsa.MLDSA65PublicKey,
    MLDSAParameterSet.ML_DSA_87: mldsa.MLDSA87PublicKey,
}


class CryptographyMLDSAAdapter:
    """ML-DSA signature adapter. Private-key bytes are the raw 32-byte seed."""

    DEFAULT_CONTEXT = b"PPML-Healthcare-Response-v1"

    def __init__(
        self,
        parameter_set: MLDSAParameterSet = MLDSAParameterSet.ML_DSA_65,
        context: bytes = DEFAULT_CONTEXT,
    ) -> None:
        self.parameter_set = MLDSAParameterSet(parameter_set)
        if not isinstance(context, bytes) or len(context) > 255:
            raise ValueError("ML-DSA context must be bytes of at most 255 bytes")
        self.context = context
        self._private_key_type = _PRIVATE_KEY_TYPES[self.parameter_set]
        self._public_key_type = _PUBLIC_KEY_TYPES[self.parameter_set]

    def generate_keypair(self) -> SignatureKeyPair:
        private_key = self._private_key_type.generate()
        return SignatureKeyPair(
            public_key=private_key.public_key().public_bytes_raw(),
            private_key=private_key.private_bytes_raw(),
        )

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        private_key_obj = self._private_key_type.from_seed_bytes(private_key)
        return private_key_obj.sign(message, context=self.context)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(message, bytes) or not isinstance(signature, bytes):
            raise TypeError("message and signature must be bytes")
        public_key_obj = self._public_key_type.from_public_bytes(public_key)
        try:
            public_key_obj.verify(signature, message, context=self.context)
        except InvalidSignature:
            return False
        return True
