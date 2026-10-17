"""Test-only protocol double for non-cryptographic workflow tests."""

from __future__ import annotations

import hashlib
import secrets

from ppml_healthcare.crypto.lrs import LRSSignature

_MAGIC = b"TEST_ONLY_LRS_STUB_V1\0"
_PROOF_SIZE = len(_MAGIC) + 8 + 32 + 32 + 32 + 32


def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ring_digest(ring: tuple[bytes, ...]) -> bytes:
    if not ring or any(not isinstance(key, bytes) or len(key) != 32 for key in ring):
        raise ValueError("ring must contain 32-byte test public keys")
    if len(set(ring)) != len(ring):
        raise ValueError("ring must not contain duplicate keys")
    return _digest(b"MOCK-RING\0" + b"".join(sorted(ring)))


class LRSProtocolStub:
    """Test-only protocol double; provides no security properties."""

    def generate_keypair(self) -> tuple[bytes, bytes]:
        secret_key = secrets.token_bytes(32)
        return _digest(b"MOCK-PUBLIC\0" + secret_key), secret_key

    def sign(
        self, secret_key: bytes, ring: tuple[bytes, ...], message: bytes, epoch: int, scope: bytes
    ) -> LRSSignature:
        if not isinstance(secret_key, bytes) or len(secret_key) != 32:
            raise ValueError("test secret key must be 32 bytes")
        if not isinstance(message, bytes) or not isinstance(scope, bytes):
            raise ValueError("message and scope must be bytes")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 <= epoch < 2**64:
            raise ValueError("epoch must be an unsigned 64-bit integer")
        signer = _digest(b"MOCK-PUBLIC\0" + secret_key)
        ring_hash = _ring_digest(ring)
        if signer not in ring:
            raise ValueError("signer key is not in ring")
        proof = (
            _MAGIC
            + epoch.to_bytes(8, "big")
            + signer
            + ring_hash
            + _digest(scope)
            + _digest(message)
        )
        link_tag = _digest(
            b"TEST-LINK\\0" + signer + ring_hash + epoch.to_bytes(8, "big") + _digest(scope)
        )
        return LRSSignature(
            proof=proof, link_tag=link_tag, epoch=epoch, ring_digest=ring_hash, scope=scope
        )

    def verify(
        self,
        ring: tuple[bytes, ...],
        message: bytes,
        signature: LRSSignature,
        epoch: int,
        scope: bytes,
    ) -> bool:
        try:
            ring_hash = _ring_digest(ring)
            if not isinstance(message, bytes) or not isinstance(scope, bytes):
                return False
            if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 <= epoch < 2**64:
                return False
            fields = self._parse(signature)
            proof_epoch, signer, proof_ring, proof_scope, proof_message = fields
            return (
                signer in ring
                and proof_epoch == epoch
                and proof_ring == ring_hash
                and proof_scope == _digest(scope)
                and proof_message == _digest(message)
            )
        except (TypeError, ValueError):
            return False

    def link(self, left: LRSSignature, right: LRSSignature) -> bool:
        try:
            left_epoch, left_signer, left_ring, left_scope, _ = self._parse(left)
            right_epoch, right_signer, right_ring, right_scope, _ = self._parse(right)
            return (left_epoch, left_signer, left_ring, left_scope) == (
                right_epoch,
                right_signer,
                right_ring,
                right_scope,
            )
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _parse(signature: LRSSignature) -> tuple[int, bytes, bytes, bytes, bytes]:
        if not isinstance(signature, LRSSignature):
            raise ValueError("invalid mock signature type")
        proof = signature.proof
        if (
            not isinstance(proof, bytes)
            or len(proof) != _PROOF_SIZE
            or not proof.startswith(_MAGIC)
        ):
            raise ValueError("malformed test proof")
        offset = len(_MAGIC)
        epoch = int.from_bytes(proof[offset : offset + 8], "big")
        offset += 8
        chunks = tuple(proof[offset + i : offset + i + 32] for i in range(0, 128, 32))
        return (epoch, *chunks)  # type: ignore[return-value]

