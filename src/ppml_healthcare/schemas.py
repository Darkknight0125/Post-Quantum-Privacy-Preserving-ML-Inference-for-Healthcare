"""Typed protocol envelopes and synthetic feature schemas.

These models validate data shape only. They do not establish cryptographic
validity, authorization, privacy, or clinical meaning.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypeAlias

from ppml_healthcare.errors import SchemaValidationError

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_OPAQUE_FIELD_BYTES = 1_048_576

ScalarFeature: TypeAlias = float | int | bool


def _require_nonempty_string(name: str, value: str, max_length: int = 256) -> None:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise SchemaValidationError(f"{name} must contain 1..{max_length} characters")


def _require_bytes(name: str, value: bytes, *, maximum: int = _MAX_OPAQUE_FIELD_BYTES) -> None:
    if not isinstance(value, bytes) or len(value) > maximum:
        raise SchemaValidationError(f"{name} must be bytes no larger than {maximum} bytes")


def _require_utc_datetime(name: str, value: datetime | None) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value)):
        raise SchemaValidationError(f"{name} must be timezone-aware UTC")


def _require_request_id(value: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise SchemaValidationError("request_id must be a UUID string") from exc
    if str(parsed) != value.lower():
        raise SchemaValidationError("request_id must use canonical UUID text")


@dataclass(frozen=True, slots=True)
class SyntheticFeatures:
    """Strict demo feature vector; feature names are synthetic, not identifiers."""

    age_years: float
    systolic_bp: float
    diastolic_bp: float
    bmi: float

    def __post_init__(self) -> None:
        for name in ("age_years", "systolic_bp", "diastolic_bp", "bmi"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SchemaValidationError(f"{name} must be numeric")
            if not math.isfinite(float(value)):
                raise SchemaValidationError(f"{name} must be finite")
        if not 0 <= self.age_years <= 120:
            raise SchemaValidationError("age_years is outside the demo range")
        if not 40 <= self.systolic_bp <= 300:
            raise SchemaValidationError("systolic_bp is outside the demo range")
        if not 20 <= self.diastolic_bp <= 200:
            raise SchemaValidationError("diastolic_bp is outside the demo range")
        if not 5 <= self.bmi <= 100:
            raise SchemaValidationError("bmi is outside the demo range")


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """Ciphertext container. Authentication and decryption are adapter concerns."""

    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 12:
            raise SchemaValidationError(
                "nonce must be exactly 12 bytes for the planned GCM profile"
            )
        _require_bytes("ciphertext", self.ciphertext)


@dataclass(frozen=True, slots=True)
class ModelDescriptor:
    model_id: str
    model_version: str
    model_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str) or not _MODEL_ID.fullmatch(self.model_id):
            raise SchemaValidationError("model_id has an invalid format")
        _require_nonempty_string("model_version", self.model_version, 64)
        if not isinstance(self.model_hash, str) or not _HEX_256.fullmatch(self.model_hash):
            raise SchemaValidationError("model_hash must be a lowercase SHA-256 hex digest")


@dataclass(frozen=True, slots=True)
class RequestEnvelope:
    protocol_version: str
    epoch: int
    model: ModelDescriptor
    request_id: str
    created_at: datetime
    expires_at: datetime | None
    kem_ciphertext: bytes
    encrypted_features: EncryptedPayload
    lrs_proof: bytes
    response_association: bytes | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string("protocol_version", self.protocol_version, 32)
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 0:
            raise SchemaValidationError("epoch must be a non-negative integer")
        if not isinstance(self.model, ModelDescriptor):
            raise SchemaValidationError("model must be a ModelDescriptor")
        _require_request_id(self.request_id)
        if not isinstance(self.created_at, datetime):
            raise SchemaValidationError("created_at must be a datetime")
        _require_utc_datetime("created_at", self.created_at)
        _require_utc_datetime("expires_at", self.expires_at)
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise SchemaValidationError("expires_at must be later than created_at")
        _require_bytes("kem_ciphertext", self.kem_ciphertext)
        if not isinstance(self.encrypted_features, EncryptedPayload):
            raise SchemaValidationError("encrypted_features must be an EncryptedPayload")
        _require_bytes("lrs_proof", self.lrs_proof)
        if self.response_association is not None:
            _require_bytes("response_association", self.response_association)


@dataclass(frozen=True, slots=True)
class ResponseEnvelope:
    protocol_version: str
    request_id: str
    model: ModelDescriptor
    response_type: str
    encrypted_prediction: EncryptedPayload
    response_association: bytes | None
    server_signature: bytes

    def __post_init__(self) -> None:
        _require_nonempty_string("protocol_version", self.protocol_version, 32)
        _require_request_id(self.request_id)
        if not isinstance(self.model, ModelDescriptor):
            raise SchemaValidationError("model must be a ModelDescriptor")
        _require_nonempty_string("response_type", self.response_type, 64)
        if not isinstance(self.encrypted_prediction, EncryptedPayload):
            raise SchemaValidationError("encrypted_prediction must be an EncryptedPayload")
        if self.response_association is not None:
            _require_bytes("response_association", self.response_association)
        _require_bytes("server_signature", self.server_signature)


@dataclass(frozen=True, slots=True)
class MembershipEpoch:
    epoch: int
    issued_at: datetime
    members: tuple[bytes, ...]
    registry_digest: str

    def __post_init__(self) -> None:
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 0:
            raise SchemaValidationError("epoch must be a non-negative integer")
        _require_utc_datetime("issued_at", self.issued_at)
        if not isinstance(self.members, tuple) or any(
            not isinstance(key, bytes) for key in self.members
        ):
            raise SchemaValidationError("members must be a tuple of opaque public-key bytes")
        if len(self.members) != len(set(self.members)):
            raise SchemaValidationError("membership epoch cannot contain duplicate public keys")
        if not isinstance(self.registry_digest, str) or not _HEX_256.fullmatch(
            self.registry_digest
        ):
            raise SchemaValidationError("registry_digest must be a lowercase SHA-256 hex digest")
