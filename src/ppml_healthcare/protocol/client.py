"""Hospital request construction and demo-only pending request state."""

from __future__ import annotations

import secrets
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.aead import AEADAdapter, AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter, KDFAdapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter, KEMAdapter
from ppml_healthcare.crypto.lrs import LRSAdapter
from ppml_healthcare.errors import RegistryConflictError, SchemaValidationError
from ppml_healthcare.schemas import (
    MembershipEpoch,
    ModelDescriptor,
    RequestEnvelope,
    ResponseEnvelope,
    ScalarFeature,
    SyntheticFeatures,
)
from ppml_healthcare.serialization import canonical_bytes

REQUEST_AUTH_SCOPE = b"ppml-healthcare/request-auth/v1"
_DEFAULT_REQUEST_TTL = timedelta(minutes=5)


class HospitalClient(Protocol):
    def build_request(self, features: SyntheticFeatures) -> RequestEnvelope: ...

    def accept_response(self, response: ResponseEnvelope) -> ScalarFeature: ...


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """Ephemeral client-only keys and correlation data for a request."""

    request_id: str
    protocol_version: str
    model: ModelDescriptor
    aes_key: bytes = field(repr=False)
    response_association: bytes = field(repr=False)


class PendingRequestStore(Protocol):
    def put(self, pending: PendingRequest) -> None: ...

    def get(self, request_id: str) -> PendingRequest | None: ...

    def remove(self, request_id: str) -> PendingRequest | None: ...


class InMemoryPendingRequestStore:
    """Process-local demo store. Pending keys are not persisted or serialized."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._pending: dict[str, PendingRequest] = {}

    def put(self, pending: PendingRequest) -> None:
        if not isinstance(pending, PendingRequest):
            raise SchemaValidationError("pending must be a PendingRequest")
        with self._lock:
            if pending.request_id in self._pending:
                raise RegistryConflictError("pending request ID already exists")
            self._pending[pending.request_id] = pending

    def get(self, request_id: str) -> PendingRequest | None:
        with self._lock:
            return self._pending.get(request_id)

    def remove(self, request_id: str) -> PendingRequest | None:
        with self._lock:
            return self._pending.pop(request_id, None)


def request_associated_data(
    *, protocol_version: str, epoch: int, model: ModelDescriptor, request_id: str
) -> bytes:
    """Canonical AES-GCM AAD binding the encrypted payload to request metadata."""
    return canonical_bytes(
        {
            "protocol_version": protocol_version,
            "epoch": epoch,
            "model": model,
            "request_id": request_id,
            "purpose": "encrypted-features",
        }
    )


def request_key_derivation_context(*, protocol_version: str, request_id: str) -> bytes:
    """Canonical HKDF context shared by the hospital and server sides."""
    return canonical_bytes(
        {
            "protocol_version": protocol_version,
            "purpose": "request-aes-256-gcm",
            "request_id": request_id,
        }
    )


def request_authentication_message(
    request: RequestEnvelope, *, ring_digest: bytes | None = None
) -> bytes:
    """Encode the request core, excluding only LRS proof and link tag.

    MAYO LRS uses a strict binary format and binds the exact current ring
    digest.
    """
    if ring_digest is not None:
        if not isinstance(ring_digest, bytes) or len(ring_digest) != 32:
            raise SchemaValidationError("ring_digest must be 32 bytes")

        def lp(raw: bytes) -> bytes:
            if len(raw) >= 2**32:
                raise SchemaValidationError("request field exceeds U32 length")
            return len(raw).to_bytes(4, "big") + raw

        def unix_seconds(value: datetime) -> bytes:
            timestamp = int(value.timestamp())
            if timestamp < 0 or timestamp >= 2**64:
                raise SchemaValidationError("request timestamp is outside U64 range")
            return timestamp.to_bytes(8, "big")

        protocol_version = request.protocol_version.encode("utf-8", errors="strict")
        request_id = request.request_id.encode("utf-8", errors="strict")
        model_id = request.model.model_id.encode("utf-8", errors="strict")
        model_version = request.model.model_version.encode("utf-8", errors="strict")
        payload = bytearray(b"MSZ-LRS/request-core-encoding/v1")
        payload.extend(lp(protocol_version))
        payload.extend(request.epoch.to_bytes(8, "big"))
        payload.extend(ring_digest)
        payload.extend(lp(request_id))
        payload.extend(unix_seconds(request.created_at))
        if request.expires_at is None:
            payload.extend(b"\x00")
        else:
            payload.extend(b"\x01")
            payload.extend(unix_seconds(request.expires_at))
        payload.extend(lp(model_id))
        payload.extend(lp(model_version))
        payload.extend(bytes.fromhex(request.model.model_hash))
        payload.extend(lp(request.kem_ciphertext))
        payload.extend(request.encrypted_features.nonce)
        payload.extend(lp(request.encrypted_features.ciphertext))
        # This project-specific extension authenticates Step 8 response
        # correlation so it cannot be replaced after anonymous authorization.
        payload.extend(lp(request.response_association or b""))
        return bytes(payload)

    return canonical_bytes(
        {
            "protocol_version": request.protocol_version,
            "epoch": request.epoch,
            "model": request.model,
            "request_id": request.request_id,
            "created_at": request.created_at,
            "expires_at": request.expires_at,
            "kem_ciphertext": request.kem_ciphertext,
            "encrypted_features": request.encrypted_features,
            "response_association": request.response_association,
        }
    )


class HospitalRequestBuilder:
    """Build and authenticate one encrypted, synthetic-feature request."""

    def __init__(
        self,
        *,
        protocol_version: str,
        membership_epoch: MembershipEpoch,
        hospital_secret_key: bytes,
        model: ModelDescriptor,
        server_kem_public_key: bytes,
        lrs: LRSAdapter,
        pending_store: PendingRequestStore,
        settings: Settings | None = None,
        kem: KEMAdapter | None = None,
        kdf: KDFAdapter | None = None,
        aead: AEADAdapter | None = None,
        request_ttl: timedelta | None = _DEFAULT_REQUEST_TTL,
    ) -> None:
        if not isinstance(membership_epoch, MembershipEpoch):
            raise SchemaValidationError("membership_epoch must be a MembershipEpoch")
        if not isinstance(model, ModelDescriptor):
            raise SchemaValidationError("model must be a ModelDescriptor")
        if not isinstance(hospital_secret_key, bytes) or not hospital_secret_key:
            raise SchemaValidationError("hospital_secret_key must be non-empty bytes")
        if not isinstance(server_kem_public_key, bytes) or not server_kem_public_key:
            raise SchemaValidationError("server_kem_public_key must be non-empty bytes")
        if not protocol_version or len(protocol_version) > 32:
            raise SchemaValidationError("protocol_version must contain 1..32 characters")
        if request_ttl is not None and (
            not isinstance(request_ttl, timedelta) or request_ttl <= timedelta(0)
        ):
            raise SchemaValidationError("request_ttl must be positive or None")
        if not callable(getattr(lrs, "sign", None)):
            raise SchemaValidationError("lrs adapter does not implement signing")
        if settings is not None and not isinstance(settings, Settings):
            raise SchemaValidationError("settings must be a Settings instance")
        self._lrs = lrs
        self._protocol_version = protocol_version
        self._epoch = membership_epoch
        self._hospital_secret_key = hospital_secret_key
        self._model = model
        self._server_kem_public_key = server_kem_public_key
        self._pending_store = pending_store
        self._kem = kem or CryptographyMLKEMAdapter()
        self._kdf = kdf or HKDFSHA256Adapter()
        self._aead = aead or AES256GCMAdapter()

        # Signing performs the definitive credential and membership check.
        if not self._epoch.members:
            raise SchemaValidationError("membership epoch must contain at least one member")
        if request_ttl is not None:
            self._request_ttl_seconds = request_ttl.total_seconds()
        else:
            self._request_ttl_seconds = None

    def build_request(self, features: SyntheticFeatures) -> RequestEnvelope:
        if not isinstance(features, SyntheticFeatures):
            raise SchemaValidationError("features must be SyntheticFeatures")

        request_id = str(uuid.uuid4())
        created_at = datetime.now(UTC)
        expires_at = (
            None
            if self._request_ttl_seconds is None
            else created_at + timedelta(seconds=self._request_ttl_seconds)
        )
        encapsulation = self._kem.encapsulate(self._server_kem_public_key)
        kdf_context = request_key_derivation_context(
            protocol_version=self._protocol_version,
            request_id=request_id,
        )
        aes_key = self._kdf.derive_key(encapsulation.shared_secret, kdf_context, length=32)
        aad = request_associated_data(
            protocol_version=self._protocol_version,
            epoch=self._epoch.epoch,
            model=self._model,
            request_id=request_id,
        )
        encrypted = self._aead.encrypt(aes_key, canonical_bytes(features), aad)

        # This token provides workflow correlation, not a separate zero-knowledge
        # response-association proof.
        response_association = secrets.token_bytes(32)
        unsigned = RequestEnvelope(
            protocol_version=self._protocol_version,
            epoch=self._epoch.epoch,
            model=self._model,
            request_id=request_id,
            created_at=created_at,
            expires_at=expires_at,
            kem_ciphertext=encapsulation.ciphertext,
            encrypted_features=encrypted,
            lrs_proof=b"pending",
            response_association=response_association,
        )
        proof = self._lrs.sign(
            self._hospital_secret_key,
            self._epoch.members,
            request_authentication_message(
                unsigned,
                ring_digest=(
                    self._lrs.ring_digest(self._epoch.members, self._epoch.epoch)
                    if callable(getattr(self._lrs, "ring_digest", None))
                    else None
                ),
            ),
            self._epoch.epoch,
            REQUEST_AUTH_SCOPE,
        )
        request = RequestEnvelope(
            protocol_version=unsigned.protocol_version,
            epoch=unsigned.epoch,
            model=unsigned.model,
            request_id=unsigned.request_id,
            created_at=unsigned.created_at,
            expires_at=unsigned.expires_at,
            kem_ciphertext=unsigned.kem_ciphertext,
            encrypted_features=unsigned.encrypted_features,
            lrs_proof=proof.proof,
            response_association=unsigned.response_association,
            link_tag=proof.link_tag,
        )
        self._pending_store.put(
            PendingRequest(
                request_id=request_id,
                protocol_version=self._protocol_version,
                model=self._model,
                aes_key=aes_key,
                response_association=response_association,
            )
        )
        return request
