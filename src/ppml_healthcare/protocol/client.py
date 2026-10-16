"""Hospital request construction and demo-only pending request state."""

from __future__ import annotations

import secrets
import threading
import uuid
from dataclasses import dataclass
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
    SyntheticFeatures,
)
from ppml_healthcare.serialization import canonical_bytes

REQUEST_AUTH_SCOPE = b"ppml-healthcare/request-auth/v1"
_DEFAULT_REQUEST_TTL = timedelta(minutes=5)


class HospitalClient(Protocol):
    def build_request(self, features: SyntheticFeatures) -> RequestEnvelope: ...

    def accept_response(self, response: ResponseEnvelope) -> object: ...


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """Ephemeral client-only keys and correlation data for a request."""

    request_id: str
    aes_key: bytes
    response_association: bytes


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


def request_authentication_message(request: RequestEnvelope) -> bytes:
    """Canonical signed fields; deliberately excludes only the proof itself."""
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
        selected_settings = settings or Settings()
        if getattr(lrs, "insecure_test_only", False) and (
            selected_settings.environment != "test"
            or selected_settings.crypto_mode != "INSECURE_TEST_MOCK"
        ):
            raise SchemaValidationError(
                "insecure mock LRS requires test environment and INSECURE_TEST_MOCK mode"
            )
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

        # Validate the key/ring relationship without exposing a signer identity
        # through this API. Signing performs the definitive check for the mock.
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
        kdf_context = canonical_bytes(
            {
                "protocol_version": self._protocol_version,
                "purpose": "request-aes-256-gcm",
                "request_id": request_id,
            }
        )
        aes_key = self._kdf.derive_key(encapsulation.shared_secret, kdf_context, length=32)
        aad = request_associated_data(
            protocol_version=self._protocol_version,
            epoch=self._epoch.epoch,
            model=self._model,
            request_id=request_id,
        )
        encrypted = self._aead.encrypt(aes_key, canonical_bytes(features), aad)

        # This random token is only workflow correlation for the insecure mock;
        # it is not an LRS response-association proof.
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
            request_authentication_message(unsigned),
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
        )
        self._pending_store.put(
            PendingRequest(
                request_id=request_id,
                aes_key=aes_key,
                response_association=response_association,
            )
        )
        return request
