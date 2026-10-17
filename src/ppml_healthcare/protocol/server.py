"""Validated request decryption and inference (Step 7; no response yet)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Protocol

from ppml_healthcare.crypto.aead import AEADAdapter, AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter, KDFAdapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter, KEMAdapter
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.models.inference import DeterministicToyModel, InferenceAdapter
from ppml_healthcare.models.registry import ModelRegistry
from ppml_healthcare.protocol.client import (
    request_associated_data,
    request_key_derivation_context,
)
from ppml_healthcare.protocol.features import (
    CanonicalSyntheticFeatureValidator,
    FeatureValidator,
)
from ppml_healthcare.protocol.validation import RequestValidator
from ppml_healthcare.schemas import RequestEnvelope, ResponseEnvelope, ScalarFeature


class InferenceServer(Protocol):
    def handle_request(self, request: RequestEnvelope) -> ResponseEnvelope: ...


@dataclass(frozen=True, slots=True)
class ProcessedInference:
    """Step 7 output for Step 8; key material is hidden from repr/logging."""

    request_id: str
    model_id: str
    model_version: str
    model_hash: str
    prediction: ScalarFeature
    request_key: bytes = field(repr=False)


class RequestInferenceProcessor:
    """Run validation, artifact integrity checks, decryption, and inference."""

    def __init__(
        self,
        *,
        validator: RequestValidator,
        models: ModelRegistry,
        server_kem_private_key: bytes,
        kem: KEMAdapter | None = None,
        kdf: KDFAdapter | None = None,
        aead: AEADAdapter | None = None,
        feature_validator: FeatureValidator | None = None,
        inference: InferenceAdapter | None = None,
    ) -> None:
        if not isinstance(server_kem_private_key, bytes) or not server_kem_private_key:
            raise ValueError("server_kem_private_key must be non-empty bytes")
        self._validator = validator
        self._models = models
        self._server_kem_private_key = server_kem_private_key
        self._kem = kem or CryptographyMLKEMAdapter()
        self._kdf = kdf or HKDFSHA256Adapter()
        self._aead = aead or AES256GCMAdapter()
        self._features = feature_validator or CanonicalSyntheticFeatureValidator()
        self._inference = inference or DeterministicToyModel()

    def process_request(self, request: RequestEnvelope) -> ProcessedInference:
        """Return a prediction and request key after the full Step 7 pipeline."""
        self._validator.validate_before_decryption(request)

        # Re-hash the registered artifact before decrypting or invoking the
        # model. A changed or unavailable artifact fails closed.
        try:
            artifact_valid = self._models.verify_artifact(
                request.model.model_id, request.model.model_version
            )
        except Exception as exc:
            raise ProtocolRejectedError("registered model artifact verification failed") from exc
        if not artifact_valid:
            raise ProtocolRejectedError("registered model artifact failed integrity verification")

        try:
            shared_secret = self._kem.decapsulate(
                self._server_kem_private_key, request.kem_ciphertext
            )
        except Exception as exc:
            raise ProtocolRejectedError("request key decapsulation failed") from exc

        try:
            kdf_context = request_key_derivation_context(
                protocol_version=request.protocol_version,
                request_id=request.request_id,
            )
            request_key = self._kdf.derive_key(shared_secret, kdf_context, length=32)
        except Exception as exc:
            raise ProtocolRejectedError("request key derivation failed") from exc

        aad = request_associated_data(
            protocol_version=request.protocol_version,
            epoch=request.epoch,
            model=request.model,
            request_id=request.request_id,
        )
        try:
            plaintext = self._aead.decrypt(request_key, request.encrypted_features, aad)
        except Exception as exc:
            # This also handles ML-KEM implicit rejection: the derived key is
            # not evidence that the ciphertext was valid, and GCM must reject.
            raise ProtocolRejectedError("encrypted feature payload authentication failed") from exc

        features = self._features.validate(plaintext)
        try:
            prediction = self._inference.predict(request.model, features)
        except Exception as exc:
            if isinstance(exc, ProtocolRejectedError):
                raise
            raise ProtocolRejectedError("inference adapter failed") from exc
        if isinstance(prediction, bool) or not isinstance(prediction, (int, float)):
            raise ProtocolRejectedError("inference adapter returned a non-numeric prediction")
        if not math.isfinite(float(prediction)):
            raise ProtocolRejectedError("inference adapter returned a non-finite prediction")

        return ProcessedInference(
            request_id=request.request_id,
            model_id=request.model.model_id,
            model_version=request.model.model_version,
            model_hash=request.model.model_hash,
            prediction=prediction,
            request_key=request_key,
        )
