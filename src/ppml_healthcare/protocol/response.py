"""Signed response creation and hospital-side verification (Step 8)."""

from __future__ import annotations

import hmac
import json
import math
from threading import Lock
from typing import Protocol

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.aead import AEADAdapter, AES256GCMAdapter
from ppml_healthcare.crypto.server_signatures import (
    CryptographyMLDSAAdapter,
    ServerSignatureAdapter,
)
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.protocol.client import PendingRequestStore
from ppml_healthcare.protocol.server import ProcessedInference
from ppml_healthcare.schemas import (
    ModelDescriptor,
    RequestEnvelope,
    ResponseEnvelope,
    ScalarFeature,
)
from ppml_healthcare.serialization import canonical_bytes

PREDICTION_RESPONSE_TYPE = "prediction"


class ResponseGenerator(Protocol):
    def create_response(
        self, request: RequestEnvelope, processed: ProcessedInference
    ) -> ResponseEnvelope: ...


class ResponseVerifier(Protocol):
    def accept_response(self, response: ResponseEnvelope) -> ScalarFeature: ...


def response_associated_data(
    *,
    protocol_version: str,
    request_id: str,
    model: ModelDescriptor,
    response_type: str,
    response_association: bytes | None,
) -> bytes:
    """Canonical GCM AAD for response metadata and its correlation token."""
    return canonical_bytes(
        {
            "protocol_version": protocol_version,
            "request_id": request_id,
            "model": model,
            "response_type": response_type,
            "response_association": response_association,
            "purpose": "encrypted-prediction",
        }
    )


def response_authentication_message(response: ResponseEnvelope) -> bytes:
    """Canonical response fields covered by ML-DSA; excludes only the signature."""
    return canonical_bytes(
        {
            "protocol_version": response.protocol_version,
            "request_id": response.request_id,
            "model": response.model,
            "response_type": response.response_type,
            "encrypted_prediction": response.encrypted_prediction,
            "response_association": response.response_association,
        }
    )


class ServerResponseBuilder:
    """Encrypt prediction and sign its complete canonical response envelope."""

    def __init__(
        self,
        *,
        settings: Settings,
        server_signing_private_key: bytes,
        signer: ServerSignatureAdapter | None = None,
        aead: AEADAdapter | None = None,
    ) -> None:
        if not isinstance(server_signing_private_key, bytes) or not server_signing_private_key:
            raise ValueError("server_signing_private_key must be non-empty bytes")
        self._private_key = server_signing_private_key
        self._signer = signer or CryptographyMLDSAAdapter()
        self._aead = aead or AES256GCMAdapter()
        self._settings = settings

    def create_response(
        self, request: RequestEnvelope, processed: ProcessedInference
    ) -> ResponseEnvelope:
        if not isinstance(request, RequestEnvelope) or not isinstance(
            processed, ProcessedInference
        ):
            raise ProtocolRejectedError("response inputs have invalid types")
        if (
            processed.request_id != request.request_id
            or processed.model_id != request.model.model_id
            or processed.model_version != request.model.model_version
            or processed.model_hash != request.model.model_hash
        ):
            raise ProtocolRejectedError("inference result does not match request context")
        if not isinstance(request.response_association, bytes) or not request.response_association:
            raise ProtocolRejectedError("response correlation token is missing")
        prediction = _validate_prediction(processed.prediction)
        unsigned = ResponseEnvelope(
            protocol_version=request.protocol_version,
            request_id=request.request_id,
            model=request.model,
            response_type=PREDICTION_RESPONSE_TYPE,
            encrypted_prediction=self._aead.encrypt(
                processed.request_key,
                canonical_bytes({"prediction": prediction}),
                response_associated_data(
                    protocol_version=request.protocol_version,
                    request_id=request.request_id,
                    model=request.model,
                    response_type=PREDICTION_RESPONSE_TYPE,
                    response_association=request.response_association,
                ),
            ),
            response_association=request.response_association,
            server_signature=b"pending",
        )
        signature = self._signer.sign(self._private_key, response_authentication_message(unsigned))
        response = ResponseEnvelope(
            protocol_version=unsigned.protocol_version,
            request_id=unsigned.request_id,
            model=unsigned.model,
            response_type=unsigned.response_type,
            encrypted_prediction=unsigned.encrypted_prediction,
            response_association=unsigned.response_association,
            server_signature=signature,
        )
        if len(canonical_bytes(response)) > self._settings.max_response_bytes:
            raise ProtocolRejectedError("response exceeds configured size limit")
        return response


class HospitalResponseHandler:
    """Verify server signature, request association, and decrypt a prediction."""

    def __init__(
        self,
        *,
        settings: Settings,
        server_signing_public_key: bytes,
        pending_requests: PendingRequestStore,
        signer: ServerSignatureAdapter | None = None,
        aead: AEADAdapter | None = None,
    ) -> None:
        if not isinstance(server_signing_public_key, bytes) or not server_signing_public_key:
            raise ValueError("server_signing_public_key must be non-empty bytes")
        self._settings = settings
        self._public_key = server_signing_public_key
        self._pending = pending_requests
        self._signer = signer or CryptographyMLDSAAdapter()
        self._aead = aead or AES256GCMAdapter()
        self._consume_lock = Lock()

    def accept_response(self, response: ResponseEnvelope) -> ScalarFeature:
        if not isinstance(response, ResponseEnvelope):
            raise ProtocolRejectedError("response has an invalid envelope type")
        try:
            encoded = canonical_bytes(response)
        except Exception as exc:
            raise ProtocolRejectedError("response cannot be canonically encoded") from exc
        if len(encoded) > self._settings.max_response_bytes:
            raise ProtocolRejectedError("response exceeds configured size limit")
        try:
            signature_valid = self._signer.verify(
                self._public_key,
                response_authentication_message(response),
                response.server_signature,
            )
        except Exception as exc:
            raise ProtocolRejectedError("server response signature verification failed") from exc
        if not signature_valid:
            raise ProtocolRejectedError("server response signature is invalid")
        if response.protocol_version != self._settings.protocol_version:
            raise ProtocolRejectedError("unsupported response protocol version")
        if response.response_type != PREDICTION_RESPONSE_TYPE:
            raise ProtocolRejectedError("unsupported response type")

        pending = self._pending.get(response.request_id)
        if pending is None:
            raise ProtocolRejectedError("response has no matching pending request")
        if (
            response.request_id != pending.request_id
            or response.protocol_version != pending.protocol_version
            or response.model != pending.model
        ):
            raise ProtocolRejectedError("response request or model context does not match")
        if not isinstance(response.response_association, bytes) or not hmac.compare_digest(
            response.response_association, pending.response_association
        ):
            raise ProtocolRejectedError("response correlation does not match pending request")

        try:
            plaintext = self._aead.decrypt(
                pending.aes_key,
                response.encrypted_prediction,
                response_associated_data(
                    protocol_version=response.protocol_version,
                    request_id=response.request_id,
                    model=response.model,
                    response_type=response.response_type,
                    response_association=response.response_association,
                ),
            )
        except Exception as exc:
            raise ProtocolRejectedError("encrypted prediction authentication failed") from exc
        prediction = _decode_prediction(plaintext)

        # Only one concurrent response handler can consume this pending state.
        # The store's remove is atomic; compare the removed value to guard a
        # custom store that replaced an entry between lookup and consumption.
        with self._consume_lock:
            consumed = self._pending.remove(response.request_id)
            if consumed != pending:
                raise ProtocolRejectedError("pending request was already consumed")
        return prediction


def _validate_prediction(value: object) -> ScalarFeature:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProtocolRejectedError("prediction must be a finite number")
    if not math.isfinite(float(value)):
        raise ProtocolRejectedError("prediction must be a finite number")
    return value


def _decode_prediction(plaintext: bytes) -> ScalarFeature:
    try:
        value = json.loads(plaintext.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProtocolRejectedError("decrypted prediction is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"prediction"}:
        raise ProtocolRejectedError("decrypted prediction has an invalid schema")
    prediction = _validate_prediction(value["prediction"])
    if canonical_bytes({"prediction": prediction}) != plaintext:
        raise ProtocolRejectedError("decrypted prediction is not canonical")
    return prediction
