from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.aead import AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.crypto.server_signatures import CryptographyMLDSAAdapter
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.membership.registry import InMemoryMembershipRegistry
from ppml_healthcare.models.registry import InMemoryModelRegistry
from ppml_healthcare.protocol.client import HospitalRequestBuilder, InMemoryPendingRequestStore
from ppml_healthcare.protocol.rate_limit import InMemoryLinkabilityRateLimiter
from ppml_healthcare.protocol.replay import InMemoryReplayStore
from ppml_healthcare.protocol.response import (
    HospitalResponseHandler,
    ServerResponseBuilder,
    response_associated_data,
    response_authentication_message,
)
from ppml_healthcare.protocol.server import RequestInferenceProcessor
from ppml_healthcare.protocol.validation import OrderedRequestValidator
from ppml_healthcare.schemas import ModelDescriptor, SyntheticFeatures
from tests.support.test_lrs_support import LRSProtocolStub


@pytest.fixture
def context(tmp_path):
    settings = Settings(environment="test")
    lrs = LRSProtocolStub()
    hospital_public, hospital_secret = lrs.generate_keypair()
    membership = InMemoryMembershipRegistry((hospital_public,))
    epoch = membership.current_epoch()

    artifact_path = tmp_path / "toy-risk.bin"
    artifact = b"local deterministic toy model"
    artifact_path.write_bytes(artifact)
    model = ModelDescriptor("toy-risk", "1.0", hashlib.sha256(artifact).hexdigest())
    models = InMemoryModelRegistry()
    models.register_model(model, str(artifact_path))

    kem = CryptographyMLKEMAdapter()
    kem_keys = kem.generate_keypair()
    pending = InMemoryPendingRequestStore()
    builder = HospitalRequestBuilder(
        protocol_version="1.0",
        membership_epoch=epoch,
        hospital_secret_key=hospital_secret,
        model=model,
        server_kem_public_key=kem_keys.public_key,
        lrs=lrs,
        pending_store=pending,
        settings=settings,
        kem=kem,
    )
    validator = OrderedRequestValidator(
        settings=settings,
        membership=membership,
        models=models,
        lrs=lrs,
        replay_store=InMemoryReplayStore(),
        rate_limiter=InMemoryLinkabilityRateLimiter(lrs),
    )
    inference = RequestInferenceProcessor(
        validator=validator,
        models=models,
        server_kem_private_key=kem_keys.private_key,
        kem=kem,
        kdf=HKDFSHA256Adapter(),
        aead=AES256GCMAdapter(),
    )
    mldsa = CryptographyMLDSAAdapter()
    signing_keys = mldsa.generate_keypair()
    response_builder = ServerResponseBuilder(
        settings=settings,
        server_signing_private_key=signing_keys.private_key,
        signer=mldsa,
    )
    response_handler = HospitalResponseHandler(
        settings=settings,
        server_signing_public_key=signing_keys.public_key,
        pending_requests=pending,
        signer=mldsa,
    )
    return {
        "settings": settings,
        "pending": pending,
        "builder": builder,
        "inference": inference,
        "response_builder": response_builder,
        "response_handler": response_handler,
        "signer": mldsa,
        "signing_keys": signing_keys,
        "aead": AES256GCMAdapter(),
    }


def _exchange(context):
    request = context["builder"].build_request(SyntheticFeatures(42, 120, 80, 24.5))
    processed = context["inference"].process_request(request)
    return request, context["response_builder"].create_response(request, processed)


def _sign_response(context, response):
    signature = context["signer"].sign(
        context["signing_keys"].private_key,
        response_authentication_message(response),
    )
    return replace(response, server_signature=signature)


def test_server_and_hospital_complete_response_round_trip(context) -> None:
    request, response = _exchange(context)

    prediction = context["response_handler"].accept_response(response)

    assert prediction == 0.34875
    assert response.request_id == request.request_id
    assert response.model == request.model
    assert len(response.encrypted_prediction.nonce) == 12
    assert context["pending"].get(request.request_id) is None
    with pytest.raises(ProtocolRejectedError, match="pending request"):
        context["response_handler"].accept_response(response)


@pytest.mark.parametrize(
    "change",
    [
        lambda response: replace(response, protocol_version="2.0"),
        lambda response: replace(response, request_id="00000000-0000-4000-8000-000000000001"),
        lambda response: replace(response, model=replace(response.model, model_hash="c" * 64)),
        lambda response: replace(response, response_type="other"),
        lambda response: replace(
            response,
            encrypted_prediction=replace(
                response.encrypted_prediction,
                nonce=bytes([response.encrypted_prediction.nonce[0] ^ 1])
                + response.encrypted_prediction.nonce[1:],
            ),
        ),
        lambda response: replace(response, response_association=b"X" * 32),
    ],
)
def test_signature_binds_every_response_critical_field(context, change) -> None:
    _, response = _exchange(context)
    tampered = change(response)

    with pytest.raises(ProtocolRejectedError, match="signature"):
        context["response_handler"].accept_response(tampered)


def test_forged_signature_is_rejected_and_does_not_consume_pending_request(context) -> None:
    request, response = _exchange(context)
    forged = replace(response, server_signature=b"forged")

    with pytest.raises(ProtocolRejectedError, match="signature"):
        context["response_handler"].accept_response(forged)
    assert context["pending"].get(request.request_id) is not None
    assert context["response_handler"].accept_response(response) == 0.34875


def test_correctly_signed_wrong_correlation_is_rejected(context) -> None:
    request, response = _exchange(context)
    wrong_token = replace(response, response_association=b"X" * 32)
    wrong_token = _sign_response(context, wrong_token)

    with pytest.raises(ProtocolRejectedError, match="correlation"):
        context["response_handler"].accept_response(wrong_token)
    assert context["pending"].get(request.request_id) is not None


def test_correctly_signed_model_context_mismatch_is_rejected(context) -> None:
    request, response = _exchange(context)
    mismatched = replace(response, model=replace(response.model, model_version="2.0"))
    mismatched = _sign_response(context, mismatched)

    with pytest.raises(ProtocolRejectedError, match="context"):
        context["response_handler"].accept_response(mismatched)
    assert context["pending"].get(request.request_id) is not None


def test_gcm_failure_after_valid_signature_does_not_consume_pending(context) -> None:
    request, response = _exchange(context)
    payload = response.encrypted_prediction
    changed = bytes([payload.ciphertext[0] ^ 1]) + payload.ciphertext[1:]
    tampered = replace(
        response,
        encrypted_prediction=replace(payload, ciphertext=changed),
    )
    tampered = _sign_response(context, tampered)

    with pytest.raises(ProtocolRejectedError, match="authentication failed"):
        context["response_handler"].accept_response(tampered)
    assert context["pending"].get(request.request_id) is not None


def test_response_for_another_pending_request_is_not_accepted(context) -> None:
    request_a, _ = _exchange(context)
    request_b, response_b = _exchange(context)
    mismatched = replace(
        response_b,
        request_id=request_a.request_id,
        model=request_a.model,
        response_association=request_a.response_association,
    )
    mismatched = _sign_response(context, mismatched)

    with pytest.raises(ProtocolRejectedError, match="authentication failed"):
        context["response_handler"].accept_response(mismatched)
    assert context["pending"].get(request_a.request_id) is not None
    assert context["pending"].get(request_b.request_id) is not None


def test_hospital_a_cannot_decrypt_hospital_b_response(context) -> None:
    request_a, _ = _exchange(context)
    request_b, response_b = _exchange(context)
    key_a = context["pending"].get(request_a.request_id).aes_key

    with pytest.raises(InvalidTag):
        context["aead"].decrypt(
            key_a,
            response_b.encrypted_prediction,
            response_associated_data(
                protocol_version=response_b.protocol_version,
                request_id=response_b.request_id,
                model=response_b.model,
                response_type=response_b.response_type,
                response_association=response_b.response_association,
            ),
        )
    assert request_a.request_id != request_b.request_id


def test_secure_response_builder_and_handler_can_use_request_bound_correlation(context) -> None:
    builder = ServerResponseBuilder(
        settings=Settings(),
        server_signing_private_key=context["signing_keys"].private_key,
        signer=context["signer"],
    )
    handler = HospitalResponseHandler(
        settings=Settings(),
        server_signing_public_key=context["signing_keys"].public_key,
        pending_requests=InMemoryPendingRequestStore(),
        signer=context["signer"],
    )
    assert builder is not None
    assert handler is not None

