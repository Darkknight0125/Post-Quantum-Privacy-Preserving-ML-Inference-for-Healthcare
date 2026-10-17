from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.aead import AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.membership.registry import InMemoryMembershipRegistry
from ppml_healthcare.models.inference import DeterministicToyModel
from ppml_healthcare.models.registry import InMemoryModelRegistry
from ppml_healthcare.protocol.client import (
    REQUEST_AUTH_SCOPE,
    HospitalRequestBuilder,
    InMemoryPendingRequestStore,
    request_associated_data,
    request_authentication_message,
)
from ppml_healthcare.protocol.features import CanonicalSyntheticFeatureValidator
from ppml_healthcare.protocol.rate_limit import InMemoryLinkabilityRateLimiter
from ppml_healthcare.protocol.replay import InMemoryReplayStore
from ppml_healthcare.protocol.server import RequestInferenceProcessor
from ppml_healthcare.protocol.validation import OrderedRequestValidator
from ppml_healthcare.schemas import EncryptedPayload, ModelDescriptor, SyntheticFeatures
from ppml_healthcare.serialization import canonical_bytes
from tests.support.test_lrs_support import LRSProtocolStub


class _CountingKEM:
    def __init__(self, adapter: CryptographyMLKEMAdapter) -> None:
        self.adapter = adapter
        self.decapsulation_calls = 0

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        self.decapsulation_calls += 1
        return self.adapter.decapsulate(private_key, ciphertext)


class _CountingInference:
    def __init__(self) -> None:
        self.calls = 0
        self.model = DeterministicToyModel()

    def predict(self, model: ModelDescriptor, features: SyntheticFeatures) -> float:
        self.calls += 1
        return self.model.predict(model, features)


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
    server_keys = kem.generate_keypair()
    pending = InMemoryPendingRequestStore()
    builder = HospitalRequestBuilder(
        protocol_version="1.0",
        membership_epoch=epoch,
        hospital_secret_key=hospital_secret,
        model=model,
        server_kem_public_key=server_keys.public_key,
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
    counting_kem = _CountingKEM(kem)
    inference = _CountingInference()
    processor = RequestInferenceProcessor(
        validator=validator,
        models=models,
        server_kem_private_key=server_keys.private_key,
        kem=counting_kem,
        kdf=HKDFSHA256Adapter(),
        aead=AES256GCMAdapter(),
        feature_validator=CanonicalSyntheticFeatureValidator(),
        inference=inference,
    )
    return {
        "settings": settings,
        "lrs": lrs,
        "secret": hospital_secret,
        "epoch": epoch,
        "model": model,
        "models": models,
        "artifact_path": artifact_path,
        "builder": builder,
        "pending": pending,
        "processor": processor,
        "kem": counting_kem,
        "aead": AES256GCMAdapter(),
        "inference": inference,
    }


def _build(context):
    return context["builder"].build_request(SyntheticFeatures(42, 120, 80, 24.5))


def _resign(context, request, *, encrypted_features: EncryptedPayload):
    unsigned = replace(request, encrypted_features=encrypted_features)
    proof = context["lrs"].sign(
        context["secret"],
        context["epoch"].members,
        request_authentication_message(unsigned),
        request.epoch,
        REQUEST_AUTH_SCOPE,
    )
    return replace(unsigned, lrs_proof=proof.proof)


def test_valid_request_is_decrypted_and_toy_inference_is_deterministic(context) -> None:
    request = _build(context)

    result = context["processor"].process_request(request)

    assert result.request_id == request.request_id
    assert result.model_id == "toy-risk"
    assert result.model_version == "1.0"
    assert result.prediction == 0.34875
    assert len(result.request_key) == 32
    assert context["kem"].decapsulation_calls == 1
    assert context["inference"].calls == 1
    assert result.request_key not in repr(result).encode()


def test_invalid_authentication_never_reaches_decapsulation_or_inference(context) -> None:
    request = _build(context)
    request = replace(request, lrs_proof=b"forged")

    with pytest.raises(ProtocolRejectedError, match="authentication"):
        context["processor"].process_request(request)

    assert context["kem"].decapsulation_calls == 0
    assert context["inference"].calls == 0


def test_invalid_gcm_tag_never_reaches_inference(context) -> None:
    request = _build(context)
    payload = request.encrypted_features
    changed_ciphertext = bytes([payload.ciphertext[0] ^ 1]) + payload.ciphertext[1:]
    tampered = EncryptedPayload(payload.nonce, changed_ciphertext)
    request = _resign(context, request, encrypted_features=tampered)

    with pytest.raises(ProtocolRejectedError, match="authentication failed"):
        context["processor"].process_request(request)

    assert context["kem"].decapsulation_calls == 1
    assert context["inference"].calls == 0


@pytest.mark.parametrize(
    "plaintext",
    [
        b"not-json",
        b'{"age_years":42,"age_years":43,"systolic_bp":120,"diastolic_bp":80,"bmi":24.5}',
        b'{"age_years":42,"systolic_bp":120,"diastolic_bp":80,"bmi":24.5,"extra":1}',
        b'{"age_years":true,"systolic_bp":120,"diastolic_bp":80,"bmi":24.5}',
        b'{"age_years":999,"systolic_bp":120,"diastolic_bp":80,"bmi":24.5}',
        b'{ "age_years":42,"systolic_bp":120,"diastolic_bp":80,"bmi":24.5}',
    ],
)
def test_invalid_decrypted_features_never_reach_inference(context, plaintext: bytes) -> None:
    request = _build(context)
    pending = context["pending"].get(request.request_id)
    aad = request_associated_data(
        protocol_version=request.protocol_version,
        epoch=request.epoch,
        model=request.model,
        request_id=request.request_id,
    )
    encrypted = context["aead"].encrypt(pending.aes_key, plaintext, aad)
    request = _resign(context, request, encrypted_features=encrypted)

    with pytest.raises(ProtocolRejectedError, match="features|feature payload"):
        context["processor"].process_request(request)

    assert context["inference"].calls == 0


def test_model_descriptor_mismatch_fails_before_decapsulation(context) -> None:
    request = _build(context)
    request = replace(request, model=replace(request.model, model_hash="c" * 64))

    with pytest.raises(ProtocolRejectedError, match="model descriptor"):
        context["processor"].process_request(request)

    assert context["kem"].decapsulation_calls == 0
    assert context["inference"].calls == 0


def test_modified_model_artifact_fails_before_decapsulation(context) -> None:
    request = _build(context)
    context["artifact_path"].write_bytes(b"changed after registration")

    with pytest.raises(ProtocolRejectedError, match="artifact"):
        context["processor"].process_request(request)

    assert context["kem"].decapsulation_calls == 0
    assert context["inference"].calls == 0


def test_canonical_feature_validator_checks_schema_and_ranges() -> None:
    validator = CanonicalSyntheticFeatureValidator()
    assert validator.validate(
        canonical_bytes(SyntheticFeatures(42, 120, 80, 24.5))
    ) == SyntheticFeatures(42, 120, 80, 24.5)

    with pytest.raises(ProtocolRejectedError):
        validator.validate(b'{"age_years":42,"systolic_bp":120,"diastolic_bp":80}')

