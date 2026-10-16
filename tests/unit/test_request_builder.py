from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.aead import AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.crypto.lrs import LRSSignature
from ppml_healthcare.crypto.mock_lrs import InsecureTestMockLRSAdapter
from ppml_healthcare.errors import SchemaValidationError
from ppml_healthcare.protocol.client import (
    REQUEST_AUTH_SCOPE,
    HospitalRequestBuilder,
    InMemoryPendingRequestStore,
    request_associated_data,
    request_authentication_message,
)
from ppml_healthcare.schemas import (
    EncryptedPayload,
    MembershipEpoch,
    ModelDescriptor,
    SyntheticFeatures,
)
from ppml_healthcare.serialization import canonical_bytes


@pytest.fixture
def request_context():
    lrs = InsecureTestMockLRSAdapter()
    hospital_public, hospital_secret = lrs.generate_keypair()
    kem = CryptographyMLKEMAdapter()
    server_keys = kem.generate_keypair()
    epoch = MembershipEpoch(
        epoch=7,
        issued_at=datetime.now(UTC),
        members=(hospital_public,),
        registry_digest="a" * 64,
    )
    model = ModelDescriptor("toy-risk", "1.0", "b" * 64)
    pending = InMemoryPendingRequestStore()
    builder = HospitalRequestBuilder(
        protocol_version="1.0",
        membership_epoch=epoch,
        hospital_secret_key=hospital_secret,
        model=model,
        server_kem_public_key=server_keys.public_key,
        lrs=lrs,
        pending_store=pending,
        settings=Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"),
        kem=kem,
        kdf=HKDFSHA256Adapter(salt=b"step-5-test-salt"),
        aead=AES256GCMAdapter(),
    )
    return builder, pending, lrs, kem, server_keys, epoch, model


def test_build_request_round_trip_encrypts_and_authenticates_synthetic_features(
    request_context,
) -> None:
    builder, pending, lrs, kem, server_keys, epoch, model = request_context
    features = SyntheticFeatures(42, 120, 80, 24.5)

    request = builder.build_request(features)

    assert lrs.verify(
        epoch.members,
        request_authentication_message(request),
        LRSSignature(request.lrs_proof),
        request.epoch,
        REQUEST_AUTH_SCOPE,
    )
    shared_secret = kem.decapsulate(server_keys.private_key, request.kem_ciphertext)
    kdf_context = canonical_bytes(
        {
            "protocol_version": request.protocol_version,
            "purpose": "request-aes-256-gcm",
            "request_id": request.request_id,
        }
    )
    key = HKDFSHA256Adapter(salt=b"step-5-test-salt").derive_key(shared_secret, kdf_context)
    aad = request_associated_data(
        protocol_version=request.protocol_version,
        epoch=request.epoch,
        model=request.model,
        request_id=request.request_id,
    )
    plaintext = AES256GCMAdapter().decrypt(key, request.encrypted_features, aad)
    assert plaintext == canonical_bytes(features)
    assert pending.get(request.request_id).aes_key == key
    assert pending.get(request.request_id).response_association == request.response_association
    assert len(request.response_association) == 32
    assert request.created_at.tzinfo is UTC
    assert request.expires_at > request.created_at
    assert shared_secret not in canonical_bytes(request)
    assert key not in canonical_bytes(request)


def test_critical_request_field_changes_invalidate_mock_authentication(request_context) -> None:
    builder, _, lrs, _, _, epoch, _ = request_context
    request = builder.build_request(SyntheticFeatures(42, 120, 80, 24.5))

    def verifies(candidate) -> bool:
        return lrs.verify(
            epoch.members,
            request_authentication_message(candidate),
            LRSSignature(candidate.lrs_proof),
            candidate.epoch,
            REQUEST_AUTH_SCOPE,
        )

    assert verifies(request)
    changed = replace(request, protocol_version="2.0")
    assert not verifies(changed)
    changed = replace(request, epoch=request.epoch + 1)
    assert not verifies(changed)
    changed = replace(request, request_id="00000000-0000-4000-8000-000000000001")
    assert not verifies(changed)
    changed_kem_ciphertext = bytes([request.kem_ciphertext[0] ^ 1]) + request.kem_ciphertext[1:]
    changed = replace(request, kem_ciphertext=changed_kem_ciphertext)
    assert not verifies(changed)
    changed = replace(request, response_association=b"X" * 32)
    assert not verifies(changed)
    changed = replace(request, model=replace(request.model, model_version="2.0"))
    assert not verifies(changed)
    changed = replace(request, model=replace(request.model, model_hash="c" * 64))
    assert not verifies(changed)
    changed = replace(request, created_at=request.created_at + timedelta(seconds=1))
    assert not verifies(changed)
    changed = replace(request, expires_at=request.expires_at + timedelta(seconds=1))
    assert not verifies(changed)
    changed_payload = EncryptedPayload(
        nonce=bytes([request.encrypted_features.nonce[0] ^ 1])
        + request.encrypted_features.nonce[1:],
        ciphertext=request.encrypted_features.ciphertext,
    )
    changed = replace(request, encrypted_features=changed_payload)
    assert not verifies(changed)


def test_each_request_gets_fresh_ids_keys_ciphertexts_and_nonces(request_context) -> None:
    builder, pending, _, _, _, _, _ = request_context
    features = SyntheticFeatures(42, 120, 80, 24.5)

    first = builder.build_request(features)
    second = builder.build_request(features)

    first_pending = pending.get(first.request_id)
    second_pending = pending.get(second.request_id)
    assert first.request_id != second.request_id
    assert first.kem_ciphertext != second.kem_ciphertext
    assert first.encrypted_features.nonce != second.encrypted_features.nonce
    assert first_pending.aes_key != second_pending.aes_key
    assert first.response_association != second.response_association
    assert first_pending.aes_key not in canonical_bytes(first)


def test_pending_request_removal_consumes_local_key_material(request_context) -> None:
    builder, pending, *_ = request_context
    request = builder.build_request(SyntheticFeatures(42, 120, 80, 24.5))

    saved = pending.remove(request.request_id)

    assert saved is not None
    assert saved.request_id == request.request_id
    assert pending.get(request.request_id) is None
    assert pending.remove(request.request_id) is None


def test_builder_rejects_wrong_features_and_empty_epoch(request_context) -> None:
    builder, _, lrs, kem, server_keys, _, model = request_context
    with pytest.raises(SchemaValidationError, match="SyntheticFeatures"):
        builder.build_request({"age_years": 40})

    empty_epoch = MembershipEpoch(
        epoch=8,
        issued_at=datetime.now(UTC),
        members=(),
        registry_digest="c" * 64,
    )
    with pytest.raises(SchemaValidationError, match="at least one member"):
        HospitalRequestBuilder(
            protocol_version="1.0",
            membership_epoch=empty_epoch,
            hospital_secret_key=b"secret",
            model=model,
            server_kem_public_key=server_keys.public_key,
            lrs=lrs,
            pending_store=InMemoryPendingRequestStore(),
            settings=Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"),
            kem=kem,
        )


def test_builder_rejects_insecure_mock_without_test_mode(request_context) -> None:
    _, _, lrs, kem, server_keys, epoch, model = request_context
    _, hospital_secret = lrs.generate_keypair()
    with pytest.raises(SchemaValidationError, match="requires test environment"):
        HospitalRequestBuilder(
            protocol_version="1.0",
            membership_epoch=epoch,
            hospital_secret_key=hospital_secret,
            model=model,
            server_kem_public_key=server_keys.public_key,
            lrs=lrs,
            pending_store=InMemoryPendingRequestStore(),
            kem=kem,
        )
