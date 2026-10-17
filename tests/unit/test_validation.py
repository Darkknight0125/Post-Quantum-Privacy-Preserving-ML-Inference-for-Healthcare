from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.membership.registry import InMemoryMembershipRegistry
from ppml_healthcare.models.registry import InMemoryModelRegistry
from ppml_healthcare.protocol.client import (
    REQUEST_AUTH_SCOPE,
    HospitalRequestBuilder,
    InMemoryPendingRequestStore,
)
from ppml_healthcare.protocol.rate_limit import InMemoryLinkabilityRateLimiter
from ppml_healthcare.protocol.replay import InMemoryReplayStore
from ppml_healthcare.protocol.validation import OrderedRequestValidator
from ppml_healthcare.schemas import ModelDescriptor, SyntheticFeatures
from tests.support.test_lrs_support import LRSProtocolStub


class _Observer:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def on_stage_complete(self, stage: str, request_id: str) -> None:
        self.events.append((stage, request_id))


@pytest.fixture
def context(tmp_path):
    settings = Settings(environment="test")
    lrs = LRSProtocolStub()
    hospital_public, hospital_secret = lrs.generate_keypair()
    membership = InMemoryMembershipRegistry((hospital_public,))
    epoch = membership.current_epoch()

    model_path = tmp_path / "toy-model.bin"
    artifact = b"synthetic-test-model-artifact"
    model_path.write_bytes(artifact)
    model = ModelDescriptor("toy-risk", "1.0", hashlib.sha256(artifact).hexdigest())
    models = InMemoryModelRegistry()
    models.register_model(model, str(model_path))

    kem = CryptographyMLKEMAdapter()
    server_kem = kem.generate_keypair()
    builder = HospitalRequestBuilder(
        protocol_version=settings.protocol_version,
        membership_epoch=epoch,
        hospital_secret_key=hospital_secret,
        model=model,
        server_kem_public_key=server_kem.public_key,
        lrs=lrs,
        pending_store=InMemoryPendingRequestStore(),
        settings=settings,
        kem=kem,
    )
    return {
        "settings": settings,
        "lrs": lrs,
        "membership": membership,
        "models": models,
        "model": model,
        "epoch": epoch,
        "builder": builder,
        "hospital_secret": hospital_secret,
    }


def _validator(context, *, limit: int = 60, **kwargs):
    lrs = context["lrs"]
    return OrderedRequestValidator(
        settings=context["settings"],
        membership=context["membership"],
        models=context["models"],
        lrs=lrs,
        replay_store=kwargs.pop("replay_store", InMemoryReplayStore()),
        rate_limiter=kwargs.pop(
            "rate_limiter",
            InMemoryLinkabilityRateLimiter(lrs),
        ),
        request_limit=limit,
        **kwargs,
    )


def _request(context):
    return context["builder"].build_request(SyntheticFeatures(42, 120, 80, 24.5))


def test_validation_completes_in_documented_order_and_emits_safe_hooks(context) -> None:
    observer = _Observer()
    validator = _validator(context, observer=observer)
    request = _request(context)

    validator.validate_before_decryption(request)

    assert [stage for stage, _ in observer.events] == [
        "basic_format",
        "epoch",
        "model",
        "freshness",
        "replay",
        "lrs_verification",
        "rate_limit",
    ]
    assert {request_id for _, request_id in observer.events} == {request.request_id}


def test_format_epoch_model_and_freshness_fail_before_replay_or_lrs(context) -> None:
    request = _request(context)
    observer = _Observer()
    validator = _validator(context, observer=observer)
    with pytest.raises(ProtocolRejectedError, match="unsupported protocol"):
        validator.validate_before_decryption(replace(request, protocol_version="unsupported"))
    assert observer.events == []

    # Publishing a membership change makes the signed request's old epoch stale.
    extra_public, _ = context["lrs"].generate_keypair()
    context["membership"].add_hospital(extra_public)
    with pytest.raises(ProtocolRejectedError, match="membership epoch"):
        validator.validate_before_decryption(request)
    assert [stage for stage, _ in observer.events] == ["basic_format"]


def test_request_size_limit(context) -> None:
    request = _request(context)
    small_settings = Settings(
        environment="test",
        protocol_version="1.0",
        max_request_bytes=64,
    )
    with pytest.raises(ProtocolRejectedError, match="size limit"):
        OrderedRequestValidator(
            settings=small_settings,
            membership=context["membership"],
            models=context["models"],
            lrs=context["lrs"],
            replay_store=InMemoryReplayStore(),
            rate_limiter=InMemoryLinkabilityRateLimiter(context["lrs"]),
        ).validate_before_decryption(request)


def test_unregistered_model_is_rejected_before_request_id_claim(context) -> None:
    request = _request(context)
    validator = _validator(context)
    forged_model_request = replace(request, model=replace(request.model, model_version="9.9"))

    with pytest.raises(ProtocolRejectedError, match="model descriptor"):
        validator.validate_before_decryption(forged_model_request)
    # The valid request using that ID can still be processed, proving the
    # validator rejected it before replay state was claimed.
    validator.validate_before_decryption(request)


def test_expired_and_future_requests_are_rejected(context) -> None:
    request = _request(context)
    future_now = request.expires_at + timedelta(seconds=1)
    validator = _validator(context, now=lambda: future_now)
    with pytest.raises(ProtocolRejectedError, match="expired"):
        validator.validate_before_decryption(request)

    future_request = replace(
        _request(context),
        created_at=datetime.now(UTC) + timedelta(minutes=1),
        expires_at=datetime.now(UTC) + timedelta(minutes=6),
    )
    with pytest.raises(ProtocolRejectedError, match="future"):
        _validator(context).validate_before_decryption(future_request)


def test_bad_lrs_proof_is_rejected_before_rate_limiter(context) -> None:
    request = _request(context)
    validator = _validator(context, limit=1)
    changed_proof = replace(request, lrs_proof=b"not-a-proof")
    with pytest.raises(ProtocolRejectedError, match="authentication"):
        validator.validate_before_decryption(changed_proof)

    # Invalid proof did not consume the signer's rate-limit allowance.
    second = _request(context)
    validator.validate_before_decryption(second)


def test_duplicate_request_is_rejected_and_claim_is_atomic(context) -> None:
    request = _request(context)
    validator = _validator(context)

    def validate() -> bool:
        try:
            validator.validate_before_decryption(request)
            return True
        except ProtocolRejectedError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: validate(), range(16)))
    assert sum(results) == 1


def test_linkability_rate_limit_counts_same_signer_and_resets_after_window(context) -> None:
    now = [100.0]
    limiter = InMemoryLinkabilityRateLimiter(
        context["lrs"], window_seconds=10, clock=lambda: now[0]
    )
    first = _request(context)
    second = _request(context)

    from ppml_healthcare.crypto.lrs import LRSSignature

    assert limiter.accept(LRSSignature(first.lrs_proof), REQUEST_AUTH_SCOPE, 1)
    assert not limiter.accept(LRSSignature(second.lrs_proof), REQUEST_AUTH_SCOPE, 1)
    now[0] += 10.1
    assert limiter.accept(LRSSignature(second.lrs_proof), REQUEST_AUTH_SCOPE, 1)


def test_replay_store_claims_concurrently_and_expires_old_entries() -> None:
    now = [100.0]
    replay = InMemoryReplayStore(retention_seconds=10, clock=lambda: now[0])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: replay.claim("request-id"), range(16)))
    assert sum(results) == 1
    now[0] = 111.0
    assert replay.claim("request-id")
