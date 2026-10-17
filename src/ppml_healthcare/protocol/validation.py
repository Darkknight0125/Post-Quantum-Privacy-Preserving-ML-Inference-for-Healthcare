"""Ordered pre-decryption request validation pipeline (Step 6)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.lrs import LRSAdapter, LRSSignature
from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.membership.epochs import EpochPolicy, LatestEpochOnlyPolicy
from ppml_healthcare.membership.registry import MembershipRegistry
from ppml_healthcare.models.registry import ModelRegistry
from ppml_healthcare.protocol.client import REQUEST_AUTH_SCOPE, request_authentication_message
from ppml_healthcare.protocol.rate_limit import AnonymousRateLimiter
from ppml_healthcare.protocol.replay import ReplayStore
from ppml_healthcare.schemas import RequestEnvelope
from ppml_healthcare.serialization import canonical_bytes


class RequestValidator(Protocol):
    def validate_before_decryption(self, request: RequestEnvelope) -> None: ...


class ValidationObserver(Protocol):
    """Test instrumentation receives only the stage name and request ID."""

    def on_stage_complete(self, stage: str, request_id: str) -> None: ...


class OrderedRequestValidator:
    """Validate format, authorization metadata, replay, proof, and rate limit.

    No KEM decapsulation, decryption, inference, or sensitive-value logging is
    performed here. In-memory replay and limit stores are single-process only.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        membership: MembershipRegistry,
        models: ModelRegistry,
        lrs: LRSAdapter,
        replay_store: ReplayStore,
        rate_limiter: AnonymousRateLimiter,
        request_limit: int = 60,
        request_age: timedelta = timedelta(minutes=5),
        allowed_clock_skew: timedelta = timedelta(seconds=30),
        epoch_policy: EpochPolicy | None = None,
        observer: ValidationObserver | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            isinstance(request_limit, bool)
            or not isinstance(request_limit, int)
            or request_limit <= 0
        ):
            raise ValueError("request_limit must be a positive integer")
        if request_age <= timedelta(0) or allowed_clock_skew < timedelta(0):
            raise ValueError("request_age must be positive and clock skew non-negative")
        self._settings = settings
        self._membership = membership
        self._models = models
        self._lrs = lrs
        self._replay = replay_store
        self._rate_limiter = rate_limiter
        self._request_limit = request_limit
        self._request_age = request_age
        self._clock_skew = allowed_clock_skew
        self._epoch_policy = epoch_policy or LatestEpochOnlyPolicy()
        self._observer = observer
        self._now = now or (lambda: datetime.now(UTC))

    def validate_before_decryption(self, request: RequestEnvelope) -> None:
        self._basic_format(request)
        self._stage("basic_format", request)

        try:
            current_epoch = self._membership.current_epoch()
        except Exception as exc:
            raise ProtocolRejectedError("membership epoch could not be loaded") from exc
        if (
            not self._epoch_policy.accepts(request.epoch, current_epoch)
            or request.epoch != current_epoch.epoch
        ):
            raise ProtocolRejectedError("request references an unacceptable membership epoch")
        # The approved policy accepts only the immutable current snapshot.
        # Using this same snapshot avoids a get_epoch/current_epoch race with
        # concurrent membership changes.
        accepted_epoch = current_epoch
        self._stage("epoch", request)

        try:
            registered_model = self._models.get_model(
                request.model.model_id, request.model.model_version
            )
        except Exception as exc:
            raise ProtocolRejectedError("model registry lookup failed") from exc
        if registered_model != request.model:
            raise ProtocolRejectedError("request model descriptor is not registered")
        self._stage("model", request)

        self._check_freshness(request)
        self._stage("freshness", request)

        # Per the documented validation order, claim the request ID before
        # expensive proof checks. Even a later rejected proof consumes its ID.
        try:
            claimed = self._replay.claim(request.request_id)
        except Exception as exc:
            raise ProtocolRejectedError("replay store operation failed") from exc
        if not claimed:
            raise ProtocolRejectedError("request ID has already been claimed")
        self._stage("replay", request)

        signature = LRSSignature(
            proof=request.lrs_proof,
            response_association=request.response_association,
            link_tag=request.link_tag,
            epoch=request.epoch,
            ring_digest=(
                self._lrs.ring_digest(accepted_epoch.members, request.epoch)
                if callable(getattr(self._lrs, "ring_digest", None))
                else None
            ),
            scope=REQUEST_AUTH_SCOPE,
        )
        try:
            authenticated = self._lrs.verify(
                accepted_epoch.members,
                request_authentication_message(
                    request,
                    ring_digest=(
                        signature.ring_digest if signature.ring_digest is not None else None
                    ),
                ),
                signature,
                request.epoch,
                REQUEST_AUTH_SCOPE,
            )
        except Exception as exc:
            raise ProtocolRejectedError("LRS verification failed") from exc
        if not authenticated:
            raise ProtocolRejectedError("request authentication failed")
        self._stage("lrs_verification", request)

        try:
            rate_accepted = self._rate_limiter.accept(
                signature, REQUEST_AUTH_SCOPE, self._request_limit
            )
        except Exception as exc:
            raise ProtocolRejectedError("linkability rate-limit check failed") from exc
        if not rate_accepted:
            raise ProtocolRejectedError("anonymous request limit exceeded")
        self._stage("rate_limit", request)

    def _basic_format(self, request: RequestEnvelope) -> None:
        if not isinstance(request, RequestEnvelope):
            raise ProtocolRejectedError("request has an invalid envelope type")
        if request.protocol_version != self._settings.protocol_version:
            raise ProtocolRejectedError("unsupported protocol version")
        if not request.lrs_proof:
            raise ProtocolRejectedError("request authentication proof is missing")
        if not isinstance(request.link_tag, bytes) or len(request.link_tag) != 32:
            raise ProtocolRejectedError("anonymous request link tag is missing or malformed")
        if request.response_association is None or not request.response_association:
            raise ProtocolRejectedError("request correlation material is missing")
        if len(request.kem_ciphertext) == 0:
            raise ProtocolRejectedError("KEM ciphertext is missing")
        if len(request.encrypted_features.ciphertext) < 16:
            raise ProtocolRejectedError("encrypted feature payload is too short")
        try:
            encoded = canonical_bytes(request)
        except Exception as exc:
            raise ProtocolRejectedError("request cannot be canonically encoded") from exc
        if len(encoded) > self._settings.max_request_bytes:
            raise ProtocolRejectedError("request exceeds configured size limit")

    def _check_freshness(self, request: RequestEnvelope) -> None:
        now = self._now()
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ValueError("validator clock must return timezone-aware UTC")
        if request.created_at > now + self._clock_skew:
            raise ProtocolRejectedError("request creation time is in the future")
        if now - request.created_at > self._request_age + self._clock_skew:
            raise ProtocolRejectedError("request has expired by age")
        if request.expires_at is not None:
            if request.expires_at <= now:
                raise ProtocolRejectedError("request has expired")
            if request.expires_at <= request.created_at:
                raise ProtocolRejectedError("request expiry is not after creation")
            if request.expires_at - request.created_at > self._request_age:
                raise ProtocolRejectedError("request validity window exceeds policy")

    def _stage(self, stage: str, request: RequestEnvelope) -> None:
        if self._observer is not None:
            self._observer.on_stage_complete(stage, request.request_id)
