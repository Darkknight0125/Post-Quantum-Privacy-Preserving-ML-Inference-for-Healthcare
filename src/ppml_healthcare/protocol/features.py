"""Strict post-decryption parsing for synthetic demo features."""

from __future__ import annotations

import json
from typing import Protocol

from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.schemas import SyntheticFeatures
from ppml_healthcare.serialization import canonical_bytes


class FeatureValidator(Protocol):
    def validate(self, plaintext: bytes) -> SyntheticFeatures: ...


class CanonicalSyntheticFeatureValidator:
    """Parse the exact four-field feature schema; never accept extra fields."""

    _FIELDS = frozenset({"age_years", "systolic_bp", "diastolic_bp", "bmi"})

    def validate(self, plaintext: bytes) -> SyntheticFeatures:
        if not isinstance(plaintext, bytes):
            raise ProtocolRejectedError("decrypted feature payload must be bytes")

        try:
            decoded = plaintext.decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=self._unique_object,
                parse_constant=self._reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise ProtocolRejectedError("decrypted feature payload is not valid JSON") from exc

        if not isinstance(value, dict) or set(value) != self._FIELDS:
            raise ProtocolRejectedError("decrypted features do not match the expected schema")
        try:
            features = SyntheticFeatures(
                age_years=value["age_years"],
                systolic_bp=value["systolic_bp"],
                diastolic_bp=value["diastolic_bp"],
                bmi=value["bmi"],
            )
            if canonical_bytes(features) != plaintext:
                raise ValueError("feature JSON is not canonical")
            return features
        except (TypeError, ValueError) as exc:
            raise ProtocolRejectedError("decrypted features failed schema validation") from exc

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")
