from __future__ import annotations

import math
import unittest
from datetime import UTC, datetime, timedelta

from ppml_healthcare.errors import SchemaValidationError
from ppml_healthcare.schemas import (
    EncryptedPayload,
    ModelDescriptor,
    RequestEnvelope,
    ResponseEnvelope,
    SyntheticFeatures,
)
from ppml_healthcare.serialization import canonical_bytes


def valid_model() -> ModelDescriptor:
    return ModelDescriptor("toy-risk-v1", "1.0.0", "a" * 64)


class SyntheticFeaturesTests(unittest.TestCase):
    def test_accepts_synthetic_feature_vector(self) -> None:
        features = SyntheticFeatures(42.0, 120.0, 80.0, 24.5)
        self.assertEqual(features.age_years, 42.0)

    def test_rejects_non_finite_and_out_of_range_values(self) -> None:
        with self.assertRaises(SchemaValidationError):
            SyntheticFeatures(math.nan, 120.0, 80.0, 24.5)
        with self.assertRaises(SchemaValidationError):
            SyntheticFeatures(121.0, 120.0, 80.0, 24.5)

    def test_rejects_boolean_as_numeric_feature(self) -> None:
        with self.assertRaises(SchemaValidationError):
            SyntheticFeatures(True, 120.0, 80.0, 24.5)  # type: ignore[arg-type]


class EnvelopeTests(unittest.TestCase):
    def test_valid_request_constructs_and_serializes_deterministically(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        request = RequestEnvelope(
            protocol_version="1.0",
            epoch=3,
            model=valid_model(),
            request_id="12345678-1234-5678-1234-567812345678",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
            kem_ciphertext=b"kem-ciphertext",
            encrypted_features=EncryptedPayload(b"n" * 12, b"ciphertext"),
            lrs_proof=b"opaque-proof",
        )
        encoded = canonical_bytes(request)
        self.assertEqual(encoded, canonical_bytes(request))
        self.assertIn(b'"request_id"', encoded)
        self.assertNotIn(b"shared_secret", encoded)

    def test_rejects_bad_request_id_expiry_and_nonce(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        with self.assertRaises(SchemaValidationError):
            EncryptedPayload(b"short", b"ciphertext")
        with self.assertRaises(SchemaValidationError):
            RequestEnvelope(
                "1.0",
                1,
                valid_model(),
                "not-a-uuid",
                now,
                None,
                b"kem",
                EncryptedPayload(b"n" * 12, b"ciphertext"),
                b"proof",
            )
        with self.assertRaises(SchemaValidationError):
            RequestEnvelope(
                "1.0",
                1,
                valid_model(),
                "12345678-1234-5678-1234-567812345678",
                now,
                now,
                b"kem",
                EncryptedPayload(b"n" * 12, b"ciphertext"),
                b"proof",
            )

    def test_link_tag_is_optional_for_mock_but_fixed_length_when_present(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        request = RequestEnvelope(
            protocol_version="1.0",
            epoch=3,
            model=valid_model(),
            request_id="12345678-1234-5678-1234-567812345678",
            created_at=now,
            expires_at=None,
            kem_ciphertext=b"kem-ciphertext",
            encrypted_features=EncryptedPayload(b"n" * 12, b"ciphertext"),
            lrs_proof=b"opaque-proof",
            link_tag=b"T" * 32,
        )
        self.assertEqual(request.link_tag, b"T" * 32)
        with self.assertRaises(SchemaValidationError):
            RequestEnvelope(
                protocol_version="1.0",
                epoch=3,
                model=valid_model(),
                request_id="12345678-1234-5678-1234-567812345678",
                created_at=now,
                expires_at=None,
                kem_ciphertext=b"kem-ciphertext",
                encrypted_features=EncryptedPayload(b"n" * 12, b"ciphertext"),
                lrs_proof=b"opaque-proof",
                link_tag=b"short",
            )

    def test_response_schema_validates_critical_fields(self) -> None:
        response = ResponseEnvelope(
            "1.0",
            "12345678-1234-5678-1234-567812345678",
            valid_model(),
            "prediction",
            EncryptedPayload(b"r" * 12, b"encrypted"),
            b"association",
            b"signature",
        )
        self.assertIn(b"server_signature", canonical_bytes(response))
        with self.assertRaises(SchemaValidationError):
            ModelDescriptor("bad model id", "1.0", "a" * 64)


if __name__ == "__main__":
    unittest.main()
