"""Validated process configuration (no secrets are loaded in Step 1)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ppml_healthcare.errors import SchemaValidationError


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str = "development"
    crypto_mode: str = "SECURE"
    protocol_version: str = "1.0"
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 1_048_576
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test"}:
            raise SchemaValidationError("environment must be development or test")
        if self.crypto_mode not in {"SECURE", "INSECURE_TEST_MOCK"}:
            raise SchemaValidationError("crypto_mode must be SECURE or INSECURE_TEST_MOCK")
        if self.crypto_mode == "INSECURE_TEST_MOCK" and self.environment != "test":
            raise SchemaValidationError("INSECURE_TEST_MOCK is allowed only in test environment")
        if not self.protocol_version or len(self.protocol_version) > 32:
            raise SchemaValidationError("protocol_version must contain 1..32 characters")
        for field_name in ("max_request_bytes", "max_response_bytes"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise SchemaValidationError(f"{field_name} must be a positive integer")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise SchemaValidationError("unsupported log_level")


def load_settings(environ: dict[str, str] | None = None) -> Settings:
    """Load non-secret settings from environment variables."""
    env = os.environ if environ is None else environ
    try:
        return Settings(
            environment=env.get("PPML_ENV", "development"),
            crypto_mode=env.get("PPML_CRYPTO_MODE", "SECURE").upper(),
            protocol_version=env.get("PPML_PROTOCOL_VERSION", "1.0"),
            max_request_bytes=int(env.get("PPML_MAX_REQUEST_BYTES", "1048576")),
            max_response_bytes=int(env.get("PPML_MAX_RESPONSE_BYTES", "1048576")),
            log_level=env.get("PPML_LOG_LEVEL", "INFO").upper(),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, SchemaValidationError):
            raise
        raise SchemaValidationError("invalid environment configuration") from exc
