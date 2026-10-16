"""Ordered server-validation contract; pipeline implementation belongs to Step 6."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import RequestEnvelope


class RequestValidator(Protocol):
    def validate_before_decryption(self, request: RequestEnvelope) -> None: ...
