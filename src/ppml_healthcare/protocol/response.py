"""Response generation and hospital verification interfaces; implementations belong to Step 8."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import RequestEnvelope, ResponseEnvelope


class ResponseProcessor(Protocol):
    def create_response(self, request: RequestEnvelope, prediction: object) -> ResponseEnvelope: ...

    def verify_response(self, response: ResponseEnvelope, pending_request_id: str) -> bool: ...
