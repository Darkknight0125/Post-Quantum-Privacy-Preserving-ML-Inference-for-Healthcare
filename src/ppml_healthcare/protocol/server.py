"""Server request handler interface; validation/inference workflow belongs to Steps 6–8."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import RequestEnvelope, ResponseEnvelope


class InferenceServer(Protocol):
    def handle_request(self, request: RequestEnvelope) -> ResponseEnvelope: ...
