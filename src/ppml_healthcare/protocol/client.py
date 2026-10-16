"""Hospital client workflow interface; request construction belongs to Step 5."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import RequestEnvelope, ResponseEnvelope, SyntheticFeatures


class HospitalClient(Protocol):
    def build_request(self, features: SyntheticFeatures) -> RequestEnvelope: ...

    def accept_response(self, response: ResponseEnvelope) -> object: ...
