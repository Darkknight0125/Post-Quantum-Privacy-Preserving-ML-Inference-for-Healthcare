"""Post-decryption feature validation contract; implementation belongs to Step 7."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import SyntheticFeatures


class FeatureValidator(Protocol):
    def validate(self, plaintext: bytes) -> SyntheticFeatures: ...
