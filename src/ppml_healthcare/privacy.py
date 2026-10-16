"""Input de-identification contract; this is not an anonymity guarantee."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import SyntheticFeatures


class FeatureDeidentifier(Protocol):
    def transform(self, source_record: object) -> SyntheticFeatures: ...
