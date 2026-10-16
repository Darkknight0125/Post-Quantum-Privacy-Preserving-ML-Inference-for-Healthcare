"""Replaceable inference interface; toy model implementation belongs to Step 7."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import ScalarFeature, SyntheticFeatures


class InferenceAdapter(Protocol):
    def predict(self, model: ModelDescriptorLike, features: SyntheticFeatures) -> ScalarFeature: ...


class ModelDescriptorLike(Protocol):
    model_id: str
    model_version: str
    model_hash: str
