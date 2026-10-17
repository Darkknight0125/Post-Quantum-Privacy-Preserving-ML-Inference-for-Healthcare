"""Replaceable inference interface and deterministic synthetic-data toy model."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.errors import ProtocolRejectedError
from ppml_healthcare.schemas import ModelDescriptor, ScalarFeature, SyntheticFeatures


class InferenceAdapter(Protocol):
    def predict(self, model: ModelDescriptor, features: SyntheticFeatures) -> ScalarFeature: ...


class DeterministicToyModel:
    """Non-clinical deterministic score for the registered ``toy-risk`` demo."""

    MODEL_ID = "toy-risk"

    def predict(self, model: ModelDescriptor, features: SyntheticFeatures) -> float:
        if model.model_id != self.MODEL_ID:
            raise ProtocolRejectedError("toy inference adapter only supports the toy-risk model")
        if not isinstance(features, SyntheticFeatures):
            raise ProtocolRejectedError("toy model requires validated synthetic features")
        # A weighted normalized sum in [0, 1]; it has no clinical meaning.
        score = (
            (float(features.age_years) / 120.0) * 0.25
            + (float(features.systolic_bp) / 300.0) * 0.35
            + (float(features.diastolic_bp) / 200.0) * 0.15
            + (float(features.bmi) / 100.0) * 0.25
        )
        return round(score, 6)
