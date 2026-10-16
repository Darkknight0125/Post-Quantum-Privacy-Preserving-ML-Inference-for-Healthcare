"""Model registry contract; registration and artifact verification belong to Step 3."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import ModelDescriptor


class ModelRegistry(Protocol):
    def get_model(self, model_id: str, model_version: str) -> ModelDescriptor | None: ...

    def register_model(self, descriptor: ModelDescriptor, artifact_path: str) -> None: ...
