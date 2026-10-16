"""Model registry implementation and replaceable inference adapter."""

from ppml_healthcare.models.registry import InMemoryModelRegistry, compute_artifact_sha256

__all__ = ["InMemoryModelRegistry", "compute_artifact_sha256"]
