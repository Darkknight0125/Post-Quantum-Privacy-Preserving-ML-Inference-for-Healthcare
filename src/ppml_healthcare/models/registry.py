"""Thread-safe in-memory model registry with artifact hash verification."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ppml_healthcare.errors import (
    ModelArtifactMismatchError,
    RegistryConflictError,
    RegistryError,
    SchemaValidationError,
)
from ppml_healthcare.schemas import ModelDescriptor


class ModelRegistry(Protocol):
    def get_model(self, model_id: str, model_version: str) -> ModelDescriptor | None: ...

    def register_model(self, descriptor: ModelDescriptor, artifact_path: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _RegisteredModel:
    descriptor: ModelDescriptor
    artifact_path: Path


def compute_artifact_sha256(artifact_path: str | Path) -> str:
    """Return SHA-256 of the exact artifact bytes, streaming in bounded chunks."""
    path = Path(artifact_path)
    try:
        if not path.is_file():
            raise RegistryError("model artifact path must name a regular file")
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise RegistryError("unable to read model artifact") from exc


class InMemoryModelRegistry:
    """Process-local registry; each model ID/version is immutable once added."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._models: dict[tuple[str, str], _RegisteredModel] = {}

    def get_model(self, model_id: str, model_version: str) -> ModelDescriptor | None:
        with self._lock:
            entry = self._models.get((model_id, model_version))
            return None if entry is None else entry.descriptor

    def register_model(self, descriptor: ModelDescriptor, artifact_path: str) -> None:
        if not isinstance(descriptor, ModelDescriptor):
            raise SchemaValidationError("descriptor must be a ModelDescriptor")
        if not isinstance(artifact_path, str) or not artifact_path:
            raise SchemaValidationError("artifact_path must be a non-empty path string")
        path = Path(artifact_path)
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise RegistryError("model artifact path does not exist") from exc
        if not resolved_path.is_file():
            raise RegistryError("model artifact path must name a regular file")

        actual_hash = compute_artifact_sha256(resolved_path)
        if actual_hash != descriptor.model_hash:
            raise ModelArtifactMismatchError("model artifact hash does not match descriptor")

        key = (descriptor.model_id, descriptor.model_version)
        candidate = _RegisteredModel(descriptor, resolved_path)
        with self._lock:
            existing = self._models.get(key)
            if existing is not None:
                if existing == candidate:
                    return
                raise RegistryConflictError("model ID/version is already registered")
            self._models[key] = candidate

    def get_artifact_path(self, model_id: str, model_version: str) -> Path | None:
        with self._lock:
            entry = self._models.get((model_id, model_version))
            return None if entry is None else entry.artifact_path

    def verify_artifact(self, model_id: str, model_version: str) -> bool:
        """Check current file bytes against the immutable registered digest."""
        with self._lock:
            entry = self._models.get((model_id, model_version))
        if entry is None:
            return False
        try:
            current_hash = compute_artifact_sha256(entry.artifact_path)
        except RegistryError:
            return False
        return current_hash == entry.descriptor.model_hash
