"""Factory for the single MAYO scoped zero-knowledge LRS adapter."""

from __future__ import annotations

from ppml_healthcare.crypto.mayo_zk_lrs import MayoScopedZKLRSAdapter
from ppml_healthcare.errors import AdapterNotImplementedError


def create_lrs_adapter() -> MayoScopedZKLRSAdapter:
    """Create the real adapter, failing closed when its native backend is absent."""
    try:
        return MayoScopedZKLRSAdapter()
    except FileNotFoundError as exc:
        raise AdapterNotImplementedError(
            "MAYO LRS backend is unavailable: build native/msz_lrs before secure operation"
        ) from exc
