"""Explicit LRS adapter selection with secure mode failing closed."""

from __future__ import annotations

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.lrs import LRSAdapter
from ppml_healthcare.crypto.mock_lrs import InsecureTestMockLRSAdapter
from ppml_healthcare.errors import AdapterNotImplementedError


def create_lrs_adapter(settings: Settings) -> LRSAdapter:
    """Create the configured adapter; no real LRS is currently approved."""
    if settings.crypto_mode == "INSECURE_TEST_MOCK":
        if settings.environment != "test":
            raise ValueError("insecure mock adapter requires test environment")
        return InsecureTestMockLRSAdapter()
    raise AdapterNotImplementedError(
        "no reviewed LRS implementation is available; secure mode cannot create an adapter"
    )
