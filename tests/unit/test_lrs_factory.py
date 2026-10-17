import pytest

from ppml_healthcare.crypto import factory
from ppml_healthcare.crypto.mayo_zk_lrs import MayoScopedZKLRSAdapter
from ppml_healthcare.errors import AdapterNotImplementedError


def test_factory_returns_only_the_mayo_adapter(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setattr(factory, "MayoScopedZKLRSAdapter", lambda: sentinel)
    assert factory.create_lrs_adapter() is sentinel


def test_factory_fails_closed_when_native_backend_is_missing(monkeypatch) -> None:
    def missing_backend():
        raise FileNotFoundError("native binary not present")

    monkeypatch.setattr(factory, "MayoScopedZKLRSAdapter", missing_backend)
    with pytest.raises(AdapterNotImplementedError, match="MAYO LRS backend is unavailable"):
        factory.create_lrs_adapter()


def test_adapter_type_is_mayo_scoped_zk_lrs() -> None:
    assert MayoScopedZKLRSAdapter.__name__ == "MayoScopedZKLRSAdapter"
