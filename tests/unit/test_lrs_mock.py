import pytest

from ppml_healthcare.config import Settings
from ppml_healthcare.crypto.factory import create_lrs_adapter
from ppml_healthcare.crypto.lrs import LRSSignature
from ppml_healthcare.errors import AdapterNotImplementedError, SchemaValidationError


def test_mock_sign_verify_and_tamper_rejection() -> None:
    adapter = create_lrs_adapter(Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"))
    public_a, secret_a = adapter.generate_keypair()
    public_b, _ = adapter.generate_keypair()
    ring = (public_a, public_b)
    proof = adapter.sign(secret_a, ring, b"request", 3, b"inference")

    assert adapter.verify(ring, b"request", proof, 3, b"inference")
    assert not adapter.verify(ring, b"changed", proof, 3, b"inference")
    assert not adapter.verify(ring, b"request", proof, 4, b"inference")
    assert not adapter.verify(ring, b"request", proof, 3, b"other-scope")
    assert not adapter.verify((public_b,), b"request", proof, 3, b"inference")
    assert adapter.verify(ring, b"request", LRSSignature(b"bad"), 3, b"inference") is False


def test_mock_linkability_is_scoped_to_signer_ring_epoch_and_scope() -> None:
    adapter = create_lrs_adapter(Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"))
    public_a, secret_a = adapter.generate_keypair()
    public_b, secret_b = adapter.generate_keypair()
    ring = (public_a, public_b)
    first = adapter.sign(secret_a, ring, b"first", 3, b"inference")
    second = adapter.sign(secret_a, ring, b"second", 3, b"inference")
    other_signer = adapter.sign(secret_b, ring, b"second", 3, b"inference")
    other_scope = adapter.sign(secret_a, ring, b"second", 3, b"training")
    other_epoch = adapter.sign(secret_a, ring, b"second", 4, b"inference")

    assert adapter.link(first, second)
    assert not adapter.link(first, other_signer)
    assert not adapter.link(first, other_scope)
    assert not adapter.link(first, other_epoch)
    assert not adapter.link(first, LRSSignature(b"invalid"))


def test_mock_rejects_signing_key_outside_ring() -> None:
    adapter = create_lrs_adapter(Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"))
    public, secret = adapter.generate_keypair()
    other_public, _ = adapter.generate_keypair()
    with pytest.raises(ValueError, match="not in ring"):
        adapter.sign(secret, (other_public,), b"request", 0, b"scope")
    with pytest.raises(ValueError, match="duplicate"):
        adapter.sign(secret, (public, public), b"request", 0, b"scope")


def test_factory_fails_closed_outside_explicit_test_mock() -> None:
    with pytest.raises(AdapterNotImplementedError, match="no reviewed LRS"):
        create_lrs_adapter(Settings())
    with pytest.raises(SchemaValidationError, match="only in test"):
        Settings(environment="development", crypto_mode="INSECURE_TEST_MOCK")
    assert create_lrs_adapter(Settings(environment="test", crypto_mode="INSECURE_TEST_MOCK"))
