import base64

from ppml_healthcare.crypto.lrs import LRSSignature
from ppml_healthcare.crypto.mayo_zk_lrs import MayoScopedZKLRSAdapter


def test_native_adapter_serializes_opaque_credentials_and_proof(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "backend.exe"
    binary.write_bytes(b"stub")
    adapter = MayoScopedZKLRSAdapter(binary)
    calls = []
    row = b"MSZMEM01" + len(b"pk").to_bytes(4, "big") + b"pk" + b"C" * 32

    def call(payload):
        calls.append(payload)
        if payload["op"] == "keygen":
            return {
                "public_key": base64.b64encode(row).decode(),
                "secret_key": base64.b64encode(b"credential").decode(),
            }
        return {
            "proof": base64.b64encode(b"receipt").decode(),
            "link_tag": base64.b64encode(b"T" * 32).decode(),
            "valid": payload.get("message") == base64.b64encode(b"request").decode(),
        }

    monkeypatch.setattr(adapter, "_call", call)
    public, secret = adapter.generate_keypair()
    other = b"MSZMEM01" + len(b"qk").to_bytes(4, "big") + b"qk" + b"D" * 32
    ring = (public, other)
    signature = adapter.sign(secret, ring, b"request", 7, b"request-scope")

    assert public == row
    assert secret == b"credential"
    assert signature.proof == b"receipt"
    assert signature.link_tag == b"T" * 32
    assert calls[1]["credential"] == base64.b64encode(secret).decode()
    assert adapter.verify(ring, b"request", signature, 7, b"request-scope")
    assert not adapter.verify(ring, b"tampered", signature, 7, b"request-scope")


def test_native_link_uses_epoch_scoped_tag_in_constant_time() -> None:
    left = LRSSignature(b"proof-a", link_tag=b"A" * 32, epoch=3, scope=b"request")
    same = LRSSignature(b"proof-b", link_tag=b"A" * 32, epoch=3, scope=b"request")
    other_member = LRSSignature(b"proof-c", link_tag=b"B" * 32, epoch=3, scope=b"request")
    other_epoch = LRSSignature(b"proof-d", link_tag=b"A" * 32, epoch=4, scope=b"request")
    adapter = MayoScopedZKLRSAdapter.__new__(MayoScopedZKLRSAdapter)

    assert adapter.link(left, same)
    assert not adapter.link(left, other_member)
    assert not adapter.link(left, other_epoch)


def test_ring_digest_uses_the_native_canonical_encoding() -> None:
    first = b"MSZMEM01" + (2).to_bytes(4, "big") + b"\x01\x02" + b"\x03" * 32
    second = b"MSZMEM01" + (1).to_bytes(4, "big") + b"\x04" + b"\x05" * 32
    assert MayoScopedZKLRSAdapter.ring_digest((first, second), 7).hex() == (
        "0f7ff6d9ea86c1540449788529796a4b64730ee327c145b04754779b11ba43e8"
    )
