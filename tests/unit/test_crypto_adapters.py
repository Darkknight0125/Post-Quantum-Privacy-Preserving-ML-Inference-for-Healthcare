from __future__ import annotations

import unittest

from cryptography.exceptions import InvalidTag

from ppml_healthcare.crypto.aead import AES256GCMAdapter
from ppml_healthcare.crypto.kdf import HKDFSHA256Adapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.crypto.server_signatures import CryptographyMLDSAAdapter
from ppml_healthcare.schemas import EncryptedPayload


class KEMAdapterTests(unittest.TestCase):
    def test_encapsulate_decapsulate_round_trip_and_freshness(self) -> None:
        adapter = CryptographyMLKEMAdapter()
        keypair = adapter.generate_keypair()
        first = adapter.encapsulate(keypair.public_key)
        second = adapter.encapsulate(keypair.public_key)

        self.assertEqual(
            first.shared_secret,
            adapter.decapsulate(keypair.private_key, first.ciphertext),
        )
        self.assertEqual(
            second.shared_secret,
            adapter.decapsulate(keypair.private_key, second.ciphertext),
        )
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertNotEqual(first.shared_secret, second.shared_secret)
        self.assertEqual(len(first.shared_secret), 32)

    def test_wrong_private_key_does_not_recover_original_secret(self) -> None:
        adapter = CryptographyMLKEMAdapter()
        sender_key = adapter.generate_keypair()
        other_key = adapter.generate_keypair()
        encapsulation = adapter.encapsulate(sender_key.public_key)

        recovered = adapter.decapsulate(other_key.private_key, encapsulation.ciphertext)
        self.assertNotEqual(encapsulation.shared_secret, recovered)

    def test_rejects_wrong_length_ciphertext(self) -> None:
        adapter = CryptographyMLKEMAdapter()
        keypair = adapter.generate_keypair()
        with self.assertRaises(ValueError):
            adapter.decapsulate(keypair.private_key, b"bad")


class KDFAdapterTests(unittest.TestCase):
    def test_context_separates_derived_keys_and_is_deterministic(self) -> None:
        adapter = HKDFSHA256Adapter(salt=b"unit-test-salt")
        material = b"shared secret test fixture"
        first = adapter.derive_key(material, b"protocol/v1/request/one")
        same = adapter.derive_key(material, b"protocol/v1/request/one")
        other = adapter.derive_key(material, b"protocol/v1/request/two")

        self.assertEqual(len(first), 32)
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)

    def test_rejects_invalid_output_length(self) -> None:
        with self.assertRaises(ValueError):
            HKDFSHA256Adapter().derive_key(b"secret", b"context", length=0)


class AES256GCMAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = AES256GCMAdapter()
        self.key = b"K" * 32
        self.plaintext = b"synthetic features only"
        self.aad = b"request/v1/model/id"

    def test_round_trip_and_random_nonce(self) -> None:
        first = self.adapter.encrypt(self.key, self.plaintext, self.aad)
        second = self.adapter.encrypt(self.key, self.plaintext, self.aad)

        self.assertEqual(self.adapter.decrypt(self.key, first, self.aad), self.plaintext)
        self.assertEqual(len(first.nonce), 12)
        self.assertNotEqual(first.nonce, second.nonce)

    def test_ciphertext_nonce_aad_and_key_tampering_fail_authentication(self) -> None:
        payload = self.adapter.encrypt(self.key, self.plaintext, self.aad)
        tampered_ciphertext = EncryptedPayload(
            payload.nonce, payload.ciphertext[:-1] + bytes([payload.ciphertext[-1] ^ 1])
        )
        tampered_nonce = EncryptedPayload(
            bytes([payload.nonce[0] ^ 1]) + payload.nonce[1:], payload.ciphertext
        )

        with self.assertRaises(InvalidTag):
            self.adapter.decrypt(self.key, tampered_ciphertext, self.aad)
        with self.assertRaises(InvalidTag):
            self.adapter.decrypt(self.key, tampered_nonce, self.aad)
        with self.assertRaises(InvalidTag):
            self.adapter.decrypt(self.key, payload, self.aad + b"!")
        with self.assertRaises(InvalidTag):
            self.adapter.decrypt(b"W" * 32, payload, self.aad)

    def test_rejects_non_256_bit_key(self) -> None:
        with self.assertRaises(ValueError):
            self.adapter.encrypt(b"short", self.plaintext, self.aad)


class MLDSAAdapterTests(unittest.TestCase):
    def test_keygen_sign_verify_and_tamper_rejection(self) -> None:
        adapter = CryptographyMLDSAAdapter()
        keypair = adapter.generate_keypair()
        message = b"canonical response test bytes"
        signature = adapter.sign(keypair.private_key, message)

        self.assertTrue(adapter.verify(keypair.public_key, message, signature))
        self.assertFalse(adapter.verify(keypair.public_key, message + b"!", signature))
        self.assertFalse(adapter.verify(keypair.public_key, message, signature[:-1] + b"!"))

    def test_wrong_public_key_and_context_are_rejected(self) -> None:
        signer = CryptographyMLDSAAdapter()
        other = CryptographyMLDSAAdapter()
        signer_key = signer.generate_keypair()
        other_key = other.generate_keypair()
        message = b"response"
        signature = signer.sign(signer_key.private_key, message)

        self.assertFalse(signer.verify(other_key.public_key, message, signature))
        self.assertFalse(
            CryptographyMLDSAAdapter(context=b"different-purpose").verify(
                signer_key.public_key, message, signature
            )
        )


if __name__ == "__main__":
    unittest.main()
