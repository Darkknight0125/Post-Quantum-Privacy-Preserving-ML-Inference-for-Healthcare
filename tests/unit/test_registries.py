from __future__ import annotations

import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ppml_healthcare.errors import (
    ModelArtifactMismatchError,
    RegistryConflictError,
    UnknownMemberError,
)
from ppml_healthcare.membership.epochs import LatestEpochOnlyPolicy
from ppml_healthcare.membership.registry import InMemoryMembershipRegistry
from ppml_healthcare.models.registry import InMemoryModelRegistry
from ppml_healthcare.schemas import ModelDescriptor


class MembershipRegistryTests(unittest.TestCase):
    def test_each_change_creates_a_new_epoch_and_preserves_history(self) -> None:
        registry = InMemoryMembershipRegistry()
        epoch_zero = registry.current_epoch()

        epoch_one = registry.add_hospital(b"hospital-public-key-a")
        epoch_two = registry.add_hospital(b"hospital-public-key-b")
        epoch_three = registry.revoke_hospital(b"hospital-public-key-a")

        self.assertEqual(
            [epoch_zero.epoch, epoch_one.epoch, epoch_two.epoch, epoch_three.epoch], [0, 1, 2, 3]
        )
        self.assertEqual(epoch_zero.members, ())
        self.assertEqual(epoch_one.members, (b"hospital-public-key-a",))
        self.assertEqual(
            epoch_two.members,
            (b"hospital-public-key-a", b"hospital-public-key-b"),
        )
        self.assertEqual(epoch_three.members, (b"hospital-public-key-b",))
        self.assertIs(registry.get_epoch(1), epoch_one)
        self.assertIs(registry.current_epoch(), epoch_three)

    def test_rotation_replaces_key_in_a_new_snapshot(self) -> None:
        registry = InMemoryMembershipRegistry((b"old-key",))
        old_epoch = registry.current_epoch()
        new_epoch = registry.rotate_hospital_key(b"old-key", b"new-key")

        self.assertEqual(old_epoch.members, (b"old-key",))
        self.assertEqual(new_epoch.members, (b"new-key",))
        self.assertEqual(new_epoch.epoch, old_epoch.epoch + 1)

    def test_duplicate_unknown_and_invalid_members_are_rejected(self) -> None:
        registry = InMemoryMembershipRegistry((b"known",))
        with self.assertRaises(RegistryConflictError):
            registry.add_hospital(b"known")
        with self.assertRaises(UnknownMemberError):
            registry.revoke_hospital(b"unknown")
        with self.assertRaises(UnknownMemberError):
            registry.rotate_hospital_key(b"unknown", b"new")
        with self.assertRaises(ValueError):
            registry.add_hospital(b"")

    def test_latest_epoch_policy_rejects_old_unknown_and_malformed_values(self) -> None:
        registry = InMemoryMembershipRegistry((b"member",))
        current = registry.add_hospital(b"another")
        policy = LatestEpochOnlyPolicy()

        self.assertTrue(policy.accepts(current.epoch, current))
        self.assertFalse(policy.accepts(0, current))
        self.assertFalse(policy.accepts(current.epoch + 1, current))
        self.assertFalse(policy.accepts(True, current))
        self.assertFalse(policy.accepts("1", current))  # type: ignore[arg-type]

    def test_concurrent_additions_publish_distinct_epochs(self) -> None:
        registry = InMemoryMembershipRegistry()
        keys = [f"hospital-key-{index}".encode() for index in range(12)]
        with ThreadPoolExecutor(max_workers=6) as executor:
            epochs = list(executor.map(registry.add_hospital, keys))

        current = registry.current_epoch()
        self.assertEqual(current.epoch, len(keys))
        self.assertEqual(len(current.members), len(keys))
        self.assertEqual(len({epoch.epoch for epoch in epochs}), len(keys))


class ModelRegistryTests(unittest.TestCase):
    def test_registers_exact_artifact_hash_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "toy-model.bin"
            contents = b"deterministic synthetic toy model artifact"
            artifact.write_bytes(contents)
            descriptor = ModelDescriptor("toy-model", "1.0", hashlib.sha256(contents).hexdigest())
            registry = InMemoryModelRegistry()

            registry.register_model(descriptor, str(artifact))
            registry.register_model(descriptor, str(artifact))

            self.assertEqual(registry.get_model("toy-model", "1.0"), descriptor)
            self.assertEqual(registry.get_artifact_path("toy-model", "1.0"), artifact.resolve())
            self.assertTrue(registry.verify_artifact("toy-model", "1.0"))

    def test_rejects_hash_mismatch_and_immutable_version_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "model.bin"
            artifact.write_bytes(b"model bytes v1")
            correct = ModelDescriptor(
                "toy-model", "1.0", hashlib.sha256(b"model bytes v1").hexdigest()
            )
            wrong = ModelDescriptor("toy-model", "1.0", hashlib.sha256(b"different").hexdigest())
            registry = InMemoryModelRegistry()

            with self.assertRaises(ModelArtifactMismatchError):
                registry.register_model(wrong, str(artifact))
            registry.register_model(correct, str(artifact))
            artifact.write_bytes(b"model bytes v2")
            self.assertFalse(registry.verify_artifact("toy-model", "1.0"))
            with self.assertRaises(ModelArtifactMismatchError):
                registry.register_model(correct, str(artifact))

    def test_unknown_model_returns_none(self) -> None:
        registry = InMemoryModelRegistry()
        self.assertIsNone(registry.get_model("missing", "0"))
        self.assertFalse(registry.verify_artifact("missing", "0"))


if __name__ == "__main__":
    unittest.main()
