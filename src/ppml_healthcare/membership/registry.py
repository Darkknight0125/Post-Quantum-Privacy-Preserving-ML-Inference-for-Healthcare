"""Thread-safe in-memory membership authority and immutable epoch history."""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime
from typing import Protocol

from ppml_healthcare.errors import RegistryConflictError, SchemaValidationError, UnknownMemberError
from ppml_healthcare.schemas import MembershipEpoch
from ppml_healthcare.serialization import canonical_bytes


class MembershipRegistry(Protocol):
    def current_epoch(self) -> MembershipEpoch: ...

    def get_epoch(self, epoch: int) -> MembershipEpoch | None: ...

    def add_hospital(self, public_key: bytes) -> MembershipEpoch: ...

    def revoke_hospital(self, public_key: bytes) -> MembershipEpoch: ...

    def rotate_hospital_key(
        self, old_public_key: bytes, new_public_key: bytes
    ) -> MembershipEpoch: ...


class InMemoryMembershipRegistry:
    """Membership authority for the local prototype.

    Every successful mutation creates a new epoch. Earlier frozen epoch
    objects remain available through :meth:`get_epoch`; their contents are
    never modified. This implementation is process-local and non-persistent.
    """

    def __init__(self, initial_members: tuple[bytes, ...] = ()) -> None:
        self._lock = threading.RLock()
        self._epochs: dict[int, MembershipEpoch] = {}
        normalized = self._validate_members(initial_members)
        self._epochs[0] = self._build_epoch(0, normalized)

    def current_epoch(self) -> MembershipEpoch:
        with self._lock:
            return self._epochs[max(self._epochs)]

    def get_epoch(self, epoch: int) -> MembershipEpoch | None:
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            return None
        with self._lock:
            return self._epochs.get(epoch)

    def add_hospital(self, public_key: bytes) -> MembershipEpoch:
        self._validate_public_key(public_key)
        with self._lock:
            current = self.current_epoch()
            if public_key in current.members:
                raise RegistryConflictError("hospital public key is already registered")
            return self._publish((*current.members, public_key))

    def revoke_hospital(self, public_key: bytes) -> MembershipEpoch:
        self._validate_public_key(public_key)
        with self._lock:
            current = self.current_epoch()
            if public_key not in current.members:
                raise UnknownMemberError("hospital public key is not in the current epoch")
            return self._publish(tuple(key for key in current.members if key != public_key))

    def rotate_hospital_key(self, old_public_key: bytes, new_public_key: bytes) -> MembershipEpoch:
        self._validate_public_key(old_public_key)
        self._validate_public_key(new_public_key)
        if old_public_key == new_public_key:
            raise SchemaValidationError("key rotation requires a different public key")
        with self._lock:
            current = self.current_epoch()
            if old_public_key not in current.members:
                raise UnknownMemberError("old hospital public key is not in the current epoch")
            if new_public_key in current.members:
                raise RegistryConflictError("new hospital public key is already registered")
            members = tuple(key for key in current.members if key != old_public_key)
            return self._publish((*members, new_public_key))

    def _publish(self, members: tuple[bytes, ...]) -> MembershipEpoch:
        next_epoch = max(self._epochs) + 1
        epoch = self._build_epoch(next_epoch, self._validate_members(members))
        self._epochs[next_epoch] = epoch
        return epoch

    @classmethod
    def _build_epoch(cls, number: int, members: tuple[bytes, ...]) -> MembershipEpoch:
        issued_at = datetime.now(UTC)
        canonical_record = canonical_bytes(
            {"epoch": number, "issued_at": issued_at, "members": members}
        )
        digest = hashlib.sha256(canonical_record).hexdigest()
        return MembershipEpoch(
            epoch=number,
            issued_at=issued_at,
            members=members,
            registry_digest=digest,
        )

    @classmethod
    def _validate_members(cls, members: tuple[bytes, ...]) -> tuple[bytes, ...]:
        if not isinstance(members, tuple):
            raise SchemaValidationError("initial_members must be a tuple of public-key bytes")
        for key in members:
            cls._validate_public_key(key)
        if len(set(members)) != len(members):
            raise RegistryConflictError("membership epoch cannot contain duplicate public keys")
        return tuple(sorted(members))

    @staticmethod
    def _validate_public_key(public_key: bytes) -> None:
        if not isinstance(public_key, bytes) or not public_key:
            raise SchemaValidationError("hospital public key must be non-empty bytes")
