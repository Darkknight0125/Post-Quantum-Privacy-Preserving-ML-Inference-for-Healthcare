"""Membership registry contract; registry operations belong to Step 3."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import MembershipEpoch


class MembershipRegistry(Protocol):
    def current_epoch(self) -> MembershipEpoch: ...

    def get_epoch(self, epoch: int) -> MembershipEpoch | None: ...

    def add_hospital(self, public_key: bytes) -> MembershipEpoch: ...

    def revoke_hospital(self, public_key: bytes) -> MembershipEpoch: ...

    def rotate_hospital_key(self, old_public_key: bytes, new_public_key: bytes) -> MembershipEpoch: ...
