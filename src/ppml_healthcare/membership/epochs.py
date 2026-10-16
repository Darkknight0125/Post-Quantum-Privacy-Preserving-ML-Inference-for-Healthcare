"""Epoch policy contract: only the latest valid epoch is accepted."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import MembershipEpoch


class EpochPolicy(Protocol):
    def accepts(self, presented_epoch: int, current: MembershipEpoch) -> bool: ...
