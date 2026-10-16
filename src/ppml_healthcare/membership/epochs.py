"""Latest-epoch-only membership policy."""

from __future__ import annotations

from typing import Protocol

from ppml_healthcare.schemas import MembershipEpoch


class EpochPolicy(Protocol):
    def accepts(self, presented_epoch: int, current: MembershipEpoch) -> bool: ...


class LatestEpochOnlyPolicy:
    """Accept requests that reference exactly the current membership epoch."""

    def accepts(self, presented_epoch: int, current: MembershipEpoch) -> bool:
        if isinstance(presented_epoch, bool) or not isinstance(presented_epoch, int):
            return False
        return presented_epoch == current.epoch
