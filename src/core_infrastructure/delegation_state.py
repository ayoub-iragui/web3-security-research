"""
Delegation quota state-machine simulation.

Models the asymmetric signature validation vulnerability: during creation
with a signature bypass the quota deduction is skipped, but termination
unconditionally refunds it — allowing infinite reserve minting.

Reference: Core-Infrastructure/Asymmetric_State_Minting.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, Tuple


class DelegationError(Exception):
    """Raised for invalid delegation operations."""


class DelegationFlag(Enum):
    DELEGATE_CREATE = auto()
    DELEGATE_END = auto()


@dataclass
class DelegationEntry:
    """Tracks a single delegated object between sponsor and delegatee."""

    object_id: str
    funded: bool = False


@dataclass
class DelegationRelation:
    """Tracks the quota and active objects between two parties."""

    reserve_count: int = 0
    objects: Dict[str, DelegationEntry] = field(default_factory=dict)


class DelegationLedger:
    """Manages delegation relationships and enforces (or fails to enforce)
    the quota symmetry invariant.

    Parameters
    ----------
    patched : bool
        When *True* the ledger enforces the correct invariant (refund only
        when funded).  When *False* (default) it reproduces the vulnerable
        behaviour described in the research.
    """

    def __init__(self, patched: bool = False) -> None:
        self._relations: Dict[Tuple[str, str], DelegationRelation] = {}
        self._patched = patched

    def setup_delegation(
        self, sponsor: str, delegatee: str, initial_reserve: int
    ) -> None:
        if initial_reserve < 0:
            raise DelegationError("Reserve count cannot be negative")
        key = (sponsor, delegatee)
        if key in self._relations:
            raise DelegationError("Delegation already exists")
        self._relations[key] = DelegationRelation(reserve_count=initial_reserve)

    def get_reserve_count(self, sponsor: str, delegatee: str) -> int:
        rel = self._relations.get((sponsor, delegatee))
        if rel is None:
            raise DelegationError("No delegation between these parties")
        return rel.reserve_count

    def get_entry(self, sponsor: str, delegatee: str, object_id: str) -> Optional[DelegationEntry]:
        rel = self._relations.get((sponsor, delegatee))
        if rel is None:
            raise DelegationError("No delegation between these parties")
        return rel.objects.get(object_id)

    def delegate_transfer(
        self,
        sponsor: str,
        delegatee: str,
        object_id: str,
        flag: DelegationFlag,
        *,
        signature_bypass: bool = False,
    ) -> None:
        key = (sponsor, delegatee)
        rel = self._relations.get(key)
        if rel is None:
            raise DelegationError("No delegation between these parties")

        if flag is DelegationFlag.DELEGATE_CREATE:
            if object_id in rel.objects:
                raise DelegationError("Object already delegated")

            funded = True
            if signature_bypass:
                # BUG (vulnerable path): skip the quota deduction
                funded = False
            else:
                if rel.reserve_count <= 0:
                    raise DelegationError("No remaining reserve quota")
                rel.reserve_count -= 1

            rel.objects[object_id] = DelegationEntry(
                object_id=object_id, funded=funded
            )

        elif flag is DelegationFlag.DELEGATE_END:
            entry = rel.objects.pop(object_id, None)
            if entry is None:
                raise DelegationError("Object not found in delegation")

            if self._patched:
                # Correct behaviour: only refund if originally funded
                if entry.funded:
                    rel.reserve_count += 1
            else:
                # Vulnerable behaviour: blind refund
                rel.reserve_count += 1
        else:
            raise DelegationError(f"Unknown flag: {flag}")
