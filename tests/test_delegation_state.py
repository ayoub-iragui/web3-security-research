"""Tests for the delegation quota state-machine module."""

import pytest

from src.core_infrastructure.delegation_state import (
    DelegationEntry,
    DelegationError,
    DelegationFlag,
    DelegationLedger,
)


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

SPONSOR = "sponsor"
ATTACKER = "attacker"
OBJ_A = "obj_a"
OBJ_B = "obj_b"


def _make_ledger(patched: bool = False, reserve: int = 1) -> DelegationLedger:
    ledger = DelegationLedger(patched=patched)
    ledger.setup_delegation(SPONSOR, ATTACKER, reserve)
    return ledger


# ---------------------------------------------------------------------------
# Basic delegation lifecycle
# ---------------------------------------------------------------------------


class TestDelegationLifecycle:
    def test_setup_initial_reserve(self):
        ledger = _make_ledger(reserve=5)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 5

    def test_duplicate_setup_raises(self):
        ledger = _make_ledger()
        with pytest.raises(DelegationError, match="already exists"):
            ledger.setup_delegation(SPONSOR, ATTACKER, 1)

    def test_negative_reserve_raises(self):
        ledger = DelegationLedger()
        with pytest.raises(DelegationError, match="negative"):
            ledger.setup_delegation("a", "b", -1)

    def test_get_reserve_unknown_pair(self):
        ledger = DelegationLedger()
        with pytest.raises(DelegationError, match="No delegation"):
            ledger.get_reserve_count("x", "y")

    def test_create_deducts_quota(self):
        ledger = _make_ledger(reserve=3)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 2

    def test_create_then_end_restores_quota(self):
        ledger = _make_ledger(reserve=3)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 3

    def test_create_no_remaining_quota_raises(self):
        ledger = _make_ledger(reserve=0)
        with pytest.raises(DelegationError, match="No remaining"):
            ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)

    def test_end_nonexistent_object_raises(self):
        ledger = _make_ledger(reserve=1)
        with pytest.raises(DelegationError, match="Object not found"):
            ledger.delegate_transfer(SPONSOR, ATTACKER, "phantom", DelegationFlag.DELEGATE_END)

    def test_create_duplicate_object_raises(self):
        ledger = _make_ledger(reserve=3)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)
        with pytest.raises(DelegationError, match="already delegated"):
            ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)

    def test_get_entry_returns_entry(self):
        ledger = _make_ledger(reserve=2)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)
        entry = ledger.get_entry(SPONSOR, ATTACKER, OBJ_A)
        assert entry is not None
        assert entry.object_id == OBJ_A
        assert entry.funded is True

    def test_get_entry_returns_none_for_missing(self):
        ledger = _make_ledger(reserve=2)
        assert ledger.get_entry(SPONSOR, ATTACKER, OBJ_A) is None

    def test_get_entry_unknown_pair_raises(self):
        ledger = DelegationLedger()
        with pytest.raises(DelegationError, match="No delegation"):
            ledger.get_entry("x", "y", "z")

    def test_transfer_unknown_pair_raises(self):
        ledger = DelegationLedger()
        with pytest.raises(DelegationError, match="No delegation"):
            ledger.delegate_transfer("x", "y", "z", DelegationFlag.DELEGATE_CREATE)

    def test_multiple_objects(self):
        ledger = _make_ledger(reserve=5)
        for i in range(3):
            ledger.delegate_transfer(SPONSOR, ATTACKER, f"obj_{i}", DelegationFlag.DELEGATE_CREATE)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 2

    def test_unknown_flag_raises(self):
        ledger = _make_ledger(reserve=1)
        with pytest.raises(DelegationError, match="Unknown flag"):
            ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, "INVALID")


# ---------------------------------------------------------------------------
# Vulnerability reproduction: asymmetric state minting
# ---------------------------------------------------------------------------


class TestAsymmetricMintingVulnerability:
    def test_signature_bypass_skips_deduction(self):
        ledger = _make_ledger(reserve=1)
        ledger.delegate_transfer(
            SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE,
            signature_bypass=True,
        )
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 1  # unchanged

    def test_bypass_entry_marked_unfunded(self):
        ledger = _make_ledger(reserve=1)
        ledger.delegate_transfer(
            SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE,
            signature_bypass=True,
        )
        entry = ledger.get_entry(SPONSOR, ATTACKER, OBJ_A)
        assert entry is not None
        assert entry.funded is False

    def test_vulnerable_blind_refund_mints_quota(self):
        """Core exploit: bypass create + blind end = +1 ghost quota."""
        ledger = _make_ledger(patched=False, reserve=1)
        ledger.delegate_transfer(
            SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE,
            signature_bypass=True,
        )
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 1

        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 2  # minted!

    def test_vulnerable_loop_accumulates_quota(self):
        """Looping the exploit amplifies the minting."""
        ledger = _make_ledger(patched=False, reserve=1)
        for i in range(10):
            oid = f"obj_{i}"
            ledger.delegate_transfer(
                SPONSOR, ATTACKER, oid, DelegationFlag.DELEGATE_CREATE,
                signature_bypass=True,
            )
            ledger.delegate_transfer(SPONSOR, ATTACKER, oid, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 11  # 1 + 10 minted


# ---------------------------------------------------------------------------
# Patched behaviour
# ---------------------------------------------------------------------------


class TestPatchedDelegation:
    def test_patched_no_blind_refund(self):
        ledger = _make_ledger(patched=True, reserve=1)
        ledger.delegate_transfer(
            SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE,
            signature_bypass=True,
        )
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 1  # unchanged

    def test_patched_normal_cycle_symmetric(self):
        ledger = _make_ledger(patched=True, reserve=3)
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_CREATE)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 2
        ledger.delegate_transfer(SPONSOR, ATTACKER, OBJ_A, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 3

    def test_patched_loop_no_accumulation(self):
        ledger = _make_ledger(patched=True, reserve=1)
        for i in range(10):
            oid = f"obj_{i}"
            ledger.delegate_transfer(
                SPONSOR, ATTACKER, oid, DelegationFlag.DELEGATE_CREATE,
                signature_bypass=True,
            )
            ledger.delegate_transfer(SPONSOR, ATTACKER, oid, DelegationFlag.DELEGATE_END)
        assert ledger.get_reserve_count(SPONSOR, ATTACKER) == 1
