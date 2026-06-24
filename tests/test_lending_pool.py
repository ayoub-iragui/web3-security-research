"""Tests for the multi-collateral lending pool module."""

import pytest

from src.defi_logic.lending_pool import (
    SCALE,
    DEFAULT_LIQUIDATION_THRESHOLD,
    AccountData,
    LendingPool,
    LiquidationError,
    Oracle,
)


# ---------------------------------------------------------------------------
# Oracle tests
# ---------------------------------------------------------------------------


class TestOracle:
    def test_set_and_get_price(self):
        oracle = Oracle()
        oracle.set_price("ETH", 2000 * SCALE)
        assert oracle.get_price("ETH") == 2000 * SCALE

    def test_get_missing_price_raises(self):
        oracle = Oracle()
        with pytest.raises(KeyError, match="No price"):
            oracle.get_price("BTC")

    def test_set_zero_price_raises(self):
        oracle = Oracle()
        with pytest.raises(ValueError, match="positive"):
            oracle.set_price("ETH", 0)

    def test_set_negative_price_raises(self):
        oracle = Oracle()
        with pytest.raises(ValueError, match="positive"):
            oracle.set_price("ETH", -1)

    def test_update_price(self):
        oracle = Oracle()
        oracle.set_price("ETH", 1000)
        oracle.set_price("ETH", 2000)
        assert oracle.get_price("ETH") == 2000


# ---------------------------------------------------------------------------
# LendingPool basic operations
# ---------------------------------------------------------------------------

ASSET_A = "ASSET_A"
ASSET_B = "ASSET_B"
ASSET_C = "ASSET_C"
USER = "user"
LIQUIDATOR = "liquidator"


def _make_oracle() -> Oracle:
    oracle = Oracle()
    oracle.set_price(ASSET_A, SCALE)  # $1
    oracle.set_price(ASSET_B, SCALE)  # $1
    oracle.set_price(ASSET_C, SCALE)  # $1
    return oracle


class TestLendingPoolBasics:
    def test_supply_increases_collateral(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 1000)
        data = pool.get_account_data(USER)
        assert data.total_collateral == 1000 * SCALE

    def test_supply_zero_raises(self):
        pool = LendingPool(_make_oracle())
        with pytest.raises(ValueError, match="positive"):
            pool.supply(USER, ASSET_A, 0)

    def test_supply_negative_raises(self):
        pool = LendingPool(_make_oracle())
        with pytest.raises(ValueError, match="positive"):
            pool.supply(USER, ASSET_A, -5)

    def test_borrow_increases_debt(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 10000)
        pool.borrow(USER, ASSET_B, 5000)
        data = pool.get_account_data(USER)
        assert data.total_debt == 5000 * SCALE

    def test_borrow_zero_raises(self):
        pool = LendingPool(_make_oracle())
        with pytest.raises(ValueError, match="positive"):
            pool.borrow(USER, ASSET_B, 0)

    def test_health_factor_computation(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 10000)
        pool.borrow(USER, ASSET_B, 5000)
        data = pool.get_account_data(USER)
        expected_hf = (10000 * SCALE * DEFAULT_LIQUIDATION_THRESHOLD * SCALE) // (
            5000 * SCALE * 100
        )
        assert data.health_factor == expected_hf

    def test_no_debt_health_factor_zero(self):
        pool = LendingPool(_make_oracle())
        pool.supply(USER, ASSET_A, 100)
        data = pool.get_account_data(USER)
        assert data.health_factor == 0

    def test_get_position(self):
        pool = LendingPool(_make_oracle())
        pool.supply(USER, ASSET_A, 500)
        pool.borrow(USER, ASSET_A, 100)
        pos = pool.get_position(USER, ASSET_A)
        assert pos.supplied == 500
        assert pos.borrowed == 100

    def test_get_position_missing_raises(self):
        pool = LendingPool(_make_oracle())
        with pytest.raises(KeyError):
            pool.get_position(USER, ASSET_A)


# ---------------------------------------------------------------------------
# Liquidation basics
# ---------------------------------------------------------------------------


class TestLiquidationBasics:
    def test_liquidation_healthy_account_raises(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 10000)
        pool.borrow(USER, ASSET_B, 1000)
        with pytest.raises(LiquidationError, match="healthy"):
            pool.liquidate(LIQUIDATOR, ASSET_A, ASSET_B, USER, 100)

    def test_liquidation_no_debt_raises(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 1000)
        pool.borrow(USER, ASSET_B, 900)
        # Force HF < 1
        oracle.set_price(ASSET_B, 2 * SCALE)
        with pytest.raises(LiquidationError, match="no debt"):
            pool.liquidate(LIQUIDATOR, ASSET_A, ASSET_A, USER, 100)

    def test_liquidation_no_collateral_raises(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 1000)
        pool.borrow(USER, ASSET_B, 900)
        oracle.set_price(ASSET_B, 2 * SCALE)
        with pytest.raises(LiquidationError, match="no collateral"):
            pool.liquidate(LIQUIDATOR, ASSET_C, ASSET_B, USER, 100)

    def test_normal_liquidation_reduces_debt(self):
        oracle = _make_oracle()
        pool = LendingPool(oracle)
        pool.supply(USER, ASSET_A, 10000)
        pool.borrow(USER, ASSET_B, 8000)
        # Make slightly under-collateralized
        oracle.set_price(ASSET_B, int(SCALE * 1.15))
        data_before = pool.get_account_data(USER)
        assert data_before.health_factor < SCALE

        seized = pool.liquidate(LIQUIDATOR, ASSET_A, ASSET_B, USER, 100)
        assert seized > 0
        pos = pool.get_position(USER, ASSET_B)
        assert pos.borrowed == 8000 - 100


# ---------------------------------------------------------------------------
# Vulnerability reproduction: triple-asset debt wipeout
# ---------------------------------------------------------------------------


class TestTripleAssetDebtWipeout:
    def _setup_topology(self, patched: bool = False):
        oracle = Oracle()
        oracle.set_price(ASSET_A, SCALE)
        oracle.set_price(ASSET_B, SCALE)
        oracle.set_price(ASSET_C, SCALE)
        pool = LendingPool(oracle, patched=patched)

        pool.supply(USER, ASSET_A, 10_000_000_000)
        pool.supply(USER, ASSET_C, 2_000)
        pool.borrow(USER, ASSET_B, 7_400_000_000)
        return pool, oracle

    def test_vulnerable_debt_wipeout(self):
        """Core exploit: liquidate dust collateral → entire debt wiped."""
        pool, oracle = self._setup_topology(patched=False)

        # Force HF < 1.0
        oracle.set_price(ASSET_A, int(SCALE * 0.85))
        oracle.set_price(ASSET_B, int(SCALE * 1.15))

        data = pool.get_account_data(USER)
        assert data.health_factor < SCALE

        # Liquidate targeting the dust Asset C
        seized = pool.liquidate(LIQUIDATOR, ASSET_C, ASSET_B, USER, 1_000_000_000)

        final = pool.get_account_data(USER)
        # Debt is wiped even though massive Asset A collateral remains
        assert final.total_debt == 0
        # Asset A collateral untouched
        assert pool.get_position(USER, ASSET_A).supplied == 10_000_000_000

    def test_vulnerable_dust_seized_fully(self):
        pool, oracle = self._setup_topology(patched=False)
        oracle.set_price(ASSET_A, int(SCALE * 0.85))
        oracle.set_price(ASSET_B, int(SCALE * 1.15))

        seized = pool.liquidate(LIQUIDATOR, ASSET_C, ASSET_B, USER, 1_000_000_000)
        assert seized == 2_000  # all dust taken
        assert pool.get_position(USER, ASSET_C).supplied == 0


# ---------------------------------------------------------------------------
# Patched behaviour
# ---------------------------------------------------------------------------


class TestPatchedLendingPool:
    def _setup_topology(self):
        oracle = Oracle()
        oracle.set_price(ASSET_A, SCALE)
        oracle.set_price(ASSET_B, SCALE)
        oracle.set_price(ASSET_C, SCALE)
        pool = LendingPool(oracle, patched=True)

        pool.supply(USER, ASSET_A, 10_000_000_000)
        pool.supply(USER, ASSET_C, 2_000)
        pool.borrow(USER, ASSET_B, 7_400_000_000)
        return pool, oracle

    def test_patched_no_wipeout(self):
        """Patched pool checks global solvency; debt is NOT wiped."""
        pool, oracle = self._setup_topology()
        oracle.set_price(ASSET_A, int(SCALE * 0.85))
        oracle.set_price(ASSET_B, int(SCALE * 1.15))

        pool.liquidate(LIQUIDATOR, ASSET_C, ASSET_B, USER, 1_000_000_000)

        final = pool.get_account_data(USER)
        # Debt is NOT fully wiped because global collateral is nonzero
        assert final.total_debt > 0

    def test_patched_global_insolvency_does_wipe(self):
        """When ALL collateral is truly exhausted, debt socialization is ok."""
        oracle = Oracle()
        oracle.set_price(ASSET_A, SCALE)
        oracle.set_price(ASSET_B, SCALE)
        pool = LendingPool(oracle, patched=True)

        pool.supply(USER, ASSET_A, 100)
        pool.borrow(USER, ASSET_B, 90)
        oracle.set_price(ASSET_B, 2 * SCALE)

        pool.liquidate(LIQUIDATOR, ASSET_A, ASSET_B, USER, 90)
        # All collateral exhausted → debt socialized
        final = pool.get_account_data(USER)
        assert final.total_collateral == 0
        assert final.total_debt == 0
