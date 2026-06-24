"""
Multi-collateral lending pool simulation.

Models the triple-asset debt wipeout vulnerability: bad-debt socialization
is triggered by a *localized* collateral exhaustion check instead of a
*global* solvency check, allowing an attacker to erase massive debt by
liquidating a dust position.

Reference: DeFi-Logic-Flaws/Triple_Asset_Debt_Wipeout.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


class LiquidationError(Exception):
    """Raised when a liquidation cannot proceed."""


@dataclass
class AccountData:
    """Snapshot of a user's aggregate position."""

    total_collateral: int
    total_debt: int
    health_factor: int  # scaled by 1e18


@dataclass
class Oracle:
    """Price oracle backed by a simple dictionary.

    Prices are integers scaled by 1e18.
    """

    _prices: Dict[str, int] = field(default_factory=dict)

    def set_price(self, asset: str, price: int) -> None:
        if price <= 0:
            raise ValueError("Price must be positive")
        self._prices[asset] = price

    def get_price(self, asset: str) -> int:
        price = self._prices.get(asset)
        if price is None:
            raise KeyError(f"No price for asset {asset}")
        return price


SCALE = 10**18
DEFAULT_LTV = 80  # 80 %
DEFAULT_LIQUIDATION_THRESHOLD = 85  # 85 %
LIQUIDATION_BONUS_BPS = 500  # 5 %


@dataclass
class _ReservePosition:
    supplied: int = 0
    borrowed: int = 0


class LendingPool:
    """Simplified multi-collateral lending pool.

    Parameters
    ----------
    oracle : Oracle
        Price feed.
    patched : bool
        When *True* the pool checks global solvency before socializing debt.
        When *False* (default) it reproduces the vulnerable behaviour.
    """

    def __init__(self, oracle: Oracle, *, patched: bool = False) -> None:
        self._oracle = oracle
        self._patched = patched
        # user -> asset -> position
        self._positions: Dict[str, Dict[str, _ReservePosition]] = {}

    def _ensure_user(self, user: str) -> Dict[str, _ReservePosition]:
        return self._positions.setdefault(user, {})

    def _ensure_position(self, user: str, asset: str) -> _ReservePosition:
        positions = self._ensure_user(user)
        return positions.setdefault(asset, _ReservePosition())

    # --- Public API ---

    def supply(self, user: str, asset: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("Supply amount must be positive")
        pos = self._ensure_position(user, asset)
        pos.supplied += amount

    def borrow(self, user: str, asset: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("Borrow amount must be positive")
        pos = self._ensure_position(user, asset)
        pos.borrowed += amount

    def get_account_data(self, user: str) -> AccountData:
        positions = self._positions.get(user, {})
        total_collateral = 0
        total_debt = 0
        for asset, pos in positions.items():
            price = self._oracle.get_price(asset)
            total_collateral += pos.supplied * price
            total_debt += pos.borrowed * price
        hf = (
            (total_collateral * DEFAULT_LIQUIDATION_THRESHOLD * SCALE)
            // (total_debt * 100)
            if total_debt > 0
            else 0
        )
        return AccountData(
            total_collateral=total_collateral,
            total_debt=total_debt,
            health_factor=hf,
        )

    def get_position(self, user: str, asset: str) -> _ReservePosition:
        positions = self._positions.get(user, {})
        pos = positions.get(asset)
        if pos is None:
            raise KeyError(f"No position for {user} in {asset}")
        return pos

    def liquidate(
        self,
        liquidator: str,
        collateral_asset: str,
        debt_asset: str,
        user: str,
        repay_amount: int,
    ) -> int:
        """Execute a liquidation.

        Returns the amount of collateral seized.

        Raises LiquidationError on invalid scenarios.
        """
        account = self.get_account_data(user)
        if account.health_factor >= SCALE:
            raise LiquidationError("Account is healthy (HF >= 1.0)")

        debt_pos = self._ensure_position(user, debt_asset)
        if debt_pos.borrowed == 0:
            raise LiquidationError("User has no debt in this asset")

        coll_pos = self._ensure_position(user, collateral_asset)
        if coll_pos.supplied == 0:
            raise LiquidationError("User has no collateral in this asset")

        coll_price = self._oracle.get_price(collateral_asset)
        debt_price = self._oracle.get_price(debt_asset)

        # How much collateral corresponds to repay_amount of debt?
        seize_value = repay_amount * debt_price * (10000 + LIQUIDATION_BONUS_BPS) // 10000
        seize_amount = seize_value // coll_price

        # Check localized collateral exhaustion
        is_collateral_exhausted = seize_amount >= coll_pos.supplied

        if is_collateral_exhausted:
            seize_amount = coll_pos.supplied
            coll_pos.supplied = 0
        else:
            coll_pos.supplied -= seize_amount

        # Reduce debt by actual repayment
        actual_repay = min(repay_amount, debt_pos.borrowed)
        debt_pos.borrowed -= actual_repay

        # --- Bad debt socialization (the vulnerability) ---
        if is_collateral_exhausted:
            if self._patched:
                # Correct: check GLOBAL solvency before forgiving
                remaining = self.get_account_data(user)
                if remaining.total_collateral == 0:
                    debt_pos.borrowed = 0
            else:
                # Vulnerable: local exhaustion → unconditional wipe
                debt_pos.borrowed = 0

        return seize_amount
