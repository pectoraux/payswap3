"""Exact fixed-point fee arithmetic for market fills.

Fees are computed as ``amount × price_bps / 10000`` plus a flat fee in
minor units, using the deterministic integer rounding authority owned by
the money domain (WORK-006, :func:`src.money.rounding.round_ratio`) with
an explicit frozen rounding mode. No floating-point value is ever
constructed: the market domain consumes the money authority for exact
fixed-point arithmetic, exactly as the ledger posting model requires.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.money.rounding import RoundingMode, round_ratio

from .contracts import MAX_PRICE_BPS, MIN_PRICE_BPS

#: Frozen rounding mode for all market fee computation.
MARKET_FEE_ROUNDING_MODE = RoundingMode.FLOOR

#: Price denominator: prices are declared in basis points.
BPS_DENOMINATOR = 10000


def _require_amount_value(amount_value: int) -> int:
    if not isinstance(amount_value, int) or isinstance(amount_value, bool):
        raise CoreValidationError(
            f"fill amount must be an integer, got {type(amount_value).__name__}"
        )
    if amount_value < 0:
        raise CoreValidationError(f"fill amount must be non-negative, got {amount_value!r}")
    return amount_value


def _require_price_bps(price_bps: int) -> int:
    if not isinstance(price_bps, int) or isinstance(price_bps, bool):
        raise CoreValidationError(
            f"fill price must be an integer, got {type(price_bps).__name__}"
        )
    if not MIN_PRICE_BPS <= price_bps <= MAX_PRICE_BPS:
        raise CoreValidationError(
            f"fill price must be between {MIN_PRICE_BPS} and {MAX_PRICE_BPS} "
            f"basis points, got {price_bps!r}"
        )
    return price_bps


def _require_flat_fee(flat_fee: int) -> int:
    if not isinstance(flat_fee, int) or isinstance(flat_fee, bool):
        raise CoreValidationError(
            f"flat fee must be an integer, got {type(flat_fee).__name__}"
        )
    if flat_fee < 0:
        raise CoreValidationError(f"flat fee must be non-negative, got {flat_fee!r}")
    return flat_fee


def fee_for_fill(amount_value: int, price_bps: int, flat_fee: int) -> int:
    """Exact fee of one fill, in minor units.

    ``fee = floor(amount_value × price_bps / 10000) + flat_fee`` — pure
    integer arithmetic through the money rounding authority; exact
    divisions stay exact and inexact ones floor by the frozen policy.
    """
    _require_amount_value(amount_value)
    _require_price_bps(price_bps)
    _require_flat_fee(flat_fee)
    proportional = round_ratio(
        amount_value * price_bps, BPS_DENOMINATOR, MARKET_FEE_ROUNDING_MODE
    )
    return proportional + flat_fee
