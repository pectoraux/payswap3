"""Deterministic residual allocation of indivisible minor units.

Allocation never creates or destroys value: the parts always sum exactly
to the allocated amount. Residual minor units are distributed by the
largest-remainder rule with a deterministic lowest-index tie-break, so the
same inputs always produce byte-identical canonical outputs.
"""

from __future__ import annotations

from typing import Sequence

from ..core.errors import CoreValidationError
from .amount import Amount


def _require_amount(amount: Amount) -> Amount:
    if not isinstance(amount, Amount):
        raise CoreValidationError(f"allocation requires an Amount, got {type(amount).__name__}")
    return amount


def _require_count(count: int) -> int:
    if not isinstance(count, int) or isinstance(count, bool):
        raise CoreValidationError(f"allocation count must be an integer, got {type(count).__name__}")
    if count < 1:
        raise CoreValidationError(f"allocation count must be at least 1, got {count!r}")
    return count


def _validate_weights(weights: Sequence[int]) -> tuple[int, ...]:
    if isinstance(weights, (str, bytes)) or not isinstance(weights, (list, tuple)):
        raise CoreValidationError(
            f"allocation weights must be a list or tuple of positive integers, got {type(weights).__name__}"
        )
    result = tuple(weights)
    if not result:
        raise CoreValidationError("allocation weights must not be empty")
    for weight in result:
        if not isinstance(weight, int) or isinstance(weight, bool):
            raise CoreValidationError(f"allocation weights must be integers, got {type(weight).__name__}")
        if weight < 1:
            raise CoreValidationError(f"allocation weights must be positive, got {weight!r}")
    return result


def allocate_equal(amount: Amount, count: int) -> tuple[Amount, ...]:
    """Split ``amount`` into ``count`` parts that sum exactly to it.

    The base share is floor division; the ``value % count`` leftover minor
    units are given one each to the lowest-index parts.
    """
    _require_amount(amount)
    _require_count(count)
    quotient, remainder = divmod(amount.value, count)
    return tuple(
        Amount(
            currency=amount.currency,
            value=quotient + (1 if index < remainder else 0),
            scale=amount.scale,
        )
        for index in range(count)
    )


def allocate_weighted(amount: Amount, weights: Sequence[int]) -> tuple[Amount, ...]:
    """Split ``amount`` proportionally to positive integer weights.

    Exact fractional shares are floored, then the leftover minor units are
    given to the parts with the largest fractional remainders; ties are
    broken by lowest index. Parts sum exactly to ``amount``.
    """
    _require_amount(amount)
    weight_tuple = _validate_weights(weights)
    total_weight = sum(weight_tuple)
    bases: list[int] = []
    remainders: list[int] = []
    for weight in weight_tuple:
        quotient, remainder = divmod(amount.value * weight, total_weight)
        bases.append(quotient)
        remainders.append(remainder)
    leftover = amount.value - sum(bases)
    if leftover < 0 or leftover >= len(weight_tuple):
        raise CoreValidationError("weighted allocation invariant violated: leftover out of range")
    order = sorted(range(len(weight_tuple)), key=lambda index: (-remainders[index], index))
    winners = frozenset(order[:leftover])
    return tuple(
        Amount(
            currency=amount.currency,
            value=bases[index] + (1 if index in winners else 0),
            scale=amount.scale,
        )
        for index in range(len(weight_tuple))
    )
