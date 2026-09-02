"""Explicit integer rounding for deterministic fixed-point money.

Every operation that can lose precision requires an explicit
``RoundingMode``; there are no implicit defaults. ``round_ratio`` is pure
integer arithmetic: no floats, no platform-dependent behavior, and
byte-stable results across processes and repeated runs.
"""

from __future__ import annotations

from enum import StrEnum

from ..core.errors import CoreValidationError


class RoundingMode(StrEnum):
    """Closed vocabulary of rounding directions at an integer boundary."""

    HALF_EVEN = "HALF_EVEN"  # ties to even (banker's rounding)
    HALF_UP = "HALF_UP"      # ties away from zero
    HALF_DOWN = "HALF_DOWN"  # ties toward zero
    FLOOR = "FLOOR"          # toward negative infinity
    CEILING = "CEILING"      # toward positive infinity
    TRUNCATE = "TRUNCATE"    # toward zero


def round_ratio(numerator: int, denominator: int, mode: RoundingMode) -> int:
    """Round the exact rational ``numerator / denominator`` to an integer.

    ``denominator`` must be a positive integer and ``mode`` must belong to
    the closed vocabulary; anything else fails closed with a
    ``CoreValidationError``. Exact divisions return the exact quotient, so
    rounding never perturbs values that are already representable.
    """
    if not isinstance(numerator, int) or isinstance(numerator, bool):
        raise CoreValidationError(f"round_ratio numerator must be an integer, got {type(numerator).__name__}")
    if not isinstance(denominator, int) or isinstance(denominator, bool):
        raise CoreValidationError(f"round_ratio denominator must be an integer, got {type(denominator).__name__}")
    if denominator <= 0:
        raise CoreValidationError(f"round_ratio denominator must be a positive integer, got {denominator!r}")
    if not isinstance(mode, RoundingMode):
        raise CoreValidationError(
            f"rounding mode must use the closed RoundingMode vocabulary, got {mode!r}"
        )

    # Python floor division with a positive denominator yields a remainder
    # in [0, denominator), which makes every case below purely integer.
    quotient, remainder = divmod(numerator, denominator)
    if remainder == 0:
        return quotient
    if mode is RoundingMode.FLOOR:
        return quotient
    if mode is RoundingMode.CEILING:
        return quotient + 1
    if mode is RoundingMode.TRUNCATE:
        return quotient + 1 if numerator < 0 else quotient

    twice_remainder = 2 * remainder
    if twice_remainder > denominator:
        return quotient + 1
    if twice_remainder < denominator:
        return quotient
    # Exact half: the tie is decided by the mode.
    if mode is RoundingMode.HALF_EVEN:
        return quotient if quotient % 2 == 0 else quotient + 1
    if mode is RoundingMode.HALF_UP:
        return quotient if numerator < 0 else quotient + 1
    if mode is RoundingMode.HALF_DOWN:
        return quotient + 1 if numerator < 0 else quotient
    raise CoreValidationError(f"unhandled rounding mode: {mode!r}")  # pragma: no cover - fail closed
