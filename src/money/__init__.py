"""Fixed-point monetary arithmetic and FX primitives (WORK-006).

Public surface: canonical currency minor-unit definitions, exact
fixed-point amounts, explicit integer rounding modes, deterministic
residual allocation, exact FX rates with conservation-preserving
conversion, and envelope-backed durable FX quotes.

``CoreValidationError`` is the single validation error authority; it is
owned by ``src.core`` and re-exported here for convenience. The money
domain never raises a parallel error class.
"""

from __future__ import annotations

from ..core import CoreValidationError
from .allocation import allocate_equal, allocate_weighted
from .amount import Amount
from .currencies import CANONICAL_CURRENCIES, Currency, get_currency
from .fx import (
    FX_QUOTE_OBJECT_TYPE,
    FxConversion,
    FxQuote,
    FxQuoteState,
    FxRate,
    convert,
)
from .rounding import RoundingMode, round_ratio

__all__ = [
    "CANONICAL_CURRENCIES",
    "CoreValidationError",
    "Currency",
    "FX_QUOTE_OBJECT_TYPE",
    "Amount",
    "FxConversion",
    "FxQuote",
    "FxQuoteState",
    "FxRate",
    "RoundingMode",
    "allocate_equal",
    "allocate_weighted",
    "convert",
    "get_currency",
    "round_ratio",
]
