"""Canonical currency minor-unit definitions for fixed-point money.

This module is the single money-domain authority for the decimal scale of
known currencies (ISO-4217 style minor-unit exponents). The frozen
canonical table ``CANONICAL_CURRENCIES`` is deterministic: the same lookups
always return the same values, and a known currency code presented with a
conflicting scale fails closed.

``Currency`` is an internal value primitive, not a protocol-visible object
type: durable value-instrument objects are owned by the value domain
(``src/value``, WORK-005). The frozen ledger posting model realizes
``Amount = integer_value + scale + asset``; here the asset term of a
monetary amount is a currency code plus its minor-unit scale.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ..core.errors import CoreValidationError

CURRENCY_CODE_LENGTH = 3
MIN_SCALE = 0
MAX_SCALE = 8

# Frozen canonical minor-unit exponents (ISO-4217 style, sorted by code).
_CANONICAL_SCALES: dict[str, int] = {
    "AED": 2, "AUD": 2, "BGN": 2, "BHD": 3, "BRL": 2, "CAD": 2,
    "CHF": 2, "CLP": 0, "CNY": 2, "COP": 2, "CZK": 2, "DKK": 2,
    "EGP": 2, "EUR": 2, "GBP": 2, "GHS": 2, "HKD": 2, "HUF": 2,
    "IDR": 2, "ILS": 2, "INR": 2, "ISK": 0, "JOD": 3, "JPY": 0,
    "KES": 2, "KRW": 0, "KWD": 3, "MAD": 2, "MXN": 2, "MYR": 2,
    "NGN": 2, "NOK": 2, "NZD": 2, "OMR": 3, "PHP": 2, "PKR": 2,
    "PLN": 2, "QAR": 2, "RON": 2, "RUB": 2, "SAR": 2, "SEK": 2,
    "SGD": 2, "THB": 2, "TND": 3, "TRY": 2, "TWD": 2, "USD": 2,
    "VND": 0, "ZAR": 2,
}


def _validate_code(code: str) -> str:
    if not isinstance(code, str):
        raise CoreValidationError(f"currency code must be a string, got {type(code).__name__}")
    if (
        len(code) != CURRENCY_CODE_LENGTH
        or not code.isascii()
        or not code.isalpha()
        or not code.isupper()
    ):
        raise CoreValidationError(
            f"currency code must be exactly {CURRENCY_CODE_LENGTH} uppercase ASCII letters, got {code!r}"
        )
    return code


def _validate_scale(scale: int) -> int:
    if not isinstance(scale, int) or isinstance(scale, bool):
        raise CoreValidationError(f"currency scale must be an integer, got {type(scale).__name__}")
    if not MIN_SCALE <= scale <= MAX_SCALE:
        raise CoreValidationError(
            f"currency scale must be between {MIN_SCALE} and {MAX_SCALE}, got {scale!r}"
        )
    return scale


@dataclass(frozen=True, slots=True)
class Currency:
    """A monetary currency with an explicit minor-unit decimal scale."""

    code: str
    scale: int

    def __post_init__(self) -> None:
        _validate_code(self.code)
        _validate_scale(self.scale)
        canonical_scale = _CANONICAL_SCALES.get(self.code)
        if canonical_scale is not None and canonical_scale != self.scale:
            raise CoreValidationError(
                f"currency {self.code} is canonically scale {canonical_scale}; "
                f"refusing conflicting scale {self.scale}"
            )


#: Frozen canonical currency table; the single authority for known codes.
CANONICAL_CURRENCIES: Mapping[str, Currency] = MappingProxyType(
    {code: Currency(code=code, scale=scale) for code, scale in _CANONICAL_SCALES.items()}
)


def get_currency(code: str) -> Currency:
    """Resolve a currency from the frozen canonical table, failing closed."""
    _validate_code(code)
    currency = CANONICAL_CURRENCIES.get(code)
    if currency is None:
        raise CoreValidationError(f"unknown canonical currency code: {code}")
    return currency
