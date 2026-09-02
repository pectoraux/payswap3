"""Fixed-point monetary amounts: ``integer_value + scale + asset``.

Every amount is an exact signed integer of minor units in its currency's
canonical scale. Arithmetic is exact integer arithmetic (arbitrary
precision, therefore overflow-safe); inexact operations require an
explicit ``RoundingMode`` and never default silently. Floating-point
values are rejected at every boundary, consistent with the canonical core
value domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..core.errors import CoreValidationError
from ..core.serialization import canonical_json, loads_canonical
from .currencies import Currency
from .rounding import RoundingMode, round_ratio

AMOUNT_FIELDS = frozenset({"currency", "scale", "value"})


def _require_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer, got {type(value).__name__}")
    return value


def _require_mode(mode: RoundingMode) -> RoundingMode:
    if not isinstance(mode, RoundingMode):
        raise CoreValidationError(
            f"rounding mode must use the closed RoundingMode vocabulary, got {mode!r}"
        )
    return mode


@dataclass(frozen=True, slots=True)
class Amount:
    """An exact fixed-point monetary amount in minor units of one currency."""

    currency: Currency
    value: int
    scale: int

    def __post_init__(self) -> None:
        if not isinstance(self.currency, Currency):
            raise CoreValidationError(
                f"amount currency must be a Currency, got {type(self.currency).__name__}"
            )
        _require_int("amount value", self.value)
        _require_int("amount scale", self.scale)
        if self.scale != self.currency.scale:
            raise CoreValidationError(
                f"amount scale {self.scale} does not match canonical scale "
                f"{self.currency.scale} of currency {self.currency.code}"
            )

    @classmethod
    def zero(cls, currency: Currency) -> "Amount":
        return cls(currency=currency, value=0, scale=currency.scale)

    # -- exact arithmetic -------------------------------------------------

    def add(self, other: "Amount") -> "Amount":
        self._require_same_currency(other, "addition")
        return Amount(currency=self.currency, value=self.value + other.value, scale=self.scale)

    def sub(self, other: "Amount") -> "Amount":
        self._require_same_currency(other, "subtraction")
        return Amount(currency=self.currency, value=self.value - other.value, scale=self.scale)

    def negate(self) -> "Amount":
        return Amount(currency=self.currency, value=-self.value, scale=self.scale)

    def absolute(self) -> "Amount":
        return Amount(currency=self.currency, value=abs(self.value), scale=self.scale)

    def multiply(self, factor: int) -> "Amount":
        """Exact integer multiplication; never loses precision."""
        _require_int("multiplication factor", factor)
        return Amount(currency=self.currency, value=self.value * factor, scale=self.scale)

    def divide(self, divisor: int, mode: RoundingMode) -> "Amount":
        """Divide by a positive integer with an explicit rounding mode."""
        _require_int("division divisor", divisor)
        if divisor <= 0:
            raise CoreValidationError(f"division divisor must be a positive integer, got {divisor!r}")
        _require_mode(mode)
        return Amount(
            currency=self.currency,
            value=round_ratio(self.value, divisor, mode),
            scale=self.scale,
        )

    def quantize(self, multiple: int, mode: RoundingMode) -> "Amount":
        """Round the minor-unit value to an exact multiple of ``multiple``."""
        _require_int("quantization multiple", multiple)
        if multiple <= 0:
            raise CoreValidationError(
                f"quantization multiple must be a positive integer, got {multiple!r}"
            )
        _require_mode(mode)
        return Amount(
            currency=self.currency,
            value=round_ratio(self.value, multiple, mode) * multiple,
            scale=self.scale,
        )

    # -- inspection -------------------------------------------------------

    def is_zero(self) -> bool:
        return self.value == 0

    def is_positive(self) -> bool:
        return self.value > 0

    def is_negative(self) -> bool:
        return self.value < 0

    def _require_same_currency(self, other: "Amount", operation: str) -> None:
        if not isinstance(other, Amount):
            raise CoreValidationError(
                f"money {operation} requires another Amount, got {type(other).__name__}"
            )
        if other.currency != self.currency:
            raise CoreValidationError(
                f"money {operation} requires the same currency, got "
                f"{self.currency.code} and {other.currency.code}"
            )

    def __lt__(self, other: "Amount") -> bool:
        self._require_same_currency(other, "comparison")
        return self.value < other.value

    def __le__(self, other: "Amount") -> bool:
        self._require_same_currency(other, "comparison")
        return self.value <= other.value

    def __gt__(self, other: "Amount") -> bool:
        self._require_same_currency(other, "comparison")
        return self.value > other.value

    def __ge__(self, other: "Amount") -> bool:
        self._require_same_currency(other, "comparison")
        return self.value >= other.value

    # -- canonical serialization ------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {"currency": self.currency.code, "scale": self.scale, "value": self.value}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Amount":
        if not isinstance(value, Mapping):
            raise CoreValidationError(f"amount must be an object, got {type(value).__name__}")
        if set(value) != AMOUNT_FIELDS:
            missing = sorted(AMOUNT_FIELDS - set(value))
            extra = sorted(set(value) - AMOUNT_FIELDS)
            raise CoreValidationError(
                f"non-canonical amount fields; missing={missing}, extra={extra}"
            )
        scale = _require_int("amount scale", value["scale"])
        currency = Currency(code=value["currency"], scale=scale)
        return cls(currency=currency, value=value["value"], scale=scale)

    @classmethod
    def from_json(cls, value: str) -> "Amount":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("amount JSON must decode to an object")
        return cls.from_dict(decoded)
