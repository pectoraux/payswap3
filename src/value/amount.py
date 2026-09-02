"""Ledger amounts: ``Amount = integer value + scale + asset``.

Every amount is an exact signed integer of minor units in its asset's
declared scale. The value domain performs the exact same-asset integer
arithmetic the ledger needs (addition, subtraction, negation,
comparisons) — nothing more. Inexact operations (rounding,
quantization, residual allocation) and cross-asset conversion (FX) are
owned by the money domain (WORK-006) and are deliberately absent here;
cross-scale and cross-asset arithmetic fail closed instead of silently
rescaling. Floating-point values are rejected at every boundary,
consistent with the canonical core value domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .contracts import MAX_SCALE
from .validation import require_identifier, require_int, strict_fields

AMOUNT_FIELDS = frozenset({"value", "scale", "asset"})


@dataclass(frozen=True, slots=True)
class Amount:
    """An exact fixed-point ledger amount in minor units of one asset.

    ``value`` is signed so derived positions (net of debits and credits)
    can be represented; legs and holds always carry positive amounts.
    """

    value: int
    scale: int
    asset: str

    def __post_init__(self) -> None:
        require_int("amount.value", self.value)
        require_int("amount.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        require_identifier("amount.asset", self.asset)

    @classmethod
    def zero(cls, asset: str, scale: int) -> "Amount":
        return cls(value=0, scale=scale, asset=asset)

    # -- exact same-asset arithmetic -------------------------------------

    def _require_comparable(self, other: "Amount", operation: str) -> None:
        if not isinstance(other, Amount):
            raise CoreValidationError(
                f"amount {operation} requires an Amount, got {type(other).__name__}"
            )
        if other.asset != self.asset:
            raise CoreValidationError(
                f"amount {operation} requires the same asset; {self.asset} vs {other.asset}"
            )
        if other.scale != self.scale:
            raise CoreValidationError(
                f"amount {operation} requires the same scale; scale conversion is "
                f"money-domain work (WORK-006); {self.scale} vs {other.scale}"
            )

    def add(self, other: "Amount") -> "Amount":
        self._require_comparable(other, "addition")
        return Amount(value=self.value + other.value, scale=self.scale, asset=self.asset)

    def sub(self, other: "Amount") -> "Amount":
        self._require_comparable(other, "subtraction")
        return Amount(value=self.value - other.value, scale=self.scale, asset=self.asset)

    def negate(self) -> "Amount":
        return Amount(value=-self.value, scale=self.scale, asset=self.asset)

    def compare_to(self, other: "Amount") -> int:
        """Total comparison within the same asset and scale."""
        self._require_comparable(other, "comparison")
        if self.value < other.value:
            return -1
        if self.value > other.value:
            return 1
        return 0

    # -- inspection -------------------------------------------------------

    def is_zero(self) -> bool:
        return self.value == 0

    def is_positive(self) -> bool:
        return self.value > 0

    def is_negative(self) -> bool:
        return self.value < 0

    # -- canonical serialization -------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "scale": self.scale, "asset": self.asset}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Amount":
        strict_fields("amount", value, AMOUNT_FIELDS)
        return cls(value=value["value"], scale=value["scale"], asset=value["asset"])

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "Amount":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("amount JSON must decode to an object")
        return cls.from_dict(decoded)
