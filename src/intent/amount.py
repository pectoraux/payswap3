"""Canonical amount declaration for the intent domain.

``Amount`` is the declaration ``integer value + scale + asset`` from the
frozen ledger/posting model. The intent domain declares amounts on intents,
funding caps and economic slack; it performs no monetary arithmetic —
scaling, rounding, conversion and FX are owned by the money domain
(WORK-006). Comparisons inside this domain are limited to same-scale,
same-asset integer bound checks, which need no arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError

from .validation import require_identifier, require_int, strict_fields

# Structural sanity bound. Exact scale and rounding semantics are owned by
# the money domain (WORK-006); this bound only rejects absurd declarations.
MAX_SCALE = 18


@dataclass(frozen=True, slots=True)
class Amount:
    """Immutable scaled-integer amount declaration (no arithmetic surface)."""

    value: int
    scale: int
    asset: str

    def __post_init__(self) -> None:
        require_int("amount.value", self.value, minimum=0)
        require_int("amount.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        require_identifier("amount.asset", self.asset)

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "scale": self.scale, "asset": self.asset}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Amount":
        strict_fields("amount", value, {"value", "scale", "asset"})
        return cls(value=value["value"], scale=value["scale"], asset=value["asset"])
