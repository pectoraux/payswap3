"""Intent-side funding binding over opaque funding source references.

The ``FundingSource`` value object belongs to the value family owned by
WORK-005 (``src/value``); this domain must not reproduce it. The intent
domain only declares the ordered binding of funding sources an intent
authorizes for fulfillment: opaque references plus optional per-source caps
declared in the intent amount's asset and scale. Cross-scale or cross-asset
conversion of caps is money-domain work (WORK-006) and is rejected here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError

from .amount import Amount
from .validation import require_identifier, strict_fields


@dataclass(frozen=True, slots=True)
class FundingSourceRef:
    """An opaque, ordered reference to a funding source owned by the value domain."""

    source_id: str
    cap: Amount | None = None

    def __post_init__(self) -> None:
        require_identifier("funding.source_id", self.source_id)
        if self.cap is not None and not isinstance(self.cap, Amount):
            raise CoreValidationError("funding.cap must be an Amount")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "cap": None if self.cap is None else self.cap.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FundingSourceRef":
        strict_fields("funding source reference", value, {"source_id", "cap"})
        cap = value["cap"]
        if cap is not None:
            cap = Amount.from_dict(cap)
        return cls(source_id=value["source_id"], cap=cap)


@dataclass(frozen=True, slots=True)
class FundingBinding:
    """Immutable ordered funding binding; tuple order is the priority order."""

    sources: tuple[FundingSourceRef, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.sources, tuple):
            raise CoreValidationError("funding.sources must be a tuple")
        if not self.sources:
            raise CoreValidationError(
                "funding.sources must declare at least one funding source"
            )
        source_ids = []
        for ref in self.sources:
            if not isinstance(ref, FundingSourceRef):
                raise CoreValidationError("funding.sources entries must be FundingSourceRef")
            source_ids.append(ref.source_id)
        if len(set(source_ids)) != len(source_ids):
            raise CoreValidationError(
                "funding.sources must not repeat a funding source"
            )

    @classmethod
    def build(cls, sources: Iterable[FundingSourceRef]) -> "FundingBinding":
        if not isinstance(sources, (list, tuple)):
            raise CoreValidationError("funding sources must be provided as a sequence")
        return cls(sources=tuple(sources))

    def to_dict(self) -> dict[str, Any]:
        return {"sources": [ref.to_dict() for ref in self.sources]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FundingBinding":
        strict_fields("funding binding", value, {"sources"})
        sources = value["sources"]
        if not isinstance(sources, list):
            raise CoreValidationError("funding.sources must deserialize from an array")
        return cls(sources=tuple(FundingSourceRef.from_dict(item) for item in sources))
