"""Corridors: the asset pair a liquidity or credit commitment serves.

A corridor is a declarative pair of opaque value-domain asset references:
the source asset (in which capacity, limits and exposure are denominated)
and the target asset the payment flows terminate in. Corridors carry no
 FX semantics — conversion belongs to the money domain (WORK-006) — they
are pure grouping keys for bounded liquidity, credit and exposure
control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ._validation import require_identifier, strict_fields

CORRIDOR_FIELDS = frozenset({"source_asset", "target_asset"})


@dataclass(frozen=True, slots=True)
class Corridor:
    """A payment corridor between two opaque asset references.

    ``[source_asset, target_asset)``-style flow: liquidity capacity, credit
    limits and exposure limits are denominated in ``source_asset``'s
    currency; the derived ``corridor_id`` is the canonical grouping key
    used by aggregation and concentration controls.
    """

    source_asset: str
    target_asset: str

    def __post_init__(self) -> None:
        require_identifier("corridor.source_asset", self.source_asset)
        require_identifier("corridor.target_asset", self.target_asset)

    @property
    def corridor_id(self) -> str:
        """Canonical deterministic grouping key of this corridor."""
        return f"{self.source_asset}->{self.target_asset}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_asset": self.source_asset,
            "target_asset": self.target_asset,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Corridor":
        strict_fields("corridor", value, CORRIDOR_FIELDS)
        return cls(
            source_asset=value["source_asset"],
            target_asset=value["target_asset"],
        )
