"""Frozen public-boundary contracts for the evidence domain (WORK-018).

The evidence domain owns the frozen v0.1 lifecycles of the canonical
"Safety and knowledge" vocabulary ``Evidence``, ``Attestation``,
``Observation`` and ``Uncertainty``. No evidence object type is listed in
the frozen protocol registry (the registry lists protocol-visible
``payswap/...`` object types only), so — following the sibling convention
of ``src/intent``, ``src/capability`` and ``src/market`` — every evidence
object type below uses an internal non-registry ``evidence/...`` format.
No new protocol-visible name is invented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.core.errors import CoreValidationError

# -- typed, versioned public boundary --------------------------------------

EVIDENCE_PROTOCOL_VERSION = "v0.1"
EVIDENCE_SCHEMA_VERSION = 1

# Internal (non-registry) object types of the evidence domain.
EVIDENCE_OBJECT_TYPE = "evidence/evidence/v1"
ATTESTATION_OBJECT_TYPE = "evidence/attestation/v1"
OBSERVATION_OBJECT_TYPE = "evidence/observation/v1"
UNCERTAINTY_OBJECT_TYPE = "evidence/uncertainty/v1"


class EpistemicType(StrEnum):
    """Closed vocabulary of epistemic knowledge types.

    This is the frozen ``simulation.md`` "Epistemic separation" vocabulary
    — ``OBSERVED``, ``ESTIMATED``, ``PREDICTED``, ``SIMULATED`` and
    ``COUNTERFACTUAL`` — carried explicitly on every evidence and
    observation record (constitution §3, "one machine, many worlds": the
    same protocol state machine runs in every world; the epistemic type
    records which kind of knowledge a value is). Mixing types fails
    closed: a simulated value can never masquerade as an observation and
    a predicted value can never be sealed as OBSERVED.
    """

    OBSERVED = "OBSERVED"
    ESTIMATED = "ESTIMATED"
    PREDICTED = "PREDICTED"
    SIMULATED = "SIMULATED"
    COUNTERFACTUAL = "COUNTERFACTUAL"


class PayloadRefKind(StrEnum):
    """Closed vocabulary of typed payload references carried by evidence."""

    OBSERVATION = "OBSERVATION"
    ATTESTATION = "ATTESTATION"
    UNCERTAINTY = "UNCERTAINTY"


class UncertaintyForm(StrEnum):
    """Closed vocabulary of typed uncertainty representations."""

    INTERVAL = "INTERVAL"
    QUANTILES = "QUANTILES"
    BAND = "BAND"


#: Maximum decimal scale of a typed value (minor-unit exponent bound,
#: mirroring the money domain's scale bound).
MAX_SCALE = 18

#: Quantile levels are expressed in basis points of probability.
MAX_QUANTILE_BPS = 10000


@dataclass(frozen=True, slots=True)
class ScaledValue:
    """An exact typed value: integer amount, declared scale, declared unit.

    Evidence-domain values are exact integers in minor units of the
    declared scale, quantifying the declared unit (an asset identifier or
    any opaque measure label). No floating-point value is ever
    constructed: ``value`` must be an ``int`` (booleans rejected), so
    there is no float ambiguity anywhere in the domain.
    """

    value: int
    scale: int
    unit: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise CoreValidationError("typed value must be an exact integer")
        if not isinstance(self.scale, int) or isinstance(self.scale, bool):
            raise CoreValidationError("typed value scale must be an integer")
        if not 0 <= self.scale <= MAX_SCALE:
            raise CoreValidationError(
                f"typed value scale must be between 0 and {MAX_SCALE}"
            )
        if not isinstance(self.unit, str) or not self.unit.strip():
            raise CoreValidationError("typed value unit must be a non-empty string")

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "scale": self.scale, "unit": self.unit}

    @classmethod
    def from_dict(cls, value: object) -> "ScaledValue":
        if not isinstance(value, dict) or set(value) != {"value", "scale", "unit"}:
            raise CoreValidationError(
                "typed value fields are not canonical; expected "
                "{value, scale, unit}"
            )
        return cls(value=value["value"], scale=value["scale"], unit=value["unit"])
