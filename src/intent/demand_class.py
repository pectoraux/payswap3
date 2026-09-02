"""Demand classes: deterministic DERIVED classification of demand.

Classification dimensions (all declared data, no wall clock):

- ``asset`` — the demanded asset;
- ``urgency`` — a band over the declared completion window width
  (IMMEDIATE <= 3600s < DEADLINE <= 86400s < FLEXIBLE);
- ``shape`` — whether the demand may be fulfilled by split payments.

DemandClass objects are DERIVED: they never outrank their source of truth
(the demand). The class id is derived deterministically from the
dimensions. Object type ``intent/demand-class`` is an internal
(non-registry) identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from .contracts import DEMAND_CLASS_OBJECT_TYPE
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import parse_timestamp, require_identifier, strict_fields

if TYPE_CHECKING:  # pragma: no cover - annotation-only import
    from .demand import Demand

# Urgency band boundaries, in whole seconds of declared window width.
IMMEDIATE_WINDOW_SECONDS = 3600
DEADLINE_WINDOW_SECONDS = 86400


class UrgencyClass(StrEnum):
    IMMEDIATE = "IMMEDIATE"
    DEADLINE = "DEADLINE"
    FLEXIBLE = "FLEXIBLE"


class DemandShape(StrEnum):
    SINGLE = "SINGLE"
    SPLIT = "SPLIT"


class DemandClassState(StrEnum):
    ACTIVE = "ACTIVE"


def window_seconds(earliest_completion: str, latest_completion: str) -> int:
    """Whole-second width of a declared completion window (no clock reads)."""
    earliest = parse_timestamp("demand.earliest_completion", earliest_completion)
    latest = parse_timestamp("demand.latest_completion", latest_completion)
    if latest < earliest:
        raise CoreValidationError(
            "demand.latest_completion must not be earlier than demand.earliest_completion"
        )
    delta = latest - earliest
    # Sub-second components are ignored for banding; the result stays an
    # integer so no floating-point value ever enters the domain.
    return delta.days * 86400 + delta.seconds


def urgency_for_window(earliest_completion: str, latest_completion: str) -> UrgencyClass:
    seconds = window_seconds(earliest_completion, latest_completion)
    if seconds <= IMMEDIATE_WINDOW_SECONDS:
        return UrgencyClass.IMMEDIATE
    if seconds <= DEADLINE_WINDOW_SECONDS:
        return UrgencyClass.DEADLINE
    return UrgencyClass.FLEXIBLE


def demand_class_id(asset: str, urgency: UrgencyClass, shape: DemandShape) -> str:
    """Deterministic internal class id derived from the classification dimensions."""
    require_identifier("demand class asset", asset)
    if not isinstance(urgency, UrgencyClass):
        raise CoreValidationError("demand class urgency must use the closed vocabulary")
    if not isinstance(shape, DemandShape):
        raise CoreValidationError("demand class shape must use the closed vocabulary")
    return f"{DEMAND_CLASS_OBJECT_TYPE}/{asset}/{urgency.value}/{shape.value}"


def _convert_enum(name: str, value: Any, enum_type: type[StrEnum]) -> StrEnum:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError as exc:
            raise CoreValidationError(f"unknown {name} {value!r}") from exc
    raise CoreValidationError(f"{name} must be a string or {enum_type.__name__} member")


@dataclass(frozen=True, slots=True)
class DemandClassSpec:
    """Immutable demand classification dimensions plus the derived class id."""

    asset: str
    urgency: UrgencyClass
    shape: DemandShape
    class_id: str

    def __post_init__(self) -> None:
        require_identifier("demand class asset", self.asset)
        if not isinstance(self.urgency, UrgencyClass):
            raise CoreValidationError(
                "demand class urgency must use the closed vocabulary"
            )
        if not isinstance(self.shape, DemandShape):
            raise CoreValidationError(
                "demand class shape must use the closed vocabulary"
            )
        expected = demand_class_id(self.asset, self.urgency, self.shape)
        if self.class_id != expected:
            raise CoreValidationError(
                f"demand class id must match its classification dimensions; "
                f"expected {expected!r}, got {self.class_id!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_id": self.class_id,
            "asset": self.asset,
            "urgency": self.urgency.value,
            "shape": self.shape.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DemandClassSpec":
        strict_fields(
            "demand class", value, {"class_id", "asset", "urgency", "shape"}
        )
        return cls(
            class_id=value["class_id"],
            asset=value["asset"],
            urgency=_convert_enum("demand class urgency", value["urgency"], UrgencyClass),
            shape=_convert_enum("demand class shape", value["shape"], DemandShape),
        )


@dataclass(frozen=True, slots=True)
class DemandClass:
    """Durable DERIVED demand class (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: DemandClassSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = DEMAND_CLASS_OBJECT_TYPE
    STATE_TYPE = DemandClassState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("demand class envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, DemandClassSpec):
            raise CoreValidationError("demand class spec must be a DemandClassSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != DEMAND_CLASS_OBJECT_TYPE:
            raise CoreValidationError(
                f"demand class object_type must be {DEMAND_CLASS_OBJECT_TYPE!r}"
            )
        try:
            DemandClassState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown demand class state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.class_id:
            raise CoreValidationError(
                "demand class object id must equal its classification-derived class id"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: DemandClassSpec,
        provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "DemandClass":
        if not isinstance(spec, DemandClassSpec):
            raise CoreValidationError("demand class spec must be a DemandClassSpec")
        if object_id != spec.class_id:
            raise CoreValidationError(
                "demand class object_id must equal its classification-derived class_id"
            )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=DEMAND_CLASS_OBJECT_TYPE,
            state=DemandClassState.ACTIVE.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec))

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> DemandClassState:
        return DemandClassState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DemandClass":
        envelope, payload = decode_composite(
            value,
            expected_object_type=DEMAND_CLASS_OBJECT_TYPE,
            state_type=DemandClassState,
        )
        spec = DemandClassSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "DemandClass":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=DEMAND_CLASS_OBJECT_TYPE,
            state_type=DemandClassState,
        )
        spec = DemandClassSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def classify_demand(
    demand: "Demand",
    *,
    environment_id: str,
    domain_id: str,
    provenance,
) -> DemandClass:
    """Derive the demand class of a demand, deterministically from declared data."""
    from .demand import Demand

    if not isinstance(demand, Demand):
        raise CoreValidationError("classify_demand requires a Demand")
    urgency = urgency_for_window(
        demand.spec.earliest_completion, demand.spec.latest_completion
    )
    shape = DemandShape.SPLIT if demand.spec.allow_split else DemandShape.SINGLE
    spec = DemandClassSpec(
        asset=demand.spec.asset,
        urgency=urgency,
        shape=shape,
        class_id=demand_class_id(demand.spec.asset, urgency, shape),
    )
    return DemandClass.build(
        object_id=spec.class_id,
        environment_id=environment_id,
        domain_id=domain_id,
        spec=spec,
        provenance=provenance,
        correlation_id=demand.envelope.correlation_id,
        causation_id=demand.object_id,
    )
