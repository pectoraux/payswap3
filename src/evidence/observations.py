"""Observations: authoritative records of what was observed, and when.

An :class:`Observation` is an immutable record (the frozen external-entry
command ``RecordObservation``) of one observed value about one subject:
it carries the epistemic type explicitly, the instant the world was
observed (``observed_at``), and a half-open validity window
``[valid_from, valid_until)`` during which the observation is fresh.
Observations record what was observed — they never claim to be
authoritative about the outside world; the observation is the protocol's
typed record of an external observation event.

Observations have no lifecycle commands: the vocabulary is the single
``RECORDED`` state and the record is immutable forever (corrections are
new observations, never mutations — constitution invariant 17).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    OBSERVATION_OBJECT_TYPE,
    EpistemicType,
    ScaledValue,
)
from ._validation import (
    parse_enum,
    require_identifier,
    require_utc_timestamp,
    require_utc_timestamp_order,
    require_utc_timestamp_strictly_after,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_OBSERVATION_SPEC_FIELDS = frozenset(
    {
        "subject_ref",
        "epistemic_type",
        "observed_at",
        "valid_from",
        "valid_until",
        "value",
    }
)


class ObservationState(StrEnum):
    """Closed lifecycle vocabulary of an observation (immutable record)."""

    RECORDED = "RECORDED"


@dataclass(frozen=True, slots=True)
class ObservationSpec:
    """Immutable observation payload.

    The epistemic type is carried explicitly on every observation record
    (constitution §3): an observation of type ``OBSERVED`` records a live
    world observation; ``PREDICTED``/``SIMULATED``/``COUNTERFACTUAL``
    observations are generated knowledge from the forecast/simulation
    worlds driven through the same machine. Freshness is explicit and
    half-open: the observation is fresh at ``as_of`` exactly when
    ``valid_from <= as_of < valid_until`` — never computed from a clock.
    """

    subject_ref: str
    epistemic_type: EpistemicType
    observed_at: str
    valid_from: str
    valid_until: str
    value: ScaledValue

    def __post_init__(self) -> None:
        require_identifier("observation.subject_ref", self.subject_ref)
        parse_enum("observation epistemic type", EpistemicType, self.epistemic_type)
        require_utc_timestamp("observation.observed_at", self.observed_at)
        require_utc_timestamp("observation.valid_from", self.valid_from)
        require_utc_timestamp("observation.valid_until", self.valid_until)
        # the validity window may not open before the observation instant
        require_utc_timestamp_order(
            "observation.observed_at", self.observed_at,
            "observation.valid_from", self.valid_from,
        )
        # half-open window: valid_until strictly after valid_from (a
        # non-empty window [valid_from, valid_until))
        require_utc_timestamp_strictly_after(
            "observation.valid_from", self.valid_from,
            "observation.valid_until", self.valid_until,
        )
        if not isinstance(self.value, ScaledValue):
            raise CoreValidationError("observation.value must be a ScaledValue")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref": self.subject_ref,
            "epistemic_type": self.epistemic_type.value,
            "observed_at": self.observed_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "value": self.value.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationSpec":
        strict_fields("observation", value, _OBSERVATION_SPEC_FIELDS)
        return cls(
            subject_ref=value["subject_ref"],
            epistemic_type=parse_enum(
                "observation epistemic type", EpistemicType, value["epistemic_type"]
            ),
            observed_at=value["observed_at"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            value=ScaledValue.from_dict(value["value"]),
        )


@dataclass(frozen=True, slots=True)
class Observation:
    """Durable observation record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ObservationSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = OBSERVATION_OBJECT_TYPE
    STATE_TYPE = ObservationState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("observation envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ObservationSpec):
            raise CoreValidationError("observation spec must be an ObservationSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != OBSERVATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"observation object_type must be {OBSERVATION_OBJECT_TYPE!r}"
            )
        try:
            ObservationState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown observation state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ObservationState:
        return ObservationState(self.envelope.state)

    @property
    def epistemic_type(self) -> EpistemicType:
        return self.spec.epistemic_type

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Observation":
        envelope, payload = decode_composite(
            value,
            expected_object_type=OBSERVATION_OBJECT_TYPE,
            state_type=ObservationState,
        )
        spec = ObservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Observation":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=OBSERVATION_OBJECT_TYPE,
            state_type=ObservationState,
        )
        spec = ObservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def record_observation(
    *,
    observation_id: str,
    subject_ref: str,
    epistemic_type: EpistemicType,
    observed_at: str,
    valid_from: str,
    valid_until: str,
    value: ScaledValue,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Observation:
    """Record one observation (the frozen ``RecordObservation`` command).

    The epistemic type is declared by the caller and sealed into the
    record: the evidence domain records what was observed and of which
    epistemic kind — it never claims authority over the outside world.
    """
    spec = ObservationSpec(
        subject_ref=subject_ref,
        epistemic_type=parse_enum(
            "observation epistemic type", EpistemicType, epistemic_type
        ),
        observed_at=observed_at,
        valid_from=valid_from,
        valid_until=valid_until,
        value=value,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("observation.observation_id", observation_id),
        object_type=OBSERVATION_OBJECT_TYPE,
        state=ObservationState.RECORDED.value,
        environment_id=require_identifier("observation.environment_id", environment_id),
        domain_id=require_identifier("observation.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return Observation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def observation_is_fresh(observation: Observation, as_of: str) -> bool:
    """Deterministic freshness test against an explicit ``as_of`` instant.

    Half-open semantics: fresh exactly on ``[valid_from, valid_until)``.
    Staleness is computed only from the declared window and the explicit
    ``as_of`` — never from a wall clock.
    """
    _require_observation(observation)
    require_utc_timestamp("observation as_of", as_of)
    return utc_timestamp_within(observation.spec.valid_from, as_of, observation.spec.valid_until)


def require_fresh_observation(observation: Observation, as_of: str) -> None:
    """Fail closed unless the observation is fresh at ``as_of``."""
    if not observation_is_fresh(observation, as_of):
        raise CoreValidationError(
            f"observation {observation.object_id} is not fresh at as_of {as_of} "
            f"(fresh window [{observation.spec.valid_from}, "
            f"{observation.spec.valid_until}))"
        )


def _require_observation(observation: Observation) -> Observation:
    if not isinstance(observation, Observation):
        raise CoreValidationError("operation requires an Observation")
    return observation


def partition_observations_by_epistemic_type(
    observations: Iterable[Observation],
) -> dict[EpistemicType, tuple[Observation, ...]]:
    """Partition observation records by their explicit epistemic type.

    Deterministic: every vocabulary member is present as a key (empty
    tuple when unused) and input order is preserved within each type.
    """
    partition: dict[EpistemicType, list[Observation]] = {
        member: [] for member in EpistemicType
    }
    for observation in observations:
        _require_observation(observation)
        partition[observation.spec.epistemic_type].append(observation)
    return {
        member: tuple(partition[member]) for member in EpistemicType
    }
