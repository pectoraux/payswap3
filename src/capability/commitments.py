"""Capability commitments: provider commitments bound to operating windows.

A capability commitment is a STATEFUL declarative record: the provider
commits capacity and a service level for an explicit operating window that
must be contained in a single operating window of an ACTIVE capability.
The lifecycle mirrors the frozen v0.1 command family for commitments
(Create/Amend/Cancel/Expire/RecordBreach) with explicit terminal states.

Expiry and breach are evaluated only against explicit timestamps and
records supplied by the caller — never wall-clock time, never external
providers, never side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from ..core.envelope import ObjectEnvelope, Provenance
from ..core.errors import CoreValidationError
from ..core.relationships import Relationship, RelationshipType
from ..core.serialization import canonical_json, loads_canonical

from ._validation import (
    parse_enum,
    require_internal_id,
    require_positive_int,
    require_text,
)
from .records import GOVERNING_PROTOCOL_VERSION, CapabilityRecord, CapabilityState, classify_environment
from .windows import OperatingWindow, parse_utc_timestamp, validate_utc_timestamp

COMMITMENT_OBJECT_TYPE = "capability/commitment/v1"

_TERMS_FIELDS = frozenset({"window", "capacity_units", "service_level"})
_SERVICE_LEVEL_FIELDS = frozenset({"max_latency_seconds", "availability_floor_basis_points"})
_BREACH_FIELDS = frozenset({"reason", "occurred_at", "description", "evidence_refs"})
_COMMITMENT_FIELDS = frozenset({"capability_id", "terms", "breach"})


class CommitmentState(StrEnum):
    """Closed commitment lifecycle: ACTIVE then an explicit terminal state."""

    ACTIVE = "ACTIVE"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    BREACHED = "BREACHED"


COMMITMENT_TRANSITIONS: Mapping[CommitmentState, frozenset[CommitmentState]] = {
    CommitmentState.ACTIVE: frozenset(
        {CommitmentState.CANCELLED, CommitmentState.EXPIRED, CommitmentState.BREACHED}
    ),
    CommitmentState.CANCELLED: frozenset(),
    CommitmentState.EXPIRED: frozenset(),
    CommitmentState.BREACHED: frozenset(),
}


class BreachReason(StrEnum):
    """Closed internal vocabulary of commitment breach causes."""

    AVAILABILITY = "availability"
    LATENCY = "latency"
    CAPACITY = "capacity"
    QUALITY = "quality"
    COMPLIANCE = "compliance"


@dataclass(frozen=True, slots=True)
class ServiceLevel:
    """Deterministic service-level bounds using scaled integers only."""

    max_latency_seconds: int
    availability_floor_basis_points: int

    def __post_init__(self) -> None:
        require_positive_int("service level max_latency_seconds", self.max_latency_seconds)
        if not isinstance(self.availability_floor_basis_points, int) or isinstance(
            self.availability_floor_basis_points, bool
        ):
            raise CoreValidationError(
                "service level availability_floor_basis_points must be an integer"
            )
        if not 0 <= self.availability_floor_basis_points <= 10000:
            raise CoreValidationError(
                "service level availability_floor_basis_points must be within 0..10000 basis points"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_latency_seconds": self.max_latency_seconds,
            "availability_floor_basis_points": self.availability_floor_basis_points,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ServiceLevel":
        if not isinstance(value, Mapping):
            raise CoreValidationError("service level must be an object")
        if set(value) != _SERVICE_LEVEL_FIELDS:
            raise CoreValidationError("service level fields are not canonical")
        return cls(
            max_latency_seconds=value["max_latency_seconds"],
            availability_floor_basis_points=value["availability_floor_basis_points"],
        )


@dataclass(frozen=True, slots=True)
class CommitmentTerms:
    """Committed capacity and service level bounded by an explicit window."""

    window: OperatingWindow
    capacity_units: int
    service_level: ServiceLevel | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.window, OperatingWindow):
            raise CoreValidationError("commitment terms window must be an OperatingWindow")
        require_positive_int("commitment capacity_units", self.capacity_units)
        if self.service_level is not None and not isinstance(self.service_level, ServiceLevel):
            raise CoreValidationError("commitment service_level must be a ServiceLevel")

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window.to_dict(),
            "capacity_units": self.capacity_units,
            "service_level": None if self.service_level is None else self.service_level.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CommitmentTerms":
        if not isinstance(value, Mapping):
            raise CoreValidationError("commitment terms must be an object")
        if set(value) != _TERMS_FIELDS:
            missing = sorted(_TERMS_FIELDS - set(value))
            extra = sorted(set(value) - _TERMS_FIELDS)
            raise CoreValidationError(
                f"commitment terms fields are not canonical; missing={missing}, extra={extra}"
            )
        service_level = value["service_level"]
        if service_level is not None and not isinstance(service_level, Mapping):
            raise CoreValidationError("commitment service_level must be an object or null")
        return cls(
            window=OperatingWindow.from_dict(value["window"]),
            capacity_units=value["capacity_units"],
            service_level=(
                None if service_level is None else ServiceLevel.from_dict(service_level)
            ),
        )


@dataclass(frozen=True, slots=True)
class BreachRecord:
    """Explicit record of one commitment breach event."""

    reason: BreachReason
    occurred_at: str
    description: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.reason, BreachReason):
            raise CoreValidationError("breach reason must use the closed vocabulary")
        validate_utc_timestamp("breach occurred_at", self.occurred_at)
        require_text("breach description", self.description)
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("breach evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            require_text("breach evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "occurred_at": self.occurred_at,
            "description": self.description,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BreachRecord":
        if not isinstance(value, Mapping):
            raise CoreValidationError("breach record must be an object")
        if set(value) != _BREACH_FIELDS:
            missing = sorted(_BREACH_FIELDS - set(value))
            extra = sorted(set(value) - _BREACH_FIELDS)
            raise CoreValidationError(
                f"breach record fields are not canonical; missing={missing}, extra={extra}"
            )
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError("breach evidence_refs must deserialize from a list")
        return cls(
            reason=parse_enum("breach reason", BreachReason, value["reason"]),
            occurred_at=value["occurred_at"],
            description=value["description"],
            evidence_refs=tuple(refs),
        )


@dataclass(frozen=True, slots=True)
class CapabilityCommitment:
    """Immutable, sealed capability commitment record."""

    envelope: ObjectEnvelope
    capability_id: str
    terms: CommitmentTerms
    breach: BreachRecord | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("commitment envelope must be an ObjectEnvelope")
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"commitment {self.envelope.object_id} must be sealed with with_integrity_hash() before storage"
            )
        if self.envelope.object_type != COMMITMENT_OBJECT_TYPE:
            if self.envelope.object_type.startswith("payswap/"):
                raise CoreValidationError(
                    "commitment object_type must not claim a registry-governed protocol-visible "
                    f"type; commitments use the internal type {COMMITMENT_OBJECT_TYPE}"
                )
            raise CoreValidationError(
                f"commitment object_type must be exactly {COMMITMENT_OBJECT_TYPE}"
            )
        if self.envelope.protocol_version != GOVERNING_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"commitment protocol_version must be the frozen {GOVERNING_PROTOCOL_VERSION}"
            )
        self._parse_state()
        classify_environment(self.envelope.environment_id)
        require_internal_id("commitment capability_id", self.capability_id)
        if not isinstance(self.terms, CommitmentTerms):
            raise CoreValidationError("commitment terms must be CommitmentTerms")
        if self.breach is not None and not isinstance(self.breach, BreachRecord):
            raise CoreValidationError("commitment breach must be a BreachRecord")
        if (self.breach is not None) != (self.state is CommitmentState.BREACHED):
            raise CoreValidationError(
                "a breach record is present exactly when the commitment is BREACHED"
            )

    def _parse_state(self) -> CommitmentState:
        return parse_enum("commitment state", CommitmentState, self.envelope.state)

    @property
    def state(self) -> CommitmentState:
        return self._parse_state()

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": {
                "capability_id": self.capability_id,
                "terms": self.terms.to_dict(),
                "breach": None if self.breach is None else self.breach.to_dict(),
            },
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityCommitment":
        if not isinstance(value, Mapping):
            raise CoreValidationError("commitment record must be an object")
        if set(value) != {"envelope", "payload"}:
            raise CoreValidationError(
                "commitment record fields are not canonical; expected exactly 'envelope' and 'payload'"
            )
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        payload = value["payload"]
        if not isinstance(payload, Mapping):
            raise CoreValidationError("commitment payload must be an object")
        if set(payload) != _COMMITMENT_FIELDS:
            missing = sorted(_COMMITMENT_FIELDS - set(payload))
            extra = sorted(set(payload) - _COMMITMENT_FIELDS)
            raise CoreValidationError(
                f"commitment payload fields are not canonical; missing={missing}, extra={extra}"
            )
        breach = payload["breach"]
        if breach is not None and not isinstance(breach, Mapping):
            raise CoreValidationError("commitment breach must be an object or null")
        return cls(
            envelope=envelope,
            capability_id=payload["capability_id"],
            terms=CommitmentTerms.from_dict(payload["terms"]),
            breach=None if breach is None else BreachRecord.from_dict(breach),
        )

    @classmethod
    def from_json(cls, value: str) -> "CapabilityCommitment":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("commitment record JSON must decode to an object")
        return cls.from_dict(decoded)

    def _advance(
        self,
        new_state: CommitmentState,
        *,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        **payload_changes: Any,
    ) -> "CapabilityCommitment":
        if new_state == self.state:
            if not COMMITMENT_TRANSITIONS[self.state]:
                raise CoreValidationError(
                    f"commitment is in the terminal state {self.state.value}"
                )
        elif new_state not in COMMITMENT_TRANSITIONS[self.state]:
            raise CoreValidationError(
                f"commitment cannot transition from {self.state.value} to {new_state.value}"
            )
        envelope_changes: dict[str, Any] = {"state": new_state.value}
        if causation_id is not None:
            envelope_changes["causation_id"] = causation_id
        if correlation_id is not None:
            envelope_changes["correlation_id"] = correlation_id
        envelope = self.envelope.next_version(**envelope_changes).with_integrity_hash()
        return replace(self, envelope=envelope, **payload_changes)


# -- commitment commands (Create/Amend/Cancel/Expire/RecordBreach) --------


def _ensure_window_supported(capability: CapabilityRecord, window: OperatingWindow) -> None:
    opens = parse_utc_timestamp("commitment window opens_at", window.opens_at)
    closes = parse_utc_timestamp("commitment window closes_at", window.closes_at)
    for operating_window in capability.operating_windows:
        if (
            parse_utc_timestamp("operating window opens_at", operating_window.opens_at) <= opens
            and closes
            <= parse_utc_timestamp("operating window closes_at", operating_window.closes_at)
        ):
            return
    raise CoreValidationError(
        f"commitment window {window.opens_at}..{window.closes_at} is not contained in any single "
        f"operating window of capability {capability.envelope.object_id}"
    )


def create_commitment(
    *,
    object_id: str,
    capability: CapabilityRecord,
    terms: CommitmentTerms,
    issuer: str,
    source: str,
    recorded_at: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityCommitment:
    """Create an ACTIVE commitment against an ACTIVE capability."""
    require_internal_id("commitment object_id", object_id)
    if capability.state is not CapabilityState.ACTIVE:
        raise CoreValidationError(
            f"capability must be ACTIVE to receive commitments; current state is "
            f"{capability.state.value}"
        )
    if not isinstance(terms, CommitmentTerms):
        raise CoreValidationError("commitment terms must be CommitmentTerms")
    _ensure_window_supported(capability, terms.window)
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type=COMMITMENT_OBJECT_TYPE,
        object_version=1,
        environment_id=capability.envelope.environment_id,
        domain_id=capability.envelope.domain_id,
        schema_version=1,
        protocol_version=GOVERNING_PROTOCOL_VERSION,
        state=CommitmentState.ACTIVE.value,
        provenance=Provenance(issuer=issuer, source=source, recorded_at=recorded_at),
        causation_id=causation_id,
        correlation_id=correlation_id,
    ).with_integrity_hash()
    return CapabilityCommitment(
        envelope=envelope,
        capability_id=capability.envelope.object_id,
        terms=terms,
    )


def amend_commitment(
    commitment: CapabilityCommitment,
    *,
    capability: CapabilityRecord,
    terms: CommitmentTerms,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityCommitment:
    """Amend the terms of an ACTIVE commitment (new immutable version)."""
    if commitment.state is not CommitmentState.ACTIVE:
        raise CoreValidationError(
            f"commitment must be ACTIVE to amend; current state is {commitment.state.value}"
        )
    if capability.state is not CapabilityState.ACTIVE:
        raise CoreValidationError(
            f"capability must be ACTIVE to amend its commitments; current state is "
            f"{capability.state.value}"
        )
    if commitment.capability_id != capability.envelope.object_id:
        raise CoreValidationError(
            "amendment capability does not match the commitment's capability"
        )
    if not isinstance(terms, CommitmentTerms):
        raise CoreValidationError("commitment terms must be CommitmentTerms")
    _ensure_window_supported(capability, terms.window)
    envelope_changes: dict[str, Any] = {"state": CommitmentState.ACTIVE.value}
    if causation_id is not None:
        envelope_changes["causation_id"] = causation_id
    if correlation_id is not None:
        envelope_changes["correlation_id"] = correlation_id
    envelope = commitment.envelope.next_version(**envelope_changes).with_integrity_hash()
    return replace(commitment, envelope=envelope, terms=terms)


def cancel_commitment(
    commitment: CapabilityCommitment,
    *,
    reason: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityCommitment:
    """Cancel an ACTIVE commitment before its window closes."""
    require_text("cancellation reason", reason)
    return commitment._advance(
        CommitmentState.CANCELLED,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def expire_commitment(
    commitment: CapabilityCommitment,
    *,
    as_of: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityCommitment:
    """Expire an ACTIVE commitment once its window has closed at an explicit timestamp."""
    if commitment.state is not CommitmentState.ACTIVE:
        raise CoreValidationError(
            f"commitment must be ACTIVE to expire; current state is {commitment.state.value}"
        )
    closes_at = parse_utc_timestamp("commitment window closes_at", commitment.terms.window.closes_at)
    if parse_utc_timestamp("as_of", as_of) < closes_at:
        raise CoreValidationError(
            f"commitment window has not closed at {as_of}; use cancel for early termination"
        )
    return commitment._advance(
        CommitmentState.EXPIRED,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def record_commitment_breach(
    commitment: CapabilityCommitment,
    *,
    breach: BreachRecord,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityCommitment:
    """Record an explicit breach of an ACTIVE commitment."""
    if commitment.state is not CommitmentState.ACTIVE:
        raise CoreValidationError(
            f"commitment must be ACTIVE to record a breach; current state is "
            f"{commitment.state.value}"
        )
    if not isinstance(breach, BreachRecord):
        raise CoreValidationError("breach must be a BreachRecord")
    return commitment._advance(
        CommitmentState.BREACHED,
        causation_id=causation_id,
        correlation_id=correlation_id,
        breach=breach,
    )


def build_dependency_relationship(commitment_id: str, capability_id: str) -> Relationship:
    """Commitment DEPENDS_ON capability."""
    require_internal_id("depends_on subject commitment_id", commitment_id)
    require_internal_id("depends_on object capability_id", capability_id)
    return Relationship.build(RelationshipType.DEPENDS_ON, commitment_id, capability_id)
