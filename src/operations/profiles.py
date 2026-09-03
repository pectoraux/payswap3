"""Declared resilience profiles (security-risk model, WORK-024).

A :class:`ResilienceProfile` is the DECLARED policy of one critical
service: availability target, degradation/unavailability thresholds,
ordered redundancy targets (failover candidates), the declared recovery
action plan, and recovery point/time objectives (security-risk.md:
"critical services declare availability, capacity, redundancy, recovery
point/time, failover and dependency policies").

Declared data discipline: profiles are sealed configuration validated at
engine construction (the execution engine's adapter-binding precedent) —
they are not journal-derived state and never re-derive sibling state. The
classification function :func:`classify_health` is the single
deterministic mapping from probe evidence to the derived health status,
and it is load-bearing: every incident, degradation, failover and
resolution gate classifies through it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_identifier_tuple,
    require_text,
    strict_fields,
)
from .contracts import (
    RESILIENCE_PROFILE_OBJECT_TYPE,
    HealthStatus,
    RecoveryActionKind,
    require_bps,
)
from .graph import DECLARED_STATE, DependencyRecordState
from .metrics import ProbeResult
from .seal import (
    build_domain_envelope,
    decode_record,
    record_to_dict,
    seal_record,
    verify_composite,
)

_PROFILE_OBJECT_ID_PREFIX = "operations/profile/"

_SPEC_FIELDS = frozenset(
    {
        "service_id",
        "availability_target_bps",
        "degraded_below_bps",
        "unavailable_below_bps",
        "redundancy",
        "recovery_actions",
        "recovery_time_objective_seconds",
        "recovery_point_objective_seconds",
        "note",
    }
)


@dataclass(frozen=True, slots=True)
class ResilienceProfileSpec:
    """Immutable declared resilience policy of one critical service."""

    service_id: str
    availability_target_bps: int
    degraded_below_bps: int
    unavailable_below_bps: int
    redundancy: tuple[str, ...]
    recovery_actions: tuple[str, ...]
    recovery_time_objective_seconds: int
    recovery_point_objective_seconds: int
    note: str

    def __post_init__(self) -> None:
        require_identifier("profile.service_id", self.service_id)
        require_bps("profile.availability_target_bps", self.availability_target_bps)
        require_bps("profile.degraded_below_bps", self.degraded_below_bps)
        require_bps("profile.unavailable_below_bps", self.unavailable_below_bps)
        if not (self.unavailable_below_bps < self.degraded_below_bps):
            raise CoreValidationError(
                "profile thresholds must satisfy "
                f"unavailable_below_bps < degraded_below_bps "
                f"(got {self.unavailable_below_bps} < {self.degraded_below_bps} false); "
                "the classification bands would be empty"
            )
        redundancy = tuple(self.redundancy)
        object.__setattr__(self, "redundancy", redundancy)
        if not redundancy:
            raise CoreValidationError(
                "profile.redundancy must declare at least one failover target "
                "(a critical service without declared redundancy fails closed)"
            )
        for entry in redundancy:
            require_identifier("profile.redundancy entry", entry)
        if len(set(redundancy)) != len(redundancy):
            raise CoreValidationError("profile.redundancy contains duplicates")
        actions = tuple(self.recovery_actions)
        object.__setattr__(self, "recovery_actions", actions)
        if not actions:
            raise CoreValidationError(
                "profile.recovery_actions must declare a non-empty recovery plan"
            )
        for entry in actions:
            parse_enum("profile.recovery_actions entry", entry, RecoveryActionKind)
        if len(set(actions)) != len(actions):
            raise CoreValidationError("profile.recovery_actions contains duplicates")
        require_int(
            "profile.recovery_time_objective_seconds",
            self.recovery_time_objective_seconds,
            minimum=1,
        )
        require_int(
            "profile.recovery_point_objective_seconds",
            self.recovery_point_objective_seconds,
            minimum=0,
        )
        require_text("profile.note", self.note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "availability_target_bps": self.availability_target_bps,
            "degraded_below_bps": self.degraded_below_bps,
            "unavailable_below_bps": self.unavailable_below_bps,
            "redundancy": list(self.redundancy),
            "recovery_actions": list(self.recovery_actions),
            "recovery_time_objective_seconds": self.recovery_time_objective_seconds,
            "recovery_point_objective_seconds": self.recovery_point_objective_seconds,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResilienceProfileSpec":
        strict_fields("profile spec", value, _SPEC_FIELDS)
        return cls(
            service_id=value["service_id"],
            availability_target_bps=value["availability_target_bps"],
            degraded_below_bps=value["degraded_below_bps"],
            unavailable_below_bps=value["unavailable_below_bps"],
            redundancy=tuple(value["redundancy"]),
            recovery_actions=tuple(value["recovery_actions"]),
            recovery_time_objective_seconds=value["recovery_time_objective_seconds"],
            recovery_point_objective_seconds=value["recovery_point_objective_seconds"],
            note=value["note"],
        )


@dataclass(frozen=True, slots=True)
class ResilienceProfile:
    """One sealed resilience profile record (``operations/resilience-profile/v1``)."""

    envelope: Any
    spec: ResilienceProfileSpec
    integrity_hash: str

    def __post_init__(self) -> None:
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.object_id,
            payload_key="spec",
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> str:
        return self.envelope.state

    def to_dict(self) -> dict[str, Any]:
        from .seal import record_to_dict

        return record_to_dict(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResilienceProfile":
        envelope, spec, integrity_hash = decode_record(
            value,
            object_type=RESILIENCE_PROFILE_OBJECT_TYPE,
            state_type=DependencyRecordState,
        )
        return cls(
            envelope=envelope,
            spec=ResilienceProfileSpec.from_dict(spec),
            integrity_hash=integrity_hash,
        )


def make_profile_record(
    *,
    service_id: str,
    availability_target_bps: int,
    degraded_below_bps: int,
    unavailable_below_bps: int,
    redundancy: Iterable[str],
    recovery_actions: Iterable[RecoveryActionKind | str],
    recovery_time_objective_seconds: int,
    recovery_point_objective_seconds: int,
    note: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance | None = None,
) -> ResilienceProfile:
    """Build and seal one declared resilience profile record."""
    spec = ResilienceProfileSpec(
        service_id=service_id,
        availability_target_bps=availability_target_bps,
        degraded_below_bps=degraded_below_bps,
        unavailable_below_bps=unavailable_below_bps,
        redundancy=tuple(redundancy),
        recovery_actions=tuple(recovery_actions),
        recovery_time_objective_seconds=recovery_time_objective_seconds,
        recovery_point_objective_seconds=recovery_point_objective_seconds,
        note=note,
    )
    if provenance is None:
        provenance = Provenance(
            issuer="principal/operations-service",
            source="operations/domain",
            recorded_at="2026-01-01T00:00:00Z",
        )
    envelope = build_domain_envelope(
        object_id=f"{_PROFILE_OBJECT_ID_PREFIX}{service_id}",
        object_type=RESILIENCE_PROFILE_OBJECT_TYPE,
        state=DECLARED_STATE.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
    )
    return ResilienceProfile(
        envelope=envelope, spec=spec, integrity_hash=seal_record(envelope, spec)
    )


def classify_health(
    probe: ProbeResult,
    profile: ResilienceProfile,
    *,
    dependency_service: str | None = None,
) -> HealthStatus:
    """The single deterministic health classification (load-bearing).

    Bands over the probe's declared availability ratio in basis points,
    using the profile's declared thresholds:

    * ``availability_bps >= degraded_below_bps`` → ``HEALTHY``;
    * ``unavailable_below_bps <= availability_bps < degraded_below_bps``
      → ``DEGRADED``;
    * below that → ``UNAVAILABLE``.

    When the caller supplies the dependency's owning service (the graph
    is the declared mapping), a profile of a DIFFERENT service fails
    closed — classification is never performed against the wrong
    service's policy.
    """
    if not isinstance(probe, ProbeResult):
        raise CoreValidationError("classify_health requires a ProbeResult")
    if not isinstance(profile, ResilienceProfile):
        raise CoreValidationError("classify_health requires a ResilienceProfile")
    if dependency_service is not None and dependency_service != profile.spec.service_id:
        raise CoreValidationError(
            f"probe of dependency {probe.dependency_id!r} belongs to service "
            f"{dependency_service!r}; it cannot be classified against the "
            f"profile of service {profile.spec.service_id!r}"
        )
    if probe.availability_bps >= profile.spec.degraded_below_bps:
        return HealthStatus.HEALTHY
    if probe.availability_bps >= profile.spec.unavailable_below_bps:
        return HealthStatus.DEGRADED
    return HealthStatus.UNAVAILABLE
