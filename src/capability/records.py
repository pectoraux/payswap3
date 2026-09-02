"""Capability records: declarative provider capabilities with verification metadata.

A capability is a versioned, immutable record (sealed ``ObjectEnvelope`` plus
a strictly validated payload) describing what a provider can do, under which
authority tier, in which jurisdictions, within which operating windows, and
with which verification metadata. Capabilities are records, never executors:
this module performs no execution and causes no provider side effects.

Object identity and integrity are owned by the canonical core
(:mod:`src.core`); this module only consumes ``ObjectEnvelope``,
``next_version`` and ``with_integrity_hash``. All validation failures raise
the single core error authority ``CoreValidationError``.

The lifecycle mirrors the frozen v0.1 command family for capabilities
(Register/Verify/Activate/Update/Suspend/Resume/Retire) with an explicit
per-object state machine and fail-closed preconditions.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from ..core.envelope import ObjectEnvelope, Provenance
from ..core.errors import CoreValidationError
from ..core.relationships import Relationship, RelationshipType
from ..core.serialization import canonical_json, loads_canonical

from ._validation import (
    normalize_text_tuple,
    parse_enum,
    require_bool,
    require_internal_id,
    require_jurisdictions,
    require_protocol_versions,
    require_text,
)
from .verification import VerificationMetadata, VerificationResult
from .windows import OperatingWindow, validate_disjoint_windows

CAPABILITY_OBJECT_TYPE = "capability/capability/v1"
GOVERNING_PROTOCOL_VERSION = "v0.1"

PRODUCTION_ENVIRONMENT_PREFIX = "env/production"
SANDBOX_ENVIRONMENT_PREFIX = "env/sandbox"

_RECORD_FIELDS = frozenset(
    {
        "provider_id",
        "kind",
        "description",
        "authority_tier",
        "jurisdictions",
        "protocol_versions",
        "simulation_support",
        "production_support",
        "operating_windows",
        "verification",
    }
)


class CapabilityKind(StrEnum):
    """Closed internal vocabulary of provider capability kinds."""

    PAYMENT_EXECUTION = "payment_execution"
    SETTLEMENT = "settlement"
    LIQUIDITY_PROVISION = "liquidity_provision"
    COMPLIANCE_VERIFICATION = "compliance_verification"


class AuthorityTier(StrEnum):
    """Extension authority tiers R0-R5 (registry-listed authority classes)."""

    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


class CapabilityState(StrEnum):
    """Closed capability lifecycle: CREATED -> ACTIVE -> SUSPENDED -> terminal."""

    REGISTERED = "REGISTERED"
    VERIFIED = "VERIFIED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"


CAPABILITY_TRANSITIONS: Mapping[CapabilityState, frozenset[CapabilityState]] = {
    CapabilityState.REGISTERED: frozenset({CapabilityState.VERIFIED, CapabilityState.RETIRED}),
    CapabilityState.VERIFIED: frozenset({CapabilityState.ACTIVE, CapabilityState.RETIRED}),
    CapabilityState.ACTIVE: frozenset({CapabilityState.SUSPENDED, CapabilityState.RETIRED}),
    CapabilityState.SUSPENDED: frozenset({CapabilityState.ACTIVE, CapabilityState.RETIRED}),
    CapabilityState.RETIRED: frozenset(),
}

# Extensions architecture: reserve/execute/financial-exposure tiers require
# stronger (bounded, evidenced) verification before activation.
STRONGER_VERIFICATION_TIERS = frozenset(
    {AuthorityTier.R3, AuthorityTier.R4, AuthorityTier.R5}
)


def classify_environment(environment_id: str) -> str:
    """Classify an environment id as production or sandbox, failing closed."""
    if environment_id.startswith(PRODUCTION_ENVIRONMENT_PREFIX):
        return "production"
    if environment_id.startswith(SANDBOX_ENVIRONMENT_PREFIX):
        return "sandbox"
    raise CoreValidationError(
        f"environment_id {environment_id!r} must be classified as "
        f"'{PRODUCTION_ENVIRONMENT_PREFIX}*' or '{SANDBOX_ENVIRONMENT_PREFIX}*' "
        "(fail closed on unknown environment class)"
    )


@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    """Immutable, sealed capability record: envelope plus validated payload."""

    envelope: ObjectEnvelope
    provider_id: str
    kind: CapabilityKind
    description: str
    authority_tier: AuthorityTier
    jurisdictions: tuple[str, ...]
    protocol_versions: tuple[str, ...]
    simulation_support: bool
    production_support: bool
    operating_windows: tuple[OperatingWindow, ...]
    verification: VerificationMetadata | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("capability envelope must be an ObjectEnvelope")
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"capability {self.envelope.object_id} must be sealed with with_integrity_hash() before storage"
            )
        if self.envelope.object_type != CAPABILITY_OBJECT_TYPE:
            if self.envelope.object_type.startswith("payswap/"):
                raise CoreValidationError(
                    "capability object_type must not claim a registry-governed protocol-visible "
                    f"type; capabilities use the internal type {CAPABILITY_OBJECT_TYPE}"
                )
            raise CoreValidationError(
                f"capability object_type must be exactly {CAPABILITY_OBJECT_TYPE}"
            )
        if self.envelope.protocol_version != GOVERNING_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"capability protocol_version must be the frozen {GOVERNING_PROTOCOL_VERSION}"
            )
        self._parse_state()
        require_internal_id("capability provider_id", self.provider_id)
        if not isinstance(self.kind, CapabilityKind):
            raise CoreValidationError("capability kind must use the closed vocabulary")
        require_text("capability description", self.description)
        if not isinstance(self.authority_tier, AuthorityTier):
            raise CoreValidationError("capability authority_tier must use the closed vocabulary")
        require_jurisdictions("capability jurisdictions", self.jurisdictions)
        require_protocol_versions(
            "capability protocol_versions", self.protocol_versions, GOVERNING_PROTOCOL_VERSION
        )
        require_bool("capability simulation_support", self.simulation_support)
        require_bool("capability production_support", self.production_support)
        if not self.simulation_support and not self.production_support:
            raise CoreValidationError(
                "capability must declare simulation or production support"
            )
        if not isinstance(self.operating_windows, tuple):
            raise CoreValidationError("capability operating_windows must be a tuple")
        validate_disjoint_windows("capability operating_windows", self.operating_windows)
        if self.verification is not None and not isinstance(self.verification, VerificationMetadata):
            raise CoreValidationError("capability verification must be VerificationMetadata")
        environment_class = classify_environment(self.envelope.environment_id)
        if environment_class == "sandbox" and not self.simulation_support:
            raise CoreValidationError(
                "sandbox-environment capabilities must declare simulation support; "
                "simulation objects never acquire production authority"
            )
        if environment_class == "production" and not self.production_support:
            raise CoreValidationError(
                "production-environment capabilities must declare production support"
            )

    def _parse_state(self) -> CapabilityState:
        return parse_enum("capability state", CapabilityState, self.envelope.state)

    @property
    def state(self) -> CapabilityState:
        return self._parse_state()

    # -- canonical serialization ------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": {
                "provider_id": self.provider_id,
                "kind": self.kind.value,
                "description": self.description,
                "authority_tier": self.authority_tier.value,
                "jurisdictions": list(self.jurisdictions),
                "protocol_versions": list(self.protocol_versions),
                "simulation_support": self.simulation_support,
                "production_support": self.production_support,
                "operating_windows": [window.to_dict() for window in self.operating_windows],
                "verification": None if self.verification is None else self.verification.to_dict(),
            },
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityRecord":
        if not isinstance(value, Mapping):
            raise CoreValidationError("capability record must be an object")
        if set(value) != {"envelope", "payload"}:
            raise CoreValidationError(
                "capability record fields are not canonical; expected exactly 'envelope' and 'payload'"
            )
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        payload = value["payload"]
        if not isinstance(payload, Mapping):
            raise CoreValidationError("capability payload must be an object")
        if set(payload) != _RECORD_FIELDS:
            missing = sorted(_RECORD_FIELDS - set(payload))
            extra = sorted(set(payload) - _RECORD_FIELDS)
            raise CoreValidationError(
                f"capability payload fields are not canonical; missing={missing}, extra={extra}"
            )
        windows = payload["operating_windows"]
        if not isinstance(windows, list):
            raise CoreValidationError("capability operating_windows must deserialize from a list")
        jurisdictions = payload["jurisdictions"]
        if not isinstance(jurisdictions, list):
            raise CoreValidationError("capability jurisdictions must deserialize from a list")
        protocol_versions = payload["protocol_versions"]
        if not isinstance(protocol_versions, list):
            raise CoreValidationError("capability protocol_versions must deserialize from a list")
        verification = payload["verification"]
        if verification is not None and not isinstance(verification, Mapping):
            raise CoreValidationError("capability verification must be an object or null")
        return cls(
            envelope=envelope,
            provider_id=payload["provider_id"],
            kind=parse_enum("capability kind", CapabilityKind, payload["kind"]),
            description=payload["description"],
            authority_tier=parse_enum(
                "capability authority_tier", AuthorityTier, payload["authority_tier"]
            ),
            jurisdictions=tuple(jurisdictions),
            protocol_versions=tuple(protocol_versions),
            simulation_support=payload["simulation_support"],
            production_support=payload["production_support"],
            operating_windows=tuple(OperatingWindow.from_dict(item) for item in windows),
            verification=(
                None if verification is None else VerificationMetadata.from_dict(verification)
            ),
        )

    @classmethod
    def from_json(cls, value: str) -> "CapabilityRecord":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("capability record JSON must decode to an object")
        return cls.from_dict(decoded)

    # -- internal transition machinery ------------------------------------

    def _advance(
        self,
        new_state: CapabilityState,
        *,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        **payload_changes: Any,
    ) -> "CapabilityRecord":
        if new_state == self.state:
            if not CAPABILITY_TRANSITIONS[self.state]:
                raise CoreValidationError(
                    f"capability is in the terminal state {self.state.value}"
                )
        elif new_state not in CAPABILITY_TRANSITIONS[self.state]:
            raise CoreValidationError(
                f"capability cannot transition from {self.state.value} to {new_state.value}"
            )
        envelope_changes: dict[str, Any] = {"state": new_state.value}
        if causation_id is not None:
            envelope_changes["causation_id"] = causation_id
        if correlation_id is not None:
            envelope_changes["correlation_id"] = correlation_id
        envelope = self.envelope.next_version(**envelope_changes).with_integrity_hash()
        return replace(self, envelope=envelope, **payload_changes)

    def _require_operational_readiness(self, as_of: str) -> None:
        """Preconditions shared by activation and resume."""
        if self.verification is None:
            raise CoreValidationError(
                f"capability {self.envelope.object_id} has no verification record"
            )
        if self.verification.result is not VerificationResult.PASSED:
            raise CoreValidationError(
                f"capability {self.envelope.object_id} verification did not pass"
            )
        if not self.verification.is_valid_at(as_of):
            raise CoreValidationError(
                f"capability {self.envelope.object_id} verification expired at {as_of}"
            )
        if self.authority_tier in STRONGER_VERIFICATION_TIERS:
            if self.verification.valid_until is None:
                raise CoreValidationError(
                    f"authority tier {self.authority_tier.value} requires bounded verification validity"
                )
            if not self.verification.evidence_refs:
                raise CoreValidationError(
                    f"authority tier {self.authority_tier.value} requires verification evidence"
                )
        if not self.operating_windows:
            raise CoreValidationError(
                f"capability {self.envelope.object_id} cannot be active without a declared operating window"
            )


# -- capability commands (Register/Verify/Activate/Update/Suspend/Resume/Retire) --


def register_capability(
    *,
    object_id: str,
    provider_id: str,
    kind: CapabilityKind,
    description: str,
    authority_tier: AuthorityTier,
    jurisdictions: Iterable[str],
    protocol_versions: Iterable[str],
    simulation_support: bool,
    production_support: bool,
    operating_windows: Iterable[OperatingWindow],
    environment_id: str,
    domain_id: str,
    issuer: str,
    source: str,
    recorded_at: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Register a new capability record (version 1, state REGISTERED)."""
    require_internal_id("capability object_id", object_id)
    require_text("capability environment_id", environment_id)
    require_text("capability domain_id", domain_id)
    windows = tuple(operating_windows)
    for window in windows:
        if not isinstance(window, OperatingWindow):
            raise CoreValidationError("operating_windows entries must be OperatingWindow values")
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type=CAPABILITY_OBJECT_TYPE,
        object_version=1,
        environment_id=environment_id,
        domain_id=domain_id,
        schema_version=1,
        protocol_version=GOVERNING_PROTOCOL_VERSION,
        state=CapabilityState.REGISTERED.value,
        provenance=Provenance(issuer=issuer, source=source, recorded_at=recorded_at),
        causation_id=causation_id,
        correlation_id=correlation_id,
    ).with_integrity_hash()
    return CapabilityRecord(
        envelope=envelope,
        provider_id=provider_id,
        kind=kind,
        description=description,
        authority_tier=authority_tier,
        jurisdictions=normalize_text_tuple("capability jurisdictions", jurisdictions),
        protocol_versions=normalize_text_tuple("capability protocol_versions", protocol_versions),
        simulation_support=simulation_support,
        production_support=production_support,
        operating_windows=windows,
    )


def apply_verification(
    record: CapabilityRecord,
    verification: VerificationMetadata,
    *,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Record verification metadata; a passing first verification advances REGISTERED -> VERIFIED."""
    if record.state is CapabilityState.RETIRED:
        raise CoreValidationError("retired capabilities cannot be verified")
    if record.state is CapabilityState.REGISTERED and verification.result is VerificationResult.PASSED:
        new_state = CapabilityState.VERIFIED
    else:
        new_state = record.state
    return record._advance(
        new_state,
        causation_id=causation_id,
        correlation_id=correlation_id,
        verification=verification,
    )


def activate_capability(
    record: CapabilityRecord,
    *,
    as_of: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Activate a verified capability at an explicit, deterministic timestamp."""
    if record.state is not CapabilityState.VERIFIED:
        raise CoreValidationError(
            f"capability must be VERIFIED to activate; current state is {record.state.value}"
        )
    record._require_operational_readiness(as_of)
    return record._advance(
        CapabilityState.ACTIVE,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def update_capability(
    record: CapabilityRecord,
    *,
    description: str | None = None,
    jurisdictions: Iterable[str] | None = None,
    protocol_versions: Iterable[str] | None = None,
    simulation_support: bool | None = None,
    production_support: bool | None = None,
    operating_windows: Iterable[OperatingWindow] | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Amend declarative details without changing the lifecycle state.

    Identity, kind, provider and authority tier are structural and cannot be
    updated; verification metadata is owned by ``apply_verification``.
    """
    if record.state is CapabilityState.RETIRED:
        raise CoreValidationError("retired capabilities cannot be updated")
    changes: dict[str, Any] = {}
    if description is not None:
        changes["description"] = description
    if jurisdictions is not None:
        changes["jurisdictions"] = normalize_text_tuple("capability jurisdictions", jurisdictions)
    if protocol_versions is not None:
        changes["protocol_versions"] = normalize_text_tuple(
            "capability protocol_versions", protocol_versions
        )
    if simulation_support is not None:
        changes["simulation_support"] = simulation_support
    if production_support is not None:
        changes["production_support"] = production_support
    if operating_windows is not None:
        windows = tuple(operating_windows)
        for window in windows:
            if not isinstance(window, OperatingWindow):
                raise CoreValidationError("operating_windows entries must be OperatingWindow values")
        changes["operating_windows"] = windows
        if record.state is CapabilityState.ACTIVE and not windows:
            raise CoreValidationError(
                "an active capability cannot drop its declared operating windows"
            )
    updated = replace(record, **changes) if changes else record
    envelope_changes: dict[str, Any] = {"state": record.state.value}
    if causation_id is not None:
        envelope_changes["causation_id"] = causation_id
    if correlation_id is not None:
        envelope_changes["correlation_id"] = correlation_id
    envelope = record.envelope.next_version(**envelope_changes).with_integrity_hash()
    return replace(updated, envelope=envelope)


def suspend_capability(
    record: CapabilityRecord,
    *,
    reason: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Suspend an active capability (explicit reason required)."""
    require_text("suspension reason", reason)
    if record.state is not CapabilityState.ACTIVE:
        raise CoreValidationError(
            f"capability must be ACTIVE to suspend; current state is {record.state.value}"
        )
    return record._advance(
        CapabilityState.SUSPENDED,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def resume_capability(
    record: CapabilityRecord,
    *,
    as_of: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Resume a suspended capability, re-checking verification and windows."""
    if record.state is not CapabilityState.SUSPENDED:
        raise CoreValidationError(
            f"capability must be SUSPENDED to resume; current state is {record.state.value}"
        )
    record._require_operational_readiness(as_of)
    return record._advance(
        CapabilityState.ACTIVE,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def retire_capability(
    record: CapabilityRecord,
    *,
    reason: str,
    active_dependent_commitments: Iterable[str] = (),
    successor_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CapabilityRecord:
    """Retire a capability; active dependent commitments require a governed successor."""
    require_text("retirement reason", reason)
    if record.state is CapabilityState.RETIRED:
        raise CoreValidationError("capability is already retired")
    dependents = normalize_text_tuple("active dependent commitments", active_dependent_commitments)
    for dependent in dependents:
        require_internal_id("active dependent commitment", dependent)
    if dependents and successor_id is None:
        raise CoreValidationError(
            f"capability {record.envelope.object_id} cannot retire while {len(dependents)} "
            "active dependent commitment(s) require it; provide a governed successor capability"
        )
    if successor_id is not None:
        require_internal_id("successor capability id", successor_id)
    return record._advance(
        CapabilityState.RETIRED,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


# -- relationship builders over the core closed vocabulary ----------------


def build_services_relationship(provider_id: str, capability_id: str) -> Relationship:
    """Provider SERVICES capability."""
    require_internal_id("services subject provider_id", provider_id)
    require_internal_id("services object capability_id", capability_id)
    return Relationship.build(RelationshipType.SERVICES, provider_id, capability_id)


def build_attests_relationship(verifier_id: str, capability_id: str) -> Relationship:
    """Verifier ATTESTS capability verification."""
    require_internal_id("attests subject verifier_id", verifier_id)
    require_internal_id("attests object capability_id", capability_id)
    return Relationship.build(RelationshipType.ATTESTS, verifier_id, capability_id)


def build_authorizes_relationship(principal_id: str, capability_id: str) -> Relationship:
    """Principal AUTHORIZES capability activation."""
    require_internal_id("authorizes subject principal_id", principal_id)
    require_internal_id("authorizes object capability_id", capability_id)
    return Relationship.build(RelationshipType.AUTHORIZES, principal_id, capability_id)
