"""Incident records and lifecycle facts (WORK-024).

The :class:`Incident` record (``operations/incident/v1``) is the STATEFUL
lifecycle object driven by the frozen v0.1 ``Operations`` command family
``DeclareDegradation/Failover/Incident/Emergency/Resolve``: exactly one
incident is advanced by each accepted command, appending typed facts
(degradation, failover, emergency, resolution) to its immutable spec and
sealing every version with the single canonical hash authority.

Every fact is EVIDENCE-BOUND, not payload-trusted: degradation facts bind
the fresh probe digest that classifies the severity, failover facts bind
the redundancy target's healthy probe digest and the conserved
affected-authority digests, emergency facts bind an explicit window and
scope, and resolution facts bind the recovery action records, the fresh
healthy probes and the journal-only rebuild evidence that proves no
authoritative state was lost (authority conservation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

from ._validation import (
    elapsed_seconds,
    parse_enum,
    require_digest,
    require_identifier,
    require_identifier_tuple,
    require_int,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .contracts import (
    INCIDENT_OBJECT_TYPE,
    DEGRADATION_SEVERITY_ORDER,
    DegradationSeverity,
    IncidentState,
    RecoveryActionKind,
)
from .seal import (
    build_domain_envelope,
    decode_record,
    record_to_dict,
    seal_record,
    verify_composite,
)

# -- typed evidence pairs ---------------------------------------------------

_AUTHORITY_DIGEST_FIELDS = frozenset({"authority_ref", "digest"})

#: Field set of one authority-rebuild evidence record.
_AUTHORITY_REBUILD_FIELDS = frozenset(
    {"authority_ref", "live_index_digest", "rebuilt_index_digest"}
)


@dataclass(frozen=True, slots=True)
class AuthorityRebuild:
    """Journal-only rebuild evidence for one affected authority.

    ``live_index_digest``/``rebuilt_index_digest`` are canonical digests
    over an authority's public record index (the caller computes both
    through the sibling's public boundary — e.g. the engine's
    ``records()``/``objects()`` accessors). The resolve gate requires
    equality: the authority must be reproducible from its journal alone,
    proving no silent state loss (constitution invariant 12 — all
    material outcomes are reconcilable).
    """

    authority_ref: str
    live_index_digest: str
    rebuilt_index_digest: str

    def __post_init__(self) -> None:
        require_identifier("authority rebuild authority_ref", self.authority_ref)
        require_digest("authority rebuild live_index_digest", self.live_index_digest)
        require_digest("authority rebuild rebuilt_index_digest", self.rebuilt_index_digest)
        if self.live_index_digest != self.rebuilt_index_digest:
            raise CoreValidationError(
                f"authority conservation gate for {self.authority_ref!r}: the "
                "journal-only rebuild index digest diverges from the live index "
                "digest — authoritative state was lost or diverged, and divergent "
                "rebuild evidence fails closed at construction (the resolve gate "
                "re-verifies it on the command path)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_ref": self.authority_ref,
            "live_index_digest": self.live_index_digest,
            "rebuilt_index_digest": self.rebuilt_index_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityRebuild":
        strict_fields("authority rebuild", value, _AUTHORITY_REBUILD_FIELDS)
        return cls(
            authority_ref=value["authority_ref"],
            live_index_digest=value["live_index_digest"],
            rebuilt_index_digest=value["rebuilt_index_digest"],
        )


@dataclass(frozen=True, slots=True)
class RecoveryActionRecord:
    """One executed recovery action (orchestration evidence).

    The action kind comes from the closed vocabulary; ``authority_ref``
    names the authority the action touched through its public boundary
    (``None`` for pure observation actions such as REPROBE); the record is
    declarative evidence — the orchestration itself happened through the
    sibling's public APIs before the resolve command was submitted.
    """

    action: RecoveryActionKind
    authority_ref: str | None
    detail: str
    at: str

    def __post_init__(self) -> None:
        action = parse_enum("recovery action", self.action, RecoveryActionKind)
        object.__setattr__(self, "action", action)
        if self.authority_ref is not None:
            require_identifier("recovery action authority_ref", self.authority_ref)
        require_text("recovery action detail", self.detail)
        require_utc_timestamp("recovery action at", self.at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "authority_ref": self.authority_ref,
            "detail": self.detail,
            "at": self.at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecoveryActionRecord":
        strict_fields(
            "recovery action record", value, _RECOVERY_ACTION_FIELDS
        )
        return cls(
            action=RecoveryActionKind(value["action"]),
            authority_ref=value["authority_ref"],
            detail=value["detail"],
            at=value["at"],
        )


_RECOVERY_ACTION_FIELDS = frozenset({"action", "authority_ref", "detail", "at"})

# -- lifecycle facts --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DegradationFact:
    """One declared degradation (severity, scope and affected authorities)."""

    severity: str
    probe_digest: str
    probe_as_of: str
    affected_dependencies: tuple[str, ...]
    affected_authorities: tuple[tuple[str, str], ...]
    observed_at: str
    detail: str

    def __post_init__(self) -> None:
        severity = parse_enum("degradation severity", self.severity, DegradationSeverity)
        object.__setattr__(self, "severity", severity.value)
        require_digest("degradation probe_digest", self.probe_digest)
        require_utc_timestamp("degradation probe_as_of", self.probe_as_of)
        object.__setattr__(
            self, "affected_dependencies", require_identifier_tuple(
                "degradation affected_dependencies", self.affected_dependencies
            )
        )
        object.__setattr__(
            self, "affected_authorities", _normalize_authority_digests(
                self.affected_authorities
            )
        )
        require_utc_timestamp("degradation observed_at", self.observed_at)
        require_text("degradation detail", self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "probe_digest": self.probe_digest,
            "probe_as_of": self.probe_as_of,
            "affected_dependencies": list(self.affected_dependencies),
            "affected_authorities": [
                list(pair) for pair in self.affected_authorities
            ],
            "observed_at": self.observed_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DegradationFact":
        strict_fields("degradation fact", value, _DEGRADATION_FACT_FIELDS)
        return cls(
            severity=value["severity"],
            probe_digest=value["probe_digest"],
            probe_as_of=value["probe_as_of"],
            affected_dependencies=tuple(value["affected_dependencies"]),
            affected_authorities=tuple(
                tuple(pair) for pair in value["affected_authorities"]
            ),
            observed_at=value["observed_at"],
            detail=value["detail"],
        )


_DEGRADATION_FACT_FIELDS = frozenset(
    {
        "severity",
        "probe_digest",
        "probe_as_of",
        "affected_dependencies",
        "affected_authorities",
        "observed_at",
        "detail",
    }
)

_ADAPTER_CONTRACT_FIELDS = frozenset(
    {"adapter_id", "fidelity_class", "effect_operations"}
)

#: The interoperability domain's closed effect-capable fidelity classes
#: (the single fidelity authority, consumed — never redefined here).
_EFFECT_CAPABLE_FIDELITY = frozenset({"SIMULATION", "PRODUCTION"})


@dataclass(frozen=True, slots=True)
class FailoverFact:
    """One executed failover onto a declared redundancy target."""

    from_dependency: str
    target_dependency: str
    target_probe_digest: str
    target_probe_as_of: str
    adapter_contract: dict[str, Any]
    authority_digests: tuple[tuple[str, str], ...]
    executed_at: str
    detail: str

    def __post_init__(self) -> None:
        require_identifier("failover from_dependency", self.from_dependency)
        require_identifier("failover target_dependency", self.target_dependency)
        if self.from_dependency == self.target_dependency:
            raise CoreValidationError(
                "failover target must differ from the failed dependency"
            )
        require_digest("failover target_probe_digest", self.target_probe_digest)
        require_utc_timestamp("failover target_probe_as_of", self.target_probe_as_of)
        contract = dict(self.adapter_contract)
        strict_fields("failover adapter_contract", contract, _ADAPTER_CONTRACT_FIELDS)
        object.__setattr__(self, "adapter_contract", contract)
        require_identifier("failover adapter_id", contract["adapter_id"])
        require_text("failover fidelity_class", contract["fidelity_class"])
        if contract["fidelity_class"] not in _EFFECT_CAPABLE_FIDELITY:
            raise CoreValidationError(
                f"failover target adapter {contract['adapter_id']!r} declares "
                f"fidelity class {contract['fidelity_class']!r}, which is not "
                "effect-capable; failover onto a pure observation adapter fails "
                "closed (the interoperability domain's fidelity contract)"
            )
        operations = tuple(contract["effect_operations"])
        if not operations:
            raise CoreValidationError(
                "failover target adapter declares an empty effect interface; "
                "execution submission requires an effect-capable adapter"
            )
        for entry in operations:
            require_identifier("failover effect operation", entry)
        object.__setattr__(
            self, "authority_digests", _normalize_authority_digests(self.authority_digests)
        )
        require_utc_timestamp("failover executed_at", self.executed_at)
        require_text("failover detail", self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_dependency": self.from_dependency,
            "target_dependency": self.target_dependency,
            "target_probe_digest": self.target_probe_digest,
            "target_probe_as_of": self.target_probe_as_of,
            "adapter_contract": dict(self.adapter_contract),
            "authority_digests": [list(pair) for pair in self.authority_digests],
            "executed_at": self.executed_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FailoverFact":
        strict_fields("failover fact", value, _FAILOVER_FACT_FIELDS)
        return cls(
            from_dependency=value["from_dependency"],
            target_dependency=value["target_dependency"],
            target_probe_digest=value["target_probe_digest"],
            target_probe_as_of=value["target_probe_as_of"],
            adapter_contract=dict(value["adapter_contract"]),
            authority_digests=tuple(
                tuple(pair) for pair in value["authority_digests"]
            ),
            executed_at=value["executed_at"],
            detail=value["detail"],
        )


_FAILOVER_FACT_FIELDS = frozenset(
    {
        "from_dependency",
        "target_dependency",
        "target_probe_digest",
        "target_probe_as_of",
        "adapter_contract",
        "authority_digests",
        "executed_at",
        "detail",
    }
)


@dataclass(frozen=True, slots=True)
class EmergencyFact:
    """One declared narrow, time-bounded operational emergency.

    governance.md "Emergency authority": emergency actions are narrowly
    scoped (the declared dependency scope), time-bounded (the explicit
    window), heavily audited (the kernel journal), and cannot rewrite
    history, erase liabilities, manufacture value or override genuine
    settlement finality — this record is control-plane only and mutates
    nothing.
    """

    window_from: str
    window_until: str
    mandate: str
    scope: tuple[str, ...]
    declared_at: str

    def __post_init__(self) -> None:
        require_utc_timestamp("emergency window_from", self.window_from)
        require_utc_timestamp("emergency window_until", self.window_until)
        require_utc_timestamp_order(
            "emergency window_from", self.window_from, "emergency window_until", self.window_until
        )
        require_text("emergency mandate", self.mandate)
        object.__setattr__(
            self, "scope", require_identifier_tuple("emergency scope", self.scope)
        )
        require_utc_timestamp("emergency declared_at", self.declared_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_from": self.window_from,
            "window_until": self.window_until,
            "mandate": self.mandate,
            "scope": list(self.scope),
            "declared_at": self.declared_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EmergencyFact":
        strict_fields("emergency fact", value, _EMERGENCY_FACT_FIELDS)
        return cls(
            window_from=value["window_from"],
            window_until=value["window_until"],
            mandate=value["mandate"],
            scope=tuple(value["scope"]),
            declared_at=value["declared_at"],
        )


_EMERGENCY_FACT_FIELDS = frozenset(
    {"window_from", "window_until", "mandate", "scope", "declared_at"}
)


@dataclass(frozen=True, slots=True)
class ResolutionFact:
    """One recorded resolution with complete recovery evidence."""

    probe_digests: tuple[tuple[str, str], ...]
    recovery_actions: tuple[RecoveryActionRecord, ...]
    authority_rebuilds: tuple[AuthorityRebuild, ...]
    recovery_duration_seconds: int
    resolved_at: str
    note: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "probe_digests", _normalize_pairs(self.probe_digests))
        for dependency_id, digest in self.probe_digests:
            require_identifier("resolution probe dependency_id", dependency_id)
            require_digest("resolution probe digest", digest)
        actions = tuple(
            action
            if isinstance(action, RecoveryActionRecord)
            else RecoveryActionRecord.from_dict(action)
            for action in self.recovery_actions
        )
        object.__setattr__(self, "recovery_actions", actions)
        rebuilds = tuple(
            rebuild
            if isinstance(rebuild, AuthorityRebuild)
            else AuthorityRebuild.from_dict(rebuild)
            for rebuild in self.authority_rebuilds
        )
        object.__setattr__(self, "authority_rebuilds", rebuilds)
        require_int(
            "resolution recovery_duration_seconds",
            self.recovery_duration_seconds,
            minimum=0,
        )
        require_utc_timestamp("resolution resolved_at", self.resolved_at)
        require_text("resolution note", self.note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_digests": [list(pair) for pair in self.probe_digests],
            "recovery_actions": [action.to_dict() for action in self.recovery_actions],
            "authority_rebuilds": [
                rebuild.to_dict() for rebuild in self.authority_rebuilds
            ],
            "recovery_duration_seconds": self.recovery_duration_seconds,
            "resolved_at": self.resolved_at,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResolutionFact":
        strict_fields("resolution fact", value, _RESOLUTION_FACT_FIELDS)
        return cls(
            probe_digests=tuple(tuple(pair) for pair in value["probe_digests"]),
            recovery_actions=tuple(
                RecoveryActionRecord.from_dict(action)
                for action in value["recovery_actions"]
            ),
            authority_rebuilds=tuple(
                AuthorityRebuild.from_dict(rebuild)
                for rebuild in value["authority_rebuilds"]
            ),
            recovery_duration_seconds=value["recovery_duration_seconds"],
            resolved_at=value["resolved_at"],
            note=value["note"],
        )


_RESOLUTION_FACT_FIELDS = frozenset(
    {
        "probe_digests",
        "recovery_actions",
        "authority_rebuilds",
        "recovery_duration_seconds",
        "resolved_at",
        "note",
    }
)


def _normalize_authority_digests(
    value: Iterable[Mapping[str, Any] | tuple[str, str]] | Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if isinstance(value, Mapping):
        items: tuple[Any, ...] = tuple(value.items())
    else:
        items = tuple(value)
    if not items:
        raise CoreValidationError("affected authority digest pairs must not be empty")
    result: list[tuple[str, str]] = []
    for entry in items:
        if isinstance(entry, Mapping):
            strict_fields("authority digest pair", entry, _AUTHORITY_DIGEST_FIELDS)
            result.append((entry["authority_ref"], entry["digest"]))
        else:
            pair = tuple(entry)
            if len(pair) != 2:
                raise CoreValidationError(
                    "authority digest entries must be (authority_ref, digest) pairs"
                )
            result.append((pair[0], pair[1]))
    for authority_ref, digest in result:
        require_identifier("authority_ref", authority_ref)
        require_digest("authority digest", digest)
    refs = [ref for ref, _ in result]
    if len(set(refs)) != len(refs):
        raise CoreValidationError("affected authorities contain duplicate references")
    return tuple(result)


def _normalize_pairs(value: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple((pair[0], pair[1]) for pair in value)


# -- the incident record ----------------------------------------------------


_INCIDENT_SPEC_FIELDS = frozenset(
    {
        "incident_id",
        "dependency_id",
        "summary",
        "trigger_probe_digest",
        "trigger_as_of",
        "opened_at",
        "severity",
        "degradation_facts",
        "failover_fact",
        "emergency_fact",
        "resolution_fact",
    }
)


@dataclass(frozen=True, slots=True)
class IncidentSpec:
    """Immutable incident payload (identity + the append-only fact chain).

    Identity fields (``incident_id``, ``dependency_id``,
    ``trigger_probe_digest``, ``trigger_as_of``, ``opened_at``) are frozen
    for the incident's whole life; every lifecycle fact is appended
    exactly once by its owning command (``degradation_facts`` may append a
    WORSENING severity) and the current ``severity`` is the worst declared
    so far.
    """

    incident_id: str
    dependency_id: str
    summary: str
    trigger_probe_digest: str
    trigger_as_of: str
    opened_at: str
    severity: str
    degradation_facts: tuple[DegradationFact, ...]
    failover_fact: FailoverFact | None
    emergency_fact: EmergencyFact | None
    resolution_fact: ResolutionFact | None

    def __post_init__(self) -> None:
        require_identifier("incident.incident_id", self.incident_id)
        require_identifier("incident.dependency_id", self.dependency_id)
        require_text("incident.summary", self.summary)
        require_digest("incident.trigger_probe_digest", self.trigger_probe_digest)
        require_utc_timestamp("incident.trigger_as_of", self.trigger_as_of)
        require_utc_timestamp("incident.opened_at", self.opened_at)
        severity = parse_enum("incident.severity", self.severity, DegradationSeverity)
        object.__setattr__(self, "severity", severity.value)
        facts = tuple(
            fact if isinstance(fact, DegradationFact) else DegradationFact.from_dict(fact)
            for fact in self.degradation_facts
        )
        object.__setattr__(self, "degradation_facts", facts)
        if self.failover_fact is not None and not isinstance(self.failover_fact, FailoverFact):
            object.__setattr__(
                self, "failover_fact", FailoverFact.from_dict(self.failover_fact)
            )
        if self.emergency_fact is not None and not isinstance(
            self.emergency_fact, EmergencyFact
        ):
            object.__setattr__(
                self, "emergency_fact", EmergencyFact.from_dict(self.emergency_fact)
            )
        if self.resolution_fact is not None and not isinstance(
            self.resolution_fact, ResolutionFact
        ):
            object.__setattr__(
                self, "resolution_fact", ResolutionFact.from_dict(self.resolution_fact)
            )
        self._require_severity_consistency()

    def _require_severity_consistency(self) -> None:
        if not self.degradation_facts:
            return
        worst = max(
            (DEGRADATION_SEVERITY_ORDER[DegradationSeverity(fact.severity)]
             for fact in self.degradation_facts)
        )
        if DEGRADATION_SEVERITY_ORDER[DegradationSeverity(self.severity)] != worst:
            raise CoreValidationError(
                f"incident severity {self.severity} is not the worst declared "
                "degradation severity; severity must track the worst fact"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "dependency_id": self.dependency_id,
            "summary": self.summary,
            "trigger_probe_digest": self.trigger_probe_digest,
            "trigger_as_of": self.trigger_as_of,
            "opened_at": self.opened_at,
            "severity": self.severity,
            "degradation_facts": [fact.to_dict() for fact in self.degradation_facts],
            "failover_fact": self.failover_fact.to_dict() if self.failover_fact else None,
            "emergency_fact": self.emergency_fact.to_dict() if self.emergency_fact else None,
            "resolution_fact": (
                self.resolution_fact.to_dict() if self.resolution_fact else None
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IncidentSpec":
        strict_fields("incident spec", value, _INCIDENT_SPEC_FIELDS)
        return cls(
            incident_id=value["incident_id"],
            dependency_id=value["dependency_id"],
            summary=value["summary"],
            trigger_probe_digest=value["trigger_probe_digest"],
            trigger_as_of=value["trigger_as_of"],
            opened_at=value["opened_at"],
            severity=value["severity"],
            degradation_facts=tuple(
                DegradationFact.from_dict(fact) for fact in value["degradation_facts"]
            ),
            failover_fact=(
                FailoverFact.from_dict(value["failover_fact"])
                if value["failover_fact"]
                else None
            ),
            emergency_fact=(
                EmergencyFact.from_dict(value["emergency_fact"])
                if value["emergency_fact"]
                else None
            ),
            resolution_fact=(
                ResolutionFact.from_dict(value["resolution_fact"])
                if value["resolution_fact"]
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class Incident:
    """One sealed operational incident record (``operations/incident/v1``)."""

    envelope: Any
    spec: IncidentSpec
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
    def state(self) -> IncidentState:
        return IncidentState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        from .seal import record_to_dict

        return record_to_dict(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Incident":
        envelope, spec, integrity_hash = decode_record(
            value, object_type=INCIDENT_OBJECT_TYPE, state_type=IncidentState
        )
        return cls(
            envelope=envelope,
            spec=IncidentSpec.from_dict(spec),
            integrity_hash=integrity_hash,
        )


def make_incident_record(
    *,
    incident_id: str,
    dependency_id: str,
    summary: str,
    trigger_probe_digest: str,
    trigger_as_of: str,
    opened_at: str,
    severity: DegradationSeverity | str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Incident:
    """Build and seal one incident record in the OPEN state."""
    severity_value = parse_enum("incident severity", severity, DegradationSeverity)
    spec = IncidentSpec(
        incident_id=incident_id,
        dependency_id=dependency_id,
        summary=summary,
        trigger_probe_digest=trigger_probe_digest,
        trigger_as_of=trigger_as_of,
        opened_at=opened_at,
        severity=severity_value.value,
        degradation_facts=(),
        failover_fact=None,
        emergency_fact=None,
        resolution_fact=None,
    )
    envelope = build_domain_envelope(
        object_id=incident_id,
        object_type=INCIDENT_OBJECT_TYPE,
        state=IncidentState.OPEN.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return Incident(
        envelope=envelope, spec=spec, integrity_hash=seal_record(envelope, spec)
    )


def degradation_recovery_seconds(fact: DegradationFact, resolved_at: str) -> int:
    """Deterministic seconds between the latest degradation and resolution."""
    return elapsed_seconds(
        "recovery", fact.observed_at, resolved_at
    )
