"""The declared dependency/exposure graph (security-risk model, WORK-024).

``Dependency`` records are DECLARED operational topology — which critical
service depends on which external provider, federated domain or protocol
service — sealed as durable objects and validated at graph construction.
The graph is declared data, never a mirror of live sibling state: health is
probed through typed probe ports (see :mod:`src.operations.metrics`) and
classification happens against the resilience profile's declared
thresholds. This module never re-derives authoritative sibling state.

Systemic contagion (security-risk.md): the graph supports deterministic
stress propagation — the transitive dependents of a failed dependency are
the affected set (:meth:`DependencyGraph.dependents_of` and
:func:`src.operations.metrics.assess_systemic_risk`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    parse_enum,
    require_identifier,
    require_text,
    strict_fields,
)
from .contracts import DEPENDENCY_OBJECT_TYPE, DependencyKind
from .seal import (
    build_domain_envelope,
    decode_record,
    record_to_dict,
    seal_record,
    verify_composite,
)


class DependencyRecordState(StrEnum):
    """Closed declared-state vocabulary of dependency/profile records.

    Dependency and resilience-profile records are DECLARED configuration
    (immutable once sealed): the derived live health of a dependency is
    never written onto these records (no alternate source of truth) — it
    lives in probe results and incident records.
    """

    DECLARED = "DECLARED"


#: The single declared state of a dependency record.
DECLARED_STATE = DependencyRecordState.DECLARED

_SPEC_FIELDS = frozenset(
    {
        "dependency_id",
        "kind",
        "service_id",
        "depends_on",
        "critical",
        "note",
    }
)


@dataclass(frozen=True, slots=True)
class DependencySpec:
    """Immutable declared topology of one dependency node."""

    dependency_id: str
    kind: str
    service_id: str
    depends_on: tuple[str, ...]
    critical: bool
    note: str

    def __post_init__(self) -> None:
        require_identifier("dependency.dependency_id", self.dependency_id)
        kind = parse_enum("dependency.kind", self.kind, DependencyKind)
        object.__setattr__(self, "kind", kind.value)
        require_identifier("dependency.service_id", self.service_id)
        depends_on = tuple(self.depends_on)
        object.__setattr__(self, "depends_on", depends_on)
        for entry in depends_on:
            require_identifier("dependency.depends_on entry", entry)
        if len(set(depends_on)) != len(depends_on):
            raise CoreValidationError("dependency.depends_on contains duplicates")
        if self.dependency_id in depends_on:
            raise CoreValidationError(
                f"dependency {self.dependency_id} must not depend on itself"
            )
        if not isinstance(self.critical, bool):
            raise CoreValidationError("dependency.critical must be a boolean")
        require_text("dependency.note", self.note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "kind": self.kind,
            "service_id": self.service_id,
            "depends_on": list(self.depends_on),
            "critical": self.critical,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DependencySpec":
        strict_fields("dependency spec", value, _SPEC_FIELDS)
        return cls(
            dependency_id=value["dependency_id"],
            kind=value["kind"],
            service_id=value["service_id"],
            depends_on=tuple(value["depends_on"]),
            critical=value["critical"],
            note=value["note"],
        )


@dataclass(frozen=True, slots=True)
class Dependency:
    """One sealed dependency record (``operations/dependency/v1``)."""

    envelope: Any
    spec: DependencySpec
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
    def from_dict(cls, value: Mapping[str, Any]) -> "Dependency":
        envelope, spec, integrity_hash = decode_record(
            value, object_type=DEPENDENCY_OBJECT_TYPE, state_type=DependencyRecordState
        )
        return cls(
            envelope=envelope,
            spec=DependencySpec.from_dict(spec),
            integrity_hash=integrity_hash,
        )


def make_dependency_record(
    *,
    dependency_id: str,
    kind: DependencyKind | str,
    service_id: str,
    depends_on: Iterable[str] = (),
    critical: bool = True,
    note: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance | None = None,
) -> Dependency:
    """Build and seal one declared dependency record."""
    spec = DependencySpec(
        dependency_id=dependency_id,
        kind=kind,
        service_id=service_id,
        depends_on=tuple(depends_on),
        critical=critical,
        note=note,
    )
    if provenance is None:
        provenance = Provenance(
            issuer="principal/operations-service",
            source="operations/domain",
            recorded_at="2026-01-01T00:00:00Z",
        )
    envelope = build_domain_envelope(
        object_id=dependency_id,
        object_type=DEPENDENCY_OBJECT_TYPE,
        state=DECLARED_STATE.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
    )
    return Dependency(
        envelope=envelope, spec=spec, integrity_hash=seal_record(envelope, spec)
    )


class DependencyGraph:
    """The validated declared dependency/exposure graph.

    Construction is fail-closed: identifiers must be unique, every
    ``depends_on`` reference must exist, and the graph must be a DAG (a
    cyclic dependency graph makes stress propagation and failover
    reasoning non-total, so it is rejected outright). Every member record
    is re-verified on the trusted decode path at construction.
    """

    __slots__ = ("_records", "_by_id", "_dependents", "_digest")

    def __init__(self, records: Iterable[Dependency]) -> None:
        materialized = tuple(records)
        seen: dict[str, Dependency] = {}
        for record in materialized:
            if not isinstance(record, Dependency):
                raise CoreValidationError(
                    "dependency graph members must be Dependency records"
                )
            # re-verify the seal on the trusted path (tampered records fail)
            Dependency.from_dict(record.to_dict())
            if record.object_id in seen:
                raise CoreValidationError(
                    f"dependency {record.object_id} is declared twice"
                )
            seen[record.object_id] = record
        for record in materialized:
            for ref in record.spec.depends_on:
                if ref not in seen:
                    raise CoreValidationError(
                        f"dependency {record.object_id} depends on unknown "
                        f"dependency {ref!r}"
                    )
        self._records: tuple[Dependency, ...] = tuple(
            seen[record.object_id] for record in materialized
        )
        self._by_id = seen
        self._dependents = self._build_dependents()
        self._require_acyclic()
        self._digest = canonical_sha256([record.to_dict() for record in self._records])

    @classmethod
    def build(cls, records: Iterable[Dependency]) -> "DependencyGraph":
        return cls(records)

    def _build_dependents(self) -> dict[str, tuple[str, ...]]:
        direct: dict[str, list[str]] = {record.object_id: [] for record in self._records}
        for record in self._records:
            for ref in record.spec.depends_on:
                direct[ref].append(record.object_id)
        closure: dict[str, set[str]] = {}
        for node in direct:
            affected: set[str] = set()
            frontier = list(direct[node])
            while frontier:
                current = frontier.pop()
                if current in affected:
                    continue
                affected.add(current)
                frontier.extend(direct[current])
            closure[node] = affected
        return {node: tuple(sorted(members)) for node, members in closure.items()}

    def _require_acyclic(self) -> None:
        # Deterministic cycle check: a cycle exists iff some node is its
        # own transitive dependent.
        for node, dependents in self._dependents.items():
            if node in dependents:
                raise CoreValidationError(
                    f"the dependency graph is cyclic: {node!r} transitively depends "
                    "on itself; a cyclic dependency graph fails closed"
                )

    def dependencies(self) -> tuple[Dependency, ...]:
        return self._records

    def dependency(self, dependency_id: str) -> Dependency:
        require_identifier("dependency id", dependency_id)
        record = self._by_id.get(dependency_id)
        if record is None:
            raise CoreValidationError(f"unknown dependency {dependency_id!r}")
        return record

    def has_dependency(self, dependency_id: str) -> bool:
        return dependency_id in self._by_id

    def service_of(self, dependency_id: str) -> str:
        return self.dependency(dependency_id).spec.service_id

    def kind_of(self, dependency_id: str) -> DependencyKind:
        return DependencyKind(self.dependency(dependency_id).spec.kind)

    def dependencies_for_service(self, service_id: str) -> tuple[Dependency, ...]:
        require_identifier("service id", service_id)
        return tuple(
            record for record in self._records if record.spec.service_id == service_id
        )

    def dependents_of(self, dependency_id: str) -> tuple[str, ...]:
        """Transitive dependents of one dependency (stress propagation)."""
        self.dependency(dependency_id)
        return self._dependents[dependency_id]

    @property
    def digest(self) -> str:
        """Canonical digest of the declared graph (deterministic)."""
        return self._digest
