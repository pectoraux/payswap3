"""Derived health and economic metrics (WORK-024).

DERIVED lifecycle class (ownership-lifecycle.md): everything in this
module is computed, never authoritative. Health is derived from typed
probe evidence against the declared resilience profile thresholds;
economic exposure is derived from REAL clearing obligation records through
their public boundary; systemic risk is the deterministic stress
propagation of the declared dependency graph. No metric is ever written
back onto any sibling record and none survives as a second authority —
every derived record carries the digest of exactly what it was derived
from.

Epistemic discipline: probe results carry the frozen evidence-domain
vocabulary (:class:`src.evidence.EpistemicType`, WORK-018) and accept only
``OBSERVED`` — a simulated or predicted value can never masquerade as a
live health observation (fail closed at construction).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import SYSTEMIC_RISK_OBJECT_TYPE, HealthStatus
from .graph import DependencyGraph

_PROBE_FIELDS = frozenset(
    {
        "probe_id",
        "dependency_id",
        "as_of",
        "epistemic",
        "availability_bps",
        "samples",
        "detail",
    }
)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One typed health probe observation of one dependency (DERIVED).

    Probes are caller-supplied evidence gathered through a typed probe
    port over a public boundary (ports over providers, implementation
    principle 4): the concrete probe strategy is external and remains
    replaceable. The epistemic type must be ``OBSERVED`` (the frozen
    evidence-domain vocabulary — WORK-018): cross-type confusion fails
    closed at construction. ``availability_bps`` is the probe's own
    deterministic availability sample ratio in basis points; the derived
    health classification happens against the resilience profile's
    declared thresholds, never here.
    """

    probe_id: str
    dependency_id: str
    as_of: str
    epistemic: EpistemicType
    availability_bps: int
    samples: int
    detail: str

    def __post_init__(self) -> None:
        require_identifier("probe.probe_id", self.probe_id)
        require_identifier("probe.dependency_id", self.dependency_id)
        require_utc_timestamp("probe.as_of", self.as_of)
        epistemic = self.epistemic
        epistemic_type = _epistemic_type()
        if not isinstance(epistemic, epistemic_type):
            epistemic = parse_enum("probe.epistemic", epistemic, epistemic_type)
            object.__setattr__(self, "epistemic", epistemic)
        if self.epistemic is not epistemic_type.OBSERVED:
            raise CoreValidationError(
                "probe results must be OBSERVED evidence (the frozen evidence "
                f"vocabulary); got {self.epistemic.value} — a simulated or "
                "predicted value can never masquerade as a health observation"
            )
        require_int("probe.availability_bps", self.availability_bps, minimum=0)
        if self.availability_bps > 10000:
            raise CoreValidationError("probe.availability_bps must not exceed 10000")
        require_int("probe.samples", self.samples, minimum=1)
        require_text("probe.detail", self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "dependency_id": self.dependency_id,
            "as_of": self.as_of,
            "epistemic": self.epistemic.value,
            "availability_bps": self.availability_bps,
            "samples": self.samples,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProbeResult":
        strict_fields("probe result", value, _PROBE_FIELDS)
        return cls(
            probe_id=value["probe_id"],
            dependency_id=value["dependency_id"],
            as_of=value["as_of"],
            epistemic=_epistemic_type()(value["epistemic"]),
            availability_bps=value["availability_bps"],
            samples=value["samples"],
            detail=value["detail"],
        )


def _epistemic_type() -> type:
    """The frozen evidence-domain epistemic vocabulary (lazy import).

    ``src.evidence`` transitively imports the trust domain (attestations
    are issued by trust principals), and the operations import closure is
    deliberately lean: importing ``src.operations`` must not drag the
    trust graph in. The vocabulary is therefore consumed at validation
    time — the contract (the frozen ``EpistemicType`` enum, WORK-018) is
    unchanged, only its import moment moves.
    """
    from src.evidence.contracts import EpistemicType

    return EpistemicType


def probe_digest(probe: "ProbeResult") -> str:
    """Deterministic digest binding evidence records to probe results."""
    if not isinstance(probe, ProbeResult):
        raise CoreValidationError("probe_digest requires a ProbeResult")
    return canonical_sha256(probe.to_dict())


_SNAPSHOT_FIELDS = frozenset(
    {"as_of", "statuses", "probe_digests", "digest"}
)


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """One derived health snapshot across the probed dependencies.

    ``statuses``/``probe_digests`` are tuples of
    ``(dependency_id, value)`` pairs in canonical (sorted) order; the
    snapshot ``digest`` covers the as-of instant, every classification and
    every probe digest — the exact derivation inputs.
    """

    as_of: str
    statuses: tuple[tuple[str, HealthStatus], ...]
    probe_digests: tuple[tuple[str, str], ...]
    digest: str

    def __post_init__(self) -> None:
        require_utc_timestamp("snapshot.as_of", self.as_of)
        object.__setattr__(
            self,
            "statuses",
            tuple(
                (dep, status if isinstance(status, HealthStatus) else HealthStatus(status))
                for dep, status in self.statuses
            ),
        )
        for dependency_id, status in self.statuses:
            require_identifier("snapshot status dependency_id", dependency_id)
            if not isinstance(status, HealthStatus):
                raise CoreValidationError("snapshot statuses must use HealthStatus")
        for dependency_id, digest in self.probe_digests:
            require_identifier("snapshot probe dependency_id", dependency_id)
            if len(digest) != 64:
                raise CoreValidationError("snapshot probe digests must be SHA-256 hex")
        if [dep for dep, _ in self.statuses] != sorted(dep for dep, _ in self.statuses):
            raise CoreValidationError("snapshot statuses must be canonically sorted")
        if [dep for dep, _ in self.probe_digests] != sorted(
            dep for dep, _ in self.probe_digests
        ):
            raise CoreValidationError("snapshot probe digests must be canonically sorted")
        if len({dep for dep, _ in self.statuses}) != len(self.statuses):
            raise CoreValidationError("snapshot statuses contain duplicates")
        expected = canonical_sha256(
            {
                "as_of": self.as_of,
                "statuses": [[dep, status.value] for dep, status in self.statuses],
                "probe_digests": [list(pair) for pair in self.probe_digests],
            }
        )
        if self.digest != expected:
            raise CoreValidationError("health snapshot digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "statuses": [[dep, status.value] for dep, status in self.statuses],
            "probe_digests": [list(pair) for pair in self.probe_digests],
            "digest": self.digest,
        }


def health_snapshot(
    probes: Iterable[ProbeResult],
    graph: DependencyGraph,
    profiles: Mapping[str, ResilienceProfile],
) -> HealthSnapshot:
    """Classify one set of probes against the declared profiles (derived).

    Fail-closed gates: every probed dependency must be declared in the
    graph; the owning service must declare a resilience profile; every
    probe must share one as-of instant (a snapshot is a single point in
    time); no dependency may be probed twice.
    """
    if not isinstance(graph, DependencyGraph):
        raise CoreValidationError("health_snapshot requires a DependencyGraph")
    # late import: profiles consume ProbeResult (metrics) at module level,
    # so the reverse edge stays inside this function body.
    from .profiles import ResilienceProfile, classify_health

    materialized = tuple(probes)
    as_of_values = {probe.as_of for probe in materialized}
    if len(as_of_values) > 1:
        raise CoreValidationError(
            "health snapshot probes must share one as-of instant; a snapshot is "
            "a single point in declared time"
        )
    if not materialized:
        raise CoreValidationError("health snapshot requires at least one probe")
    seen: set[str] = set()
    statuses: list[tuple[str, HealthStatus]] = []
    probe_digests: list[tuple[str, str]] = []
    for probe in materialized:
        if not isinstance(probe, ProbeResult):
            raise CoreValidationError("health_snapshot probes must be ProbeResults")
        if probe.dependency_id in seen:
            raise CoreValidationError(
                f"dependency {probe.dependency_id!r} was probed twice"
            )
        seen.add(probe.dependency_id)
        if not graph.has_dependency(probe.dependency_id):
            raise CoreValidationError(
                f"probe targets undeclared dependency {probe.dependency_id!r}"
            )
        service_id = graph.service_of(probe.dependency_id)
        profile = profiles.get(service_id)
        if profile is None:
            raise CoreValidationError(
                f"service {service_id!r} declares no resilience profile; health "
                "classification fails closed"
            )
        status = classify_health(
            probe, profile, dependency_service=service_id
        )
        statuses.append((probe.dependency_id, status))
        probe_digests.append((probe.dependency_id, probe_digest(probe)))
    statuses.sort(key=lambda pair: pair[0])
    probe_digests.sort(key=lambda pair: pair[0])
    digest = canonical_sha256(
        {
            "as_of": materialized[0].as_of,
            "statuses": [[dep, status.value] for dep, status in statuses],
            "probe_digests": [list(pair) for pair in probe_digests],
        }
    )
    return HealthSnapshot(
        as_of=materialized[0].as_of,
        statuses=tuple(statuses),
        probe_digests=tuple(probe_digests),
        digest=digest,
    )


_EXPOSURE_FIELDS = frozenset(
    {"obligation_count", "outstanding_count", "asset_totals", "digest"}
)


@dataclass(frozen=True, slots=True)
class EconomicExposure:
    """Derived economic exposure of real clearing obligations.

    ``asset_totals`` is a canonically sorted tuple of
    ``(asset, minor_units, obligation_count)`` covering only OUTSTANDING
    (non-terminal) obligations; terminal obligations are excluded —
    exposure is what can still fail, not what already closed.
    """

    obligation_count: int
    outstanding_count: int
    asset_totals: tuple[tuple[str, int, int], ...]
    digest: str

    def __post_init__(self) -> None:
        require_int("exposure.obligation_count", self.obligation_count, minimum=0)
        require_int("exposure.outstanding_count", self.outstanding_count, minimum=0)
        object.__setattr__(self, "asset_totals", tuple(self.asset_totals))
        for asset, minor, count in self.asset_totals:
            require_identifier("exposure asset", asset)
            require_int("exposure minor units", minor, minimum=0)
            require_int("exposure count", count, minimum=1)
        expected = canonical_sha256(
            {
                "obligation_count": self.obligation_count,
                "outstanding_count": self.outstanding_count,
                "asset_totals": [list(entry) for entry in self.asset_totals],
            }
        )
        if self.digest != expected:
            raise CoreValidationError("economic exposure digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_count": self.obligation_count,
            "outstanding_count": self.outstanding_count,
            "asset_totals": [list(entry) for entry in self.asset_totals],
            "digest": self.digest,
        }


def economic_exposure(obligations: Iterable[Any]) -> EconomicExposure:
    """Derive economic exposure from REAL clearing obligation records.

    The input must be real :class:`src.clearing.Obligation` records
    (WORK-015 — the sole obligation authority); the totals are computed
    from the records' own sealed facts (never payload-trusted values) and
    the exposure digest is the deterministic canonical digest over the
    exposure record's own content (the same digest the record verifies
    at construction — the derived record is tamper-evident).
    """

    from src.clearing.obligations import Obligation
    from src.clearing.contracts import OBLIGATION_TERMINAL_STATES

    materialized = tuple(obligations)
    per_asset: dict[str, list[int]] = {}
    outstanding = 0
    for record in materialized:
        if not isinstance(record, Obligation):
            raise CoreValidationError(
                "economic exposure requires real clearing Obligation records "
                f"(got {type(record).__name__})"
            )
        state = record.envelope.state
        if state in {member.value for member in OBLIGATION_TERMINAL_STATES}:
            continue
        outstanding += 1
        totals = per_asset.setdefault(record.spec.asset, [0, 0])
        totals[0] += record.spec.amount.value
        totals[1] += 1
    asset_totals = tuple(
        (asset, totals[0], totals[1]) for asset, totals in sorted(per_asset.items())
    )
    digest = canonical_sha256(
        {
            "obligation_count": len(materialized),
            "outstanding_count": outstanding,
            "asset_totals": [list(entry) for entry in asset_totals],
        }
    )
    return EconomicExposure(
        obligation_count=len(materialized),
        outstanding_count=outstanding,
        asset_totals=asset_totals,
        digest=digest,
    )


_RISK_FIELDS = frozenset(
    {
        "as_of",
        "failed_dependencies",
        "affected_dependencies",
        "affected_services",
        "exposure_digest",
        "digest",
    }
)


@dataclass(frozen=True, slots=True)
class SystemicRiskAssessment:
    """One derived systemic-risk assessment (stress propagation).

    DERIVED record: ``failed_dependencies`` are the non-healthy probed
    dependencies of the snapshot; ``affected_dependencies`` adds their
    transitive dependents (the declared graph's contagion closure);
    ``affected_services`` are the owning services. The ``digest`` covers
    the derivation inputs (snapshot digest + graph digest + exposure
    digest when bound). An optional economic exposure digest binds the
    assessment to the exposure it was computed with — derived objects
    never outrank their source of truth (canonical-object-model.md).
    """

    as_of: str
    failed_dependencies: tuple[str, ...]
    affected_dependencies: tuple[str, ...]
    affected_services: tuple[str, ...]
    exposure_digest: str | None
    digest: str

    def __post_init__(self) -> None:
        require_utc_timestamp("assessment.as_of", self.as_of)
        object.__setattr__(self, "failed_dependencies", tuple(self.failed_dependencies))
        object.__setattr__(self, "affected_dependencies", tuple(self.affected_dependencies))
        object.__setattr__(self, "affected_services", tuple(self.affected_services))
        if self.exposure_digest is not None:
            if len(self.exposure_digest) != 64:
                raise CoreValidationError("assessment exposure_digest must be SHA-256 hex")
        for field in ("failed_dependencies", "affected_dependencies", "affected_services"):
            values = getattr(self, field)
            if list(values) != sorted(values):
                raise CoreValidationError(f"assessment {field} must be canonically sorted")
            if len(set(values)) != len(values):
                raise CoreValidationError(f"assessment {field} contains duplicates")
        expected = canonical_sha256(
            {
                "as_of": self.as_of,
                "failed_dependencies": list(self.failed_dependencies),
                "affected_dependencies": list(self.affected_dependencies),
                "affected_services": list(self.affected_services),
                "exposure_digest": self.exposure_digest,
            }
        )
        if self.digest != expected:
            raise CoreValidationError("systemic risk assessment digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_type": SYSTEMIC_RISK_OBJECT_TYPE,
            "as_of": self.as_of,
            "failed_dependencies": list(self.failed_dependencies),
            "affected_dependencies": list(self.affected_dependencies),
            "affected_services": list(self.affected_services),
            "exposure_digest": self.exposure_digest,
            "digest": self.digest,
        }


def assess_systemic_risk(
    graph: DependencyGraph,
    snapshot: HealthSnapshot,
    exposure: EconomicExposure | None = None,
) -> SystemicRiskAssessment:
    """Deterministic stress propagation over the declared graph (derived).

    The affected set is the closed contagion computation of
    security-risk.md ("the protocol maintains a dependency/exposure graph
    and supports stress propagation"): every non-healthy dependency plus
    every transitive dependent. Computed, never stored as authority.
    """
    if not isinstance(graph, DependencyGraph):
        raise CoreValidationError("assess_systemic_risk requires a DependencyGraph")
    if not isinstance(snapshot, HealthSnapshot):
        raise CoreValidationError("assess_systemic_risk requires a HealthSnapshot")
    if exposure is not None and not isinstance(exposure, EconomicExposure):
        raise CoreValidationError("assess_systemic_risk exposure must be an EconomicExposure")
    failed = tuple(
        sorted(
            dependency_id
            for dependency_id, status in snapshot.statuses
            if status is not HealthStatus.HEALTHY
        )
    )
    affected: set[str] = set(failed)
    for dependency_id in failed:
        affected.update(graph.dependents_of(dependency_id))
    services: set[str] = set()
    for dependency_id in affected:
        services.add(graph.service_of(dependency_id))
    exposure_digest = exposure.digest if exposure is not None else None
    digest = canonical_sha256(
        {
            "as_of": snapshot.as_of,
            "failed_dependencies": list(failed),
            "affected_dependencies": sorted(affected),
            "affected_services": sorted(services),
            "exposure_digest": exposure_digest,
        }
    )
    return SystemicRiskAssessment(
        as_of=snapshot.as_of,
        failed_dependencies=failed,
        affected_dependencies=tuple(sorted(affected)),
        affected_services=tuple(sorted(services)),
        exposure_digest=exposure_digest,
        digest=digest,
    )
