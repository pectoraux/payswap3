"""The IG-003 composition harness: the simulation parity gate.

:class:`SimulationParityGate` binds TWO environments of the SAME
protocol machine — the merged IG-002 fulfillment lifecycle harness over
the real domain engines — and is the comparison authority between them:

* the simulation world: an IG-002 ``FulfillmentLifecycleGate`` bound to
  the SIMULATION environment (sandbox class, SIMULATION-fidelity rail
  over a WORK-019 scripted world of SIMULATED observations);
* the production-compatible world: the same lifecycle harness bound to
  the production-compatible environment (production class,
  PRODUCTION-fidelity rail through the same typed ports over a WORK-019
  scripted world of OBSERVED observations).

The gate drives no lifecycle semantics of its own: both worlds are
driven through the public IG-002 stage API by the scenario drivers, and
the gate then projects both executions, applies the frozen
normalization layer, classifies every residual difference and issues
the parity verdict — failing closed on any semantic divergence, and
reporting the epistemic provenance of both worlds (SIMULATED
simulation-world evidence vs OBSERVED production-compatible
observations) as an explicit, never-normalized environment fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.integration.lifecycle import FulfillmentLifecycleGate

from .contracts import (
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_PARITY_ACTOR,
    PARITY_GATE_ID,
    WorldRole,
    validate_parity_gate_id,
)
from .projection import (
    NORMALIZATION_DIGEST,
    ClassifiedDifference,
    compare_projections,
    raw_state_digest,
    semantic_projection,
    semantic_projection_digest,
    semantic_state,
)
from .worlds import EnvironmentPair, ParityWorld

_VERDICTS = frozenset({"PARITY", "DIVERGENCE"})


@dataclass(frozen=True, slots=True)
class WorldExecutionReport:
    """The execution report of one world of one parity scenario."""

    role: str
    environment_id: str
    domain_id: str
    environment_class: str
    adapter_id: str
    fidelity_class: str
    world_source_id: str
    mode: str
    world_evidence_class: str
    world_observation_count: int
    world_observation_digest: str
    execution_observation_count: int
    execution_observation_class: str
    raw_state_digest: str
    semantic_projection_digest: str
    stage_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "environment_class": self.environment_class,
            "adapter_id": self.adapter_id,
            "fidelity_class": self.fidelity_class,
            "world_source_id": self.world_source_id,
            "mode": self.mode,
            "world_evidence_class": self.world_evidence_class,
            "world_observation_count": self.world_observation_count,
            "world_observation_digest": self.world_observation_digest,
            "execution_observation_count": self.execution_observation_count,
            "execution_observation_class": self.execution_observation_class,
            "raw_state_digest": self.raw_state_digest,
            "semantic_projection_digest": self.semantic_projection_digest,
            "stage_count": self.stage_count,
        }


@dataclass(frozen=True, slots=True)
class EpistemicProvenanceReport:
    """The epistemic provenance report of one parity comparison.

    The world-coupling evidence classes are the declared, frozen
    environment facts (SIMULATED for the simulation world, OBSERVED for
    the production-compatible world); the execution-domain external
    observations are OBSERVED knowledge in BOTH worlds by the frozen
    execution contract (an observation of what the adapter stated).
    The comparison NEVER relabels either: the classes are asserted
    exactly and reported, never normalized away.
    """

    simulation_world_evidence_class: str
    production_world_evidence_class: str
    simulation_world_observation_digest: str
    production_world_observation_digest: str
    execution_observation_class: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation_world_evidence_class": self.simulation_world_evidence_class,
            "production_world_evidence_class": self.production_world_evidence_class,
            "simulation_world_observation_digest": (
                self.simulation_world_observation_digest
            ),
            "production_world_observation_digest": (
                self.production_world_observation_digest
            ),
            "execution_observation_class": self.execution_observation_class,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class ParityVerdict:
    """The typed, versioned parity verdict of one scenario comparison."""

    schema_version: int
    gate_id: str
    scenario_id: str
    shared_input_digest: str
    simulation: WorldExecutionReport
    production: WorldExecutionReport
    normalization_digest: str
    differences: tuple[ClassifiedDifference, ...]
    epistemic: EpistemicProvenanceReport
    verdict: str
    invariant_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CoreValidationError("the parity verdict schema version must be 1")
        validate_parity_gate_id(self.gate_id)
        if self.verdict not in _VERDICTS:
            raise CoreValidationError(
                f"unknown parity verdict {self.verdict!r}; the closed "
                f"vocabulary is {sorted(_VERDICTS)}"
            )
        if (self.verdict == "PARITY") != (len(self.differences) == 0):
            raise CoreValidationError(
                "the verdict must be PARITY exactly when no semantic "
                "differences remain after normalization"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "gate_id": self.gate_id,
            "scenario_id": self.scenario_id,
            "shared_input_digest": self.shared_input_digest,
            "simulation": self.simulation.to_dict(),
            "production": self.production.to_dict(),
            "normalization_digest": self.normalization_digest,
            "differences": [difference.to_dict() for difference in self.differences],
            "epistemic": self.epistemic.to_dict(),
            "verdict": self.verdict,
            "invariant_checks": list(self.invariant_checks),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """One parity scenario run: the verdict plus semantic facts."""

    scenario_id: str
    verdict: ParityVerdict
    facts: Mapping[str, Any]


def assert_semantic_parity(verdict: ParityVerdict) -> ParityVerdict:
    """Fail closed unless the verdict proves semantic parity."""
    if verdict.verdict != "PARITY":
        differences = "; ".join(
            difference.path for difference in verdict.differences[:5]
        )
        raise CoreValidationError(
            f"IG-003 semantic divergence between the simulation and the "
            f"production-compatible execution of scenario "
            f"{verdict.scenario_id!r} ({len(verdict.differences)} classified "
            f"difference(s), first at: {differences or 'unknown path'})"
        )
    return verdict


class SimulationParityGate:
    """IG-003: one declared scenario executing in two environments.

    The gate composes the two IG-002 lifecycle gates (one per
    environment) and owns ONLY the comparison between them. The
    lifecycle semantics stay with the composed domain engines; the
    environment-specific transport stays with the world harnesses.
    """

    def __init__(
        self,
        *,
        pair: EnvironmentPair | Sequence[ParityWorld],
        gate_id: str = PARITY_GATE_ID,
        actor: str = DEFAULT_PARITY_ACTOR,
        authorized_actors: Iterable[str] = DEFAULT_AUTHORIZED_ACTORS,
    ) -> None:
        validate_parity_gate_id(gate_id)
        if isinstance(pair, EnvironmentPair):
            simulation, production = pair.simulation, pair.production
        else:
            worlds = tuple(pair)
            if len(worlds) != 2:
                raise CoreValidationError(
                    "the parity gate requires exactly the two world harnesses"
                )
            simulation, production = worlds
        for world in (simulation, production):
            if not isinstance(world, ParityWorld):
                raise CoreValidationError(
                    "the parity gate composes ParityWorld environment harnesses"
                )
        if simulation.role is not WorldRole.SIMULATION:
            raise CoreValidationError(
                "the first world of the parity gate must be the SIMULATION world"
            )
        if production.role is not WorldRole.PRODUCTION_COMPATIBLE:
            raise CoreValidationError(
                "the second world of the parity gate must be the "
                "PRODUCTION-COMPATIBLE world"
            )
        if simulation.domain_id != production.domain_id:
            raise CoreValidationError(
                "the two worlds must share one domain binding (the frozen "
                "one-domain many-environments model)"
            )
        self._gate_id = gate_id
        self._simulation_world = simulation
        self._production_world = production
        actors = frozenset(authorized_actors) | {actor}
        self._simulation_gate = FulfillmentLifecycleGate(
            environment_id=simulation.environment_id,
            domain_id=simulation.domain_id,
            bindings={simulation.adapter_id: simulation.binding},
            authorized_actors=actors,
            actor=actor,
        )
        self._production_gate = FulfillmentLifecycleGate(
            environment_id=production.environment_id,
            domain_id=production.domain_id,
            bindings={production.adapter_id: production.binding},
            authorized_actors=actors,
            actor=actor,
        )

    # ------------------------------------------------------------------
    # read-only access to the two composed environments
    # ------------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def domain_id(self) -> str:
        return self._simulation_world.domain_id

    @property
    def simulation_world(self) -> ParityWorld:
        return self._simulation_world

    @property
    def production_world(self) -> ParityWorld:
        return self._production_world

    @property
    def simulation_gate(self) -> FulfillmentLifecycleGate:
        return self._simulation_gate

    @property
    def production_gate(self) -> FulfillmentLifecycleGate:
        return self._production_gate

    # ------------------------------------------------------------------
    # the projection, comparison and verdict authority
    # ------------------------------------------------------------------

    def semantic_state(self, role: WorldRole | str) -> dict[str, Any]:
        """The raw canonical semantic state of one world's execution."""
        return semantic_state(self._lifecycle_gate_of(role))

    def semantic_projection(self, role: WorldRole | str) -> dict[str, Any]:
        """The normalized semantic projection of one world's execution."""
        world = self._world_of(role)
        return semantic_projection(self._lifecycle_gate_of(role), world)

    def semantic_projection_digest(self, role: WorldRole | str) -> str:
        return semantic_projection_digest(self.semantic_projection(role))

    def raw_state_digest(self, role: WorldRole | str) -> str:
        return raw_state_digest(self._lifecycle_gate_of(role))

    def compare_projections(
        self,
        simulation: Mapping[str, Any] | None = None,
        production: Mapping[str, Any] | None = None,
    ) -> tuple[ClassifiedDifference, ...]:
        """Diff the two (normalized) projections; every difference is semantic.

        Explicit projections may be passed for the discrimination
        battery (corrupted feeds); by default both live projections are
        compared.
        """
        left = (
            self.semantic_projection(WorldRole.SIMULATION)
            if simulation is None
            else simulation
        )
        right = (
            self.semantic_projection(WorldRole.PRODUCTION_COMPATIBLE)
            if production is None
            else production
        )
        return compare_projections(left, right)

    def parity_verdict(
        self,
        *,
        scenario_id: str,
        shared_input_digest: str,
        invariant_checks: Iterable[str] | None = None,
    ) -> ParityVerdict:
        """Project both worlds, classify differences, issue the verdict."""
        differences = self.compare_projections()
        verdict = "PARITY" if not differences else "DIVERGENCE"
        checks: tuple[str, ...]
        if invariant_checks is not None:
            checks = tuple(invariant_checks)
        else:
            from .invariants import verify_parity_invariants

            # On PARITY the full cross-world battery validates the claim;
            # on DIVERGENCE the classified differences ARE the report and
            # the per-world structural battery still verifies both worlds
            # are internally sound.
            checks = tuple(
                verify_parity_invariants(self, cross_world=verdict == "PARITY")
            )
        return ParityVerdict(
            schema_version=1,
            gate_id=self._gate_id,
            scenario_id=scenario_id,
            shared_input_digest=shared_input_digest,
            simulation=self.world_execution_report(WorldRole.SIMULATION),
            production=self.world_execution_report(
                WorldRole.PRODUCTION_COMPATIBLE
            ),
            normalization_digest=NORMALIZATION_DIGEST,
            differences=differences,
            epistemic=self.epistemic_report(),
            verdict=verdict,
            invariant_checks=checks,
        )

    def world_execution_report(self, role: WorldRole | str) -> WorldExecutionReport:
        world = self._world_of(role)
        gate = self._lifecycle_gate_of(role)
        observations = list(gate.execution.observations())
        return WorldExecutionReport(
            role=world.role.value,
            environment_id=world.environment_id,
            domain_id=world.domain_id,
            environment_class=world.environment_class,
            adapter_id=world.adapter_id,
            fidelity_class=world.fidelity_class,
            world_source_id=world.world_source_id,
            mode=world.mode.value,
            world_evidence_class=world.epistemic_class.value,
            world_observation_count=len(world.rail.consumed_observations()),
            world_observation_digest=world.rail.consumed_observation_digest(),
            execution_observation_count=len(observations),
            execution_observation_class=(
                observations[0].spec.epistemic.value if observations else "OBSERVED"
            ),
            raw_state_digest=raw_state_digest(gate),
            semantic_projection_digest=semantic_projection_digest(
                semantic_projection(gate, world)
            ),
            stage_count=len(gate.stage_journal),
        )

    def epistemic_report(self) -> EpistemicProvenanceReport:
        simulation = self._simulation_world
        production = self._production_world
        return EpistemicProvenanceReport(
            simulation_world_evidence_class=simulation.epistemic_class.value,
            production_world_evidence_class=production.epistemic_class.value,
            simulation_world_observation_digest=(
                simulation.rail.consumed_observation_digest()
            ),
            production_world_observation_digest=(
                production.rail.consumed_observation_digest()
            ),
            execution_observation_class="OBSERVED",
            note=(
                "the simulation world consumes SIMULATED world observations "
                "(WORK-019 frozen mode binding) while the production-compatible "
                "world consumes OBSERVED world observations; execution-domain "
                "external observations are OBSERVED knowledge in both worlds "
                "(the frozen execution contract: an observation of what the "
                "adapter stated); epistemic provenance is preserved and "
                "reported, never normalized away or relabelled"
            ),
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _world_of(self, role: WorldRole | str) -> ParityWorld:
        role_name = self._role_name(role)
        if role_name == WorldRole.SIMULATION.value:
            return self._simulation_world
        if role_name == WorldRole.PRODUCTION_COMPATIBLE.value:
            return self._production_world
        raise CoreValidationError(f"unknown world role {role!r}")

    def _lifecycle_gate_of(self, role: WorldRole | str) -> FulfillmentLifecycleGate:
        role_name = self._role_name(role)
        if role_name == WorldRole.SIMULATION.value:
            return self._simulation_gate
        if role_name == WorldRole.PRODUCTION_COMPATIBLE.value:
            return self._production_gate
        raise CoreValidationError(f"unknown world role {role!r}")

    @staticmethod
    def _role_name(role: WorldRole | str) -> str:
        if isinstance(role, WorldRole):
            return role.value
        name = str(role)
        if name in ("production", "production-compatible"):
            # The short name of the PRODUCTION_COMPATIBLE role.
            return WorldRole.PRODUCTION_COMPATIBLE.value
        if name == "simulation":
            return WorldRole.SIMULATION.value
        return name


__all__ = [
    "EpistemicProvenanceReport",
    "ParityVerdict",
    "ScenarioResult",
    "SimulationParityGate",
    "WorldExecutionReport",
    "assert_semantic_parity",
]
