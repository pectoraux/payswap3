"""The IG-005 composition harness: the external rail sandbox gate.

:class:`ExternalRailSandboxGate` binds TWO rail worlds — each one a
full merged IG-002 ``FulfillmentLifecycleGate`` (compiler + execution
+ clearing + settlement over the real domain engines) bound to exactly
ONE typed adapter binding — and owns ONLY the comparison between
them:

* rail A: the Stripe test-mode world (REAL_PROVIDER_SANDBOX, the
  merged WORK-027 rail reused through import);
* rail B: the Stellar testnet world (REAL_PROVIDER_SANDBOX, the
  IG-005 rail behind the same typed ports), or — for the deterministic
  contract suite — the second world of a local deterministic pair.

The gate drives no lifecycle semantics of its own: both worlds are
driven through the public IG-002 stage API by the scenario drivers,
and the gate then projects both executions, applies the frozen
rail-normalization layer, classifies every residual difference and
issues the comparison verdict — failing closed on any semantic
divergence, and reporting each world's rail classification (a real
provider sandbox is never silently counted as a local deterministic
sandbox or vice versa).
"""

from __future__ import annotations

from collections import namedtuple
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.integration.lifecycle import FulfillmentLifecycleGate

from .contracts import (
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_RAILS_ACTOR,
    RAILS_GATE_ID,
    RAILS_SCHEMA_VERSION,
    validate_rails_gate_id,
)
from .projection import (
    RAILS_NORMALIZATION_DIGEST,
    ClassifiedDifference,
    compare_projections,
    raw_state_digest,
    semantic_projection,
    semantic_projection_digest,
    semantic_state,
)
from .worlds import RailWorld

_VERDICTS = frozenset({"EQUIVALENT", "DIVERGENCE"})

#: The two compared worlds in deterministic order.
RailWorldPair = namedtuple("RailWorldPair", ["rail_a", "rail_b"])


@dataclass(frozen=True, slots=True)
class RailWorldExecutionReport:
    """The execution report of one rail world of one comparison."""

    name: str
    rail_class: str
    environment_id: str
    domain_id: str
    environment_class: str
    adapter_id: str
    declared_currency: str
    declared_amount_minor: int
    native_references: tuple[str, ...]
    submission_class: str
    step_state: str
    finality_established: bool
    raw_state_digest: str
    semantic_projection_digest: str
    stage_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rail_class": self.rail_class,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "environment_class": self.environment_class,
            "adapter_id": self.adapter_id,
            "declared_currency": self.declared_currency,
            "declared_amount_minor": self.declared_amount_minor,
            "native_references": list(self.native_references),
            "submission_class": self.submission_class,
            "step_state": self.step_state,
            "finality_established": self.finality_established,
            "raw_state_digest": self.raw_state_digest,
            "semantic_projection_digest": self.semantic_projection_digest,
            "stage_count": self.stage_count,
        }


@dataclass(frozen=True, slots=True)
class RailComparisonVerdict:
    """The typed, versioned cross-rail comparison verdict (IG-005).

    The verdict vocabulary is ``EQUIVALENT``/``DIVERGENCE`` — the
    rail-comparison authority of THIS gate. The simulation/production
    parity verdict vocabulary stays owned by the merged IG-003 gate
    (no second parity authority).
    """

    schema_version: int
    gate_id: str
    scenario_id: str
    shared_input_digest: str
    rail_a: RailWorldExecutionReport
    rail_b: RailWorldExecutionReport
    normalization_digest: str
    differences: tuple[ClassifiedDifference, ...]
    verdict: str
    invariant_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != RAILS_SCHEMA_VERSION:
            raise CoreValidationError(
                "the rail comparison verdict schema version must be 1"
            )
        validate_rails_gate_id(self.gate_id)
        if self.verdict not in _VERDICTS:
            raise CoreValidationError(
                f"unknown rail comparison verdict {self.verdict!r}; the "
                f"closed vocabulary is {sorted(_VERDICTS)}"
            )
        if (self.verdict == "EQUIVALENT") != (len(self.differences) == 0):
            raise CoreValidationError(
                "the verdict must be EQUIVALENT exactly when no semantic "
                "differences remain after normalization"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "gate_id": self.gate_id,
            "scenario_id": self.scenario_id,
            "shared_input_digest": self.shared_input_digest,
            "rail_a": self.rail_a.to_dict(),
            "rail_b": self.rail_b.to_dict(),
            "normalization_digest": self.normalization_digest,
            "differences": [
                difference.to_dict() for difference in self.differences
            ],
            "verdict": self.verdict,
            "invariant_checks": list(self.invariant_checks),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ScenarioOutcome:
    """One rail scenario run: the verdict plus the per-world facts."""

    scenario_id: str
    verdict: RailComparisonVerdict
    facts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "verdict": self.verdict.to_dict(),
            "facts": self.facts,
        }


def assert_semantic_equivalence(verdict: RailComparisonVerdict) -> RailComparisonVerdict:
    """Fail closed unless the verdict proves cross-rail equivalence."""
    if verdict.verdict != "EQUIVALENT":
        differences = "; ".join(
            difference.path for difference in verdict.differences[:5]
        )
        raise CoreValidationError(
            f"IG-005 semantic divergence between the two rail worlds of "
            f"scenario {verdict.scenario_id!r} "
            f"({len(verdict.differences)} classified difference(s), first "
            f"at: {differences or 'unknown path'})"
        )
    return verdict


def _execution_attempts(gate: FulfillmentLifecycleGate) -> list[Any]:
    return [
        record
        for record in gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
    ]


def _execution_steps(gate: FulfillmentLifecycleGate) -> list[Any]:
    return [
        record
        for record in gate.execution.objects()
        if record.__class__.__name__ == "ExecutionStep"
    ]


def _finality_records(gate: FulfillmentLifecycleGate) -> list[Any]:
    return [
        record
        for record in gate.settlement.records()
        if record.__class__.__name__ == "Finality"
    ]


class ExternalRailSandboxGate:
    """IG-005: one declared scenario executing on two rail worlds.

    The gate composes the two IG-002 lifecycle gates (one per rail
    world) and owns ONLY the comparison between them. The lifecycle
    semantics stay with the composed domain engines; the
    world-specific transport stays with the world harnesses.
    """

    def __init__(
        self,
        pair: Sequence[RailWorld] | RailWorldPair,
        *,
        gate_id: str = RAILS_GATE_ID,
        actor: str = DEFAULT_RAILS_ACTOR,
        authorized_actors: Iterable[str] = DEFAULT_AUTHORIZED_ACTORS,
    ) -> None:
        validate_rails_gate_id(gate_id)
        if isinstance(pair, RailWorldPair):
            world_a, world_b = pair.rail_a, pair.rail_b
        else:
            worlds = tuple(pair)
            if len(worlds) != 2:
                raise CoreValidationError(
                    "the rail sandbox gate requires exactly the two rail "
                    "world harnesses"
                )
            world_a, world_b = worlds
        for world in (world_a, world_b):
            if not isinstance(world, RailWorld):
                raise CoreValidationError(
                    "the rail sandbox gate composes RailWorld harnesses"
                )
        if world_a.name == world_b.name:
            raise CoreValidationError(
                "the two compared rail worlds must carry distinct names"
            )
        if world_a.environment_id == world_b.environment_id:
            raise CoreValidationError(
                "the two compared rail worlds must run in distinct "
                "environments (environment isolation)"
            )
        if world_a.domain_id == world_b.domain_id:
            raise CoreValidationError(
                "the two compared rail worlds must bind distinct domains "
                "(domain isolation)"
            )
        if world_a.adapter_id == world_b.adapter_id:
            raise CoreValidationError(
                "the two compared rail worlds must bind distinct typed "
                "adapter contracts"
            )
        if world_a.rail_class is not world_b.rail_class:
            raise CoreValidationError(
                "one comparison compares rails of ONE classification "
                "(a real rail pair or a local deterministic pair — never "
                "mixed classes)"
            )
        self._gate_id = gate_id
        self._world_a = world_a
        self._world_b = world_b
        actors = frozenset(authorized_actors) | {actor}
        self._gate_a = FulfillmentLifecycleGate(
            environment_id=world_a.environment_id,
            domain_id=world_a.domain_id,
            bindings={world_a.adapter_id: world_a.binding},
            authorized_actors=actors,
            actor=actor,
        )
        self._gate_b = FulfillmentLifecycleGate(
            environment_id=world_b.environment_id,
            domain_id=world_b.domain_id,
            bindings={world_b.adapter_id: world_b.binding},
            authorized_actors=actors,
            actor=actor,
        )

    # ------------------------------------------------------------------
    # read-only access to the two composed worlds
    # ------------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def rail_a_world(self) -> RailWorld:
        return self._world_a

    @property
    def rail_b_world(self) -> RailWorld:
        return self._world_b

    @property
    def rail_a_gate(self) -> FulfillmentLifecycleGate:
        return self._gate_a

    @property
    def rail_b_gate(self) -> FulfillmentLifecycleGate:
        return self._gate_b

    @property
    def worlds(self) -> tuple[RailWorld, RailWorld]:
        return (self._world_a, self._world_b)

    # ------------------------------------------------------------------
    # the projection, comparison and verdict authority
    # ------------------------------------------------------------------

    def semantic_state(self, world: str | RailWorld) -> dict[str, Any]:
        """The raw canonical semantic state of one world's execution."""
        return semantic_state(self._lifecycle_gate_of(world))

    def semantic_projection(self, world: str | RailWorld) -> dict[str, Any]:
        """The normalized semantic projection of one world's execution."""
        return semantic_projection(
            self._lifecycle_gate_of(world), self._world_of(world)
        )

    def semantic_projection_digest(self, world: str | RailWorld) -> str:
        return semantic_projection_digest(self.semantic_projection(world))

    def raw_state_digest(self, world: str | RailWorld) -> str:
        return raw_state_digest(self._lifecycle_gate_of(world))

    def compare_projections(
        self,
        rail_a: dict[str, Any] | None = None,
        rail_b: dict[str, Any] | None = None,
    ) -> tuple[ClassifiedDifference, ...]:
        """Diff the two (normalized) projections; every difference is semantic.

        Explicit projections may be passed for the discrimination
        battery (corrupted feeds); by default both live projections are
        compared.
        """
        left = (
            self.semantic_projection(self.rail_a_world)
            if rail_a is None
            else rail_a
        )
        right = (
            self.semantic_projection(self.rail_b_world)
            if rail_b is None
            else rail_b
        )
        return compare_projections(left, right)

    def rail_comparison_verdict(
        self,
        *,
        scenario_id: str,
        shared_input_digest: str,
        invariant_checks: Iterable[str] | None = None,
    ) -> RailComparisonVerdict:
        """Project both worlds, classify differences, issue the verdict."""
        differences = self.compare_projections()
        verdict = "EQUIVALENT" if not differences else "DIVERGENCE"
        checks: tuple[str, ...]
        if invariant_checks is not None:
            checks = tuple(invariant_checks)
        else:
            from .invariants import verify_rails_invariants

            # On EQUIVALENT the full cross-rail battery validates the
            # claim; on DIVERGENCE the classified differences ARE the
            # report and the per-world structural battery still verifies
            # both worlds are internally sound.
            checks = tuple(
                verify_rails_invariants(self, cross_rail=verdict == "EQUIVALENT")
            )
        return RailComparisonVerdict(
            schema_version=RAILS_SCHEMA_VERSION,
            gate_id=self._gate_id,
            scenario_id=scenario_id,
            shared_input_digest=shared_input_digest,
            rail_a=self.world_execution_report(self.rail_a_world),
            rail_b=self.world_execution_report(self.rail_b_world),
            normalization_digest=RAILS_NORMALIZATION_DIGEST,
            differences=differences,
            verdict=verdict,
            invariant_checks=checks,
        )

    def world_execution_report(
        self, world: str | RailWorld
    ) -> RailWorldExecutionReport:
        world_harness = self._world_of(world)
        gate = self._lifecycle_gate_of(world)
        attempts = _execution_attempts(gate)
        steps = _execution_steps(gate)
        references = tuple(
            sorted(
                {
                    attempt.spec.native_reference
                    for attempt in attempts
                    if attempt.spec.native_reference is not None
                }
            )
        )
        submission_class = (
            attempts[-1].spec.status.value if attempts else "NONE"
        )
        step_state = steps[-1].state.value if steps else "NONE"
        finality_established = any(
            record.state.value == "ESTABLISHED"
            for record in _finality_records(gate)
        )
        return RailWorldExecutionReport(
            name=world_harness.name,
            rail_class=world_harness.rail_class.value,
            environment_id=world_harness.environment_id,
            domain_id=world_harness.domain_id,
            environment_class=world_harness.environment_class,
            adapter_id=world_harness.adapter_id,
            declared_currency=world_harness.declared_currency,
            declared_amount_minor=world_harness.declared_amount_minor,
            native_references=references,
            submission_class=submission_class,
            step_state=step_state,
            finality_established=finality_established,
            raw_state_digest=raw_state_digest(gate),
            semantic_projection_digest=semantic_projection_digest(
                semantic_projection(gate, world_harness)
            ),
            stage_count=len(gate.stage_journal),
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _world_of(self, world: str | RailWorld) -> RailWorld:
        if isinstance(world, RailWorld):
            if world is self._world_a or world is self._world_b:
                return world
            raise CoreValidationError(
                "the gate composes only its own two rail worlds"
            )
        if world in (self._world_a.name, "rail_a", "a"):
            return self._world_a
        if world in (self._world_b.name, "rail_b", "b"):
            return self._world_b
        raise CoreValidationError(f"unknown rail world {world!r}")

    def _lifecycle_gate_of(self, world: str | RailWorld) -> FulfillmentLifecycleGate:
        if self._world_of(world) is self._world_a:
            return self._gate_a
        return self._gate_b


__all__ = [
    "ExternalRailSandboxGate",
    "RailComparisonVerdict",
    "RailWorldExecutionReport",
    "RailWorldPair",
    "ScenarioOutcome",
    "assert_semantic_equivalence",
]
