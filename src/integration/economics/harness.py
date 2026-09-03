"""The IG-004 economic integration gate harness.

:class:`EconomicIntegrationGate` composes the REAL merged surfaces of
the two declared economic worlds and drives the canonical scenario
through their PUBLIC boundaries only:

* the merchant demand stage builds the sealed checkout record through
  ``src.merchant``'s public record factory and derives the typed
  demand-signal artifact;
* the extension stages drive the REAL marketplace lifecycle
  (register → sandbox → certify → submit → approve ×2 → publish →
  install → activate) and the sandboxed treatment invocation through
  the real kernel (``ExtensionRuntime.submit``);
* the agent stages drive the REAL model lifecycle, the bounded
  mandate, the hypothetical-only context, the kernel-recorded route
  proposals and the simulation-first mediation
  (``MediationEngine.mediate`` — every candidate simulated in a
  fresh SIMULATION-mode environment, deterministic policy selection,
  decision recorded through the kernel with no execution authority);
* the contribution stage measures the verified incremental
  contribution through the REAL ``extension/measure`` kernel command
  (the marketplace's own pricing and evidence-resolution discipline).

Every stage appends its semantic tuples to the gate's append-only
stage journal with per-world composed-state checkpoints, and every
REJECTED command is proven state-preserving (the composed state digest
is byte-identical before and after — the fail-closed rejection
discipline). The parity verdict projects both worlds' composed state
through the owning engines' trusted paths, applies the frozen
field-bound normalization registry and delegates the difference walk
to the merged IG-003 ``compare_projections`` authority: every residual
difference is a semantic divergence and fails the gate closed.

Determinism discipline: no clock reads, no entropy, no generated
identifiers — every instant is declared ``as_of`` data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from src.agents import MediationDecision, RouteProposal
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.extensions import ExtensionLifecycleState
from src.integration.parity import ClassifiedDifference, compare_projections
from src.merchant import Checkout
from src.simulation import EnvironmentMode
from src.transition import Command, Outcome

from src.integration.economics.contracts import (
    CONTRIBUTION_ID,
    DEFAULT_ECONOMICS_ACTOR,
    DECISION_ID,
    DEMAND_ARTIFACT_ID,
    ECONOMICS_API_VERSION,
    ECONOMICS_SCHEMA_VERSION,
    EXTENSION_ID,
    EconomicRole,
    INSTANCE_ID,
    MEDIATION_ACTOR,
    MEDIATION_ID,
    PROPOSAL_ALPHA_ID,
    PROPOSAL_BRAVO_ID,
    SANDBOX_INVOCATION_ID,
    TREATMENT_INVOCATION_ID,
    EconomicRole as _Role,
    validate_economics_gate_id,
)
from src.integration.economics.projection import (
    NORMALIZATION_DIGEST,
    economic_projection,
    economic_projection_digest,
    economic_state,
    normalize_economic_state,
)
from src.integration.economics.worlds import (
    EconomicPair,
    EconomicWorld,
    agents_command,
    build_economic_pair,
    capability_grant_fixture,
    current_extension_version,
    demand_artifact,
    economy_route_metrics_from_artifact,
    extension_command,
    build_merchant_checkout,
    premium_declared_route_metrics,
    build_mediation_world,
    record_proposal,
    register_model_commands,
    authorize_mandate,
    build_context,
    route_proposal,
)
from src.integration.economics.contracts import (
    ECONOMY_FAMILY,
    PREMIUM_FAMILY,
    T_INSTALL,
    T_MANDATE,
    T_MEDIATE,
    T_MEASURE,
    T_PROPOSE,
    T_REGISTER,
    T_REVIEW,
    T_SANDBOX,
    T_TREATMENT,
)

#: The frozen stage names of the canonical scenario (in execution order).
CANONICAL_STAGES = (
    "merchant-demand",
    "extension-register",
    "extension-sandbox",
    "extension-sandbox-invocation",
    "extension-certify",
    "extension-submit",
    "extension-approve-security",
    "extension-approve-policy",
    "extension-publish",
    "extension-install",
    "extension-activate",
    "extension-treatment",
    "agent-models",
    "agent-mandate",
    "agent-context",
    "agent-proposal-alpha",
    "agent-proposal-bravo",
    "mediation-select",
    "contribution-measure",
)


@dataclass(frozen=True)
class EconomicVerdict:
    """The sealed parity verdict of one economic scenario execution.

    ``verdict`` is ``ECONOMIC_PARITY`` when the two normalized semantic
    projections are equivalent, ``ECONOMIC_DIVERGENCE`` otherwise; the
    ``differences`` are the residual differences classified by the
    merged IG-003 diff authority (every one is a semantic divergence).
    The verdict vocabulary deliberately differs from IG-003's PARITY
    vocabulary: this gate compares the composed extension/agent
    economics surface, not the fulfillment lifecycle surface — no
    second parity authority over any already-owned semantic surface is
    introduced.
    """

    scenario_id: str
    verdict: str
    differences: tuple[ClassifiedDifference, ...]
    simulation_digest: str
    production_digest: str
    normalization_digest: str
    checks: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.verdict not in ("ECONOMIC_PARITY", "ECONOMIC_DIVERGENCE"):
            raise CoreValidationError(
                f"unknown economic verdict {self.verdict!r}"
            )
        if self.verdict == "ECONOMIC_PARITY" and self.differences:
            raise CoreValidationError(
                "an ECONOMIC_PARITY verdict cannot carry classified differences"
            )
        for difference in self.differences:
            if not isinstance(difference, ClassifiedDifference):
                raise CoreValidationError(
                    "economic verdict differences must be the merged IG-003 "
                    "ClassifiedDifference records"
                )


def assert_economic_parity(verdict: EconomicVerdict) -> EconomicVerdict:
    """Fail closed unless the verdict proves composed economic parity."""
    if verdict.verdict != "ECONOMIC_PARITY":
        differences = "; ".join(
            difference.path for difference in verdict.differences[:5]
        )
        raise CoreValidationError(
            f"IG-004 semantic divergence between the simulation and the "
            f"production-compatible execution of scenario "
            f"{verdict.scenario_id!r} ({len(verdict.differences)} classified "
            f"difference(s), first at: {differences or 'unknown path'})"
        )
    return verdict


class EconomicIntegrationGate:
    """IG-004: the extension/agent economic composition, in two worlds.

    The gate composes the two economic worlds (one domain binding per
    surface, two environment bindings) and owns ONLY the driving of
    the declared scenario and the comparison between the worlds. All
    domain semantics stay with the composed merged engines.
    """

    def __init__(
        self,
        *,
        pair: EconomicPair | tuple[EconomicWorld, EconomicWorld] | None = None,
        gate_id: str = "IG-004",
        actor: str = DEFAULT_ECONOMICS_ACTOR,
    ) -> None:
        validate_economics_gate_id(gate_id)
        if pair is None:
            pair = build_economic_pair()
        if isinstance(pair, EconomicPair):
            simulation, production = pair.simulation, pair.production
        else:
            worlds = tuple(pair)
            if len(worlds) != 2:
                raise CoreValidationError(
                    "the economic gate requires exactly the two world harnesses"
                )
            simulation, production = worlds
        for world in (simulation, production):
            if not isinstance(world, EconomicWorld):
                raise CoreValidationError(
                    "the economic gate composes EconomicWorld harnesses"
                )
        if simulation.role is not EconomicRole.SIMULATION:
            raise CoreValidationError(
                "the first world of the economic gate must be the SIMULATION world"
            )
        if production.role is not EconomicRole.PRODUCTION_COMPATIBLE:
            raise CoreValidationError(
                "the second world of the economic gate must be the "
                "PRODUCTION-COMPATIBLE world"
            )
        self._gate_id = gate_id
        self._actor = actor
        self._simulation = simulation
        self._production = production
        self._stage_journal: list[dict] = []
        # Bind the worlds' back-references (the projection reads the
        # stage journal of the owning world through them).
        simulation.gate = self
        production.gate = self

    # -- identity ------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def actor(self) -> str:
        return self._actor

    @property
    def api_version(self) -> str:
        return ECONOMICS_API_VERSION

    @property
    def schema_version(self) -> int:
        return ECONOMICS_SCHEMA_VERSION

    @property
    def worlds(self) -> tuple[EconomicWorld, EconomicWorld]:
        return (self._simulation, self._production)

    @property
    def simulation_world(self) -> EconomicWorld:
        return self._simulation

    @property
    def production_world(self) -> EconomicWorld:
        return self._production

    @property
    def stage_journal(self) -> tuple[dict, ...]:
        return tuple(self._stage_journal)

    # -- composed state digests ----------------------------------------------

    def composed_state_digest(self, world: EconomicWorld) -> str:
        """The canonical digest of one world's whole composed state.

        A pure function of the accepted command history read through
        the owning engines' trusted paths: the sealed merchant record,
        the extension domain projection digest and the agents domain
        state digest.
        """
        checkout = world.checkout
        return canonical_sha256(
            {
                "environment_id": world.environment_id,
                "checkout": checkout.to_dict() if checkout is not None else None,
                "extensions": world.runtime.domain_state_digest(),
                "agents": world.agents.state_digest(),
            }
        )

    def snapshot(self) -> dict:
        """The full composed snapshot of both worlds (deterministic)."""
        return {
            "gate_id": self._gate_id,
            "stage_journal": [dict(entry) for entry in self._stage_journal],
            "simulation": {
                "environment_id": self._simulation.environment_id,
                "composed_state_digest": self.composed_state_digest(
                    self._simulation
                ),
            },
            "production": {
                "environment_id": self._production.environment_id,
                "composed_state_digest": self.composed_state_digest(
                    self._production
                ),
            },
        }

    # -- stage driving ---------------------------------------------------------

    def _record_stage(
        self,
        stage: str,
        world: EconomicWorld,
        *,
        domain: str,
        command_id: str,
        requested_at: str,
        outcome: str,
        state_before: str,
        state_after: str,
    ) -> None:
        if self._stage_journal:
            previous = self._stage_journal[-1]
            if (
                previous["role"] == world.role.value
                and previous["state_after"] != state_before
            ):
                raise CoreValidationError(
                    f"stage journal chaining violated at {stage!r}: the world's "
                    "composed state changed outside a recorded stage"
                )
        self._stage_journal.append(
            {
                "stage": stage,
                "role": world.role.value,
                "domain": domain,
                "command_id": command_id,
                "requested_at": requested_at,
                "outcome": outcome,
                "state_before": state_before,
                "state_after": state_after,
            }
        )

    def _submit_extension(
        self, world: EconomicWorld, stage: str, command: Command
    ):
        state_before = self.composed_state_digest(world)
        result = world.runtime.submit(command)
        state_after = self.composed_state_digest(world)
        if result.outcome is not Outcome.ACCEPTED and state_after != state_before:
            raise CoreValidationError(
                f"rejected extension command {command.command_id} mutated the "
                "composed state; failing closed on divergence"
            )
        self._record_stage(
            stage,
            world,
            domain=world.extensions_domain_id,
            command_id=command.command_id,
            requested_at=command.requested_at,
            outcome=result.outcome.name,
            state_before=state_before,
            state_after=state_after,
        )
        return result

    def _submit_agents(self, world: EconomicWorld, stage: str, command: Command):
        state_before = self.composed_state_digest(world)
        result = world.agents.process(command)
        state_after = self.composed_state_digest(world)
        if result.outcome is not Outcome.ACCEPTED and state_after != state_before:
            raise CoreValidationError(
                f"rejected agents command {command.command_id} mutated the "
                "composed state; failing closed on divergence"
            )
        self._record_stage(
            stage,
            world,
            domain=world.agents_domain_id,
            command_id=command.command_id,
            requested_at=command.requested_at,
            outcome=result.outcome.name,
            state_before=state_before,
            state_after=state_after,
        )
        return result

    # -- the canonical stages (each drives both worlds in lockstep) ----------

    def stage_merchant_demand(self) -> None:
        """Build the sealed merchant checkout + the demand artifact."""
        for world in self.worlds:
            state_before = self.composed_state_digest(world)
            world.checkout = build_merchant_checkout(world.environment_id)
            world.demand_artifact = demand_artifact(world.checkout)
            state_after = self.composed_state_digest(world)
            self._record_stage(
                "merchant-demand",
                world,
                domain=world.merchant_domain_id,
                command_id=f"record/{world.checkout.spec.checkout_id}",
                requested_at=T_REGISTER,
                outcome="ACCEPTED",
                state_before=state_before,
                state_after=state_after,
            )

    def stage_extension_publish(self) -> None:
        """Sandbox-certify, review and publish the pre-registered extension.

        The manifest itself is part of the world fixture (pre-registered
        at construction through the public ``extension/register``
        command); this stage drives the REAL lifecycle advancement:
        sandbox submission, sandbox invocation, certification, review
        submission, both approvals and publication. Each sub-stage
        drives BOTH worlds before the next one starts, so the stage
        journal records the two worlds in strict lockstep.
        """
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-sandbox",
                extension_command(
                    world,
                    command_id="cmd/ig004-submit-sandbox",
                    command_type="extension/submit",
                    target_refs=(EXTENSION_ID,),
                    payload={},
                    expected_versions=(
                        (EXTENSION_ID, current_extension_version(world, EXTENSION_ID)),
                    ),
                    requested_at=T_SANDBOX,
                ),
            )
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-sandbox-invocation",
                extension_command(
                    world,
                    command_id=f"cmd/{SANDBOX_INVOCATION_ID}",
                    command_type="extension/invoke",
                    target_refs=(SANDBOX_INVOCATION_ID,),
                    payload={
                        "invocation_id": SANDBOX_INVOCATION_ID,
                        "capability": "route_proposal",
                        "inputs": [world.demand_artifact.to_dict()],
                        "resources": {
                            "read_market_data": {"spread_bps": 12},
                        },
                        "as_of": T_SANDBOX,
                        "jurisdiction": "US",
                    },
                    expected_versions=(
                        (SANDBOX_INVOCATION_ID, 0),
                        (EXTENSION_ID, current_extension_version(world, EXTENSION_ID)),
                    ),
                    requested_at=T_SANDBOX,
                ),
            )
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-certify",
                extension_command(
                    world,
                    command_id="cmd/ig004-certify",
                    command_type="extension/certify",
                    target_refs=(EXTENSION_ID,),
                    payload={},
                    expected_versions=(
                        (EXTENSION_ID, current_extension_version(world, EXTENSION_ID)),
                    ),
                    requested_at=T_SANDBOX,
                ),
            )
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-submit",
                extension_command(
                    world,
                    command_id="cmd/ig004-submit-review",
                    command_type="extension/submit",
                    target_refs=(EXTENSION_ID,),
                    payload={},
                    expected_versions=(
                        (EXTENSION_ID, current_extension_version(world, EXTENSION_ID)),
                    ),
                    requested_at=T_REVIEW,
                ),
            )
        for suffix in ("approve-security", "approve-policy"):
            for world in self.worlds:
                self._submit_extension(
                    world,
                    f"extension-{suffix}",
                    extension_command(
                        world,
                        command_id=f"cmd/ig004-{suffix}",
                        command_type="extension/approve",
                        target_refs=(EXTENSION_ID,),
                        payload={},
                        expected_versions=(
                            (
                                EXTENSION_ID,
                                current_extension_version(world, EXTENSION_ID),
                            ),
                        ),
                        requested_at=T_REVIEW,
                    ),
                )
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-publish",
                extension_command(
                    world,
                    command_id="cmd/ig004-publish",
                    command_type="extension/publish",
                    target_refs=(EXTENSION_ID,),
                    payload={},
                    expected_versions=(
                        (EXTENSION_ID, current_extension_version(world, EXTENSION_ID)),
                    ),
                    requested_at=T_REVIEW,
                ),
            )

    def stage_extension_install(self) -> None:
        """Install and activate the extension instance with its grant.

        Each sub-stage drives BOTH worlds before the next one starts
        (strict journal lockstep).
        """
        grant = capability_grant_fixture()
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-install",
                extension_command(
                    world,
                    command_id="cmd/ig004-install",
                    command_type="extension/install",
                    target_refs=(INSTANCE_ID, grant["grant_id"]),
                    payload={
                        "instance_id": INSTANCE_ID,
                        "manifest_id": EXTENSION_ID,
                        "version": "1.0.0",
                        "jurisdictions": ("US",),
                        "grants": [grant],
                    },
                    expected_versions=(
                        (INSTANCE_ID, 0),
                        (grant["grant_id"], 0),
                    ),
                    requested_at=T_INSTALL,
                ),
            )
        for world in self.worlds:
            self._submit_extension(
                world,
                "extension-activate",
                extension_command(
                    world,
                    command_id="cmd/ig004-activate",
                    command_type="extension/activate",
                    target_refs=(INSTANCE_ID,),
                    payload={},
                    expected_versions=(
                        (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
                    ),
                    requested_at=T_INSTALL,
                ),
            )

    def stage_extension_treatment(self) -> None:
        """Run the live treatment invocation and build the mediation world.

        The invocation runs against the ACTIVE instance through the
        covering grant; its output artifact (the economy route
        economics) becomes — together with the declared premium
        default — the mediation world's route observations: the
        load-bearing agent+extension composition binding.
        """
        for world in self.worlds:
            result = self._submit_extension(
                world,
                "extension-treatment",
                extension_command(
                    world,
                    command_id=f"cmd/{TREATMENT_INVOCATION_ID}",
                    command_type="extension/invoke",
                    target_refs=(TREATMENT_INVOCATION_ID,),
                    payload={
                        "invocation_id": TREATMENT_INVOCATION_ID,
                        "capability": "route_proposal",
                        "inputs": [world.demand_artifact.to_dict()],
                        "resources": {"read_market_data": {"spread_bps": 12}},
                        "as_of": T_TREATMENT,
                        "jurisdiction": "US",
                    },
                    expected_versions=(
                        (TREATMENT_INVOCATION_ID, 0),
                        (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
                    ),
                    requested_at=T_TREATMENT,
                ),
            )
            if result.outcome is not Outcome.ACCEPTED:
                raise CoreValidationError(
                    "the treatment invocation was not accepted: the composed "
                    "economic chain cannot continue"
                )
            world.treatment_invocation_ids.append(TREATMENT_INVOCATION_ID)
            invocation = world.runtime.invocation(TREATMENT_INVOCATION_ID)
            artifact = invocation.output_artifacts[0]
            world.route_metrics = {
                PREMIUM_FAMILY: premium_declared_route_metrics(),
                ECONOMY_FAMILY: economy_route_metrics_from_artifact(artifact),
            }
            world.world_source = build_mediation_world(world.route_metrics)

    def stage_agent_models(self) -> None:
        """Drive the model lifecycle (register→validate→approve→deploy ×2)."""
        for world in self.worlds:
            state_before = self.composed_state_digest(world)
            register_model_commands(world)
            state_after = self.composed_state_digest(world)
            self._record_stage(
                "agent-models",
                world,
                domain=world.agents_domain_id,
                command_id="cmd/register-model/ig004",
                requested_at=T_MEDIATE,
                outcome="ACCEPTED",
                state_before=state_before,
                state_after=state_after,
            )

    def stage_agent_mandate_context(self) -> None:
        """Authorize the bounded mandate and build the agent context."""
        from src.integration.economics.contracts import AGENT_PRINCIPAL, MANDATE_ID, PROPOSAL_AUTHORITY_CLASS
        from src.integration.economics.contracts import (
            ECONOMY_LATENCY_MS as _LAT,
            PREMIUM_LATENCY_MS as _PLAT,
        )

        del _LAT, _PLAT  # (fixture clarity only)
        for world in self.worlds:
            state_before = self.composed_state_digest(world)
            authorize_mandate(world)
            world.context = build_context(world)
            state_after = self.composed_state_digest(world)
            self._record_stage(
                "agent-mandate",
                world,
                domain=world.agents_domain_id,
                command_id="cmd/mandate-ig004",
                requested_at=T_MANDATE,
                outcome="ACCEPTED",
                state_before=state_before,
                state_after=state_after,
            )

    def stage_agent_proposals(self) -> None:
        """Record the two candidate route proposals through the kernel."""
        from src.integration.economics.contracts import (
            ECONOMY_RELIABILITY_BPS,
            PREMIUM_COST_MINOR,
            PREMIUM_LATENCY_MS,
            PREMIUM_RELIABILITY_BPS,
        )

        for proposal_id, family, stage in (
            (PROPOSAL_ALPHA_ID, PREMIUM_FAMILY, "agent-proposal-alpha"),
            (PROPOSAL_BRAVO_ID, ECONOMY_FAMILY, "agent-proposal-bravo"),
        ):
            for world in self.worlds:
                metrics = world.route_metrics[family]
                proposal = route_proposal(
                    world,
                    proposal_id=proposal_id,
                    route_family=family,
                    declared_cost_minor=metrics["cost-minor"],
                    declared_latency_ms=(
                        PREMIUM_LATENCY_MS
                        if family is PREMIUM_FAMILY
                        else metrics["latency-ms"]
                    ),
                    declared_reliability_bps=(
                        PREMIUM_RELIABILITY_BPS
                        if family is PREMIUM_FAMILY
                        else ECONOMY_RELIABILITY_BPS
                    ),
                )
                result = self._submit_agents(
                    world,
                    stage,
                    agents_command(
                        world,
                        command_id=f"propose-{proposal.proposal_id}",
                        command_type="agent/propose",
                        actor=proposal.spec.agent_principal,
                        target=proposal.proposal_id,
                        payload={"proposal": proposal.to_dict()},
                        requested_at=T_PROPOSE,
                    ),
                )
                if result.outcome is not Outcome.ACCEPTED:
                    raise CoreValidationError(
                        f"agent proposal {proposal.proposal_id} was not accepted"
                    )
                world.proposals[proposal.proposal_id] = proposal

    def stage_mediate(self) -> None:
        """Simulate every candidate and record the mediation decision.

        The mediation is simulation-first (the frozen required mode):
        every proposal is simulated in a fresh SIMULATION-mode
        environment through the merged ``simulate_candidate`` public
        contract, the deterministic policy selects, and the sealed
        decision is recorded through the kernel — a decision, never an
        execution.
        """
        for world in self.worlds:
            state_before = self.composed_state_digest(world)
            decision = world.mediator.mediate(
                context=world.context,
                proposals=tuple(
                    world.proposals[proposal_id]
                    for proposal_id in (PROPOSAL_ALPHA_ID, PROPOSAL_BRAVO_ID)
                ),
                world=world.world_source,
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=MEDIATION_ACTOR,
            )
            world.decision = decision
            state_after = self.composed_state_digest(world)
            self._record_stage(
                "mediation-select",
                world,
                domain=world.agents_domain_id,
                command_id=f"cmd/mediate/{DECISION_ID}",
                requested_at=T_MEDIATE,
                outcome="ACCEPTED",
                state_before=state_before,
                state_after=state_after,
            )

    def stage_measure_contribution(self) -> None:
        """Measure the verified incremental contribution (kernel-bound)."""
        for world in self.worlds:
            invocation = world.runtime.invocation(TREATMENT_INVOCATION_ID)
            savings = invocation.output_artifacts[0].payload_value()[
                "cost_savings_minor"
            ]
            result = self._submit_extension(
                world,
                "contribution-measure",
                extension_command(
                    world,
                    command_id="cmd/ig004-measure",
                    command_type="extension/measure",
                    target_refs=(CONTRIBUTION_ID,),
                    payload={
                        "contribution_id": CONTRIBUTION_ID,
                        "baseline": {
                            "extension_id": EXTENSION_ID,
                            "metric": "cost_savings_minor",
                            "value": 0,
                            "as_of": T_MEASURE,
                            "epistemic_type": "COUNTERFACTUAL",
                            "evidence_refs": [
                                "counterfactual/ig004-default-route"
                            ],
                        },
                        "treatment": {
                            "extension_id": EXTENSION_ID,
                            "metric": "cost_savings_minor",
                            "value": savings,
                            "as_of": T_MEASURE,
                            "epistemic_type": "SIMULATED",
                            "evidence_refs": list(
                                world.treatment_invocation_ids
                            ),
                        },
                    },
                    expected_versions=((CONTRIBUTION_ID, 0),),
                    requested_at=T_MEASURE,
                ),
            )
            if result.outcome is not Outcome.ACCEPTED:
                raise CoreValidationError(
                    "the contribution measurement was not accepted"
                )
            world.contribution = world.runtime.contribution(CONTRIBUTION_ID)

    # -- the verdict ------------------------------------------------------------

    def parity_verdict(
        self, scenario_id: str = "ig004/canonical"
    ) -> EconomicVerdict:
        """Project, normalize, compare and seal the parity verdict."""
        from src.integration.economics.invariants import verify_economic_invariants

        simulation = normalize_economic_state(
            economic_state(self._simulation), self._simulation
        )
        production = normalize_economic_state(
            economic_state(self._production), self._production
        )
        differences = compare_projections(simulation, production)
        cross_world = not differences
        checks = verify_economic_invariants(self, cross_world=cross_world)
        verdict = (
            "ECONOMIC_PARITY" if not differences else "ECONOMIC_DIVERGENCE"
        )
        return EconomicVerdict(
            scenario_id=scenario_id,
            verdict=verdict,
            differences=tuple(differences),
            simulation_digest=canonical_sha256(simulation),
            production_digest=canonical_sha256(production),
            normalization_digest=NORMALIZATION_DIGEST,
            checks=tuple(checks),
        )

    def run_canonical_scenario(self) -> EconomicVerdict:
        """Drive every canonical stage in order and seal the verdict."""
        self.stage_merchant_demand()
        self.stage_extension_publish()
        self.stage_extension_install()
        self.stage_extension_treatment()
        self.stage_agent_models()
        self.stage_agent_mandate_context()
        self.stage_agent_proposals()
        self.stage_mediate()
        self.stage_measure_contribution()
        return self.parity_verdict()
