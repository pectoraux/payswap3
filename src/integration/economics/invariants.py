"""The IG-004 economic invariant battery.

``verify_economic_invariants`` runs after the declared scenario has
executed (the parity verdict calls it) and re-runs on rebuilt gates.
Each check re-derives facts through the OWNING engines' trusted paths
— never from gate-side caches — so a violation of the composed
extension/agent economic discipline inside EITHER world fails closed
immediately, and a divergence between the two environments fails
closed too.

Checks (the frozen IG-004 dimensions):

* environment isolation: every durable record of each world carries
  exactly that world's environment id, and the composed engines of
  each world share it;
* domain isolation: every record stays in its owning engine's domain
  inside each world;
* append-only history: the stage journals chain, and the kernel
  journals of both engines carry unique event ids;
* authority containment: the extension events carry the runtime's
  frozen authority class, the agents events carry the frozen
  governance/proposal classes, the agent context is
  hypothetical-world-only, the extension invocations are RECORDED
  candidate artifacts (never production effects) and the mediation
  decision payload carries no execution authority of any kind;
* simulation-first decision: the frozen mediation mode is SIMULATION,
  every proposal is simulated before the decision (the decision's
  candidates cover the recorded proposals exactly, each in a fresh
  agents-mediation environment), the mediation world observations and
  the model outputs are SIMULATED-class evidence, and the decision
  event is a governance event recorded by an actor distinct from the
  proposing agent;
* composition binding: the demand artifact binds the sealed merchant
  checkout economics, the treatment invocation consumes exactly that
  demand artifact, the mediation world's economy-family observations
  are exactly the extension's measured route economics, and the
  extension's savings re-derive from the checkout amount;
* economic contribution: the baseline is COUNTERFACTUAL, the treatment
  is SIMULATED with recorded-invocation evidence, the incremental
  re-derives from the comparison, earnings are the exact integer
  revenue share gated on verification, attribution is conserved
  (earnings + residual == incremental), the metered resource credits
  stay a distinct typed quantity, and the manifest satisfies its
  authority-tier schedule;
* cross-world parity (when ``cross_world`` is true): the stage
  sequences, the contribution economics, the decision semantics and
  the normalized semantic projections are identical across the two
  environments.
"""

from __future__ import annotations

from typing import Any

from src.agents import (
    AGENT_ALLOWED_MODES,
    MEDIATION_REQUIRED_MODE,
    PROPOSAL_AUTHORITY_CLASS,
)
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.evidence.contracts import EpistemicType
from src.extensions import (
    RUNTIME_AUTHORITY_CLASS,
    ExtensionLifecycleState,
    InvocationEffectMode,
    TIER_MINIMUM_COLLATERAL_MINOR,
)
from src.simulation import EnvironmentMode

from src.integration.economics.contracts import (
    AGENT_PRINCIPAL,
    CONTRIBUTION_ID,
    DEMAND_ARTIFACT_ID,
    DECISION_ID,
    EXTENSION_ID,
    INSTANCE_ID,
    MEDIATION_ACTOR,
    PREMIUM_COST_MINOR,
    PROPOSAL_ALPHA_ID,
    PROPOSAL_BRAVO_ID,
    TREATMENT_INVOCATION_ID,
)
from src.integration.economics.harness import EconomicIntegrationGate
from src.integration.economics.projection import (
    MEDIATION_ENVIRONMENT_PREFIX,
    economic_projection_digest,
    economic_state,
    normalize_economic_state,
)
from src.integration.economics.worlds import EconomicWorld

_DECISION_FORBIDDEN_FIELDS = frozenset(
    {"effect_intents", "execution", "authority", "mandate_id_execute", "effects"}
)


def verify_economic_invariants(
    gate: EconomicIntegrationGate, *, cross_world: bool = True
) -> list[str]:
    """Run the battery; raise on the first violation; return check names.

    The per-world structural checks (environment/domain isolation,
    append-only history, authority containment, simulation-first
    decision, composition binding, economic contribution) always run:
    a divergence verdict never excuses an internally broken world. The
    cross-world equality checks run when ``cross_world`` is true — the
    parity verdict runs them for the PARITY case and reports the
    classified differences themselves for the DIVERGENCE case.
    """
    if not isinstance(gate, EconomicIntegrationGate):
        raise CoreValidationError(
            "the economic invariant battery requires an EconomicIntegrationGate"
        )
    checks: list[str] = []
    for world in gate.worlds:
        _check_environment_isolation(gate, world, checks)
        _check_domain_isolation(gate, world, checks)
        _check_append_only_history(gate, world, checks)
        _check_authority_containment(gate, world, checks)
        _check_simulation_first(gate, world, checks)
        _check_composition_binding(gate, world, checks)
        _check_economic_contribution(gate, world, checks)
    if cross_world:
        _check_stage_sequences(gate, checks)
        _check_contribution_economics(gate, checks)
        _check_decision_semantics(gate, checks)
        _check_normalized_projections(gate, checks)
        _check_epistemic_provenance(gate, checks)
    return checks


# -- per-world structural checks ---------------------------------------------


def _check_environment_isolation(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    state = economic_state(world)
    environment_id = world.environment_id
    if state["environment_id"] != environment_id:
        raise CoreValidationError(
            "the projected state does not bind the world's environment"
        )
    for entry in state["extensions"]["journal"]:
        if entry["environment_id"] != environment_id:
            raise CoreValidationError(
                f"extension event {entry['event_id']!r} does not carry the "
                f"world environment {environment_id!r}"
            )
    for entry in state["agents"]["journal"]:
        if entry["environment_id"] != environment_id:
            raise CoreValidationError(
                f"agents event {entry['event_id']!r} does not carry the world "
                f"environment {environment_id!r}"
            )
    merchant = state["merchant"]
    if merchant is not None:
        if merchant["envelope"]["environment_id"] != environment_id:
            raise CoreValidationError(
                "the merchant checkout record does not bind the world "
                "environment"
            )
    if world.runtime.environment_id != environment_id:
        raise CoreValidationError("the extension runtime binds a foreign environment")
    if world.agents.environment_id != environment_id:
        raise CoreValidationError("the agents engine binds a foreign environment")
    checks.append(f"environment-isolation:{world.role.value}")


def _check_domain_isolation(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    for entry in economic_state(world)["extensions"]["journal"]:
        if entry["domain_id"] != world.extensions_domain_id:
            raise CoreValidationError(
                f"extension event {entry['event_id']!r} left its owning domain"
            )
    for entry in economic_state(world)["agents"]["journal"]:
        if entry["domain_id"] != world.agents_domain_id:
            raise CoreValidationError(
                f"agents event {entry['event_id']!r} left its owning domain"
            )
    merchant = economic_state(world)["merchant"]
    if merchant is not None and (
        merchant["envelope"]["domain_id"] != world.merchant_domain_id
    ):
        raise CoreValidationError(
            "the merchant checkout record left its owning domain"
        )
    for entry in _world_stage_entries(gate, world):
        if entry["domain"] not in (
            world.extensions_domain_id,
            world.agents_domain_id,
            world.merchant_domain_id,
        ):
            raise CoreValidationError(
                f"stage {entry['stage']!r} recorded a foreign domain"
            )
    checks.append(f"domain-isolation:{world.role.value}")


def _check_append_only_history(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    entries = _world_stage_entries(gate, world)
    previous_after: str | None = None
    command_ids: set[str] = set()
    for entry in entries:
        if previous_after is not None and entry["state_before"] != previous_after:
            raise CoreValidationError(
                f"the stage journal of the {world.role.value} world broke its "
                f"chain at stage {entry['stage']!r}"
            )
        previous_after = entry["state_after"]
        if entry["command_id"] in command_ids:
            raise CoreValidationError(
                f"command {entry['command_id']!r} appears twice in the stage "
                "journal; the append-only discipline is violated"
            )
        command_ids.add(entry["command_id"])
    extension_event_ids = [
        entry.event.event_id for entry in world.runtime.engine.journal
    ]
    if len(set(extension_event_ids)) != len(extension_event_ids):
        raise CoreValidationError(
            "the extension kernel journal carries duplicate event ids"
        )
    agents_event_ids = [entry.event.event_id for entry in world.agents.journal]
    if len(set(agents_event_ids)) != len(agents_event_ids):
        raise CoreValidationError(
            "the agents kernel journal carries duplicate event ids"
        )
    checks.append(f"append-only-history:{world.role.value}")


def _check_authority_containment(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    # Extension-side containment: every extension event carries the
    # runtime's frozen authority class; the invocation records are
    # RECORDED candidate artifacts (the closed effect-mode vocabulary
    # never admits production effects); the manifest satisfies its
    # authority-tier schedule.
    for entry in economic_state(world)["extensions"]["journal"]:
        if entry["authority"] != RUNTIME_AUTHORITY_CLASS:
            raise CoreValidationError(
                f"extension event {entry['event_id']!r} carries authority "
                f"{entry['authority']!r}, not the runtime's frozen "
                f"{RUNTIME_AUTHORITY_CLASS!r}"
            )
    for invocation_id, invocation in economic_state(world)["extensions"][
        "invocations"
    ].items():
        record = invocation["record"]
        if record["effect_mode"] != InvocationEffectMode.RECORDED.value:
            raise CoreValidationError(
                f"invocation {invocation_id!r} carries effect mode "
                f"{record['effect_mode']!r}: extensions never produce "
                "production effects"
            )
    manifest = world.runtime.manifest(EXTENSION_ID)
    from src.extensions import require_tier_requirements

    require_tier_requirements("invariant manifest", manifest)
    if TIER_MINIMUM_COLLATERAL_MINOR[manifest.authority_class] > 0:
        raise CoreValidationError(
            "the composed extension declared a collateral-bearing tier; the "
            "R2 proposal tier carries no financial collateral by design"
        )

    # Agent-side containment: the context is hypothetical-world-only.
    context = world.context
    if context is None:
        raise CoreValidationError("the agent context is missing")
    modes = set(context.spec.allowed_modes)
    if not modes <= AGENT_ALLOWED_MODES:
        raise CoreValidationError(
            "the agent context admits non-hypothetical modes; agents never "
            "receive live-observation or ambient financial authority"
        )
    if EnvironmentMode.SIMULATION not in modes:
        raise CoreValidationError(
            "the agent context must include the SIMULATION mode: every "
            "proposal is mediated simulation-first"
        )

    # The decision carries no execution authority of any kind.
    decision = world.decision
    if decision is None:
        raise CoreValidationError("the mediation decision is missing")
    payload = decision.spec.to_dict()
    if _DECISION_FORBIDDEN_FIELDS & set(payload):
        raise CoreValidationError(
            "the mediation decision payload carries execution-shaped fields; "
            "a decision is never an execution"
        )
    checks.append(f"authority-containment:{world.role.value}")


def _check_simulation_first(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    if MEDIATION_REQUIRED_MODE is not EnvironmentMode.SIMULATION:
        raise CoreValidationError(
            "the frozen mediation mode must stay SIMULATION (simulation-first "
            "decision discipline)"
        )
    decision = world.decision
    if decision is None:
        raise CoreValidationError("the mediation decision is missing")
    candidates = decision.spec.candidates
    proposals = world.proposals
    if len(candidates) != len(proposals):
        raise CoreValidationError(
            "the mediation decision does not cover every recorded proposal: "
            "every candidate must be simulated before the decision"
        )
    candidate_ids = {candidate.proposal_id for candidate in candidates}
    if candidate_ids != set(proposals):
        raise CoreValidationError(
            "the decision's candidate set differs from the recorded proposals"
        )
    for candidate in candidates:
        if not candidate.environment_id.startswith(MEDIATION_ENVIRONMENT_PREFIX):
            raise CoreValidationError(
                f"candidate {candidate.proposal_id!r} was not simulated in a "
                "fresh agents-mediation environment"
            )
        metrics = candidate.as_outcome()
        if metrics.cost_minor < 0 or metrics.reliability_bps > 10_000:
            raise CoreValidationError(
                "candidate metrics violate the frozen bounds"
            )
    # The mediation world observations are SIMULATED-class evidence.
    if world.world_source is None:
        raise CoreValidationError("the mediation world source is missing")
    if world.world_source.epistemic_type is not EpistemicType.SIMULATED:
        raise CoreValidationError(
            "the mediation world observations must be SIMULATED-class "
            "evidence (the frozen mode→epistemic binding)"
        )
    # Model outputs can never masquerade as observations.
    for proposal in proposals.values():
        for output in proposal.spec.model_outputs:
            if output.epistemic_type not in (
                EpistemicType.SIMULATED,
                EpistemicType.PREDICTED,
            ):
                raise CoreValidationError(
                    "a model output carries a non-hypothetical epistemic class"
                )
    # The decision is a governance event recorded by an actor distinct
    # from the proposing agent (agents never mediate).
    journal = world.agents.journal
    if not journal or journal[-1].event.event_type != "governance/mediation-selected":
        raise CoreValidationError(
            "the mediation decision was not recorded as a governance event"
        )
    last_event = journal[-1].event
    if last_event.actor == AGENT_PRINCIPAL:
        raise CoreValidationError(
            "the proposing agent mediated its own proposals"
        )
    if last_event.actor != MEDIATION_ACTOR:
        raise CoreValidationError(
            "the mediation decision was recorded by an unexpected actor"
        )
    checks.append(f"simulation-first:{world.role.value}")


def _check_composition_binding(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    # The demand artifact binds the sealed merchant checkout economics.
    checkout = world.checkout
    demand = world.demand_artifact
    if checkout is None or demand is None:
        raise CoreValidationError("the merchant demand is missing")
    payload = demand.payload_value()
    if payload["volume_minor"] != checkout.spec.amount.value:
        raise CoreValidationError(
            "the demand artifact does not bind the checkout amount"
        )
    if payload["checkout_id"] != checkout.spec.checkout_id:
        raise CoreValidationError(
            "the demand artifact does not reference its checkout record"
        )

    # The treatment invocation consumes exactly the demand artifact and
    # produces the extension's route economics.
    invocation = world.runtime.invocation(TREATMENT_INVOCATION_ID)
    if invocation.input_artifact_ids != (DEMAND_ARTIFACT_ID,):
        raise CoreValidationError(
            "the treatment invocation did not consume the merchant demand "
            "artifact"
        )
    artifact = invocation.output_artifacts[0]
    if artifact.producer != EXTENSION_ID:
        raise CoreValidationError(
            "the treatment output artifact is not produced by the extension"
        )
    artifact_payload = artifact.payload_value()
    savings = artifact_payload["cost_savings_minor"]
    if savings != checkout.spec.amount.value // 100:
        raise CoreValidationError(
            "the extension's savings do not re-derive from the checkout amount"
        )
    if artifact_payload["cost_minor"] != PREMIUM_COST_MINOR - savings:
        raise CoreValidationError(
            "the extension's route cost does not embed its declared savings "
            "against the premium default"
        )

    # The mediation world's economy observations are exactly the
    # extension's measured route economics (the composition binding).
    economy_metrics = world.route_metrics.get("economy")
    if economy_metrics is None:
        raise CoreValidationError("the economy route metrics are missing")
    if economy_metrics["cost-minor"] != artifact_payload["cost_minor"]:
        raise CoreValidationError(
            "the mediation world's economy cost is not the extension's "
            "measured cost"
        )
    if economy_metrics["latency-ms"] != artifact_payload["latency_ms"]:
        raise CoreValidationError(
            "the mediation world's economy latency is not the extension's "
            "measured latency"
        )
    if economy_metrics["reliability-bps"] != artifact_payload["reliability_bps"]:
        raise CoreValidationError(
            "the mediation world's economy reliability is not the extension's "
            "measured reliability"
        )

    # The decision's candidate metrics come from the mediation world
    # (the world is the only metric source), and the selected proposal
    # is the deterministic policy winner (re-derived here).
    decision = world.decision
    if decision is None:
        raise CoreValidationError("the mediation decision is missing")
    for candidate in decision.spec.candidates:
        family = next(
            proposal.spec.route_family
            for proposal in world.proposals.values()
            if proposal.proposal_id == candidate.proposal_id
        )
        metrics = world.route_metrics[family]
        if candidate.as_outcome().cost_minor != metrics["cost-minor"]:
            raise CoreValidationError(
                f"candidate {candidate.proposal_id!r} cost is not the "
                "mediation world's observation"
            )
    checks.append(f"composition-binding:{world.role.value}")


def _check_economic_contribution(
    gate: EconomicIntegrationGate, world: EconomicWorld, checks: list[str]
) -> None:
    contribution = world.contribution
    if contribution is None:
        raise CoreValidationError("the contribution measurement is missing")
    if contribution.contribution_id != CONTRIBUTION_ID:
        raise CoreValidationError("the contribution identity is not the declared one")
    if contribution.baseline.epistemic_type is not EpistemicType.COUNTERFACTUAL:
        raise CoreValidationError(
            "the contribution baseline must be a COUNTERFACTUAL measurement"
        )
    if contribution.treatment.epistemic_type is EpistemicType.COUNTERFACTUAL:
        raise CoreValidationError(
            "the contribution treatment must not be COUNTERFACTUAL"
        )
    if contribution.baseline.value != 0:
        raise CoreValidationError(
            "the counterfactual baseline must measure the no-extension outcome"
        )
    invocation = world.runtime.invocation(TREATMENT_INVOCATION_ID)
    savings = invocation.output_artifacts[0].payload_value()[
        "cost_savings_minor"
    ]
    if contribution.treatment.value != savings:
        raise CoreValidationError(
            "the treatment measurement does not carry the extension's savings"
        )
    if contribution.treatment.evidence_refs != (TREATMENT_INVOCATION_ID,):
        raise CoreValidationError(
            "the treatment evidence does not point at the recorded invocation"
        )
    if contribution.incremental != contribution.treatment.value - contribution.baseline.value:
        raise CoreValidationError(
            "the incremental contribution does not re-derive from the "
            "baseline/treatment comparison"
        )
    if not contribution.verified or contribution.incremental <= 0:
        raise CoreValidationError(
            "the contribution is not verified incremental value"
        )
    expected_earnings = (
        contribution.pricing.share_bps * contribution.incremental
    ) // 10_000
    if contribution.earnings.amount_minor != expected_earnings:
        raise CoreValidationError(
            "the earnings are not the exact integer revenue share"
        )
    if contribution.billed_minor != contribution.earnings.amount_minor:
        raise CoreValidationError(
            "the price accounting does not match the earned share for the "
            "verified revenue-share measurement"
        )
    residual = contribution.incremental - contribution.earnings.amount_minor
    if residual < 0 or (
        contribution.earnings.amount_minor + residual != contribution.incremental
    ):
        raise CoreValidationError(
            "attribution is not conserved: earnings + residual != incremental"
        )
    if contribution.applied_invocations != 1:
        raise CoreValidationError(
            "the applied invocations do not derive from the recorded evidence"
        )
    if contribution.resource_credits.credits <= 0:
        raise CoreValidationError(
            "the metered resource credits are a distinct typed quantity and "
            "must be positive"
        )
    checks.append(f"economic-contribution:{world.role.value}")


# -- cross-world checks -------------------------------------------------------


def _world_stage_entries(
    gate: EconomicIntegrationGate, world: EconomicWorld
) -> list[dict]:
    return [
        entry for entry in gate.stage_journal if entry["role"] == world.role.value
    ]


def _check_stage_sequences(gate: EconomicIntegrationGate, checks: list[str]) -> None:
    simulation = _stage_tuples(gate, gate.simulation_world)
    production = _stage_tuples(gate, gate.production_world)
    if simulation != production:
        raise CoreValidationError(
            "the two worlds' stage sequences diverge: the same declared "
            "scenario must drive identical protocol transitions"
        )
    checks.append("state-machine-parity")


def _stage_tuples(gate: EconomicIntegrationGate, world: EconomicWorld) -> list[dict]:
    return [
        {
            "stage": entry["stage"],
            "domain": entry["domain"],
            "command_id": entry["command_id"],
            "requested_at": entry["requested_at"],
            "outcome": entry["outcome"],
        }
        for entry in _world_stage_entries(gate, world)
    ]


def _check_contribution_economics(
    gate: EconomicIntegrationGate, checks: list[str]
) -> None:
    simulation = gate.simulation_world.contribution
    production = gate.production_world.contribution
    if simulation is None or production is None:
        raise CoreValidationError("both worlds must measure the contribution")
    if simulation.incremental != production.incremental:
        raise CoreValidationError("the incremental contributions diverge")
    if simulation.earnings.amount_minor != production.earnings.amount_minor:
        raise CoreValidationError("the earnings diverge")
    if simulation.applied_invocations != production.applied_invocations:
        raise CoreValidationError("the applied invocations diverge")
    checks.append("contribution-parity")


def _check_decision_semantics(
    gate: EconomicIntegrationGate, checks: list[str]
) -> None:
    simulation = gate.simulation_world.decision
    production = gate.production_world.decision
    if simulation is None or production is None:
        raise CoreValidationError("both worlds must record a decision")
    if simulation.spec.selected_proposal_id != production.spec.selected_proposal_id:
        raise CoreValidationError("the selected proposals diverge")
    simulation_candidates = {
        candidate.proposal_id: candidate.as_outcome()
        for candidate in simulation.spec.candidates
    }
    production_candidates = {
        candidate.proposal_id: candidate.as_outcome()
        for candidate in production.spec.candidates
    }
    if set(simulation_candidates) != set(production_candidates):
        raise CoreValidationError("the candidate sets diverge")
    for proposal_id, outcome in simulation_candidates.items():
        other = production_candidates[proposal_id]
        if (outcome.cost_minor, outcome.latency_ms, outcome.reliability_bps) != (
            other.cost_minor,
            other.latency_ms,
            other.reliability_bps,
        ):
            raise CoreValidationError(
                f"the simulated metrics of {proposal_id!r} diverge"
            )
    checks.append("decision-parity")


def _check_normalized_projections(
    gate: EconomicIntegrationGate, checks: list[str]
) -> None:
    simulation = normalize_economic_state(
        economic_state(gate.simulation_world), gate.simulation_world
    )
    production = normalize_economic_state(
        economic_state(gate.production_world), gate.production_world
    )
    if economic_projection_digest(simulation) != economic_projection_digest(
        production
    ):
        raise CoreValidationError(
            "the normalized semantic projections of the two worlds diverge"
        )
    checks.append("semantic-projection-parity")


def _check_epistemic_provenance(
    gate: EconomicIntegrationGate, checks: list[str]
) -> None:
    simulation_invocation = gate.simulation_world.runtime.invocation(
        TREATMENT_INVOCATION_ID
    )
    production_invocation = gate.production_world.runtime.invocation(
        TREATMENT_INVOCATION_ID
    )
    if simulation_invocation.environment_mode is not EnvironmentMode.SIMULATION:
        raise CoreValidationError(
            "the simulation world's invocations must run in SIMULATION mode"
        )
    if production_invocation.environment_mode is not EnvironmentMode.PRODUCTION:
        raise CoreValidationError(
            "the production-compatible world's invocations must run in "
            "PRODUCTION mode (the declared environment binding)"
        )
    for world in gate.worlds:
        if world.world_source is None or (
            world.world_source.epistemic_type is not EpistemicType.SIMULATED
        ):
            raise CoreValidationError(
                "the mediation substrate must consume SIMULATED observations "
                "in both worlds"
            )
        if world.context is None or (
            EnvironmentMode.PRODUCTION in world.context.spec.allowed_modes
        ):
            raise CoreValidationError(
                "the agent context stays hypothetical-only in BOTH worlds"
            )
    checks.append("epistemic-provenance")
