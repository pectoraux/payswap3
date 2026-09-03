"""DOGFOOD-021: the WORK-021 conformance experiment.

The Work Order mandates the experiment: an agent proposes two routes,
BOTH routes are simulated (through ``src.simulation``'s public
environment path), a deterministic policy selects the winner, and the
agent CANNOT bypass authority — an out-of-scope proposal attempt and
an execute-tier escalation attempt both fail closed and are recorded
as kernel rejection events.

The experiment runs entirely through the real supported product path:
the real transition kernel (``AgentsEngine``), the real model registry
lifecycle, the real bounded mandate, the real proposal recording, the
real simulation environments and the real deterministic mediation
policy. Every instant is an explicit fixed declared ``as_of`` — the
transcript is byte-stable across processes by construction.

:func:`build_transcript` returns ``(transcript, digest)`` where the
digest is the canonical SHA-256 of the transcript.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.core.envelope import Provenance

from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    Outcome,
)
from src.evidence.contracts import EpistemicType
from src.simulation import EnvironmentMode, ScriptedWorld, WorldObservation

from .contracts import (
    GOVERNANCE_AUTHORITY_CLASSES,
    MEDIATION_REQUIRED_MODE,
    PROPOSAL_AUTHORITY_CLASS,
)
from .context import build_agent_context
from .engine import AgentsEngine
from .mediation import MediationEngine, MediationPolicy
from .models import ModelOutput
from .proposals import RouteProposal

ENV = "env/agents-dogfood"
DOMAIN = "domain/payments"

T_REGISTER = "2026-09-02T00:00:00Z"
T_VALIDATE = "2026-09-02T00:01:00Z"
T_APPROVE = "2026-09-02T00:02:00Z"
T_DEPLOY = "2026-09-02T00:03:00Z"
T_MANDATE = "2026-09-02T00:04:00Z"
T_OUTPUT = "2026-09-02T00:05:00Z"
T_PROPOSE = "2026-09-02T00:06:00Z"
T_MEDIATE = "2026-09-02T00:07:00Z"
T_EXPIRED = "2026-09-02T01:00:00Z"

OPERATOR = "principal/ops-mediator"
DEVELOPER = "principal/model-developer"
APPROVER = "principal/model-approver"
AGENT = "principal/agent-route-advisor"
ESCALATOR = "principal/agent-escalator"

COST_MODEL_ID = "model/route-cost-model"
RELIABILITY_MODEL_ID = "model/route-reliability-model"
MANDATE_ID = "agent-mandate/mandate-1"
CONTEXT_ID = "agent/route-advisor-1"
ALPHA_ID = "agent-proposal/alpha-premium"
BRAVO_ID = "agent-proposal/bravo-economy"
SCOPE_BYPASS_ID = "agent-proposal/offledger-bypass"
DECISION_ID = "mediation-decision/decision-1"
MEDIATION_ID = "mediation/session-1"

PREMIUM_FAMILY = "premium"
ECONOMY_FAMILY = "economy"
OFFLEDGER_FAMILY = "offledger-direct"

GOVERNANCE_CLASS = "A2"
EXECUTE_CLASS = "R4"

CODE_HASH = "a" * 64

SIMULATED_ROUTE_METRICS = {
    (PREMIUM_FAMILY, "cost-minor"): 9750,
    (PREMIUM_FAMILY, "latency-ms"): 120,
    (PREMIUM_FAMILY, "reliability-bps"): 9980,
    (ECONOMY_FAMILY, "cost-minor"): 6400,
    (ECONOMY_FAMILY, "latency-ms"): 480,
    (ECONOMY_FAMILY, "reliability-bps"): 9650,
}


def _authority_table():
    """Deterministic fixture authorization (actor -> registry class)."""

    table = {
        OPERATOR: GOVERNANCE_CLASS,
        DEVELOPER: "A1",
        APPROVER: "A1",
        AGENT: PROPOSAL_AUTHORITY_CLASS,
        ESCALATOR: EXECUTE_CLASS,
    }

    def hook(command: Command, view) -> AuthorizationDecision:
        granted = table.get(command.actor)
        if granted is None:
            return AuthorizationDecision(
                granted=False,
                authority=None,
                reason=f"actor {command.actor} holds no authority in this environment",
            )
        return AuthorizationDecision(granted=True, authority=granted, reason=None)

    return hook


def _command(
    seq: str,
    command_type: str,
    actor: str,
    target: str,
    payload: object,
    at: str,
    *,
    expected_version: int = 0,
) -> Command:
    return Command.build(
        command_id=f"cmd/{seq}",
        command_type=command_type,
        actor=actor,
        authority_refs=(f"authority/{seq}",),
        target_refs=(target,),
        payload=payload,
        environment_id=ENV,
        domain_id=DOMAIN,
        expected_versions=(
            ExpectedVersion(object_ref=target, object_version=expected_version),
        ),
        idempotency_key=f"key/{seq}",
        nonce="1",
        requested_at=at,
    )


def _model_output(output_id: str, model_id: str, value: object) -> ModelOutput:
    return ModelOutput(
        output_id=output_id,
        model_id=model_id,
        epistemic_type=EpistemicType.SIMULATED,
        confidence_bps=8000,
        value=value,
        declared_limitations=("corridor observations only",),
        produced_at=T_OUTPUT,
        valid_from=T_OUTPUT,
        valid_until=T_EXPIRED,
        provenance=Provenance(
            issuer=model_id,
            source="agents/model-output",
            recorded_at=T_OUTPUT,
            evidence_refs=(f"evidence/dogfood-{output_id}",),
        ),
    )


def _world() -> ScriptedWorld:
    observations = tuple(
        WorldObservation(
            observation_key=f"route/{family}/{metric}",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=value,
            source="world/agents-dogfood",
        )
        for (family, metric), value in sorted(SIMULATED_ROUTE_METRICS.items())
    )
    return ScriptedWorld(
        observations=observations, epistemic_type=EpistemicType.SIMULATED
    )


def _proposal(proposal_id: str, route_family: str, context) -> RouteProposal:
    return RouteProposal.build(
        proposal_id=proposal_id,
        agent_principal=context.spec.agent_principal,
        mandate_id=context.spec.mandate_id,
        route_family=route_family,
        rail=f"rail/{route_family}",
        declared_cost_minor=6500,
        declared_cost_scale=2,
        declared_cost_asset="asset/usd",
        declared_latency_ms=500,
        declared_reliability_bps=9600,
        context=context,
        model_outputs=(
            _model_output(
                f"model-output/{route_family}-cost", COST_MODEL_ID, {"cost_minor": 6400}
            ),
            _model_output(
                f"model-output/{route_family}-reliability",
                RELIABILITY_MODEL_ID,
                {"reliability_bps": 9600},
            ),
        ),
        as_of=T_PROPOSE,
    )


def build_transcript() -> tuple[str, str]:
    """Run the DOGFOOD-021 experiment and produce the sealed transcript."""
    lines: list[str] = []
    engine = AgentsEngine(
        ENV,
        DOMAIN,
        authorization=_authority_table(),
        emit_rejection_events=True,
        rejection_authority=GOVERNANCE_CLASS,
    )

    # 1. Model lifecycle: register -> validate -> approve -> deploy (x2).
    for model_id in (COST_MODEL_ID, RELIABILITY_MODEL_ID):
        engine.process(
            _command(
                f"register-{model_id}",
                "model/register",
                DEVELOPER,
                model_id,
                {
                    "model_id": model_id,
                    "developer": DEVELOPER,
                    "task": "predict route economics in exact minor units",
                    "risk_class": "LOW",
                    "declared_limitations": (
                        "trained on corridor observations only",
                        "no counterparty default modeling",
                    ),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        engine.process(
            _command(
                f"validate-{model_id}",
                "model/validate",
                DEVELOPER,
                model_id,
                {"model_id": model_id, "validation_notes": "backtests pass"},
                T_VALIDATE,
                expected_version=1,
            )
        )
        engine.process(
            _command(
                f"approve-{model_id}",
                "model/approve",
                APPROVER,
                model_id,
                {"model_id": model_id, "approver": APPROVER},
                T_APPROVE,
                expected_version=2,
            )
        )
        engine.process(
            _command(
                f"deploy-{model_id}",
                "model/deploy",
                OPERATOR,
                model_id,
                {"model_id": model_id},
                T_DEPLOY,
                expected_version=3,
            )
        )
    lines.append(
        f"step.models=DEPLOYED count={len(engine.registry.models())}"
    )

    # 2. Bounded mandate for the agent (scope, budget, expiry).
    engine.process(
        _command(
            "mandate-1",
            "agent/authorize-mandate",
            OPERATOR,
            MANDATE_ID,
            {
                "mandate_id": MANDATE_ID,
                "agent_principal": AGENT,
                "proposal_kinds": ["ROUTE"],
                "route_families": [PREMIUM_FAMILY, ECONOMY_FAMILY],
                "max_proposals": 3,
                "not_before": T_MANDATE,
                "not_after": T_EXPIRED,
                "authority_class": PROPOSAL_AUTHORITY_CLASS,
            },
            T_MANDATE,
        )
    )
    lines.append("step.mandate=AUTHORIZED")

    # 3. Agent context over the deployed models, SIMULATION mode only.
    context = build_agent_context(
        registry=engine.registry,
        mandates=engine.mandates,
        context_id=CONTEXT_ID,
        agent_principal=AGENT,
        mandate_id=MANDATE_ID,
        model_ids=(COST_MODEL_ID, RELIABILITY_MODEL_ID),
        allowed_modes=(EnvironmentMode.SIMULATION,),
        as_of=T_MANDATE,
    )
    lines.append("step.context=ACTIVE modes=SIMULATION")

    # 4. The agent proposes TWO routes (premium + economy).
    alpha = _proposal(ALPHA_ID, PREMIUM_FAMILY, context)
    bravo = _proposal(BRAVO_ID, ECONOMY_FAMILY, context)
    for seq, proposal in (("propose-alpha", alpha), ("propose-bravo", bravo)):
        result = engine.process(
            _command(
                seq,
                "agent/propose",
                AGENT,
                proposal.proposal_id,
                {"proposal": proposal.to_dict()},
                T_PROPOSE,
            )
        )
        if result.outcome is not Outcome.ACCEPTED:
            raise CoreValidationError(
                f"DOGFOOD-021 setup failed: {seq} was not accepted"
            )
    lines.append("step.proposals=RECORDED count=2")

    # 5. Bypass attempt A — undeclared scope: the agent proposes a route
    #    family outside its mandate. It must fail closed and be recorded.
    scope_bypass = _proposal(SCOPE_BYPASS_ID, OFFLEDGER_FAMILY, context)
    scope_result = engine.process(
        _command(
            "propose-scope-bypass",
            "agent/propose",
            AGENT,
            scope_bypass.proposal_id,
            {"proposal": scope_bypass.to_dict()},
            T_PROPOSE,
        )
    )
    lines.append(
        "bypass.scope="
        + ("REJECTED" if scope_result.outcome is Outcome.REJECTED else "ACCEPTED")
    )

    # 6. Bypass attempt B — tier escalation: an EXECUTE-tier principal
    #    tries to act as an agent. Agents never receive authority beyond
    #    proposing, so the kernel denies the attempt before any gate.
    escalation = _proposal("agent-proposal/escalation-direct", PREMIUM_FAMILY, context)
    escalation_result = engine.process(
        _command(
            "propose-escalation",
            "agent/propose",
            ESCALATOR,
            escalation.proposal_id,
            {"proposal": escalation.to_dict()},
            T_PROPOSE,
        )
    )
    lines.append(
        "bypass.escalation="
        + ("REJECTED" if escalation_result.outcome is Outcome.REJECTED else "ACCEPTED")
    )

    # 7. Mediation: BOTH routes simulated, deterministic policy selects.
    mediator = MediationEngine(
        engine=engine,
        policy=MediationPolicy(
            policy_id="policy/mediation-default",
            policy_version=1,
            cost_weight_bps=6000,
            latency_weight_bps=1000,
            reliability_weight_bps=3000,
        ),
    )
    decision = mediator.mediate(
        context=context,
        proposals=(alpha, bravo),
        world=_world(),
        mediation_id=MEDIATION_ID,
        decision_id=DECISION_ID,
        as_of=T_MEDIATE,
        actor=OPERATOR,
    )
    lines.append(f"step.simulated=2 mode={MEDIATION_REQUIRED_MODE.value}")
    lines.append(f"selected={decision.spec.selected_proposal_id}")
    lines.append(
        "decision.points="
        + ",".join(
            f"{candidate.proposal_id}:{candidate.total_points}"
            for candidate in decision.spec.candidates
        )
    )

    # 8. Authority audit: the decision never carries execution power and
    #    the agent cannot mediate its own proposals.
    event_types = [entry.event.event_type for entry in engine.journal]
    rejection_events = [t for t in event_types if t.endswith("command-rejected")]
    forbidden_event_namespaces = sorted(
        {t.split("/")[0] for t in event_types} - {"governance"}
    )
    checks = [
        ("models_deployed", len(engine.registry.models()) == 2),
        ("proposals_recorded", engine.get_proposal(BRAVO_ID) is not None),
        ("both_routes_simulated", len(decision.spec.candidates) == 2),
        (
            "simulation_first",
            MEDIATION_REQUIRED_MODE is EnvironmentMode.SIMULATION,
        ),
        ("policy_winner_selected", decision.spec.selected_proposal_id == BRAVO_ID),
        (
            "decision_is_governance_event",
            event_types[-1] == "governance/mediation-selected",
        ),
        (
            "decided_by_governance_authority",
            engine.journal[-1].event.authority in GOVERNANCE_AUTHORITY_CLASSES,
        ),
        ("bypass_scope_closed", scope_result.outcome is Outcome.REJECTED),
        ("bypass_escalation_closed", escalation_result.outcome is Outcome.REJECTED),
        (
            "bypasses_recorded",
            len(rejection_events) == 2,
        ),
        ("no_non_governance_events", not forbidden_event_namespaces),
    ]
    for name, ok in checks:
        lines.append(f"check.{name}=PASS" if ok else f"check.{name}=FAIL")
    if not all(ok for _, ok in checks):
        raise CoreValidationError("DOGFOOD-021 failed a conformance check")

    lines.append("DOGFOOD-021: PASS")
    transcript = "\n".join(lines) + "\n"
    return transcript, canonical_sha256(transcript)
