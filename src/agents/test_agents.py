"""WORK-021 contract and discrimination suite (red-first).

This suite was authored BEFORE the implementation and captures the frozen
contract of the models/agents/decision-mediation domain:

- the frozen ``Model`` command family
  ``Register/Validate/Approve/Deploy/Suspend/Resume/Retire`` as an explicit
  lifecycle over the REAL transition kernel, with every failure path
  explicit (fail closed on unknown model, unknown state, invalid
  transition, terminal history, duplicate registration, undeclared
  approver separation of duties);
- model outputs are typed artifacts: provenance with non-empty evidence
  references, exact basis-point confidence, declared limitations, the
  frozen epistemic vocabulary re-used from ``src.evidence``
  (``SIMULATED``/``PREDICTED`` only — a model output can never
  masquerade as an observation), explicit freshness windows and a domain
  seal that rejects tampering;
- agents act ONLY under bounded, typed, agent-scoped proposal mandates:
  explicit scope (proposal kinds + route families), explicit limits
  (proposal budget), explicit expiry (half-open window), frozen
  authority class exactly the registry ``R2`` PROPOSE tier — anything
  beyond fails closed, and this is NOT a second Mandate authority (the
  trust domain owns Mandates; this is the strictly weaker proposal bound);
- agent contexts are derived, sealed snapshots binding one agent, one
  mandate, one deployed model set and hypothetical environment modes
  only (simulation/forecast/counterfactual — shadow and production agent
  contexts fail closed: agents never receive live authority);
- mediation is simulation-before-production and the ONLY path from
  proposal to decision: every candidate proposal is evaluated in a
  SIMULATION-mode environment through ``src.simulation``'s public
  contract (EnvironmentRuntime/ScriptedWorld/one real kernel), then a
  deterministic policy with explicit basis-point weights, rank points
  and a lexicographic tie-break selects, and the decision is recorded
  through the kernel as a governance event. Decisions never execute
  anything and never carry effect intents;
- agents cannot bypass authority: undeclared scope, expired mandates,
  exhausted budgets, impersonated actors, undeployed models, proposals
  that were never kernel-recorded, tampered records, authority classes
  beyond the PROPOSE tier and self-mediation all fail closed — and the
  kernel records the rejection events;
- registry discipline: no ``model``/``agent`` event namespace is
  invented — model lifecycle and mediation decision events use the
  existing frozen ``governance`` namespace, simulated proposal outcomes
  use the existing frozen ``simulation`` namespace; command types are
  internal free-form strings and object types use internal
  non-registry ``agents/...`` formats;
- determinism: no wall-clock reads, no entropy sources, no generated
  identifiers — every instant is explicit declared ``as_of`` data.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import (
    AUTHORITY_CLASSES,
    EVENT_NAMESPACES,
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    Outcome,
    PROTOCOL_VERSION,
    RejectionReason,
    TransitionResult,
    payload_to_json_value,
)
from src.transition.registry import validate_event_type

from src.evidence.contracts import EpistemicType as EvidenceEpistemicType

from src.simulation import (
    DEFAULT_NAMESPACE_RULES,
    EnvironmentMode,
    ScriptedWorld,
    SimulationRunState,
    StateNamespace,
    WorldObservation,
    parity_digest,
)

import src.agents as agents
from src.agents import (
    AGENT_ALLOWED_MODES,
    AGENT_COMMANDS,
    AGENTS_API_VERSION,
    AGENTS_COMMANDS,
    AGENTS_EVENT_NAMESPACE,
    AGENTS_EVENT_TYPES,
    AGENTS_NAMESPACE_RULES,
    AGENTS_PROTOCOL_VERSION,
    AGENTS_SCHEMA_VERSION,
    AGENT_CONTEXT_OBJECT_TYPE,
    GOVERNANCE_AUTHORITY_CLASSES,
    MEDIATION_COMMANDS,
    MEDIATION_DECISION_OBJECT_TYPE,
    MEDIATION_EVENT_TYPES,
    MEDIATION_MIN_CANDIDATES,
    MEDIATION_REQUIRED_MODE,
    MEDIATION_WEIGHT_TOTAL_BPS,
    MODEL_COMMANDS,
    MODEL_EVENT_TYPES,
    MODEL_LIFECYCLE_STATES,
    MODEL_OBJECT_TYPE,
    MODEL_OUTPUT_EPISTEMIC_TYPES,
    MODEL_OUTPUT_OBJECT_TYPE,
    MODEL_TERMINAL_STATES,
    MODEL_TRANSITIONS,
    PROPOSAL_AUTHORITY_CLASS,
    PROPOSAL_MANDATE_OBJECT_TYPE,
    PROPOSAL_OBJECT_TYPE,
    ROUTE_EVALUATION_BINDING_ID,
    ROUTE_EVALUATION_COMMAND_TYPE,
    ROUTE_EVALUATION_EVENT_TYPE,
    ROUTE_EVALUATION_OBJECT_TYPE,
    SIMULATED_PROPOSAL_EVENT_NAMESPACE,
    AgentContext,
    AgentsEngine,
    CandidateOutcome,
    MandateBook,
    MediationDecision,
    MediationEngine,
    MediationPolicy,
    ModelLifecycleState,
    ModelOutput,
    ModelRecord,
    ModelRegistry,
    ModelRiskClass,
    PolicyEvaluation,
    ProposalBook,
    ProposalKind,
    ProposalMandate,
    RouteProposal,
    SimulatedOutcome,
    build_agent_context,
    route_evaluation_binding,
    simulate_candidate,
    CoreValidationError as AgentsCoreError,
    EpistemicType,
)

ENV = "env/agents-governance"
DOMAIN = "domain/payments"

T_REGISTER = "2026-09-02T00:00:00Z"
T_VALIDATE = "2026-09-02T00:01:00Z"
T_APPROVE = "2026-09-02T00:02:00Z"
T_DEPLOY = "2026-09-02T00:03:00Z"
T_MANDATE = "2026-09-02T00:04:00Z"
T_OUTPUT = "2026-09-02T00:05:00Z"
T_PROPOSE = "2026-09-02T00:06:00Z"
T_MEDIATE = "2026-09-02T00:07:00Z"
T_LATER = "2026-09-02T00:08:00Z"
T_EXPIRED = "2026-09-02T01:00:00Z"
T_BEFORE = "2026-09-01T23:00:00Z"

OPERATOR = "principal/ops-mediator"
DEVELOPER = "principal/model-developer"
APPROVER = "principal/model-approver"
AGENT = "principal/agent-route-advisor"
STRANGER = "principal/stranger"
ESCALATOR = "principal/agent-escalator"

GOVERNANCE_CLASS = "A2"
PROPOSAL_CLASS = "R2"
EXECUTE_CLASS = "R4"

COST_MODEL_ID = "model/route-cost-model"
RELIABILITY_MODEL_ID = "model/route-reliability-model"
MANDATE_ID = "agent-mandate/mandate-1"
CONTEXT_ID = "agent/route-advisor-1"
ALPHA_ID = "agent-proposal/alpha-premium"
BRAVO_ID = "agent-proposal/bravo-economy"
DECISION_ID = "mediation-decision/decision-1"
MEDIATION_ID = "mediation/session-1"

PREMIUM_FAMILY = "premium"
ECONOMY_FAMILY = "economy"
OFFLEDGER_FAMILY = "offledger-direct"

CODE_HASH = "a" * 64
OTHER_CODE_HASH = "b" * 64

DOMAIN_PACKAGE = Path(__file__).parent
DOMAIN_SOURCES = sorted(
    source for source in DOMAIN_PACKAGE.glob("*.py") if source.name != "test_agents.py"
)
ALLOWED_SRC_DOMAINS = frozenset({"core", "transition", "evidence", "simulation"})
FORBIDDEN_SRC_DOMAINS = frozenset(
    {
        "market",
        "intent",
        "money",
        "trust",
        "interoperability",
        "liquidity",
        "safety",
        "reservation",
        "value",
        "capability",
        "extensions",
        "integration",
    }
)
STDLIB_ROOTS = frozenset(sys.stdlib_module_names)

PINNED_ALL = frozenset(
    {
        "AGENTS_API_VERSION",
        "AGENTS_PROTOCOL_VERSION",
        "AGENTS_SCHEMA_VERSION",
        "AGENTS_EVENT_NAMESPACE",
        "SIMULATED_PROPOSAL_EVENT_NAMESPACE",
        "AGENTS_COMMANDS",
        "MODEL_COMMANDS",
        "AGENT_COMMANDS",
        "MEDIATION_COMMANDS",
        "AGENTS_EVENT_TYPES",
        "MODEL_EVENT_TYPES",
        "AGENT_EVENT_TYPES",
        "MEDIATION_EVENT_TYPES",
        "MODEL_TRANSITIONS",
        "MODEL_LIFECYCLE_STATES",
        "MODEL_TERMINAL_STATES",
        "MODEL_OBJECT_TYPE",
        "MODEL_OUTPUT_OBJECT_TYPE",
        "AGENT_CONTEXT_OBJECT_TYPE",
        "PROPOSAL_MANDATE_OBJECT_TYPE",
        "PROPOSAL_OBJECT_TYPE",
        "MEDIATION_DECISION_OBJECT_TYPE",
        "ROUTE_EVALUATION_OBJECT_TYPE",
        "ROUTE_EVALUATION_COMMAND_TYPE",
        "ROUTE_EVALUATION_EVENT_TYPE",
        "ROUTE_EVALUATION_BINDING_ID",
        "AGENTS_NAMESPACE_RULES",
        "AGENT_ALLOWED_MODES",
        "MODEL_OUTPUT_EPISTEMIC_TYPES",
        "PROPOSAL_AUTHORITY_CLASS",
        "GOVERNANCE_AUTHORITY_CLASSES",
        "MEDIATION_REQUIRED_MODE",
        "MEDIATION_MIN_CANDIDATES",
        "MEDIATION_WEIGHT_TOTAL_BPS",
        "ModelLifecycleState",
        "ModelRiskClass",
        "ProposalKind",
        "ModelRecord",
        "ModelOutput",
        "ModelRegistry",
        "ProposalMandate",
        "MandateBook",
        "AgentContext",
        "build_agent_context",
        "RouteProposal",
        "ProposalBook",
        "SimulatedOutcome",
        "CandidateOutcome",
        "MediationPolicy",
        "PolicyEvaluation",
        "MediationDecision",
        "MediationEngine",
        "AgentsEngine",
        "route_evaluation_binding",
        "simulate_candidate",
        "CoreValidationError",
        "EpistemicType",
        "EnvironmentMode",
        "Provenance",
    }
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def authority_table(**overrides: str):
    """Deterministic fixture authorization: actor -> registry authority class."""

    table = {
        OPERATOR: GOVERNANCE_CLASS,
        DEVELOPER: "A1",
        APPROVER: "A1",
        AGENT: PROPOSAL_CLASS,
        ESCALATOR: EXECUTE_CLASS,
    }
    principal_by_name = {
        "OPERATOR": OPERATOR,
        "DEVELOPER": DEVELOPER,
        "APPROVER": APPROVER,
        "AGENT": AGENT,
        "ESCALATOR": ESCALATOR,
    }
    for name, value in overrides.items():
        table[principal_by_name[name.upper()]] = value

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


def command(
    seq: str,
    command_type: str,
    actor: str,
    target: str,
    payload: object,
    at: str,
    *,
    expected: tuple[ExpectedVersion, ...] | None = None,
    environment_id: str = ENV,
) -> Command:
    return Command.build(
        command_id=f"cmd/{seq}",
        command_type=command_type,
        actor=actor,
        authority_refs=(f"authority/{seq}",),
        target_refs=(target,),
        payload=payload,
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(
            expected
            if expected is not None
            else (ExpectedVersion(object_ref=target, object_version=0),)
        ),
        idempotency_key=f"key/{seq}",
        nonce="1",
        requested_at=at,
        correlation_id="corr/agents-test",
    )


def make_engine(**authorization_overrides) -> AgentsEngine:
    return AgentsEngine(
        environment_id=ENV,
        domain_id=DOMAIN,
        authorization=authority_table(**authorization_overrides),
        emit_rejection_events=True,
        rejection_authority=GOVERNANCE_CLASS,
    )


def register_model(engine: AgentsEngine, model_id: str = COST_MODEL_ID, *, seq: str = "r1"):
    return engine.process(
        command(
            seq,
            "model/register",
            DEVELOPER,
            model_id,
            {
                "model_id": model_id,
                "developer": DEVELOPER,
                "task": "predict route cost in exact minor units",
                "risk_class": ModelRiskClass.LOW.value,
                "declared_limitations": (
                    "trained on corridor observations only",
                    "no counterparty default modeling",
                ),
                "code_hash": CODE_HASH,
            },
            T_REGISTER,
        )
    )


def full_model_lifecycle(engine: AgentsEngine, model_id: str = COST_MODEL_ID) -> None:
    suffix = model_id[len("model/") :]
    register_model(engine, model_id, seq=f"r-{suffix}")
    engine.process(
        command(
            f"v-{suffix}",
            "model/validate",
            DEVELOPER,
            model_id,
            {"model_id": model_id, "validation_notes": "backtests pass"},
            T_VALIDATE,
            expected=(ExpectedVersion(object_ref=model_id, object_version=1),),
        )
    )
    engine.process(
        command(
            f"a-{suffix}",
            "model/approve",
            APPROVER,
            model_id,
            {"model_id": model_id, "approver": APPROVER},
            T_APPROVE,
            expected=(ExpectedVersion(object_ref=model_id, object_version=2),),
        )
    )
    engine.process(
        command(
            f"d-{suffix}",
            "model/deploy",
            OPERATOR,
            model_id,
            {"model_id": model_id},
            T_DEPLOY,
            expected=(ExpectedVersion(object_ref=model_id, object_version=3),),
        )
    )


def authorize_mandate(engine: AgentsEngine, *, seq: str = "m1") -> TransitionResult:
    return engine.process(
        command(
            seq,
            "agent/authorize-mandate",
            OPERATOR,
            MANDATE_ID,
            {
                "mandate_id": MANDATE_ID,
                "agent_principal": AGENT,
                "proposal_kinds": [ProposalKind.ROUTE.value],
                "route_families": [PREMIUM_FAMILY, ECONOMY_FAMILY],
                "max_proposals": 2,
                "not_before": T_MANDATE,
                "not_after": T_EXPIRED,
                "authority_class": PROPOSAL_CLASS,
            },
            T_MANDATE,
        )
    )


def make_context(engine: AgentsEngine) -> AgentContext:
    return build_agent_context(
        registry=engine.registry,
        mandates=engine.mandates,
        context_id=CONTEXT_ID,
        agent_principal=AGENT,
        mandate_id=MANDATE_ID,
        model_ids=(COST_MODEL_ID, RELIABILITY_MODEL_ID),
        allowed_modes=(EnvironmentMode.SIMULATION,),
        as_of=T_MANDATE,
    )


def make_output(
    output_id: str,
    model_id: str,
    value: object,
    *,
    epistemic_type: EpistemicType = EpistemicType.SIMULATED,
    confidence_bps: int = 8000,
) -> ModelOutput:
    return ModelOutput(
        output_id=output_id,
        model_id=model_id,
        epistemic_type=epistemic_type,
        confidence_bps=confidence_bps,
        value=value,
        declared_limitations=("corridor observations only",),
        produced_at=T_OUTPUT,
        valid_from=T_OUTPUT,
        valid_until=T_EXPIRED,
        provenance=Provenance(
            issuer=model_id,
            source="agents/model-output",
            recorded_at=T_OUTPUT,
            evidence_refs=(f"evidence/output-{output_id}",),
        ),
    )


def make_proposal(
    proposal_id: str,
    route_family: str,
    context: AgentContext,
    *,
    outputs: tuple[ModelOutput, ...] | None = None,
) -> RouteProposal:
    if outputs is None:
        outputs = (
            make_output(f"model-output/{route_family}-cost", COST_MODEL_ID, {"cost_minor": 6400}),
            make_output(
                f"model-output/{route_family}-reliability",
                RELIABILITY_MODEL_ID,
                {"reliability_bps": 9600},
            ),
        )
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
        model_outputs=outputs,
        as_of=T_PROPOSE,
    )


def submit_proposal(
    engine: AgentsEngine, proposal: RouteProposal, *, seq: str, actor: str = AGENT
) -> TransitionResult:
    return engine.process(
        command(
            seq,
            "agent/propose",
            actor,
            proposal.spec.proposal_id,
            {"proposal": proposal.to_dict()},
            T_PROPOSE,
        )
    )


def make_world(*, economy_cost_minor: int = 6400) -> ScriptedWorld:
    observations = (
        WorldObservation(
            observation_key=f"route/{PREMIUM_FAMILY}/cost-minor",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=9750,
            source="world/agents-test",
        ),
        WorldObservation(
            observation_key=f"route/{PREMIUM_FAMILY}/latency-ms",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=120,
            source="world/agents-test",
        ),
        WorldObservation(
            observation_key=f"route/{PREMIUM_FAMILY}/reliability-bps",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=9980,
            source="world/agents-test",
        ),
        WorldObservation(
            observation_key=f"route/{ECONOMY_FAMILY}/cost-minor",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=economy_cost_minor,
            source="world/agents-test",
        ),
        WorldObservation(
            observation_key=f"route/{ECONOMY_FAMILY}/latency-ms",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=480,
            source="world/agents-test",
        ),
        WorldObservation(
            observation_key=f"route/{ECONOMY_FAMILY}/reliability-bps",
            epistemic_type=EpistemicType.SIMULATED,
            as_of=T_MEDIATE,
            value=9650,
            source="world/agents-test",
        ),
    )
    return ScriptedWorld(
        observations=observations, epistemic_type=EpistemicType.SIMULATED
    )


def make_policy(**kwargs) -> MediationPolicy:
    fields = {
        "policy_id": "policy/mediation-default",
        "policy_version": 1,
        "cost_weight_bps": 6000,
        "latency_weight_bps": 1000,
        "reliability_weight_bps": 3000,
    }
    fields.update(kwargs)
    return MediationPolicy(**fields)


def prepared_engine() -> AgentsEngine:
    """Engine with two deployed models, one mandate and one context."""
    engine = make_engine()
    full_model_lifecycle(engine, COST_MODEL_ID)
    full_model_lifecycle(engine, RELIABILITY_MODEL_ID)
    authorize_mandate(engine)
    return engine


def mediated_engine():
    """Engine plus a completed two-route mediation (the WO experiment)."""
    engine = prepared_engine()
    context = make_context(engine)
    alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
    bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
    submit_proposal(engine, alpha, seq="p1")
    submit_proposal(engine, bravo, seq="p2")
    mediator = MediationEngine(engine=engine, policy=make_policy())
    decision = mediator.mediate(
        context=context,
        proposals=(alpha, bravo),
        world=make_world(),
        mediation_id=MEDIATION_ID,
        decision_id=DECISION_ID,
        as_of=T_MEDIATE,
        actor=OPERATOR,
    )
    return engine, context, alpha, bravo, decision


# ---------------------------------------------------------------------------
# 1. Boundary and static contracts
# ---------------------------------------------------------------------------


class BoundaryContractTests(unittest.TestCase):
    """The typed, versioned public boundary and registry discipline."""

    def test_api_and_schema_versions_are_pinned(self) -> None:
        self.assertEqual(AGENTS_API_VERSION, "v0.1")
        self.assertEqual(AGENTS_PROTOCOL_VERSION, PROTOCOL_VERSION)
        self.assertEqual(AGENTS_SCHEMA_VERSION, 1)

    def test_object_types_use_internal_non_registry_formats(self) -> None:
        for object_type in (
            MODEL_OBJECT_TYPE,
            MODEL_OUTPUT_OBJECT_TYPE,
            AGENT_CONTEXT_OBJECT_TYPE,
            PROPOSAL_MANDATE_OBJECT_TYPE,
            PROPOSAL_OBJECT_TYPE,
            MEDIATION_DECISION_OBJECT_TYPE,
            ROUTE_EVALUATION_OBJECT_TYPE,
        ):
            self.assertIsInstance(object_type, str)
            self.assertTrue(object_type.startswith("agents/"))
            self.assertTrue(object_type.endswith("/v1"))
        self.assertEqual(MODEL_OBJECT_TYPE, "agents/model/v1")
        self.assertEqual(MODEL_OUTPUT_OBJECT_TYPE, "agents/model-output/v1")
        self.assertEqual(AGENT_CONTEXT_OBJECT_TYPE, "agents/agent-context/v1")
        self.assertEqual(PROPOSAL_MANDATE_OBJECT_TYPE, "agents/proposal-mandate/v1")
        self.assertEqual(PROPOSAL_OBJECT_TYPE, "agents/proposal/v1")
        self.assertEqual(MEDIATION_DECISION_OBJECT_TYPE, "agents/mediation-decision/v1")
        self.assertEqual(ROUTE_EVALUATION_OBJECT_TYPE, "agents/route-evaluation/v1")

    def test_command_families_are_frozen(self) -> None:
        self.assertEqual(
            MODEL_COMMANDS,
            frozenset(
                {
                    "model/register",
                    "model/validate",
                    "model/approve",
                    "model/deploy",
                    "model/suspend",
                    "model/resume",
                    "model/retire",
                }
            ),
        )
        self.assertEqual(
            AGENT_COMMANDS,
            frozenset({"agent/authorize-mandate", "agent/propose"}),
        )
        self.assertEqual(MEDIATION_COMMANDS, frozenset({"mediation/select"}))
        self.assertEqual(
            AGENTS_COMMANDS, MODEL_COMMANDS | AGENT_COMMANDS | MEDIATION_COMMANDS
        )
        self.assertEqual(len(AGENTS_COMMANDS), 10)

    def test_event_types_use_existing_frozen_namespaces(self) -> None:
        self.assertEqual(AGENTS_EVENT_NAMESPACE, "governance")
        self.assertEqual(SIMULATED_PROPOSAL_EVENT_NAMESPACE, "simulation")
        for event_type in AGENTS_EVENT_TYPES.values():
            validate_event_type("agents event type", event_type)
            self.assertEqual(event_type.split("/")[0], "governance")
        self.assertEqual(
            MODEL_EVENT_TYPES["model/register"], "governance/model-registered"
        )
        self.assertEqual(
            MODEL_EVENT_TYPES["model/validate"], "governance/model-validated"
        )
        self.assertEqual(
            MODEL_EVENT_TYPES["model/approve"], "governance/model-approved"
        )
        self.assertEqual(MODEL_EVENT_TYPES["model/deploy"], "governance/model-deployed")
        self.assertEqual(
            MODEL_EVENT_TYPES["model/suspend"], "governance/model-suspended"
        )
        self.assertEqual(MODEL_EVENT_TYPES["model/resume"], "governance/model-resumed")
        self.assertEqual(MODEL_EVENT_TYPES["model/retire"], "governance/model-retired")
        self.assertEqual(
            MEDIATION_EVENT_TYPES["mediation/select"],
            "governance/mediation-selected",
        )
        validate_event_type("route evaluation", ROUTE_EVALUATION_EVENT_TYPE)
        self.assertEqual(
            ROUTE_EVALUATION_EVENT_TYPE.split("/")[0],
            SIMULATED_PROPOSAL_EVENT_NAMESPACE,
        )
        self.assertEqual(ROUTE_EVALUATION_COMMAND_TYPE, "agent/simulate-route")
        self.assertEqual(ROUTE_EVALUATION_EVENT_TYPE, "simulation/route-simulated")

    def test_no_model_or_agent_event_namespace_is_invented(self) -> None:
        self.assertNotIn("model", EVENT_NAMESPACES)
        self.assertNotIn("agent", EVENT_NAMESPACES)
        self.assertIn("governance", EVENT_NAMESPACES)
        self.assertIn("simulation", EVENT_NAMESPACES)

    def test_lifecycle_state_vocabulary_is_frozen(self) -> None:
        self.assertEqual(
            MODEL_LIFECYCLE_STATES,
            frozenset(
                {
                    ModelLifecycleState.REGISTERED,
                    ModelLifecycleState.VALIDATED,
                    ModelLifecycleState.APPROVED,
                    ModelLifecycleState.DEPLOYED,
                    ModelLifecycleState.SUSPENDED,
                    ModelLifecycleState.RETIRED,
                }
            ),
        )
        self.assertEqual(MODEL_TERMINAL_STATES, frozenset({ModelLifecycleState.RETIRED}))

    def test_model_transitions_cover_every_non_creating_command(self) -> None:
        self.assertEqual(set(MODEL_TRANSITIONS), MODEL_COMMANDS - {"model/register"})
        self.assertEqual(
            MODEL_TRANSITIONS["model/validate"],
            {ModelLifecycleState.REGISTERED: ModelLifecycleState.VALIDATED},
        )
        self.assertEqual(
            MODEL_TRANSITIONS["model/approve"],
            {ModelLifecycleState.VALIDATED: ModelLifecycleState.APPROVED},
        )
        self.assertEqual(
            MODEL_TRANSITIONS["model/deploy"],
            {ModelLifecycleState.APPROVED: ModelLifecycleState.DEPLOYED},
        )
        self.assertEqual(
            MODEL_TRANSITIONS["model/suspend"],
            {ModelLifecycleState.DEPLOYED: ModelLifecycleState.SUSPENDED},
        )
        self.assertEqual(
            MODEL_TRANSITIONS["model/resume"],
            {ModelLifecycleState.SUSPENDED: ModelLifecycleState.DEPLOYED},
        )
        self.assertIn(
            ModelLifecycleState.DEPLOYED, MODEL_TRANSITIONS["model/retire"]
        )
        self.assertIn(
            ModelLifecycleState.SUSPENDED, MODEL_TRANSITIONS["model/retire"]
        )

    def test_namespace_rules_classify_agents_object_families(self) -> None:
        for object_id in (
            "agent/route-advisor-1",
            "agent-mandate/mandate-1",
            "agent-proposal/alpha-premium",
            "model-output/premium-cost",
            "mediation-decision/decision-1",
            "route-evaluation/alpha-premium",
        ):
            self.assertEqual(
                AGENTS_NAMESPACE_RULES.classify(object_id),
                StateNamespace.DEPENDENCY,
            )

    def test_model_ids_classify_under_the_frozen_default_rules(self) -> None:
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify(COST_MODEL_ID), StateNamespace.DEPENDENCY
        )

    def test_namespace_rules_digest_is_stable(self) -> None:
        self.assertEqual(
            AGENTS_NAMESPACE_RULES.digest, AGENTS_NAMESPACE_RULES.digest
        )
        self.assertNotEqual(
            AGENTS_NAMESPACE_RULES.digest, DEFAULT_NAMESPACE_RULES.digest
        )

    def test_allowed_agent_modes_exclude_live_environments(self) -> None:
        self.assertEqual(
            AGENT_ALLOWED_MODES,
            frozenset(
                {
                    EnvironmentMode.SIMULATION,
                    EnvironmentMode.FORECAST,
                    EnvironmentMode.COUNTERFACTUAL,
                }
            ),
        )
        self.assertNotIn(EnvironmentMode.SHADOW, AGENT_ALLOWED_MODES)
        self.assertNotIn(EnvironmentMode.PRODUCTION, AGENT_ALLOWED_MODES)

    def test_model_output_epistemic_types_exclude_observations(self) -> None:
        self.assertEqual(
            MODEL_OUTPUT_EPISTEMIC_TYPES,
            frozenset({EpistemicType.SIMULATED, EpistemicType.PREDICTED}),
        )
        self.assertNotIn(EpistemicType.OBSERVED, MODEL_OUTPUT_EPISTEMIC_TYPES)
        self.assertNotIn(EpistemicType.ESTIMATED, MODEL_OUTPUT_EPISTEMIC_TYPES)
        self.assertNotIn(EpistemicType.COUNTERFACTUAL, MODEL_OUTPUT_EPISTEMIC_TYPES)

    def test_authority_class_constants_come_from_the_frozen_registry(self) -> None:
        self.assertEqual(PROPOSAL_AUTHORITY_CLASS, "R2")
        self.assertIn(PROPOSAL_AUTHORITY_CLASS, AUTHORITY_CLASSES)
        self.assertEqual(
            GOVERNANCE_AUTHORITY_CLASSES,
            frozenset(f"A{index}" for index in range(8)),
        )
        self.assertTrue(GOVERNANCE_AUTHORITY_CLASSES <= AUTHORITY_CLASSES)

    def test_mediation_constants(self) -> None:
        self.assertIs(MEDIATION_REQUIRED_MODE, EnvironmentMode.SIMULATION)
        self.assertEqual(MEDIATION_MIN_CANDIDATES, 2)
        self.assertEqual(MEDIATION_WEIGHT_TOTAL_BPS, 10000)

    def test_public_all_is_pinned(self) -> None:
        self.assertEqual(frozenset(agents.__all__), PINNED_ALL)

    def test_epistemic_vocabulary_is_reused_from_evidence(self) -> None:
        self.assertIs(EpistemicType, EvidenceEpistemicType)
        self.assertIs(AgentsCoreError, CoreValidationError)

    def test_provenance_is_reused_from_core(self) -> None:
        from src.agents import Provenance as AgentsProvenance

        self.assertIs(AgentsProvenance, Provenance)

    def test_domain_modules_import_only_allowed_domains(self) -> None:
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        modules = [node.module]
                    elif node.level > 0 and node.module:
                        prefix = ("src", "agents")[: 2 - (node.level - 1)]
                        modules = [".".join((*prefix, *node.module.split(".")))]
                for module in modules:
                    if module == "src" or module.startswith("src."):
                        domain = module.split(".")[1] if module != "src" else "src"
                        self.assertIn(
                            domain,
                            ALLOWED_SRC_DOMAINS | {"agents", "src"},
                            f"{source.name} imports forbidden module {module!r}",
                        )
                        self.assertNotIn(
                            domain,
                            FORBIDDEN_SRC_DOMAINS,
                            f"{source.name} imports unmerged/undeclared sibling {module!r}",
                        )
                    else:
                        root = module.split(".")[0]
                        self.assertIn(
                            root,
                            STDLIB_ROOTS | {"__future__"},
                            f"{source.name} imports non-stdlib module {module!r}",
                        )

    def test_declared_dependency_domains_are_actually_consumed(self) -> None:
        consumed: set[str] = set()
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        consumed.add(node.module.split(".")[1])
                    elif node.level > 1 and node.module:
                        consumed.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            consumed.add(alias.name.split(".")[1])
        self.assertEqual(consumed, ALLOWED_SRC_DOMAINS)

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "time.monotonic",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "secrets",
                "time.sleep",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_error_authority_is_core(self) -> None:
        self.assertIs(AgentsCoreError, CoreValidationError)
        with self.assertRaises(CoreValidationError):
            make_output(
                "model-output/probe",
                COST_MODEL_ID,
                {"cost_minor": 1},
                epistemic_type="OBSERVED",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# 2. Model registry lifecycle
# ---------------------------------------------------------------------------


class ModelRegistryLifecycleTests(unittest.TestCase):
    """The frozen Model command family over the real kernel."""

    def test_full_lifecycle_records_every_state_and_version(self) -> None:
        engine = make_engine()
        register_model(engine)
        engine.process(
            command(
                "v1",
                "model/validate",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "validation_notes": "backtests pass"},
                T_VALIDATE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        engine.process(
            command(
                "a1",
                "model/approve",
                APPROVER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "approver": APPROVER},
                T_APPROVE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=2),),
            )
        )
        deploy = engine.process(
            command(
                "d1",
                "model/deploy",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_DEPLOY,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=3),),
            )
        )
        self.assertEqual(deploy.outcome, Outcome.ACCEPTED)
        record = engine.get_model(COST_MODEL_ID)
        self.assertEqual(record.state, ModelLifecycleState.DEPLOYED)
        self.assertEqual(record.envelope.object_version, 4)
        self.assertEqual(
            [entry.event.event_type for entry in engine.journal],
            [
                "governance/model-registered",
                "governance/model-validated",
                "governance/model-approved",
                "governance/model-deployed",
            ],
        )

    def test_lifecycle_events_carry_states_and_versions(self) -> None:
        engine = make_engine()
        full_model_lifecycle(engine, COST_MODEL_ID)
        journal = engine.journal
        for entry in journal:
            self.assertEqual(entry.event.object_refs, (COST_MODEL_ID,))
            self.assertIn(entry.event.authority, GOVERNANCE_AUTHORITY_CLASSES)
        deployed_event = journal[3].event
        self.assertEqual(
            deployed_event.previous_state, (ModelLifecycleState.APPROVED.value,)
        )
        self.assertEqual(
            deployed_event.resulting_state, (ModelLifecycleState.DEPLOYED.value,)
        )
        self.assertEqual(deployed_event.object_versions, (4,))

    def test_suspend_and_resume_cycle(self) -> None:
        engine = prepared_engine()
        suspend = engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift detected"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        self.assertEqual(suspend.outcome, Outcome.ACCEPTED)
        self.assertEqual(
            engine.get_model(COST_MODEL_ID).state, ModelLifecycleState.SUSPENDED
        )
        resume = engine.process(
            command(
                "s2",
                "model/resume",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        self.assertEqual(resume.outcome, Outcome.ACCEPTED)
        self.assertEqual(
            engine.get_model(COST_MODEL_ID).state, ModelLifecycleState.DEPLOYED
        )

    def test_retire_from_deployed_is_terminal(self) -> None:
        engine = prepared_engine()
        retire = engine.process(
            command(
                "t1",
                "model/retire",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "superseded"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        self.assertEqual(retire.outcome, Outcome.ACCEPTED)
        self.assertEqual(
            engine.get_model(COST_MODEL_ID).state, ModelLifecycleState.RETIRED
        )
        again = engine.process(
            command(
                "t2",
                "model/retire",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "again"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        self.assertEqual(again.outcome, Outcome.REJECTED)
        self.assertEqual(again.reason, RejectionReason.POLICY_REJECTED)

    def test_retire_from_suspended_is_allowed(self) -> None:
        engine = prepared_engine()
        engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        retire = engine.process(
            command(
                "t1",
                "model/retire",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "superseded"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        self.assertEqual(retire.outcome, Outcome.ACCEPTED)
        self.assertEqual(
            engine.get_model(COST_MODEL_ID).state, ModelLifecycleState.RETIRED
        )

    def test_duplicate_registration_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        duplicate = engine.process(
            command(
                "r2",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_LATER,
            )
        )
        self.assertEqual(duplicate.outcome, Outcome.REJECTED)
        self.assertEqual(duplicate.reason, RejectionReason.VERSION_CONFLICT)

    def test_register_with_missing_field_fails_closed(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.POLICY_REJECTED)

    def test_register_with_extra_field_fails_closed(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                    "surprise": True,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_register_with_empty_limitations_fails_closed(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": (),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_register_with_bad_code_hash_fails_closed(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": "not-a-digest",
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_operate_on_unknown_model_fails_closed(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "v1",
                "model/validate",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "validation_notes": "notes"},
                T_VALIDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_validate_twice_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        engine.process(
            command(
                "v1",
                "model/validate",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "validation_notes": "notes"},
                T_VALIDATE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        result = engine.process(
            command(
                "v2",
                "model/validate",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "validation_notes": "again"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=2),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_approve_unvalidated_model_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        result = engine.process(
            command(
                "a1",
                "model/approve",
                APPROVER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "approver": APPROVER},
                T_APPROVE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_approve_by_developer_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        engine.process(
            command(
                "v1",
                "model/validate",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "validation_notes": "notes"},
                T_VALIDATE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        result = engine.process(
            command(
                "a1",
                "model/approve",
                APPROVER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "approver": DEVELOPER},
                T_APPROVE,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=2),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertIn("separation", (result.detail or "").lower())

    def test_deploy_unapproved_model_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        result = engine.process(
            command(
                "d1",
                "model/deploy",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_DEPLOY,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_suspend_undeployed_model_fails_closed(self) -> None:
        engine = make_engine()
        register_model(engine)
        result = engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=1),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_suspend_suspended_model_fails_closed(self) -> None:
        engine = prepared_engine()
        engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        result = engine.process(
            command(
                "s2",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "again"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_resume_unsuspended_model_fails_closed(self) -> None:
        engine = prepared_engine()
        result = engine.process(
            command(
                "s2",
                "model/resume",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_retired_model_never_resumes(self) -> None:
        engine = prepared_engine()
        engine.process(
            command(
                "t1",
                "model/retire",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "superseded"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        result = engine.process(
            command(
                "s2",
                "model/resume",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_unknown_model_lookup_fails_closed(self) -> None:
        registry = ModelRegistry(environment_id=ENV, domain_id=DOMAIN)
        self.assertIsNone(registry.get("model/ghost"))
        with self.assertRaises(CoreValidationError):
            registry.require_model("model/ghost")

    def test_require_deployed_passes_only_for_deployed_state(self) -> None:
        engine = prepared_engine()
        engine.process(
            command(
                "t1",
                "model/retire",
                OPERATOR,
                RELIABILITY_MODEL_ID,
                {"model_id": RELIABILITY_MODEL_ID, "reason": "superseded"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=RELIABILITY_MODEL_ID, object_version=4),),
            )
        )
        engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        with self.assertRaises(CoreValidationError):
            engine.registry.require_deployed(RELIABILITY_MODEL_ID)
        with self.assertRaises(CoreValidationError):
            engine.registry.require_deployed(COST_MODEL_ID)
        engine.process(
            command(
                "s2",
                "model/resume",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=5),),
            )
        )
        deployed = engine.registry.require_deployed(COST_MODEL_ID)
        self.assertEqual(deployed.model_id, COST_MODEL_ID)

    def test_provenance_is_preserved_across_the_version_chain(self) -> None:
        engine = prepared_engine()
        record = engine.get_model(COST_MODEL_ID)
        self.assertEqual(record.envelope.provenance.evidence_refs, (CODE_HASH,))

    def test_model_record_round_trip(self) -> None:
        engine = prepared_engine()
        record = engine.get_model(COST_MODEL_ID)
        decoded = ModelRecord.from_dict(record.to_dict())
        self.assertEqual(decoded, record)
        decoded_json = ModelRecord.from_json(record.to_json())
        self.assertEqual(decoded_json, record)

    def test_tampered_model_record_fails_closed(self) -> None:
        engine = prepared_engine()
        record = engine.get_model(COST_MODEL_ID)
        value = record.to_dict()
        value["payload"]["task"] = "counterfeit semantics"
        with self.assertRaises(CoreValidationError):
            ModelRecord.from_dict(value)

    def test_registry_state_digest_is_deterministic(self) -> None:
        first = prepared_engine().registry.state_digest()
        second = prepared_engine().registry.state_digest()
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, prepared_engine_with_retired().registry.state_digest()
        )

    def test_unknown_model_command_type_is_rejected(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "x1",
                "model/explode",
                DEVELOPER,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID},
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNKNOWN_COMMAND_TYPE)

    def test_model_commands_require_governance_authority_class(self) -> None:
        engine = make_engine(DEVELOPER=PROPOSAL_CLASS)
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)

    def test_kernel_rejections_are_recorded_when_enabled(self) -> None:
        engine = make_engine()
        engine.process(
            command(
                "r1",
                "model/register",
                STRANGER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        rejection_events = [
            entry
            for entry in engine.journal
            if entry.event.event_type == "governance/command-rejected"
        ]
        self.assertEqual(len(rejection_events), 1)

    def test_kernel_rejections_are_silent_when_disabled(self) -> None:
        engine = AgentsEngine(
            environment_id=ENV,
            domain_id=DOMAIN,
            authorization=authority_table(),
            emit_rejection_events=False,
        )
        engine.process(
            command(
                "r1",
                "model/register",
                STRANGER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(engine.journal, ())

    def test_duplicate_model_command_converges(self) -> None:
        engine = make_engine()
        first = register_model(engine)
        again = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost in exact minor units",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": (
                        "trained on corridor observations only",
                        "no counterparty default modeling",
                    ),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(first.outcome, Outcome.ACCEPTED)
        self.assertEqual(again.outcome, Outcome.DUPLICATE)

    def test_command_id_reuse_with_different_content_is_rejected(self) -> None:
        engine = make_engine()
        register_model(engine)
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "different task",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": OTHER_CODE_HASH,
                },
                T_REGISTER,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.COMMAND_ID_REUSED)

    def test_kernel_store_and_books_agree(self) -> None:
        engine = prepared_engine()
        record = engine.get_model(COST_MODEL_ID)
        envelope = engine.store_object(record.model_id)
        self.assertEqual(envelope, record.envelope)
        self.assertEqual(envelope.object_type, MODEL_OBJECT_TYPE)


def prepared_engine_with_retired() -> AgentsEngine:
    engine = prepared_engine()
    engine.process(
        command(
            "t1",
            "model/retire",
            OPERATOR,
            RELIABILITY_MODEL_ID,
            {"model_id": RELIABILITY_MODEL_ID, "reason": "superseded"},
            T_LATER,
            expected=(ExpectedVersion(object_ref=RELIABILITY_MODEL_ID, object_version=4),),
        )
    )
    return engine


# ---------------------------------------------------------------------------
# 3. Model outputs
# ---------------------------------------------------------------------------


class ModelOutputTests(unittest.TestCase):
    """Typed model artifacts: provenance, confidence, limitations, epistemics."""

    def test_simulated_and_predicted_outputs_are_accepted(self) -> None:
        for epistemic in (EpistemicType.SIMULATED, EpistemicType.PREDICTED):
            output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 1}, epistemic_type=epistemic)
            self.assertEqual(output.epistemic_type, epistemic)

    def test_observed_epistemic_type_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_output(
                "model-output/probe",
                COST_MODEL_ID,
                {"cost_minor": 1},
                epistemic_type=EpistemicType.OBSERVED,
            )

    def test_estimated_epistemic_type_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_output(
                "model-output/probe",
                COST_MODEL_ID,
                {"cost_minor": 1},
                epistemic_type=EpistemicType.ESTIMATED,
            )

    def test_counterfactual_epistemic_type_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_output(
                "model-output/probe",
                COST_MODEL_ID,
                {"cost_minor": 1},
                epistemic_type=EpistemicType.COUNTERFACTUAL,
            )

    def test_confidence_bounds_are_exact(self) -> None:
        self.assertEqual(
            make_output(
                "model-output/probe", COST_MODEL_ID, {"cost_minor": 1}, confidence_bps=0
            ).confidence_bps,
            0,
        )
        self.assertEqual(
            make_output(
                "model-output/probe", COST_MODEL_ID, {"cost_minor": 1}, confidence_bps=10000
            ).confidence_bps,
            10000,
        )
        for bad in (-1, 10001, "8000", 80.0, True):
            with self.assertRaises(CoreValidationError):
                make_output(
                    "model-output/probe",
                    COST_MODEL_ID,
                    {"cost_minor": 1},
                    confidence_bps=bad,
                )

    def test_declared_limitations_must_be_non_empty(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 1})
        payload = output.to_dict()
        payload["declared_limitations"] = []
        with self.assertRaises(CoreValidationError):
            ModelOutput.from_dict(payload)

    def test_provenance_evidence_refs_must_be_non_empty(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 1})
        payload = output.to_dict()
        payload["provenance"]["evidence_refs"] = []
        with self.assertRaises(CoreValidationError):
            ModelOutput.from_dict(payload)

    def test_validity_window_ordering_is_enforced(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 1})
        payload = output.to_dict()
        payload["valid_from"] = T_EXPIRED
        payload["valid_until"] = T_OUTPUT
        with self.assertRaises(CoreValidationError):
            ModelOutput.from_dict(payload)

    def test_values_must_be_canonical(self) -> None:
        with self.assertRaises(CoreValidationError):
            ModelOutput(
                output_id="model-output/probe",
                model_id=COST_MODEL_ID,
                epistemic_type=EpistemicType.SIMULATED,
                confidence_bps=8000,
                value={"cost_minor": 6400.5},
                declared_limitations=("limitation",),
                produced_at=T_OUTPUT,
                valid_from=T_OUTPUT,
                valid_until=T_EXPIRED,
                provenance=Provenance(
                    issuer=COST_MODEL_ID,
                    source="agents/model-output",
                    recorded_at=T_OUTPUT,
                    evidence_refs=("evidence/probe",),
                ),
            )

    def test_output_ids_use_the_model_output_prefix(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_output("wrong-prefix/probe", COST_MODEL_ID, {"cost_minor": 1})

    def test_round_trip_and_digest_stability(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 6400})
        decoded = ModelOutput.from_dict(output.to_dict())
        self.assertEqual(decoded, output)
        self.assertEqual(output.digest, decoded.digest)
        self.assertEqual(output.digest, output.digest)

    def test_tampered_output_fails_closed(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 6400})
        payload = output.to_dict()
        payload["value"]["cost_minor"] = 1
        with self.assertRaises(CoreValidationError):
            ModelOutput.from_dict(payload)

    def test_unknown_output_fields_fail_closed(self) -> None:
        output = make_output("model-output/probe", COST_MODEL_ID, {"cost_minor": 6400})
        payload = output.to_dict()
        payload["effect_request"] = {"rail": "offledger"}
        with self.assertRaises(CoreValidationError):
            ModelOutput.from_dict(payload)


# ---------------------------------------------------------------------------
# 4. Bounded proposal mandates
# ---------------------------------------------------------------------------


class MandateTests(unittest.TestCase):
    """Agent-scoped proposal authority: scope, limits, expiry — nothing more."""

    def test_authorize_mandate_happy_path(self) -> None:
        engine = make_engine()
        result = authorize_mandate(engine)
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        mandate = engine.get_mandate(MANDATE_ID)
        self.assertEqual(mandate.spec.agent_principal, AGENT)
        self.assertEqual(mandate.spec.issued_by, OPERATOR)
        self.assertEqual(mandate.spec.authority_class, PROPOSAL_AUTHORITY_CLASS)
        self.assertEqual(
            engine.journal[-1].event.event_type,
            "governance/agent-mandate-authorized",
        )

    def test_mandate_authority_class_is_frozen_to_the_proposal_tier(self) -> None:
        engine = make_engine()
        for index, forbidden in enumerate((EXECUTE_CLASS, "R5", GOVERNANCE_CLASS, "R0")):
            result = engine.process(
                command(
                    f"m1-{index}",
                    "agent/authorize-mandate",
                    OPERATOR,
                    MANDATE_ID,
                    {
                        "mandate_id": MANDATE_ID,
                        "agent_principal": AGENT,
                        "proposal_kinds": [ProposalKind.ROUTE.value],
                        "route_families": [PREMIUM_FAMILY],
                        "max_proposals": 1,
                        "not_before": T_MANDATE,
                        "not_after": T_EXPIRED,
                        "authority_class": forbidden,
                    },
                    T_MANDATE,
                )
            )
            self.assertEqual(result.outcome, Outcome.REJECTED)
            self.assertIn("PROPOSE", (result.detail or ""))

    def test_issuer_must_differ_from_agent(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "m1",
                "agent/authorize-mandate",
                AGENT,
                MANDATE_ID,
                {
                    "mandate_id": MANDATE_ID,
                    "agent_principal": AGENT,
                    "proposal_kinds": [ProposalKind.ROUTE.value],
                    "route_families": [PREMIUM_FAMILY],
                    "max_proposals": 1,
                    "not_before": T_MANDATE,
                    "not_after": T_EXPIRED,
                },
                T_MANDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_route_families_must_be_non_empty_and_distinct(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "m1",
                "agent/authorize-mandate",
                OPERATOR,
                MANDATE_ID,
                {
                    "mandate_id": MANDATE_ID,
                    "agent_principal": AGENT,
                    "proposal_kinds": [ProposalKind.ROUTE.value],
                    "route_families": [],
                    "max_proposals": 1,
                    "not_before": T_MANDATE,
                    "not_after": T_EXPIRED,
                },
                T_MANDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        result = engine.process(
            command(
                "m2",
                "agent/authorize-mandate",
                OPERATOR,
                MANDATE_ID,
                {
                    "mandate_id": MANDATE_ID,
                    "agent_principal": AGENT,
                    "proposal_kinds": [ProposalKind.ROUTE.value],
                    "route_families": [PREMIUM_FAMILY, PREMIUM_FAMILY],
                    "max_proposals": 1,
                    "not_before": T_MANDATE,
                    "not_after": T_EXPIRED,
                },
                T_MANDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_max_proposals_must_be_at_least_one(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "m1",
                "agent/authorize-mandate",
                OPERATOR,
                MANDATE_ID,
                {
                    "mandate_id": MANDATE_ID,
                    "agent_principal": AGENT,
                    "proposal_kinds": [ProposalKind.ROUTE.value],
                    "route_families": [PREMIUM_FAMILY],
                    "max_proposals": 0,
                    "not_before": T_MANDATE,
                    "not_after": T_EXPIRED,
                },
                T_MANDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_window_ordering_is_enforced(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "m1",
                "agent/authorize-mandate",
                OPERATOR,
                MANDATE_ID,
                {
                    "mandate_id": MANDATE_ID,
                    "agent_principal": AGENT,
                    "proposal_kinds": [ProposalKind.ROUTE.value],
                    "route_families": [PREMIUM_FAMILY],
                    "max_proposals": 1,
                    "not_before": T_EXPIRED,
                    "not_after": T_MANDATE,
                },
                T_MANDATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_mandate_window_is_half_open_at_expiry(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        book = engine.mandates
        book.authorize_proposal(
            mandate_id=MANDATE_ID,
            agent_principal=AGENT,
            proposal_kind=ProposalKind.ROUTE,
            route_family=PREMIUM_FAMILY,
            as_of=T_PROPOSE,
            consumed=0,
        )
        with self.assertRaises(CoreValidationError):
            book.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=AGENT,
                proposal_kind=ProposalKind.ROUTE,
                route_family=PREMIUM_FAMILY,
                as_of=T_EXPIRED,
                consumed=0,
            )

    def test_authorize_proposal_before_window_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=AGENT,
                proposal_kind=ProposalKind.ROUTE,
                route_family=PREMIUM_FAMILY,
                as_of=T_BEFORE,
                consumed=0,
            )

    def test_authorize_proposal_out_of_family_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=AGENT,
                proposal_kind=ProposalKind.ROUTE,
                route_family=OFFLEDGER_FAMILY,
                as_of=T_PROPOSE,
                consumed=0,
            )

    def test_authorize_proposal_wrong_kind_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=AGENT,
                proposal_kind="settlement",
                route_family=PREMIUM_FAMILY,
                as_of=T_PROPOSE,
                consumed=0,
            )

    def test_authorize_proposal_budget_exhausted_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=AGENT,
                proposal_kind=ProposalKind.ROUTE,
                route_family=PREMIUM_FAMILY,
                as_of=T_PROPOSE,
                consumed=2,
            )

    def test_authorize_proposal_wrong_agent_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id=MANDATE_ID,
                agent_principal=STRANGER,
                proposal_kind=ProposalKind.ROUTE,
                route_family=PREMIUM_FAMILY,
                as_of=T_PROPOSE,
                consumed=0,
            )

    def test_unknown_mandate_fails_closed(self) -> None:
        engine = make_engine()
        with self.assertRaises(CoreValidationError):
            engine.mandates.authorize_proposal(
                mandate_id="agent-mandate/ghost",
                agent_principal=AGENT,
                proposal_kind=ProposalKind.ROUTE,
                route_family=PREMIUM_FAMILY,
                as_of=T_PROPOSE,
                consumed=0,
            )

    def test_mandate_record_round_trip(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        mandate = engine.get_mandate(MANDATE_ID)
        decoded = ProposalMandate.from_dict(mandate.to_dict())
        self.assertEqual(decoded, mandate)

    def test_tampered_mandate_fails_closed(self) -> None:
        engine = make_engine()
        authorize_mandate(engine)
        mandate = engine.get_mandate(MANDATE_ID)
        value = mandate.to_dict()
        value["payload"]["route_families"] = [PREMIUM_FAMILY, ECONOMY_FAMILY, OFFLEDGER_FAMILY]
        with self.assertRaises(CoreValidationError):
            ProposalMandate.from_dict(value)


# ---------------------------------------------------------------------------
# 5. Agent contexts
# ---------------------------------------------------------------------------


class AgentContextTests(unittest.TestCase):
    """Derived, sealed snapshots binding agent + mandate + models + modes."""

    def test_build_context_happy_path(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        self.assertEqual(context.spec.context_id, CONTEXT_ID)
        self.assertEqual(context.spec.agent_principal, AGENT)
        self.assertEqual(context.spec.mandate_id, MANDATE_ID)
        self.assertEqual(
            context.spec.model_ids, (COST_MODEL_ID, RELIABILITY_MODEL_ID)
        )
        self.assertEqual(context.spec.allowed_modes, (EnvironmentMode.SIMULATION,))
        self.assertEqual(context.state, "ACTIVE")

    def test_context_requires_deployed_models(self) -> None:
        engine = prepared_engine()
        engine.process(
            command(
                "t1",
                "model/retire",
                OPERATOR,
                RELIABILITY_MODEL_ID,
                {"model_id": RELIABILITY_MODEL_ID, "reason": "superseded"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=RELIABILITY_MODEL_ID, object_version=4),),
            )
        )
        with self.assertRaises(CoreValidationError):
            make_context(engine)

    def test_context_requires_registered_mandate(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id="agent-mandate/ghost",
                model_ids=(COST_MODEL_ID,),
                allowed_modes=(EnvironmentMode.SIMULATION,),
                as_of=T_MANDATE,
            )

    def test_context_requires_mandate_bound_to_agent(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=STRANGER,
                mandate_id=MANDATE_ID,
                model_ids=(COST_MODEL_ID,),
                allowed_modes=(EnvironmentMode.SIMULATION,),
                as_of=T_MANDATE,
            )

    def test_context_requires_mandate_active_at_as_of(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id=MANDATE_ID,
                model_ids=(COST_MODEL_ID,),
                allowed_modes=(EnvironmentMode.SIMULATION,),
                as_of=T_EXPIRED,
            )

    def test_context_rejects_production_mode(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id=MANDATE_ID,
                model_ids=(COST_MODEL_ID,),
                allowed_modes=(EnvironmentMode.SIMULATION, EnvironmentMode.PRODUCTION),
                as_of=T_MANDATE,
            )

    def test_context_rejects_shadow_mode(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id=MANDATE_ID,
                model_ids=(COST_MODEL_ID,),
                allowed_modes=(EnvironmentMode.SHADOW,),
                as_of=T_MANDATE,
            )

    def test_context_accepts_hypothetical_modes_only(self) -> None:
        engine = prepared_engine()
        context = build_agent_context(
            registry=engine.registry,
            mandates=engine.mandates,
            context_id=CONTEXT_ID,
            agent_principal=AGENT,
            mandate_id=MANDATE_ID,
            model_ids=(COST_MODEL_ID,),
            allowed_modes=(
                EnvironmentMode.SIMULATION,
                EnvironmentMode.FORECAST,
                EnvironmentMode.COUNTERFACTUAL,
            ),
            as_of=T_MANDATE,
        )
        self.assertEqual(len(context.spec.allowed_modes), 3)

    def test_context_requires_non_empty_models(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id=MANDATE_ID,
                model_ids=(),
                allowed_modes=(EnvironmentMode.SIMULATION,),
                as_of=T_MANDATE,
            )

    def test_context_rejects_duplicate_models(self) -> None:
        engine = prepared_engine()
        with self.assertRaises(CoreValidationError):
            build_agent_context(
                registry=engine.registry,
                mandates=engine.mandates,
                context_id=CONTEXT_ID,
                agent_principal=AGENT,
                mandate_id=MANDATE_ID,
                model_ids=(COST_MODEL_ID, COST_MODEL_ID),
                allowed_modes=(EnvironmentMode.SIMULATION,),
                as_of=T_MANDATE,
            )

    def test_context_round_trip(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        decoded = AgentContext.from_dict(context.to_dict())
        self.assertEqual(decoded, context)

    def test_tampered_context_fails_closed(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        value = context.to_dict()
        value["payload"]["model_ids"] = ["model/ghost-model"]
        with self.assertRaises(CoreValidationError):
            AgentContext.from_dict(value)


# ---------------------------------------------------------------------------
# 6. Route proposals
# ---------------------------------------------------------------------------


class ProposalTests(unittest.TestCase):
    """Route proposals: declared profiles backed by sealed model outputs."""

    def test_proposal_structural_happy_path(self) -> None:
        engine = prepared_engine()
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, make_context(engine))
        self.assertEqual(proposal.spec.proposal_id, ALPHA_ID)
        self.assertEqual(proposal.spec.route_family, PREMIUM_FAMILY)
        self.assertEqual(len(proposal.spec.model_outputs), 2)
        self.assertEqual(proposal.state, "PROPOSED")

    def test_proposal_requires_model_outputs(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        with self.assertRaises(CoreValidationError):
            make_proposal(ALPHA_ID, PREMIUM_FAMILY, context, outputs=())

    def test_proposal_output_models_must_be_in_context(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        stray = make_output("model-output/stray", "model/ghost-model", {"cost_minor": 1})
        with self.assertRaises(CoreValidationError):
            make_proposal(
                ALPHA_ID, PREMIUM_FAMILY, context, outputs=(stray,)
            )

    def test_proposal_output_must_be_fresh_at_as_of(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        stale = make_output("model-output/stale", COST_MODEL_ID, {"cost_minor": 1})
        stale_payload = stale.to_dict()
        stale_payload["valid_until"] = T_PROPOSE
        with self.assertRaises(CoreValidationError):
            make_proposal(
                ALPHA_ID,
                PREMIUM_FAMILY,
                context,
                outputs=(ModelOutput.from_dict(stale_payload),),
            )

    def test_declared_metric_bounds(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        for bad in (
            {"declared_cost_minor": -1},
            {"declared_latency_ms": -5},
            {"declared_reliability_bps": 10001},
            {"declared_cost_scale": 19},
        ):
            fields = {
                "proposal_id": ALPHA_ID,
                "agent_principal": AGENT,
                "mandate_id": MANDATE_ID,
                "route_family": PREMIUM_FAMILY,
                "rail": "rail/premium",
                "declared_cost_minor": 6500,
                "declared_cost_scale": 2,
                "declared_cost_asset": "asset/usd",
                "declared_latency_ms": 500,
                "declared_reliability_bps": 9600,
                "context": context,
                "model_outputs": (),
                "as_of": T_PROPOSE,
            }
            fields.update(bad)
            with self.assertRaises(CoreValidationError):
                RouteProposal.build(**fields)

    def test_kernel_records_proposal(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1")
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(
            engine.journal[-1].event.event_type, "governance/agent-proposal-recorded"
        )
        recorded = engine.get_proposal(ALPHA_ID)
        self.assertEqual(recorded, proposal)
        envelope = engine.store_object(ALPHA_ID)
        self.assertEqual(envelope.state, "PROPOSED")
        self.assertEqual(envelope.object_type, PROPOSAL_OBJECT_TYPE)

    def test_impersonated_proposal_is_rejected_and_recorded(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1", actor=STRANGER)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.POLICY_REJECTED)
        rejection_events = [
            entry
            for entry in engine.journal
            if entry.event.event_type == "governance/command-rejected"
        ]
        self.assertEqual(len(rejection_events), 1)

    def test_out_of_scope_proposal_is_rejected_and_recorded(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal("agent-proposal/offledger-1", OFFLEDGER_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.POLICY_REJECTED)
        self.assertIn("scope", (result.detail or "").lower())

    def test_expired_mandate_proposal_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        # A validly sealed proposal whose explicit instant is the mandate's
        # expiry: the half-open window excludes it, so the kernel rejects.
        long_fresh_outputs = (
            ModelOutput(
                output_id="model-output/premium-cost-late",
                model_id=COST_MODEL_ID,
                epistemic_type=EpistemicType.SIMULATED,
                confidence_bps=8000,
                value={"cost_minor": 6400},
                declared_limitations=("corridor observations only",),
                produced_at=T_OUTPUT,
                valid_from=T_OUTPUT,
                valid_until="2026-09-02T12:00:00Z",
                provenance=Provenance(
                    issuer=COST_MODEL_ID,
                    source="agents/model-output",
                    recorded_at=T_OUTPUT,
                    evidence_refs=("evidence/expired-probe",),
                ),
            ),
            ModelOutput(
                output_id="model-output/premium-reliability-late",
                model_id=RELIABILITY_MODEL_ID,
                epistemic_type=EpistemicType.SIMULATED,
                confidence_bps=8000,
                value={"reliability_bps": 9600},
                declared_limitations=("corridor observations only",),
                produced_at=T_OUTPUT,
                valid_from=T_OUTPUT,
                valid_until="2026-09-02T12:00:00Z",
                provenance=Provenance(
                    issuer=RELIABILITY_MODEL_ID,
                    source="agents/model-output",
                    recorded_at=T_OUTPUT,
                    evidence_refs=("evidence/expired-probe",),
                ),
            ),
        )
        proposal = RouteProposal.build(
            proposal_id=ALPHA_ID,
            agent_principal=context.spec.agent_principal,
            mandate_id=context.spec.mandate_id,
            route_family=PREMIUM_FAMILY,
            rail="rail/premium",
            declared_cost_minor=6500,
            declared_cost_scale=2,
            declared_cost_asset="asset/usd",
            declared_latency_ms=500,
            declared_reliability_bps=9600,
            context=context,
            model_outputs=long_fresh_outputs,
            as_of=T_EXPIRED,
        )
        result = engine.process(
            command(
                "p1",
                "agent/propose",
                AGENT,
                ALPHA_ID,
                {"proposal": proposal.to_dict()},
                T_EXPIRED,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_budget_exhausted_proposal_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        third = make_proposal(
            "agent-proposal/charlie-premium", PREMIUM_FAMILY, context
        )
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        result = submit_proposal(engine, third, seq="p3")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertIn("budget", (result.detail or "").lower())

    def test_proposal_citing_undeployed_model_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        engine.process(
            command(
                "s1",
                "model/suspend",
                OPERATOR,
                COST_MODEL_ID,
                {"model_id": COST_MODEL_ID, "reason": "drift"},
                T_LATER,
                expected=(ExpectedVersion(object_ref=COST_MODEL_ID, object_version=4),),
            )
        )
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertIn("deployed", (result.detail or "").lower())

    def test_proposal_citing_unknown_model_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        stray = make_output("model-output/stray", "model/ghost-model", {"cost_minor": 1})
        # The strongest gate fires first: a model output citing a model
        # outside the agent context cannot even form a sealed proposal.
        with self.assertRaises(CoreValidationError):
            make_proposal(
                "agent-proposal/offscope-1", PREMIUM_FAMILY, context, outputs=(stray,)
            )

    def test_proposal_without_simulation_mode_is_rejected(self) -> None:
        engine = prepared_engine()
        context = build_agent_context(
            registry=engine.registry,
            mandates=engine.mandates,
            context_id=CONTEXT_ID,
            agent_principal=AGENT,
            mandate_id=MANDATE_ID,
            model_ids=(COST_MODEL_ID, RELIABILITY_MODEL_ID),
            allowed_modes=(EnvironmentMode.FORECAST,),
            as_of=T_MANDATE,
        )
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertIn("simulation", (result.detail or "").lower())

    def test_malformed_proposal_payload_is_rejected(self) -> None:
        engine = prepared_engine()
        result = engine.process(
            command(
                "p1",
                "agent/propose",
                AGENT,
                ALPHA_ID,
                {"proposal": {"unexpected": "shape"}},
                T_PROPOSE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)

    def test_duplicate_proposal_id_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        submit_proposal(engine, proposal, seq="p1")
        result = submit_proposal(engine, proposal, seq="p2")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.VERSION_CONFLICT)

    def test_proposal_round_trip(self) -> None:
        engine = prepared_engine()
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, make_context(engine))
        decoded = RouteProposal.from_dict(proposal.to_dict())
        self.assertEqual(decoded, proposal)


# ---------------------------------------------------------------------------
# 7. Engine discipline (authority binding, mediation-only path)
# ---------------------------------------------------------------------------


class EngineDisciplineTests(unittest.TestCase):
    """The kernel binding: one authority per command type, fail-closed gates."""

    def test_engine_binds_every_agents_command(self) -> None:
        engine = make_engine()
        self.assertEqual(engine.command_types(), AGENTS_COMMANDS)

    def test_proposal_with_execute_tier_authority_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1", actor=ESCALATOR)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)
        self.assertIn("PROPOSE", (result.detail or ""))

    def test_proposal_with_governance_class_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, proposal, seq="p1", actor=OPERATOR)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)

    def test_model_command_with_proposal_class_is_rejected(self) -> None:
        engine = make_engine(DEVELOPER=PROPOSAL_CLASS)
        result = register_model(engine)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)

    def test_mandate_authorization_with_proposal_class_is_rejected(self) -> None:
        engine = make_engine(OPERATOR=PROPOSAL_CLASS)
        result = authorize_mandate(engine)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)

    def test_no_authorization_policy_fails_closed(self) -> None:
        engine = AgentsEngine(environment_id=ENV, domain_id=DOMAIN)
        result = register_model(engine)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)

    def test_environment_mismatch_is_rejected(self) -> None:
        engine = make_engine()
        result = engine.process(
            command(
                "r1",
                "model/register",
                DEVELOPER,
                COST_MODEL_ID,
                {
                    "model_id": COST_MODEL_ID,
                    "developer": DEVELOPER,
                    "task": "predict route cost",
                    "risk_class": ModelRiskClass.LOW.value,
                    "declared_limitations": ("limitation",),
                    "code_hash": CODE_HASH,
                },
                T_REGISTER,
                environment_id="env/somewhere-else",
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.ENVIRONMENT_MISMATCH)

    def test_engine_state_digest_is_deterministic(self) -> None:
        first = mediated_engine()[0].state_digest()
        second = mediated_engine()[0].state_digest()
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# 8. Candidate simulation through src.simulation
# ---------------------------------------------------------------------------


class CandidateSimulationTests(unittest.TestCase):
    """The mediation substrate: SIMULATION environments over the real kernel."""

    def test_route_evaluation_binding_is_well_formed(self) -> None:
        binding = route_evaluation_binding()
        self.assertEqual(binding.binding_id, ROUTE_EVALUATION_BINDING_ID)
        self.assertEqual(binding.protocol_version, PROTOCOL_VERSION)
        self.assertEqual(len(binding.registrations), 1)
        registration = binding.registrations[0]
        self.assertEqual(registration.command_type, ROUTE_EVALUATION_COMMAND_TYPE)
        self.assertEqual(registration.event_type, ROUTE_EVALUATION_EVENT_TYPE)

    def test_candidate_simulation_records_simulated_metrics(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        runtime, outcome, result = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(runtime.mode, EnvironmentMode.SIMULATION)
        self.assertEqual(outcome.cost_minor, 6400)
        self.assertEqual(outcome.latency_ms, 480)
        self.assertEqual(outcome.reliability_bps, 9650)
        self.assertEqual(outcome.proposal_id, BRAVO_ID)
        self.assertEqual(result.envelope.state, SimulationRunState.COMPLETED.value)
        self.assertEqual(
            runtime.journal[0].event.event_type, ROUTE_EVALUATION_EVENT_TYPE
        )

    def test_candidate_simulation_requires_scripted_observations(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        with self.assertRaises(CoreValidationError):
            simulate_candidate(
                proposal=proposal,
                world=make_world(),
                environment_id="env/agents-mediation/session-1/alpha-premium",
                domain_id=DOMAIN,
                as_of=T_EXPIRED,
                command_id="cmd/evaluate-alpha",
            )

    def test_candidate_simulations_produce_sealed_results(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        _, outcome, result = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertIsNotNone(outcome.simulation_result_digest)
        self.assertEqual(outcome.simulation_result_digest, result.integrity_hash)
        self.assertEqual(result.envelope.object_type, "simulation/result/v1")

    def test_same_candidate_same_world_is_byte_identical(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        first = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        second = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(
            parity_digest(first[0].journal), parity_digest(second[0].journal)
        )
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2].integrity_hash, second[2].integrity_hash)

    def test_different_world_changes_the_metrics(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        first = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        second = simulate_candidate(
            proposal=proposal,
            world=make_world(economy_cost_minor=7000),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(first[1].cost_minor, 6400)
        self.assertEqual(second[1].cost_minor, 7000)
        self.assertNotEqual(
            first[1].simulation_result_digest, second[1].simulation_result_digest
        )

    def test_simulation_observations_carry_simulated_epistemic_type(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        runtime, _, _ = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(len(runtime.observations), 3)
        for observation in runtime.observations:
            self.assertIs(observation.epistemic_type, EpistemicType.SIMULATED)

    def test_no_effect_records_are_produced(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        runtime, _, _ = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(runtime.effects, ())

    def test_world_with_wrong_epistemic_type_fails_closed(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        observed_world = ScriptedWorld(
            observations=(
                WorldObservation(
                    observation_key=f"route/{ECONOMY_FAMILY}/cost-minor",
                    epistemic_type=EpistemicType.OBSERVED,
                    as_of=T_MEDIATE,
                    value=6400,
                    source="world/agents-test",
                ),
            ),
            epistemic_type=EpistemicType.OBSERVED,
        )
        with self.assertRaises(CoreValidationError):
            simulate_candidate(
                proposal=proposal,
                world=observed_world,
                environment_id="env/agents-mediation/session-1/bravo-economy",
                domain_id=DOMAIN,
                as_of=T_MEDIATE,
                command_id="cmd/evaluate-bravo",
            )

    def test_evaluation_object_type_is_internal(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        proposal = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        runtime, _, _ = simulate_candidate(
            proposal=proposal,
            world=make_world(),
            environment_id="env/agents-mediation/session-1/bravo-economy",
            domain_id=DOMAIN,
            as_of=T_MEDIATE,
            command_id="cmd/evaluate-bravo",
        )
        self.assertEqual(
            runtime.journal[0].event.object_refs, ("route-evaluation/bravo-economy",)
        )
        self.assertEqual(
            runtime.namespace_state(StateNamespace.DEPENDENCY)[0].object_type,
            ROUTE_EVALUATION_OBJECT_TYPE,
        )


# ---------------------------------------------------------------------------
# 9. The deterministic mediation policy
# ---------------------------------------------------------------------------


def outcome(
    proposal_id: str,
    *,
    cost_minor: int,
    latency_ms: int,
    reliability_bps: int,
) -> SimulatedOutcome:
    return SimulatedOutcome(
        proposal_id=proposal_id,
        agent_principal=AGENT,
        route_family="probe",
        environment_id="env/probe",
        transition_digest="c" * 64,
        simulation_result_digest="d" * 64,
        cost_minor=cost_minor,
        latency_ms=latency_ms,
        reliability_bps=reliability_bps,
    )


class MediationPolicyTests(unittest.TestCase):
    """Explicit weights, rank points, deterministic tie-break, fail-closed."""

    def test_weights_must_sum_to_the_basis_point_total(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_policy(cost_weight_bps=5999)
        with self.assertRaises(CoreValidationError):
            make_policy(cost_weight_bps=6001)

    def test_each_weight_must_be_positive(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_policy(
                cost_weight_bps=0,
                latency_weight_bps=2000,
                reliability_weight_bps=8000,
            )

    def test_policy_identity_is_required(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_policy(policy_version=0)
        with self.assertRaises(CoreValidationError):
            make_policy(policy_id="")

    def test_policy_from_dict_rejects_unknown_schema_version(self) -> None:
        policy = make_policy()
        payload = policy.to_dict()
        payload["schema_version"] = 2
        with self.assertRaises(CoreValidationError):
            MediationPolicy.from_dict(payload)

    def test_policy_from_dict_rejects_unknown_fields(self) -> None:
        policy = make_policy()
        payload = policy.to_dict()
        payload["favorite_route"] = "premium"
        with self.assertRaises(CoreValidationError):
            MediationPolicy.from_dict(payload)

    def test_policy_digest_is_canonical_and_stable(self) -> None:
        policy = make_policy()
        self.assertEqual(policy.digest, make_policy().digest)
        self.assertNotEqual(policy.digest, make_policy(cost_weight_bps=5000, latency_weight_bps=2000, reliability_weight_bps=3000).digest)

    def test_two_candidate_selection_matches_hand_computed_points(self) -> None:
        policy = make_policy()
        evaluation = policy.evaluate(
            (
                outcome(
                    ALPHA_ID, cost_minor=9750, latency_ms=120, reliability_bps=9980
                ),
                outcome(
                    BRAVO_ID, cost_minor=6400, latency_ms=480, reliability_bps=9650
                ),
            )
        )
        self.assertEqual(evaluation.selected_proposal_id, BRAVO_ID)
        self.assertFalse(evaluation.tie_break_applied)
        by_id = {candidate.proposal_id: candidate for candidate in evaluation.ranked}
        self.assertEqual(by_id[ALPHA_ID].total_points, 4000)
        self.assertEqual(by_id[BRAVO_ID].total_points, 6000)
        self.assertEqual(by_id[BRAVO_ID].cost_points, 6000)
        self.assertEqual(by_id[ALPHA_ID].latency_points, 1000)
        self.assertEqual(by_id[ALPHA_ID].reliability_points, 3000)

    def test_equal_dimension_values_share_rank(self) -> None:
        policy = make_policy()
        evaluation = policy.evaluate(
            (
                outcome(ALPHA_ID, cost_minor=100, latency_ms=100, reliability_bps=5000),
                outcome(BRAVO_ID, cost_minor=100, latency_ms=100, reliability_bps=5000),
            )
        )
        by_id = {candidate.proposal_id: candidate for candidate in evaluation.ranked}
        self.assertEqual(
            by_id[ALPHA_ID].total_points, by_id[BRAVO_ID].total_points
        )
        self.assertTrue(evaluation.tie_break_applied)

    def test_deterministic_tie_break_selects_smallest_proposal_id(self) -> None:
        policy = make_policy(
            cost_weight_bps=4999, latency_weight_bps=4999, reliability_weight_bps=2
        )
        evaluation = policy.evaluate(
            (
                outcome(
                    "agent-proposal/zulu", cost_minor=100, latency_ms=200, reliability_bps=100
                ),
                outcome(
                    "agent-proposal/alpha", cost_minor=200, latency_ms=100, reliability_bps=100
                ),
            )
        )
        self.assertEqual(evaluation.selected_proposal_id, "agent-proposal/alpha")
        self.assertTrue(evaluation.tie_break_applied)

    def test_tie_break_is_order_independent(self) -> None:
        policy = make_policy(
            cost_weight_bps=4999, latency_weight_bps=4999, reliability_weight_bps=2
        )
        first = policy.evaluate(
            (
                outcome(
                    "agent-proposal/zulu", cost_minor=100, latency_ms=200, reliability_bps=100
                ),
                outcome(
                    "agent-proposal/alpha", cost_minor=200, latency_ms=100, reliability_bps=100
                ),
            )
        )
        second = policy.evaluate(
            (
                outcome(
                    "agent-proposal/alpha", cost_minor=200, latency_ms=100, reliability_bps=100
                ),
                outcome(
                    "agent-proposal/zulu", cost_minor=100, latency_ms=200, reliability_bps=100
                ),
            )
        )
        self.assertEqual(
            first.selected_proposal_id, second.selected_proposal_id
        )
        self.assertEqual(
            [candidate.proposal_id for candidate in first.ranked],
            [candidate.proposal_id for candidate in second.ranked],
        )

    def test_policy_prefers_lower_cost(self) -> None:
        policy = make_policy(
            cost_weight_bps=9998, latency_weight_bps=1, reliability_weight_bps=1
        )
        evaluation = policy.evaluate(
            (
                outcome(ALPHA_ID, cost_minor=100, latency_ms=100, reliability_bps=100),
                outcome(BRAVO_ID, cost_minor=99, latency_ms=100, reliability_bps=100),
            )
        )
        self.assertEqual(evaluation.selected_proposal_id, BRAVO_ID)

    def test_policy_prefers_lower_latency(self) -> None:
        policy = make_policy(
            cost_weight_bps=1, latency_weight_bps=9998, reliability_weight_bps=1
        )
        evaluation = policy.evaluate(
            (
                outcome(ALPHA_ID, cost_minor=100, latency_ms=200, reliability_bps=100),
                outcome(BRAVO_ID, cost_minor=100, latency_ms=100, reliability_bps=100),
            )
        )
        self.assertEqual(evaluation.selected_proposal_id, BRAVO_ID)

    def test_policy_prefers_higher_reliability(self) -> None:
        policy = make_policy(
            cost_weight_bps=1, latency_weight_bps=1, reliability_weight_bps=9998
        )
        evaluation = policy.evaluate(
            (
                outcome(ALPHA_ID, cost_minor=100, latency_ms=100, reliability_bps=100),
                outcome(BRAVO_ID, cost_minor=100, latency_ms=100, reliability_bps=101),
            )
        )
        self.assertEqual(evaluation.selected_proposal_id, BRAVO_ID)

    def test_three_candidate_rank_points(self) -> None:
        policy = make_policy(
            cost_weight_bps=5000, latency_weight_bps=3000, reliability_weight_bps=2000
        )
        evaluation = policy.evaluate(
            (
                outcome("agent-proposal/a", cost_minor=100, latency_ms=300, reliability_bps=100),
                outcome("agent-proposal/b", cost_minor=200, latency_ms=200, reliability_bps=200),
                outcome("agent-proposal/c", cost_minor=150, latency_ms=100, reliability_bps=300),
            )
        )
        by_id = {candidate.proposal_id: candidate for candidate in evaluation.ranked}
        # beaten counts: cost a=2 b=0 c=1 ; latency a=0 b=1 c=2 ; reliability a=0 b=1 c=2
        self.assertEqual(by_id["agent-proposal/a"].total_points, 10000 + 0 + 0)
        self.assertEqual(by_id["agent-proposal/b"].total_points, 0 + 3000 + 2000)
        self.assertEqual(by_id["agent-proposal/c"].total_points, 5000 + 6000 + 4000)
        self.assertEqual(evaluation.selected_proposal_id, "agent-proposal/c")

    def test_evaluate_requires_at_least_two_candidates(self) -> None:
        policy = make_policy()
        with self.assertRaises(CoreValidationError):
            policy.evaluate(
                (outcome(ALPHA_ID, cost_minor=1, latency_ms=1, reliability_bps=1),)
            )

    def test_evaluate_rejects_duplicate_proposal_ids(self) -> None:
        policy = make_policy()
        with self.assertRaises(CoreValidationError):
            policy.evaluate(
                (
                    outcome(ALPHA_ID, cost_minor=1, latency_ms=1, reliability_bps=1),
                    outcome(ALPHA_ID, cost_minor=2, latency_ms=2, reliability_bps=2),
                )
            )

    def test_evaluate_rejects_missing_metrics(self) -> None:
        policy = make_policy()
        partial = outcome(ALPHA_ID, cost_minor=1, latency_ms=1, reliability_bps=1)
        payload = partial.to_dict()
        del payload["cost_minor"]
        with self.assertRaises(CoreValidationError):
            policy.evaluate(
                (SimulatedOutcome.from_dict(payload), outcome(BRAVO_ID, cost_minor=1, latency_ms=1, reliability_bps=1))
            )

    def test_evaluate_rejects_out_of_range_reliability(self) -> None:
        policy = make_policy()
        payload = outcome(
            ALPHA_ID, cost_minor=1, latency_ms=1, reliability_bps=1
        ).to_dict()
        payload["reliability_bps"] = 10001
        with self.assertRaises(CoreValidationError):
            policy.evaluate(
                (
                    SimulatedOutcome.from_dict(payload),
                    outcome(BRAVO_ID, cost_minor=1, latency_ms=1, reliability_bps=1),
                )
            )

    def test_selection_is_reproducible(self) -> None:
        policy = make_policy()
        outcomes = (
            outcome(ALPHA_ID, cost_minor=9750, latency_ms=120, reliability_bps=9980),
            outcome(BRAVO_ID, cost_minor=6400, latency_ms=480, reliability_bps=9650),
        )
        first = policy.evaluate(outcomes)
        second = policy.evaluate(outcomes)
        self.assertEqual(
            [candidate.to_dict() for candidate in first.ranked],
            [candidate.to_dict() for candidate in second.ranked],
        )
        self.assertEqual(
            first.selected_proposal_id, second.selected_proposal_id
        )
        self.assertEqual(first.rationale, second.rationale)


# ---------------------------------------------------------------------------
# 10. The mediation engine (simulation-before-production, decisions only)
# ---------------------------------------------------------------------------


class MediationEngineTests(unittest.TestCase):
    """Proposals -> SIMULATED evaluation -> deterministic policy -> decision."""

    def test_mediate_two_routes_end_to_end(self) -> None:
        engine, context, alpha, bravo, decision = mediated_engine()
        self.assertEqual(
            decision.spec.selected_proposal_id, BRAVO_ID
        )
        self.assertEqual(decision.state, "DECIDED")
        self.assertEqual(
            engine.journal[-1].event.event_type, "governance/mediation-selected"
        )
        self.assertEqual(engine.get_decision(DECISION_ID), decision)
        self.assertEqual(
            engine.store_object(DECISION_ID).object_type,
            MEDIATION_DECISION_OBJECT_TYPE,
        )

    def test_decision_carries_candidate_simulation_digests(self) -> None:
        _, _, _, _, decision = mediated_engine()
        evidence_refs = decision.envelope.provenance.evidence_refs
        self.assertEqual(len(evidence_refs), 2)
        self.assertNotEqual(evidence_refs[0], evidence_refs[1])
        for candidate in decision.spec.candidates:
            self.assertIn(candidate.simulation_result_digest, evidence_refs)

    def test_decision_records_points_and_rationale(self) -> None:
        _, _, _, _, decision = mediated_engine()
        by_id = {
            candidate.proposal_id: candidate for candidate in decision.spec.candidates
        }
        self.assertEqual(by_id[BRAVO_ID].total_points, 6000)
        self.assertEqual(by_id[ALPHA_ID].total_points, 4000)
        self.assertTrue(decision.spec.rationale)
        self.assertFalse(decision.spec.tie_break_applied)
        self.assertEqual(
            decision.spec.candidates[0].cost_minor, 9750
        )

    def test_decision_has_no_execution_authority(self) -> None:
        _, _, _, _, decision = mediated_engine()
        payload = decision.spec.to_dict()
        for forbidden in (
            "effect",
            "effect_intent",
            "execution",
            "authorize",
            "production",
        ):
            self.assertNotIn(forbidden, payload)
        self.assertNotIn("effect_request", payload)

    def test_mediate_requires_at_least_two_proposals(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha,),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=OPERATOR,
            )

    def test_mediate_rejects_unrecorded_proposals(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha, bravo),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=OPERATOR,
            )

    def test_mediate_rejects_tampered_proposals(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, make_proposal(BRAVO_ID, ECONOMY_FAMILY, context), seq="p2")
        # A forged replacement: validly sealed but different content than the
        # kernel-recorded bravo proposal (declared cost changed).
        bravo_forged = RouteProposal.build(
            proposal_id=BRAVO_ID,
            agent_principal=context.spec.agent_principal,
            mandate_id=context.spec.mandate_id,
            route_family=ECONOMY_FAMILY,
            rail="rail/economy",
            declared_cost_minor=1,
            declared_cost_scale=2,
            declared_cost_asset="asset/usd",
            declared_latency_ms=480,
            declared_reliability_bps=9650,
            context=context,
            model_outputs=make_proposal(BRAVO_ID, ECONOMY_FAMILY, context).spec.model_outputs,
            as_of=T_PROPOSE,
        )
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha, bravo_forged),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=OPERATOR,
            )

    def test_mediate_rejects_proposals_from_different_contexts(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        other = build_agent_context(
            registry=engine.registry,
            mandates=engine.mandates,
            context_id="agent/route-advisor-2",
            agent_principal=AGENT,
            mandate_id=MANDATE_ID,
            model_ids=(COST_MODEL_ID, RELIABILITY_MODEL_ID),
            allowed_modes=(EnvironmentMode.SIMULATION,),
            as_of=T_MANDATE,
        )
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, other)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha, bravo),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=OPERATOR,
            )

    def test_mediate_requires_a_typed_context(self) -> None:
        engine = prepared_engine()
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context="not-a-context",  # type: ignore[arg-type]
                proposals=(),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=OPERATOR,
            )

    def test_mediation_without_simulation_mode_context_fails_at_recording(self) -> None:
        engine = prepared_engine()
        context = build_agent_context(
            registry=engine.registry,
            mandates=engine.mandates,
            context_id=CONTEXT_ID,
            agent_principal=AGENT,
            mandate_id=MANDATE_ID,
            model_ids=(COST_MODEL_ID, RELIABILITY_MODEL_ID),
            allowed_modes=(EnvironmentMode.FORECAST,),
            as_of=T_MANDATE,
        )
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        result = submit_proposal(engine, alpha, seq="p1")
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertIn("simulation", (result.detail or "").lower())

    def test_mediate_requires_active_mandate(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha, bravo),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_EXPIRED,
                actor=OPERATOR,
            )

    def test_mediate_by_proposing_agent_is_rejected(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        mediator = MediationEngine(engine=engine, policy=make_policy())
        with self.assertRaises(CoreValidationError):
            mediator.mediate(
                context=context,
                proposals=(alpha, bravo),
                world=make_world(),
                mediation_id=MEDIATION_ID,
                decision_id=DECISION_ID,
                as_of=T_MEDIATE,
                actor=AGENT,
            )

    def test_mediate_is_deterministic(self) -> None:
        first = mediated_engine()[4]
        second = mediated_engine()[4]
        self.assertEqual(first, second)
        self.assertEqual(first.spec.policy_digest, second.spec.policy_digest)
        self.assertEqual(first.integrity_hash, second.integrity_hash)

    def test_policy_weights_change_the_selection(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        mediator = MediationEngine(
            engine=engine,
            policy=make_policy(
                cost_weight_bps=1000, latency_weight_bps=1000, reliability_weight_bps=8000
            ),
        )
        decision = mediator.mediate(
            context=context,
            proposals=(alpha, bravo),
            world=make_world(),
            mediation_id=MEDIATION_ID,
            decision_id=DECISION_ID,
            as_of=T_MEDIATE,
            actor=OPERATOR,
        )
        self.assertEqual(decision.spec.selected_proposal_id, ALPHA_ID)

    def test_fabricated_decision_is_rejected_by_the_kernel(self) -> None:
        from src.agents.mediation import CandidateOutcome, DecisionSpec

        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        # A validly SEALED but fabricated decision: the recorded
        # proposals exist and the mandate is active, yet the points and
        # the selection are not the deterministic policy output. Only
        # the kernel handler's re-derivation gate can catch this — the
        # seal is intact and every reference is real.
        candidates = (
            CandidateOutcome(
                proposal_id=ALPHA_ID,
                agent_principal=AGENT,
                route_family=PREMIUM_FAMILY,
                environment_id=ENV,
                transition_digest="c" * 64,
                simulation_result_digest="d" * 64,
                cost_minor=9750,
                latency_ms=120,
                reliability_bps=9980,
                cost_points=10000,
                latency_points=10000,
                reliability_points=10000,
                total_points=30000,
            ),
            CandidateOutcome(
                proposal_id=BRAVO_ID,
                agent_principal=AGENT,
                route_family=ECONOMY_FAMILY,
                environment_id=ENV,
                transition_digest="e" * 64,
                simulation_result_digest="f" * 64,
                cost_minor=6400,
                latency_ms=480,
                reliability_bps=9650,
                cost_points=0,
                latency_points=0,
                reliability_points=0,
                total_points=0,
            ),
        )
        spec = DecisionSpec(
            decision_id=DECISION_ID,
            mediation_id=MEDIATION_ID,
            as_of=T_MEDIATE,
            context_id=CONTEXT_ID,
            mandate_id=MANDATE_ID,
            agent_principal=AGENT,
            selected_proposal_id=ALPHA_ID,
            candidates=candidates,
            rationale=(
                "fabricated: claims the loser with inflated points that the "
                "deterministic policy never produced"
            ),
            tie_break_applied=False,
            policy=make_policy(),
        )
        decision = MediationDecision.build(
            environment_id=ENV, domain_id=DOMAIN, spec=spec, actor=OPERATOR
        )
        result = engine.process(
            command(
                "fabricate-1",
                "mediation/select",
                OPERATOR,
                DECISION_ID,
                {"decision": decision.to_dict()},
                T_MEDIATE,
            )
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.POLICY_REJECTED)
        self.assertIn("deterministic policy", (result.detail or ""))
        self.assertIsNone(engine.get_decision(DECISION_ID))

    def test_mediation_decision_round_trip(self) -> None:
        _, _, _, _, decision = mediated_engine()
        decoded = MediationDecision.from_dict(decision.to_dict())
        self.assertEqual(decoded, decision)

    def test_tampered_decision_fails_closed(self) -> None:
        _, _, _, _, decision = mediated_engine()
        value = decision.to_dict()
        value["payload"]["selected_proposal_id"] = ALPHA_ID
        with self.assertRaises(CoreValidationError):
            MediationDecision.from_dict(value)

    def test_mediation_decision_id_round_trip_v2(self) -> None:
        engine = prepared_engine()
        context = make_context(engine)
        alpha = make_proposal(ALPHA_ID, PREMIUM_FAMILY, context)
        bravo = make_proposal(BRAVO_ID, ECONOMY_FAMILY, context)
        submit_proposal(engine, alpha, seq="p1")
        submit_proposal(engine, bravo, seq="p2")
        mediator = MediationEngine(engine=engine, policy=make_policy())
        first = mediator.mediate(
            context=context,
            proposals=(alpha, bravo),
            world=make_world(),
            mediation_id=MEDIATION_ID,
            decision_id=DECISION_ID,
            as_of=T_MEDIATE,
            actor=OPERATOR,
        )
        second = mediator.mediate(
            context=context,
            proposals=(alpha, bravo),
            world=make_world(),
            mediation_id="mediation/session-2",
            decision_id="mediation-decision/decision-2",
            as_of=T_MEDIATE,
            actor=OPERATOR,
        )
        self.assertNotEqual(first.spec.decision_id, second.spec.decision_id)
        self.assertEqual(
            first.spec.selected_proposal_id, second.spec.selected_proposal_id
        )


# ---------------------------------------------------------------------------
# 11. Scale sanity (deterministic ranking at realistic sizes)
# ---------------------------------------------------------------------------


class ScaleTests(unittest.TestCase):
    """Deterministic behavior on realistic candidate/model sets."""

    def test_policy_evaluation_on_realistic_candidate_set(self) -> None:
        policy = make_policy()
        candidates = tuple(
            outcome(
                f"agent-proposal/candidate-{index:02d}",
                cost_minor=5000 + 100 * index,
                latency_ms=900 - 50 * index,
                reliability_bps=9000 + 10 * index,
            )
            for index in range(8)
        )
        first = policy.evaluate(candidates)
        second = policy.evaluate(candidates)
        self.assertEqual(
            first.selected_proposal_id, second.selected_proposal_id
        )
        self.assertEqual(
            [candidate.proposal_id for candidate in first.ranked],
            [candidate.proposal_id for candidate in second.ranked],
        )
        best = [c for c in first.ranked if c.proposal_id == first.selected_proposal_id][0]
        self.assertEqual(best.total_points, max(c.total_points for c in first.ranked))

    def test_registry_lookup_over_many_models(self) -> None:
        engine = make_engine()
        for index in range(12):
            model_id = f"model/bulk-model-{index:02d}"
            full_model_lifecycle(engine, model_id)
        for index in range(12):
            record = engine.registry.require_deployed(
                f"model/bulk-model-{index:02d}"
            )
            self.assertEqual(record.state, ModelLifecycleState.DEPLOYED)
        self.assertEqual(len(engine.registry.models()), 12)

    def test_many_models_state_digest_is_deterministic(self) -> None:
        def build() -> str:
            engine = make_engine()
            for index in range(6):
                full_model_lifecycle(engine, f"model/bulk-model-{index:02d}")
            return engine.registry.state_digest()

        self.assertEqual(build(), build())


# ---------------------------------------------------------------------------
# 12. Dogfooding conformance
# ---------------------------------------------------------------------------


class DogfoodingConformanceTests(unittest.TestCase):
    """The WORK-021 experiment: two routes, both simulated, policy selects,
    bypass attempts fail closed and are recorded."""

    def test_dogfood_transcript_passes(self) -> None:
        from src.agents.dogfooding import build_transcript

        transcript, digest = build_transcript()
        self.assertIn("DOGFOOD-021: PASS", transcript)
        self.assertEqual(len(digest), 64)

    def test_dogfood_transcript_is_deterministic(self) -> None:
        from src.agents.dogfooding import build_transcript

        first, first_digest = build_transcript()
        second, second_digest = build_transcript()
        self.assertEqual(first, second)
        self.assertEqual(first_digest, second_digest)

    def test_dogfood_records_the_bypass_rejections(self) -> None:
        from src.agents.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("bypass.scope=REJECTED", transcript)
        self.assertIn("bypass.escalation=REJECTED", transcript)

    def test_dogfood_selects_the_policy_winner(self) -> None:
        from src.agents.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("selected=agent-proposal/bravo-economy", transcript)


if __name__ == "__main__":
    unittest.main()
