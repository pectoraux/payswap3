"""Simulation-before-production decision mediation (WORK-021).

Mediation is the ONLY path from an agent proposal to a decision, and a
decision is never an execution:

* every candidate proposal is evaluated in a ``SIMULATION``-mode
  environment built through ``src.simulation``'s public contract
  (:class:`~src.simulation.runtime.EnvironmentRuntime` over ONE real
  :class:`~src.transition.TransitionEngine` — the shared
  :func:`route_evaluation_binding` registers exactly one command
  ``agent/simulate-route`` whose event ``simulation/route-simulated``
  uses the existing frozen ``simulation`` event namespace). The world
  supplies the simulated route metrics (cost, latency, reliability)
  under the frozen ``SIMULATED`` epistemic type; the environment's
  effect policy is the frozen ``SIMULATION`` policy, so evaluation
  environments record zero effects (constitution invariants 5 and 14);
* a deterministic :class:`MediationPolicy` with explicit basis-point
  weights, explicit rank points and a lexicographic tie-break then
  selects the winner. Unknown metrics, unknown policy fields, weight
  sums that are not exactly the basis-point total and candidate sets
  smaller than the frozen minimum all fail closed;
* the :class:`MediationDecision` is a sealed governance record
  (``mediation/select`` → ``governance/mediation-selected``). It
  carries the per-candidate simulated metrics, the simulation result
  digests, the policy, the points and the deterministic rationale —
  and nothing else: no effect intents, no execution authority, no
  production semantics. The kernel handler re-derives the complete
  policy evaluation from the carried candidates and policy and fails
  closed unless the decision is EXACTLY the deterministic policy
  output, so a fabricated decision cannot pass.

Agents never mediate: the mediation command requires a registry
governance-side authority class (enforced by the engine's authorization
binding), so the proposing agent cannot select its own proposal.

Determinism discipline: no clock reads, no entropy sources, no
generated identifiers — every instant is explicit declared ``as_of``
data and every digest is canonical.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import (
    AuthorizationDecision,
    Command,
    Outcome,
    TransitionApplication,
    payload_to_json_value,
)
from src.simulation import (
    CommandRegistration,
    EnvironmentMode,
    EnvironmentRuntime,
    EnvironmentSpec,
    ProtocolBinding,
    SimulationRunState,
    WorldAdapter,
)

from .contracts import (
    MEDIATION_DECISION_ID_PREFIX,
    MEDIATION_DECISION_OBJECT_TYPE,
    MEDIATION_MIN_CANDIDATES,
    MEDIATION_REQUIRED_MODE,
    MEDIATION_WEIGHT_TOTAL_BPS,
    PROPOSAL_ID_PREFIX,
    RELIABILITY_BPS_MAX,
    RELIABILITY_BPS_MIN,
    ROUTE_EVALUATION_BINDING_ID,
    ROUTE_EVALUATION_COMMAND_TYPE,
    ROUTE_EVALUATION_EVENT_TYPE,
    ROUTE_EVALUATION_ID_PREFIX,
    ROUTE_EVALUATION_OBJECT_TYPE,
    AGENTS_NAMESPACE_RULES,
    AGENTS_PROTOCOL_VERSION,
    AGENTS_SCHEMA_VERSION,
    require_agents_identifier,
)
from ._validation import (
    parse_enum,
    require_bool,
    require_digest,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
    utc_timestamp_within,
)
from .context import AgentContext
from .mandates import MandateBook
from .proposals import ProposalBook, RouteProposal
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

#: The fixed internal principal that owns the route-evaluation
#: substrate: every candidate evaluation command is submitted by this
#: principal under a registry governance class, never by the proposing
#: agent (mediation is not self-service).
ROUTE_EVALUATION_OPERATOR = "principal/agents-mediation-operator"

#: Fixed authority class of the route-evaluation substrate binding.
_ROUTE_EVALUATION_AUTHORITY_CLASS = "A2"

_METRIC_KEYS = (
    "cost-minor",
    "latency-ms",
    "reliability-bps",
)

_METRIC_FIELDS = (
    "cost_minor",
    "latency_ms",
    "reliability_bps",
)

_METRIC_KEY_BY_FIELD = dict(zip(_METRIC_FIELDS, _METRIC_KEYS))

_EVALUATION_COMMAND_FIELDS = frozenset({"proposal_id", "route_family"})

_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "policy_version",
        "cost_weight_bps",
        "latency_weight_bps",
        "reliability_weight_bps",
    }
)

_OUTCOME_FIELDS = frozenset(
    {
        "proposal_id",
        "agent_principal",
        "route_family",
        "environment_id",
        "transition_digest",
        "simulation_result_digest",
        "cost_minor",
        "latency_ms",
        "reliability_bps",
    }
)

_CANDIDATE_FIELDS = _OUTCOME_FIELDS | frozenset(
    {
        "cost_points",
        "latency_points",
        "reliability_points",
        "total_points",
    }
)

_DECISION_SPEC_FIELDS = frozenset(
    {
        "decision_id",
        "mediation_id",
        "as_of",
        "context_id",
        "mandate_id",
        "agent_principal",
        "selected_proposal_id",
        "candidates",
        "rationale",
        "tie_break_applied",
        "policy",
    }
)

_SELECT_COMMAND_FIELDS = frozenset({"decision"})


class RouteEvaluationState(StrEnum):
    """Closed lifecycle vocabulary of one route evaluation (SIMULATED)."""

    SIMULATED = "SIMULATED"

    @classmethod
    def parse(cls, value: object) -> "RouteEvaluationState":
        return parse_enum("route evaluation state", value, cls)  # type: ignore[return-value]


class DecisionState(StrEnum):
    """Closed lifecycle vocabulary of one mediation decision (DECIDED)."""

    DECIDED = "DECIDED"

    @classmethod
    def parse(cls, value: object) -> "DecisionState":
        return parse_enum("decision state", value, cls)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# The route-evaluation substrate over src.simulation
# ---------------------------------------------------------------------------


def route_evaluation_binding() -> ProtocolBinding:
    """The shared protocol binding of every candidate route evaluation.

    One command registration: ``agent/simulate-route`` emits
    ``simulation/route-simulated`` (existing frozen ``simulation`` event
    namespace). The binding's business semantics are identical for
    every candidate and every environment — only the world differs.
    """
    return ProtocolBinding(
        binding_id=ROUTE_EVALUATION_BINDING_ID,
        protocol_version=AGENTS_PROTOCOL_VERSION,
        registrations=(
            CommandRegistration(
                command_type=ROUTE_EVALUATION_COMMAND_TYPE,
                event_type=ROUTE_EVALUATION_EVENT_TYPE,
                handler=_route_evaluation_handler,
            ),
        ),
        authorization=_route_evaluation_authorization,
    )


def _route_evaluation_authorization(command: Command, view) -> Any:
    if command.actor != ROUTE_EVALUATION_OPERATOR:
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                "route evaluation commands belong to the mediation substrate "
                f"operator {ROUTE_EVALUATION_OPERATOR!r}"
            ),
        )
    return AuthorizationDecision(
        granted=True,
        authority=_ROUTE_EVALUATION_AUTHORITY_CLASS,
        reason=None,
    )


def route_evaluation_id(proposal_id: str) -> str:
    """Deterministic evaluation object id of one candidate proposal."""
    require_agents_identifier("proposal_id", proposal_id, PROPOSAL_ID_PREFIX)
    return ROUTE_EVALUATION_ID_PREFIX + proposal_id[len(PROPOSAL_ID_PREFIX) :]


def _route_evaluation_handler(
    command: Command, view: Any, world: Any
) -> TransitionApplication:
    """Observe the three simulated route metrics and seal the evaluation.

    The metrics come EXCLUSIVELY from the environment's world view (the
    declared profile of the proposal is never trusted here): the world
    fails closed on unscripted observations, on wrong epistemic types
    and on instants other than the command's explicit ``requested_at``.
    """
    data = payload_to_json_value(command.payload)
    if not isinstance(data, Mapping):
        raise CoreValidationError("route evaluation payload must be an object")
    strict_fields("route evaluation command", data, _EVALUATION_COMMAND_FIELDS)
    proposal_id = data["proposal_id"]
    route_family = data["route_family"]
    require_agents_identifier("route evaluation proposal_id", proposal_id, PROPOSAL_ID_PREFIX)
    require_text("route evaluation route_family", route_family)
    evaluation_id = route_evaluation_id(proposal_id)
    if command.target_refs != (evaluation_id,):
        raise CoreValidationError(
            "route evaluation command must declare exactly its evaluation target"
        )
    observed: dict[str, int] = {}
    for field in _METRIC_FIELDS:
        key = f"route/{route_family}/{_METRIC_KEY_BY_FIELD[field]}"
        observation = world.observe(key, command.requested_at)
        value = observation.value
        maximum = (
            RELIABILITY_BPS_MAX
            if field == "reliability_bps"
            else None
        )
        observed[field] = require_int(
            f"route evaluation {field}", value, minimum=0, maximum=maximum
        )
    envelope = ObjectEnvelope(
        object_id=evaluation_id,
        object_type=ROUTE_EVALUATION_OBJECT_TYPE,
        object_version=1,
        environment_id=command.environment_id,
        domain_id=command.domain_id,
        schema_version=AGENTS_SCHEMA_VERSION,
        protocol_version=AGENTS_PROTOCOL_VERSION,
        state=RouteEvaluationState.SIMULATED.value,
        provenance=Provenance(
            issuer=command.actor,
            source="agents/agent-simulate-route",
            recorded_at=command.requested_at,
            evidence_refs=(proposal_id,),
        ),
        causation_id=command.command_id,
        correlation_id=command.correlation_id,
        previous_version=None,
    ).with_integrity_hash()
    payload = {
        "proposal_id": proposal_id,
        "route_family": route_family,
        **observed,
    }
    return TransitionApplication(
        resulting_envelopes=(envelope,),
        payload=payload,
    )


def simulate_candidate(
    *,
    proposal: RouteProposal,
    world: WorldAdapter,
    environment_id: str,
    domain_id: str,
    as_of: str,
    command_id: str,
) -> tuple[EnvironmentRuntime, "SimulatedOutcome", Any]:
    """Simulate one candidate proposal in a fresh SIMULATION environment.

    The candidate is evaluated through the real kernel inside a
    ``SIMULATION``-mode environment whose world adapter supplies the
    simulated route metrics; the run is completed and sealed, and the
    :class:`SimulatedOutcome` binds the metrics to the sealed
    simulation result digest. Zero effect records are produced
    (invariant 14): the frozen ``SIMULATION`` effect policy only
    records, and this evaluation submits no effect intents at all.
    """
    if not isinstance(proposal, RouteProposal):
        raise CoreValidationError("candidate simulation requires a RouteProposal")
    if not isinstance(world, WorldAdapter):
        raise CoreValidationError("candidate simulation requires a WorldAdapter")
    require_identifier("candidate environment_id", environment_id)
    require_identifier("candidate domain_id", domain_id)
    require_utc_timestamp("candidate as_of", as_of)
    require_identifier("candidate command_id", command_id)
    if MEDIATION_REQUIRED_MODE is not EnvironmentMode.SIMULATION:  # pragma: no cover
        raise CoreValidationError(
            "the mediation substrate mode must stay the frozen SIMULATION mode"
        )
    suffix = proposal.proposal_id[len(PROPOSAL_ID_PREFIX) :]
    runtime = EnvironmentRuntime(
        spec=EnvironmentSpec(
            environment_id=environment_id,
            mode=MEDIATION_REQUIRED_MODE,
            domain_id=domain_id,
            as_of=as_of,
            label=f"agents-route-evaluation/{suffix}",
        ),
        binding=route_evaluation_binding(),
        world=world,
        namespace_rules=AGENTS_NAMESPACE_RULES,
        simulation_id=f"agents-route-evaluation/{suffix}",
        provenance_issuer=ROUTE_EVALUATION_OPERATOR,
    )
    command = Command.build(
        command_id=command_id,
        command_type=ROUTE_EVALUATION_COMMAND_TYPE,
        actor=ROUTE_EVALUATION_OPERATOR,
        target_refs=(route_evaluation_id(proposal.proposal_id),),
        payload={
            "proposal_id": proposal.proposal_id,
            "route_family": proposal.spec.route_family,
        },
        environment_id=environment_id,
        domain_id=domain_id,
        idempotency_key=f"key/evaluate-{suffix}",
        nonce="1",
        requested_at=as_of,
    )
    transition = runtime.submit(command)
    if transition.outcome is not Outcome.ACCEPTED:
        raise CoreValidationError(
            "candidate route evaluation was not accepted: "
            f"{transition.reason.value if transition.reason else 'rejected'}"
        )
    result = runtime.complete(as_of)
    if result.envelope.state != SimulationRunState.COMPLETED.value:
        raise CoreValidationError(
            "candidate route evaluation did not complete cleanly"
        )
    metrics = payload_to_json_value(transition.result.payload)
    if not isinstance(metrics, Mapping):
        raise CoreValidationError("route evaluation payload must be an object")
    outcome = SimulatedOutcome(
        proposal_id=proposal.proposal_id,
        agent_principal=proposal.spec.agent_principal,
        route_family=proposal.spec.route_family,
        environment_id=environment_id,
        transition_digest=transition.transition_digest,
        simulation_result_digest=result.integrity_hash,
        cost_minor=metrics["cost_minor"],
        latency_ms=metrics["latency_ms"],
        reliability_bps=metrics["reliability_bps"],
    )
    return runtime, outcome, result


# ---------------------------------------------------------------------------
# Simulated outcomes and ranked candidates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SimulatedOutcome:
    """One candidate's simulated route metrics (SIMULATION-only evidence).

    The metrics are the world's simulated values, not the proposal's
    declared profile; ``simulation_result_digest`` binds them to the
    sealed simulation result and ``transition_digest`` to the kernel
    transition that produced them.
    """

    proposal_id: str
    agent_principal: str
    route_family: str
    environment_id: str
    transition_digest: str
    simulation_result_digest: str
    cost_minor: int
    latency_ms: int
    reliability_bps: int

    def __post_init__(self) -> None:
        require_agents_identifier(
            "simulated outcome proposal_id", self.proposal_id, PROPOSAL_ID_PREFIX
        )
        require_identifier("simulated outcome agent_principal", self.agent_principal)
        require_text("simulated outcome route_family", self.route_family)
        require_identifier("simulated outcome environment_id", self.environment_id)
        require_digest("simulated outcome transition_digest", self.transition_digest)
        require_digest(
            "simulated outcome simulation_result_digest", self.simulation_result_digest
        )
        require_int("simulated outcome cost_minor", self.cost_minor, minimum=0)
        require_int("simulated outcome latency_ms", self.latency_ms, minimum=0)
        require_int(
            "simulated outcome reliability_bps",
            self.reliability_bps,
            minimum=RELIABILITY_BPS_MIN,
            maximum=RELIABILITY_BPS_MAX,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "agent_principal": self.agent_principal,
            "route_family": self.route_family,
            "environment_id": self.environment_id,
            "transition_digest": self.transition_digest,
            "simulation_result_digest": self.simulation_result_digest,
            "cost_minor": self.cost_minor,
            "latency_ms": self.latency_ms,
            "reliability_bps": self.reliability_bps,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SimulatedOutcome":
        if not isinstance(value, Mapping):
            raise CoreValidationError("simulated outcome must be an object")
        strict_fields("simulated outcome", value, _OUTCOME_FIELDS)
        return cls(
            proposal_id=value["proposal_id"],
            agent_principal=value["agent_principal"],
            route_family=value["route_family"],
            environment_id=value["environment_id"],
            transition_digest=value["transition_digest"],
            simulation_result_digest=value["simulation_result_digest"],
            cost_minor=value["cost_minor"],
            latency_ms=value["latency_ms"],
            reliability_bps=value["reliability_bps"],
        )

    def as_candidate(self) -> "CandidateOutcome":
        """The unranked view of this outcome (zero points)."""
        return CandidateOutcome(
            proposal_id=self.proposal_id,
            agent_principal=self.agent_principal,
            route_family=self.route_family,
            environment_id=self.environment_id,
            transition_digest=self.transition_digest,
            simulation_result_digest=self.simulation_result_digest,
            cost_minor=self.cost_minor,
            latency_ms=self.latency_ms,
            reliability_bps=self.reliability_bps,
        )


@dataclass(frozen=True, slots=True)
class CandidateOutcome:
    """One ranked candidate: simulated metrics plus explicit points.

    ``cost_points``/``latency_points``/``reliability_points`` are the
    exact basis-point contributions of the three dimensions and
    ``total_points`` their sum; the points are rank points — the number
    of candidates this candidate beats in the dimension times the
    dimension's declared weight — so ties share points exactly and the
    arithmetic is fully reproducible by hand.
    """

    proposal_id: str
    agent_principal: str
    route_family: str
    environment_id: str
    transition_digest: str
    simulation_result_digest: str
    cost_minor: int
    latency_ms: int
    reliability_bps: int
    cost_points: int
    latency_points: int
    reliability_points: int
    total_points: int

    def __post_init__(self) -> None:
        # Re-validate the metric surface through the SimulatedOutcome
        # contract (ids, digests, bounds) before accepting the points.
        SimulatedOutcome(
            proposal_id=self.proposal_id,
            agent_principal=self.agent_principal,
            route_family=self.route_family,
            environment_id=self.environment_id,
            transition_digest=self.transition_digest,
            simulation_result_digest=self.simulation_result_digest,
            cost_minor=self.cost_minor,
            latency_ms=self.latency_ms,
            reliability_bps=self.reliability_bps,
        )
        for name in (
            "cost_points",
            "latency_points",
            "reliability_points",
            "total_points",
        ):
            require_int(f"candidate {name}", getattr(self, name), minimum=0)
        if (
            self.cost_points + self.latency_points + self.reliability_points
            != self.total_points
        ):
            raise CoreValidationError(
                "candidate total_points must be the exact sum of the "
                "dimension points"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "agent_principal": self.agent_principal,
            "route_family": self.route_family,
            "environment_id": self.environment_id,
            "transition_digest": self.transition_digest,
            "simulation_result_digest": self.simulation_result_digest,
            "cost_minor": self.cost_minor,
            "latency_ms": self.latency_ms,
            "reliability_bps": self.reliability_bps,
            "cost_points": self.cost_points,
            "latency_points": self.latency_points,
            "reliability_points": self.reliability_points,
            "total_points": self.total_points,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateOutcome":
        if not isinstance(value, Mapping):
            raise CoreValidationError("candidate outcome must be an object")
        strict_fields("candidate outcome", value, _CANDIDATE_FIELDS)
        return cls(
            proposal_id=value["proposal_id"],
            agent_principal=value["agent_principal"],
            route_family=value["route_family"],
            environment_id=value["environment_id"],
            transition_digest=value["transition_digest"],
            simulation_result_digest=value["simulation_result_digest"],
            cost_minor=value["cost_minor"],
            latency_ms=value["latency_ms"],
            reliability_bps=value["reliability_bps"],
            cost_points=value["cost_points"],
            latency_points=value["latency_points"],
            reliability_points=value["reliability_points"],
            total_points=value["total_points"],
        )

    def as_outcome(self) -> SimulatedOutcome:
        """The metric-only view used to re-derive the policy evaluation."""
        return SimulatedOutcome(
            proposal_id=self.proposal_id,
            agent_principal=self.agent_principal,
            route_family=self.route_family,
            environment_id=self.environment_id,
            transition_digest=self.transition_digest,
            simulation_result_digest=self.simulation_result_digest,
            cost_minor=self.cost_minor,
            latency_ms=self.latency_ms,
            reliability_bps=self.reliability_bps,
        )


# ---------------------------------------------------------------------------
# The deterministic mediation policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MediationPolicy:
    """The deterministic policy: explicit weights, rank points, tie-break.

    Every weight is a positive exact basis-point value and the three
    weights must sum to exactly the frozen basis-point total. Points
    are rank points (see :class:`CandidateOutcome`); the selection is
    maximum total points with a lexicographic smallest-proposal-id
    tie-break. The policy is declared data: it is sealed into every
    decision it produces.
    """

    policy_id: str
    policy_version: int
    cost_weight_bps: int
    latency_weight_bps: int
    reliability_weight_bps: int

    def __post_init__(self) -> None:
        require_identifier("policy_id", self.policy_id)
        require_int("policy_version", self.policy_version, minimum=1)
        for name in (
            "cost_weight_bps",
            "latency_weight_bps",
            "reliability_weight_bps",
        ):
            require_int(f"policy {name}", getattr(self, name), minimum=1)
        total = (
            self.cost_weight_bps
            + self.latency_weight_bps
            + self.reliability_weight_bps
        )
        if total != MEDIATION_WEIGHT_TOTAL_BPS:
            raise CoreValidationError(
                "mediation policy weights must sum to exactly "
                f"{MEDIATION_WEIGHT_TOTAL_BPS} basis points, got {total}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AGENTS_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "cost_weight_bps": self.cost_weight_bps,
            "latency_weight_bps": self.latency_weight_bps,
            "reliability_weight_bps": self.reliability_weight_bps,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MediationPolicy":
        if not isinstance(value, Mapping):
            raise CoreValidationError("mediation policy must be an object")
        strict_fields("mediation policy", value, _POLICY_FIELDS)
        if value["schema_version"] != AGENTS_SCHEMA_VERSION:
            raise CoreValidationError(
                "mediation policy schema_version must be "
                f"{AGENTS_SCHEMA_VERSION}"
            )
        return cls(
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            cost_weight_bps=value["cost_weight_bps"],
            latency_weight_bps=value["latency_weight_bps"],
            reliability_weight_bps=value["reliability_weight_bps"],
        )

    @property
    def digest(self) -> str:
        """Canonical digest of the sealed policy declaration."""
        return canonical_sha256(self.to_dict())

    def evaluate(
        self, outcomes: Iterable[SimulatedOutcome]
    ) -> "PolicyEvaluation":
        """Rank the simulated candidates and select the winner."""
        candidates = tuple(outcomes)
        if len(candidates) < MEDIATION_MIN_CANDIDATES:
            raise CoreValidationError(
                "mediation requires at least "
                f"{MEDIATION_MIN_CANDIDATES} simulated candidates; a "
                "decision without a compared alternative fails closed"
            )
        seen: set[str] = set()
        outcomes = tuple(
            candidate.as_outcome() if isinstance(candidate, CandidateOutcome) else candidate
            for candidate in candidates
        )
        for candidate in outcomes:
            if not isinstance(candidate, SimulatedOutcome):
                raise CoreValidationError(
                    "mediation candidates must be SimulatedOutcome records"
                )
            if candidate.proposal_id in seen:
                raise CoreValidationError(
                    "mediation candidates must have distinct proposal ids; "
                    f"{candidate.proposal_id!r} appears twice"
                )
            seen.add(candidate.proposal_id)
        points: dict[str, dict[str, int]] = {}
        for candidate in outcomes:
            beaten_cost = sum(
                1
                for other in outcomes
                if other.cost_minor > candidate.cost_minor
            )
            beaten_latency = sum(
                1
                for other in outcomes
                if other.latency_ms > candidate.latency_ms
            )
            beaten_reliability = sum(
                1
                for other in outcomes
                if other.reliability_bps < candidate.reliability_bps
            )
            points[candidate.proposal_id] = {
                "cost_points": beaten_cost * self.cost_weight_bps,
                "latency_points": beaten_latency * self.latency_weight_bps,
                "reliability_points": beaten_reliability
                * self.reliability_weight_bps,
            }
        ranked = tuple(
            CandidateOutcome(
                proposal_id=candidate.proposal_id,
                agent_principal=candidate.agent_principal,
                route_family=candidate.route_family,
                environment_id=candidate.environment_id,
                transition_digest=candidate.transition_digest,
                simulation_result_digest=candidate.simulation_result_digest,
                cost_minor=candidate.cost_minor,
                latency_ms=candidate.latency_ms,
                reliability_bps=candidate.reliability_bps,
                cost_points=points[candidate.proposal_id]["cost_points"],
                latency_points=points[candidate.proposal_id]["latency_points"],
                reliability_points=points[candidate.proposal_id][
                    "reliability_points"
                ],
                total_points=sum(points[candidate.proposal_id].values()),
            )
            for candidate in outcomes
        )
        ranked = tuple(sorted(ranked, key=lambda item: (-item.total_points, item.proposal_id)))
        best = ranked[0]
        tie_break_applied = (
            sum(1 for item in ranked if item.total_points == best.total_points) > 1
        )
        rationale = (
            f"deterministic mediation policy {self.policy_id} version "
            f"{self.policy_version} ranked {len(ranked)} simulated candidates "
            f"with weights cost={self.cost_weight_bps}bps "
            f"latency={self.latency_weight_bps}bps "
            f"reliability={self.reliability_weight_bps}bps; selected "
            f"{best.proposal_id} at {best.total_points} points; tie-break "
            + ("applied" if tie_break_applied else "not-applied")
        )
        return PolicyEvaluation(
            ranked=ranked,
            selected_proposal_id=best.proposal_id,
            tie_break_applied=tie_break_applied,
            rationale=rationale,
        )


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """The deterministic result of one policy evaluation."""

    ranked: tuple[CandidateOutcome, ...]
    selected_proposal_id: str
    tie_break_applied: bool
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.ranked, tuple) or not self.ranked:
            raise CoreValidationError("policy evaluation ranking must be non-empty")
        for candidate in self.ranked:
            if not isinstance(candidate, CandidateOutcome):
                raise CoreValidationError(
                    "policy evaluation ranking must contain CandidateOutcome records"
                )
        require_agents_identifier(
            "selected proposal_id", self.selected_proposal_id, PROPOSAL_ID_PREFIX
        )
        require_bool("tie_break_applied", self.tie_break_applied)
        require_text("rationale", self.rationale)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ranked": [candidate.to_dict() for candidate in self.ranked],
            "selected_proposal_id": self.selected_proposal_id,
            "tie_break_applied": self.tie_break_applied,
            "rationale": self.rationale,
        }


# ---------------------------------------------------------------------------
# The sealed mediation decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DecisionSpec:
    """Immutable mediation decision payload.

    A decision carries the simulated candidate metrics, the points, the
    deterministic policy, the rationale and the selected proposal —
    and nothing else. It is a decision record, never an instruction to
    act: it holds no capability to move value, reserve, execute or
    authorize anything (constitution invariant 5).
    """

    decision_id: str
    mediation_id: str
    as_of: str
    context_id: str
    mandate_id: str
    agent_principal: str
    selected_proposal_id: str
    candidates: tuple[CandidateOutcome, ...]
    rationale: str
    tie_break_applied: bool
    policy: MediationPolicy

    def __post_init__(self) -> None:
        require_agents_identifier(
            "decision decision_id", self.decision_id, MEDIATION_DECISION_ID_PREFIX
        )
        require_identifier("decision mediation_id", self.mediation_id)
        require_utc_timestamp("decision as_of", self.as_of)
        require_identifier("decision context_id", self.context_id)
        require_agents_identifier(
            "decision mandate_id", self.mandate_id, "agent-mandate/"
        )
        require_identifier("decision agent_principal", self.agent_principal)
        require_agents_identifier(
            "decision selected_proposal_id",
            self.selected_proposal_id,
            PROPOSAL_ID_PREFIX,
        )
        if not isinstance(self.candidates, tuple) or not self.candidates:
            raise CoreValidationError(
                "decision candidates must be a non-empty tuple of CandidateOutcome"
            )
        for candidate in self.candidates:
            if not isinstance(candidate, CandidateOutcome):
                raise CoreValidationError(
                    "decision candidates must be CandidateOutcome records"
                )
        if len({candidate.proposal_id for candidate in self.candidates}) != len(
            self.candidates
        ):
            raise CoreValidationError("decision candidates must be distinct")
        require_text("decision rationale", self.rationale)
        require_bool("decision tie_break_applied", self.tie_break_applied)
        if not isinstance(self.policy, MediationPolicy):
            raise CoreValidationError("decision policy must be a MediationPolicy")

    @property
    def policy_digest(self) -> str:
        return self.policy.digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "mediation_id": self.mediation_id,
            "as_of": self.as_of,
            "context_id": self.context_id,
            "mandate_id": self.mandate_id,
            "agent_principal": self.agent_principal,
            "selected_proposal_id": self.selected_proposal_id,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "rationale": self.rationale,
            "tie_break_applied": self.tie_break_applied,
            "policy": self.policy.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecisionSpec":
        if not isinstance(value, Mapping):
            raise CoreValidationError("decision spec must be an object")
        strict_fields("decision spec", value, _DECISION_SPEC_FIELDS)
        candidates_raw = value["candidates"]
        if not isinstance(candidates_raw, list):
            raise CoreValidationError("decision candidates must deserialize from an array")
        return cls(
            decision_id=value["decision_id"],
            mediation_id=value["mediation_id"],
            as_of=value["as_of"],
            context_id=value["context_id"],
            mandate_id=value["mandate_id"],
            agent_principal=value["agent_principal"],
            selected_proposal_id=value["selected_proposal_id"],
            candidates=tuple(
                CandidateOutcome.from_dict(item) for item in candidates_raw
            ),
            rationale=value["rationale"],
            tie_break_applied=value["tie_break_applied"],
            policy=MediationPolicy.from_dict(value["policy"]),
        )


@dataclass(frozen=True, slots=True)
class MediationDecision:
    """Durable mediation decision record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: DecisionSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = MEDIATION_DECISION_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("decision envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, DecisionSpec):
            raise CoreValidationError("decision spec must be a DecisionSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != MEDIATION_DECISION_OBJECT_TYPE:
            raise CoreValidationError(
                f"decision object_type must be {MEDIATION_DECISION_OBJECT_TYPE!r}"
            )
        try:
            DecisionState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown decision state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.decision_id:
            raise CoreValidationError(
                "decision identity mismatch: envelope and spec must name the "
                "same decision"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.spec.decision_id
        )

    @property
    def decision_id(self) -> str:
        return self.spec.decision_id

    @property
    def state(self) -> str:
        return self.envelope.state

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MediationDecision":
        if not isinstance(value, Mapping):
            raise CoreValidationError("mediation decision must be an object")
        envelope, payload = decode_composite(
            value,
            expected_object_type=MEDIATION_DECISION_OBJECT_TYPE,
            state_type=DecisionState,
        )
        spec = DecisionSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "MediationDecision":
        if not isinstance(value, str):
            raise CoreValidationError("mediation decision JSON must be a string")
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=MEDIATION_DECISION_OBJECT_TYPE,
            state_type=DecisionState,
        )
        spec = DecisionSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    @classmethod
    def build(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        spec: DecisionSpec,
        actor: str,
    ) -> "MediationDecision":
        """Seal one decision record bound to the kernel-recorded evidence."""
        require_identifier("decision actor", actor)
        evidence_refs = tuple(
            candidate.simulation_result_digest for candidate in spec.candidates
        )
        envelope = build_domain_envelope(
            object_id=spec.decision_id,
            object_type=MEDIATION_DECISION_OBJECT_TYPE,
            state=DecisionState.DECIDED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=Provenance(
                issuer=actor,
                source="agents/mediation-select",
                recorded_at=spec.as_of,
                evidence_refs=evidence_refs,
            ),
        )
        return cls(
            envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
        )


# ---------------------------------------------------------------------------
# The decision book (kernel-mediated decision recording)
# ---------------------------------------------------------------------------


class DecisionBook:
    """Typed decision store applying ``mediation/select`` commands.

    The semantic gates run at the kernel's policy stage: the decision
    must be the EXACT deterministic policy output over its carried
    simulated candidates, every candidate must be a kernel-recorded
    proposal, the mandate must be active at the decision instant, and
    the decision id must be fresh. The handler re-validates everything
    and persists the sealed record.
    """

    def __init__(
        self,
        *,
        mandates: MandateBook,
        proposals: ProposalBook,
        environment_id: str,
        domain_id: str,
    ) -> None:
        if not isinstance(mandates, MandateBook):
            raise CoreValidationError("decision book requires a MandateBook")
        if not isinstance(proposals, ProposalBook):
            raise CoreValidationError("decision book requires a ProposalBook")
        require_identifier("decision book environment_id", environment_id)
        require_identifier("decision book domain_id", domain_id)
        self._mandates = mandates
        self._proposals = proposals
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._decisions: dict[str, MediationDecision] = {}

    # -- read-only surface --------------------------------------------------

    def get(self, decision_id: str) -> MediationDecision | None:
        require_agents_identifier(
            "decision_id", decision_id, MEDIATION_DECISION_ID_PREFIX
        )
        return self._decisions.get(decision_id)

    def require_decision(self, decision_id: str) -> MediationDecision:
        decision = self.get(decision_id)
        if decision is None:
            raise CoreValidationError(
                f"unknown mediation decision {decision_id!r}: the domain fails "
                "closed on unknown decision identity"
            )
        return decision

    def decisions(self) -> tuple[MediationDecision, ...]:
        return tuple(
            self._decisions[decision_id] for decision_id in sorted(self._decisions)
        )

    def state_digest(self) -> str:
        """Canonical digest of the recorded decision state."""
        return canonical_sha256(
            [decision.to_dict() for decision in self.decisions()]
        )

    # -- semantic gate + transition handler -----------------------------------

    def evaluate_command(self, command: Command) -> str | None:
        if command.command_type != "mediation/select":
            raise CoreValidationError(
                f"decision book received command {command.command_type!r}"
            )
        try:
            self._parse_and_check(command)
        except CoreValidationError as exc:
            return f"mediation decision fails closed: {exc}"
        return None

    def apply_command(self, command: Command) -> TransitionApplication:
        decision = self._parse_and_check(command)
        self._decisions[decision.decision_id] = decision
        return TransitionApplication(
            resulting_envelopes=(decision.envelope,),
            payload=decision.spec.to_dict(),
        )

    # -- internals ---------------------------------------------------------------

    def _parse_and_check(self, command: Command) -> MediationDecision:
        data = payload_to_json_value(command.payload)
        if not isinstance(data, Mapping):
            raise CoreValidationError("mediation command payload must be an object")
        strict_fields("mediation command", data, _SELECT_COMMAND_FIELDS)
        decision_value = data["decision"]
        if not isinstance(decision_value, Mapping):
            raise CoreValidationError("mediation payload must carry the decision")
        decision = MediationDecision.from_dict(decision_value)
        if command.target_refs != (decision.decision_id,):
            raise CoreValidationError(
                "mediation command must declare exactly its decision target"
            )
        if decision.decision_id in self._decisions:
            raise CoreValidationError(
                f"mediation decision {decision.decision_id!r} is already recorded"
            )
        spec = decision.spec
        if len(spec.candidates) < MEDIATION_MIN_CANDIDATES:
            raise CoreValidationError(
                "a mediation decision requires at least "
                f"{MEDIATION_MIN_CANDIDATES} compared candidates"
            )
        mandate = self._mandates.require_mandate(spec.mandate_id)
        if mandate.spec.agent_principal != spec.agent_principal:
            raise CoreValidationError(
                "decision agent must match the principal the mandate is bound to"
            )
        if not utc_timestamp_within(
            spec.as_of, mandate.spec.not_before, mandate.spec.not_after
        ):
            raise CoreValidationError(
                f"proposal mandate {spec.mandate_id!r} is not active at "
                f"{spec.as_of}: mediation requires an active mandate"
            )
        for candidate in spec.candidates:
            recorded = self._proposals.require_proposal(candidate.proposal_id)
            if recorded.spec.context.context_id != spec.context_id:
                raise CoreValidationError(
                    "decision candidate proposals must share the decision "
                    "context"
                )
        evaluation = spec.policy.evaluate(
            tuple(candidate.as_outcome() for candidate in spec.candidates)
        )
        if evaluation.selected_proposal_id != spec.selected_proposal_id:
            raise CoreValidationError(
                "decision selection does not match the deterministic policy "
                "output over its own candidates"
            )
        if evaluation.tie_break_applied != spec.tie_break_applied:
            raise CoreValidationError(
                "decision tie-break flag does not match the deterministic "
                "policy output"
            )
        if evaluation.rationale != spec.rationale:
            raise CoreValidationError(
                "decision rationale does not match the deterministic policy "
                "output"
            )
        by_id = {
            candidate.proposal_id: candidate for candidate in evaluation.ranked
        }
        for candidate in spec.candidates:
            expected = by_id[candidate.proposal_id]
            for field in (
                "cost_points",
                "latency_points",
                "reliability_points",
                "total_points",
            ):
                if getattr(candidate, field) != getattr(expected, field):
                    raise CoreValidationError(
                        f"decision candidate {candidate.proposal_id!r} "
                        f"{field} does not match the deterministic policy output"
                    )
        return decision


# ---------------------------------------------------------------------------
# The mediation engine
# ---------------------------------------------------------------------------


class MediationEngine:
    """Simulation-first mediation: proposals → simulations → policy → decision.

    The engine composes the whole frozen promotion prefix of
    ``simulation.md`` — ``simulation → … → production decision`` stops
    at the decision: nothing here authorizes or executes anything. The
    mediation flow is:

    1. fail-closed validation of the context, the candidate proposals
       (kernel-recorded, tamper-free, one shared context) and the
       active mandate at the explicit ``as_of``;
    2. EVERY candidate is simulated in its own fresh ``SIMULATION``
       environment through ``src.simulation``'s public contract;
    3. the deterministic policy selects the winner (explicit weights,
       rank points, lexicographic tie-break);
    4. the sealed decision is recorded through the REAL kernel via the
       ``mediation/select`` command, whose handler re-derives the full
       policy evaluation and fails closed on any mismatch.

    Mediation by the proposing agent is impossible: the kernel binding
    requires a governance-side authority class for ``mediation/select``.
    """

    def __init__(self, *, engine: Any, policy: MediationPolicy) -> None:
        from .engine import AgentsEngine

        if not isinstance(engine, AgentsEngine):
            raise CoreValidationError("mediation requires an AgentsEngine")
        if not isinstance(policy, MediationPolicy):
            raise CoreValidationError("mediation requires a MediationPolicy")
        self._engine = engine
        self._policy = policy

    @property
    def policy(self) -> MediationPolicy:
        return self._policy

    def mediate(
        self,
        *,
        context: AgentContext,
        proposals: Iterable[RouteProposal],
        world: WorldAdapter,
        mediation_id: str,
        decision_id: str,
        as_of: str,
        actor: str,
    ) -> MediationDecision:
        """Mediate one candidate set and record the decision."""
        if not isinstance(context, AgentContext):
            raise CoreValidationError(
                "mediation requires a typed AgentContext: untyped contexts "
                "fail closed"
            )
        if not isinstance(world, WorldAdapter):
            raise CoreValidationError("mediation requires a WorldAdapter")
        require_identifier("mediation_id", mediation_id)
        require_agents_identifier(
            "decision_id", decision_id, MEDIATION_DECISION_ID_PREFIX
        )
        require_utc_timestamp("mediation as_of", as_of)
        require_identifier("mediation actor", actor)
        candidate_proposals = tuple(proposals)
        if len(candidate_proposals) < MEDIATION_MIN_CANDIDATES:
            raise CoreValidationError(
                "mediation requires at least "
                f"{MEDIATION_MIN_CANDIDATES} candidate proposals"
            )
        for proposal in candidate_proposals:
            if not isinstance(proposal, RouteProposal):
                raise CoreValidationError(
                    "mediation candidates must be RouteProposal records"
                )
        ids = [proposal.proposal_id for proposal in candidate_proposals]
        if len(set(ids)) != len(ids):
            raise CoreValidationError("mediation candidates must be distinct")
        context_payload = context.to_dict()
        for proposal in candidate_proposals:
            if proposal.spec.context.to_dict() != context_payload:
                raise CoreValidationError(
                    f"proposal {proposal.proposal_id!r} was recorded under a "
                    "different agent context: mediation compares one context"
                )
            recorded = self._engine.get_proposal(proposal.proposal_id)
            if recorded is None:
                raise CoreValidationError(
                    f"proposal {proposal.proposal_id!r} is not kernel-recorded: "
                    "only recorded proposals enter mediation"
                )
            if recorded.digest != proposal.digest:
                raise CoreValidationError(
                    f"proposal {proposal.proposal_id!r} does not match the "
                    "kernel-recorded proposal digest: tampered or forged "
                    "proposals fail closed"
                )
        mandate = self._engine.mandates.require_mandate(context.spec.mandate_id)
        if mandate.spec.agent_principal != context.spec.agent_principal:
            raise CoreValidationError(
                "mediation context mandate is bound to a different agent"
            )
        if not utc_timestamp_within(
            as_of, mandate.spec.not_before, mandate.spec.not_after
        ):
            raise CoreValidationError(
                f"proposal mandate {context.spec.mandate_id!r} is not active "
                f"at {as_of}: mediation requires an active mandate"
            )
        outcomes = []
        for proposal in candidate_proposals:
            suffix = proposal.proposal_id[len(PROPOSAL_ID_PREFIX) :]
            _, outcome, _ = simulate_candidate(
                proposal=proposal,
                world=world,
                environment_id=(
                    "env/agents-mediation/" + mediation_id + "/" + suffix
                ),
                domain_id=self._engine.domain_id,
                as_of=as_of,
                command_id=f"cmd/evaluate-{suffix}",
            )
            outcomes.append(outcome)
        evaluation = self._policy.evaluate(tuple(outcomes))
        by_id = {
            candidate.proposal_id: candidate for candidate in evaluation.ranked
        }
        candidates = tuple(by_id[proposal.proposal_id] for proposal in candidate_proposals)
        spec = DecisionSpec(
            decision_id=decision_id,
            mediation_id=mediation_id,
            as_of=as_of,
            context_id=context.spec.context_id,
            mandate_id=context.spec.mandate_id,
            agent_principal=context.spec.agent_principal,
            selected_proposal_id=evaluation.selected_proposal_id,
            candidates=candidates,
            rationale=evaluation.rationale,
            tie_break_applied=evaluation.tie_break_applied,
            policy=self._policy,
        )
        decision = MediationDecision.build(
            environment_id=self._engine.environment_id,
            domain_id=self._engine.domain_id,
            spec=spec,
            actor=actor,
        )
        command = Command.build(
            command_id=f"cmd/mediate/{decision_id}",
            command_type="mediation/select",
            actor=actor,
            target_refs=(decision_id,),
            payload={"decision": decision.to_dict()},
            environment_id=self._engine.environment_id,
            domain_id=self._engine.domain_id,
            idempotency_key=f"key/mediate/{decision_id}",
            nonce="1",
            requested_at=as_of,
        )
        result = self._engine.process(command)
        if result.outcome is not Outcome.ACCEPTED:
            reason = result.reason.value if result.reason is not None else "rejected"
            raise CoreValidationError(
                f"mediation/select was rejected ({reason}): {result.detail}"
            )
        recorded = self._engine.get_decision(decision_id)
        if recorded is None or recorded != decision:
            raise CoreValidationError(
                "mediation decision was not recorded faithfully by the kernel"
            )
        return recorded
