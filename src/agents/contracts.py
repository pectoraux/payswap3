"""Frozen public-boundary contracts for the agents domain (WORK-021).

This package owns the frozen v0.1 ``Model`` command family
``Register/Validate/Approve/Deploy/Suspend/Resume/Retire`` (command-event
model), the agent-scoped bounded proposal mandates, agent contexts and
the deterministic simulation-before-production decision mediation.

Registry discipline (documented choices):

* the frozen protocol registry lists NO ``model`` or ``agent`` event
  namespace, so none is invented here. Two EXISTING frozen namespaces are
  consumed, chosen for their semantics:

  - ``governance`` — model lifecycle transitions and mediation decisions.
    The frozen ``Governance`` command family
    (``Propose/Simulate/Shadow/Approve/Stage/Activate/Deprecate/RetireVersion``)
    is the registry's approve/deploy/retire-shaped decision family, and
    both the model registry lifecycle and the deterministic mediation
    policy are governance-class decisions taken by governance-side
    principals. Their events therefore use ``governance/<name>``.

  - ``simulation`` — simulated proposal outcomes. Candidate route
    proposals are evaluated inside ``SIMULATION``-mode environments
    (``simulation.md`` "Promotion":
    ``simulation → evidence → production decision → ...``), so their
    evaluation events use ``simulation/<name>`` exactly like every other
    environment event.

* command types are internal free-form strings following the sibling
  precedent (``integration/<family>.<verb>`` in WORK-026): ``model/register``,
  ``model/approve``, ``agent/propose``, ``mediation/select`` and so on.

* no ``payswap/model/v1`` object type exists in the registry, so every
  agents-domain object type uses the internal non-registry
  ``agents/...`` format per the sibling convention (``simulation/...``,
  ``evidence/...``, ``safety/...``).

* the frozen authority-class vocabulary is consumed as-is: agents act at
  exactly the ``R2`` PROPOSE tier of the frozen extension authority
  ladder (``extensions.md`` ``R0 OBSERVE / R1 ANALYZE / R2 PROPOSE /
  R3 RESERVE / R4 EXECUTE / R5 FINANCIAL_EXPOSURE``); governance-side
  commands require a registry ``A``-class.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import (
    AUTHORITY_CLASSES,
    PROTOCOL_VERSION,
    validate_authority_class,
)

from ._validation import parse_enum, require_identifier, require_text
from src.evidence.contracts import EpistemicType
from src.simulation.contracts import EnvironmentMode, StateNamespace
from src.simulation.state import DEFAULT_NAMESPACE_RULES, NamespaceRule, NamespaceRules

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
AGENTS_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
AGENTS_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of agents-domain durable objects.
AGENTS_SCHEMA_VERSION = 1

# Internal (non-registry) object types of the agents domain.
MODEL_OBJECT_TYPE = "agents/model/v1"
MODEL_OUTPUT_OBJECT_TYPE = "agents/model-output/v1"
AGENT_CONTEXT_OBJECT_TYPE = "agents/agent-context/v1"
PROPOSAL_MANDATE_OBJECT_TYPE = "agents/proposal-mandate/v1"
PROPOSAL_OBJECT_TYPE = "agents/proposal/v1"
MEDIATION_DECISION_OBJECT_TYPE = "agents/mediation-decision/v1"
ROUTE_EVALUATION_OBJECT_TYPE = "agents/route-evaluation/v1"

#: Existing frozen registry event namespace used for model lifecycle and
#: mediation decision events (choice documented in the module docstring).
AGENTS_EVENT_NAMESPACE = "governance"

#: Existing frozen registry event namespace used for simulated proposal
#: outcome events emitted inside simulation environments.
SIMULATED_PROPOSAL_EVENT_NAMESPACE = "simulation"

# -- object identity prefixes (also the namespace classification) ----------

MODEL_ID_PREFIX = "model/"
MODEL_OUTPUT_ID_PREFIX = "model-output/"
AGENT_CONTEXT_ID_PREFIX = "agent/"
PROPOSAL_MANDATE_ID_PREFIX = "agent-mandate/"
PROPOSAL_ID_PREFIX = "agent-proposal/"
MEDIATION_DECISION_ID_PREFIX = "mediation-decision/"
ROUTE_EVALUATION_ID_PREFIX = "route-evaluation/"

#: The agents-domain extension of the frozen namespace classification: the
#: dependency plane (which already owns ``model/``, ``extension/`` and
#: ``dependency/`` in the frozen default rules) also classifies the agents
#: object families. Every agents-domain object id is classification-total
#: under these rules, and ``model/...`` ids classify under the frozen
#: DEFAULT_NAMESPACE_RULES as well.
AGENTS_NAMESPACE_RULES = NamespaceRules(
    (
        *DEFAULT_NAMESPACE_RULES.rules,
        NamespaceRule(AGENT_CONTEXT_ID_PREFIX, StateNamespace.DEPENDENCY),
        NamespaceRule(MODEL_OUTPUT_ID_PREFIX, StateNamespace.DEPENDENCY),
        NamespaceRule(PROPOSAL_MANDATE_ID_PREFIX, StateNamespace.DEPENDENCY),
        NamespaceRule(PROPOSAL_ID_PREFIX, StateNamespace.DEPENDENCY),
        NamespaceRule(MEDIATION_DECISION_ID_PREFIX, StateNamespace.DEPENDENCY),
        NamespaceRule(ROUTE_EVALUATION_ID_PREFIX, StateNamespace.DEPENDENCY),
    )
)

#: The frozen authority class agents act under — exactly the PROPOSE tier
#: of the frozen extension authority ladder. Agents never receive more.
PROPOSAL_AUTHORITY_CLASS = "R2"

#: Registry governance-side authority classes (the A-family).
GOVERNANCE_AUTHORITY_CLASSES = frozenset(
    member for member in AUTHORITY_CLASSES if member.startswith("A")
)

# -- frozen command families -----------------------------------------------

#: The frozen ``Model`` command family (command-event-model.md).
MODEL_COMMANDS = frozenset(
    {
        "model/register",
        "model/validate",
        "model/approve",
        "model/deploy",
        "model/suspend",
        "model/resume",
        "model/retire",
    }
)

#: Agent-side commands (internal free-form command types).
AGENT_COMMANDS = frozenset(
    {
        "agent/authorize-mandate",
        "agent/propose",
    }
)

#: Mediation commands (internal free-form command types).
MEDIATION_COMMANDS = frozenset({"mediation/select"})

#: Every command type the agents kernel binding registers.
AGENTS_COMMANDS = MODEL_COMMANDS | AGENT_COMMANDS | MEDIATION_COMMANDS

#: Kernel event types of the model lifecycle (governance namespace).
MODEL_EVENT_TYPES: Mapping[str, str] = {
    "model/register": "governance/model-registered",
    "model/validate": "governance/model-validated",
    "model/approve": "governance/model-approved",
    "model/deploy": "governance/model-deployed",
    "model/suspend": "governance/model-suspended",
    "model/resume": "governance/model-resumed",
    "model/retire": "governance/model-retired",
}

#: Kernel event types of the agent-side commands (governance namespace).
AGENT_EVENT_TYPES: Mapping[str, str] = {
    "agent/authorize-mandate": "governance/agent-mandate-authorized",
    "agent/propose": "governance/agent-proposal-recorded",
}

#: Kernel event types of the mediation commands (governance namespace).
MEDIATION_EVENT_TYPES: Mapping[str, str] = {
    "mediation/select": "governance/mediation-selected",
}

#: Every kernel event type of the agents domain.
AGENTS_EVENT_TYPES: Mapping[str, str] = {
    **MODEL_EVENT_TYPES,
    **AGENT_EVENT_TYPES,
    **MEDIATION_EVENT_TYPES,
}

# -- route evaluation inside simulation environments -----------------------

#: Command type of the candidate route evaluation (run inside SIMULATION
#: environments through the simulation domain's public contract).
ROUTE_EVALUATION_COMMAND_TYPE = "agent/simulate-route"

#: Event type of the simulated proposal outcome (simulation namespace).
ROUTE_EVALUATION_EVENT_TYPE = "simulation/route-simulated"

#: Identity of the shared route-evaluation protocol binding.
ROUTE_EVALUATION_BINDING_ID = "binding/agents-route-evaluation"


# -- closed vocabularies ----------------------------------------------------


class ModelLifecycleState(StrEnum):
    """Closed lifecycle vocabulary of one registered model.

    The frozen ``Model`` command family is
    ``Register/Validate/Approve/Deploy/Suspend/Resume/Retire``; every
    transition between these states is explicit and every other transition
    fails closed. ``RETIRED`` is terminal: retired models never resume and
    their history is immutable.
    """

    REGISTERED = "REGISTERED"
    VALIDATED = "VALIDATED"
    APPROVED = "APPROVED"
    DEPLOYED = "DEPLOYED"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"

    @classmethod
    def parse(cls, value: object) -> "ModelLifecycleState":
        """Fail closed on unknown lifecycle states."""
        return parse_enum("model lifecycle state", value, cls)  # type: ignore[return-value]


class ModelRiskClass(StrEnum):
    """Closed vocabulary of declared model risk classes.

    Model risk is a first-class risk dimension (security-risk.md); the
    class is declared at registration and carried on every record.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def parse(cls, value: object) -> "ModelRiskClass":
        return parse_enum("model risk class", value, cls)  # type: ignore[return-value]


class ProposalKind(StrEnum):
    """Closed vocabulary of what a bounded proposal mandate may cover."""

    ROUTE = "ROUTE"

    @classmethod
    def parse(cls, value: object) -> "ProposalKind":
        return parse_enum("proposal kind", value, cls)  # type: ignore[return-value]


#: All lifecycle states.
MODEL_LIFECYCLE_STATES = frozenset(set(ModelLifecycleState))

#: Terminal lifecycle states: history stays immutable after them.
MODEL_TERMINAL_STATES = frozenset({ModelLifecycleState.RETIRED})

#: Explicit lifecycle transitions of the frozen Model command family
#: (``model/register`` is the creation transition and is absent: creation
#: requires the model not to exist yet).
MODEL_TRANSITIONS: Mapping[str, Mapping[ModelLifecycleState, ModelLifecycleState]] = {
    "model/validate": {ModelLifecycleState.REGISTERED: ModelLifecycleState.VALIDATED},
    "model/approve": {ModelLifecycleState.VALIDATED: ModelLifecycleState.APPROVED},
    "model/deploy": {ModelLifecycleState.APPROVED: ModelLifecycleState.DEPLOYED},
    "model/suspend": {ModelLifecycleState.DEPLOYED: ModelLifecycleState.SUSPENDED},
    "model/resume": {ModelLifecycleState.SUSPENDED: ModelLifecycleState.DEPLOYED},
    "model/retire": {
        state: ModelLifecycleState.RETIRED
        for state in (
            ModelLifecycleState.REGISTERED,
            ModelLifecycleState.VALIDATED,
            ModelLifecycleState.APPROVED,
            ModelLifecycleState.DEPLOYED,
            ModelLifecycleState.SUSPENDED,
        )
    },
}

#: Epistemic types a model output may carry (the frozen vocabulary is
#: owned by ``src.evidence``): models produce ``SIMULATED`` or ``PREDICTED``
#: knowledge only — a model output can never masquerade as an observation.
MODEL_OUTPUT_EPISTEMIC_TYPES = frozenset(
    {EpistemicType.SIMULATED, EpistemicType.PREDICTED}
)

#: Environment modes an agent context may declare: hypothetical worlds
#: only. Shadow and production contexts fail closed — agents never
#: receive live-observation authority or ambient financial authority.
AGENT_ALLOWED_MODES = frozenset(
    {
        EnvironmentMode.SIMULATION,
        EnvironmentMode.FORECAST,
        EnvironmentMode.COUNTERFACTUAL,
    }
)

#: The mediation substrate mode: candidate proposals are ALWAYS evaluated
#: in ``SIMULATION`` environments first (simulation-before-production).
MEDIATION_REQUIRED_MODE = EnvironmentMode.SIMULATION

#: A mediation decision requires a compared alternative.
MEDIATION_MIN_CANDIDATES = 2

#: Basis-point total the mediation policy weights must sum to exactly.
MEDIATION_WEIGHT_TOTAL_BPS = 10000

#: Confidence is an exact basis-point value on the explicit 0..10000 scale.
CONFIDENCE_BPS_MIN = 0
CONFIDENCE_BPS_MAX = 10000

#: Reliability metrics are exact basis-point values.
RELIABILITY_BPS_MIN = 0
RELIABILITY_BPS_MAX = 10000

#: Maximum decimal scale of a declared cost (mirrors the sibling bound).
MAX_SCALE = 18


def validate_agents_command(command_type: str) -> str:
    """Require a command type from the frozen agents command families."""
    require_text("agents command type", command_type)
    if command_type not in AGENTS_COMMANDS:
        raise CoreValidationError(
            f"command type {command_type!r} is not part of the frozen agents "
            "command families"
        )
    return command_type


def validate_agents_event_type(command_type: str, event_type: str) -> str:
    """Fail closed unless the event type is the frozen binding of the command."""
    validate_agents_command(command_type)
    require_text("agents event type", event_type)
    expected = AGENTS_EVENT_TYPES[command_type]
    if event_type != expected:
        raise CoreValidationError(
            f"command type {command_type!r} must emit event type {expected!r}"
        )
    return event_type


def validate_proposal_authority_class(name: str, value: str) -> str:
    """Fail closed unless the authority is exactly the frozen PROPOSE tier."""
    validate_authority_class(name, value)
    if value != PROPOSAL_AUTHORITY_CLASS:
        raise CoreValidationError(
            f"{name} must be exactly the frozen {PROPOSAL_AUTHORITY_CLASS} "
            "PROPOSE tier: agents never receive authority beyond proposing"
        )
    return value


def require_agents_identifier(name: str, value: str, prefix: str) -> str:
    """Require an agents-domain object identifier with its family prefix."""
    require_identifier(name, value)
    if not value.startswith(prefix):
        raise CoreValidationError(f"{name} must use the {prefix!r} identifier prefix")
    return value
