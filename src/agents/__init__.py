"""PaySwap models, agents and decision mediation domain (WORK-021).

The public boundary is typed and versioned (``AGENTS_API_VERSION``
``v0.1``, frozen kernel protocol version, schema version 1):

- the frozen v0.1 ``Model`` command family
  ``Register/Validate/Approve/Deploy/Suspend/Resume/Retire`` applied by
  the :class:`~src.agents.registry.ModelRegistry` as explicit sealed
  lifecycle record versions over the REAL transition kernel, with the
  consumption gate: only ``DEPLOYED`` models may back agent proposals
  (unregistered, unapproved, suspended and retired models fail closed);
- :class:`~src.agents.models.ModelOutput` — typed model artifacts with
  the frozen epistemic vocabulary re-used from ``src.evidence``
  (``SIMULATED``/``PREDICTED`` only: a model output can never
  masquerade as an observation), exact basis-point confidence, declared
  limitations, explicit freshness windows, provenance with non-empty
  evidence references and a domain seal;
- bounded, typed, agent-scoped proposal mandates
  (:class:`~src.agents.mandates.ProposalMandate`): explicit scope
  (proposal kinds + route families), explicit limits (proposal budget),
  explicit expiry (half-open window) and the authority class frozen to
  exactly the registry ``R2`` PROPOSE tier of the frozen extension
  authority ladder. This is NOT a second Mandate authority: the frozen
  ``Mandate`` concept is owned by the merged trust domain; this is the
  strictly weaker proposal bound (agents propose, never execute);
- :class:`~src.agents.context.AgentContext` — derived sealed snapshots
  binding one agent, one mandate, one deployed model set and
  hypothetical environment modes only (``SIMULATION``/``FORECAST``/
  ``COUNTERFACTUAL``): shadow and production agent contexts fail closed
  — no agent receives live-observation or ambient financial authority;
- :class:`~src.agents.proposals.RouteProposal` — kernel-recorded
  candidate route proposals whose declared profiles are backed by fresh
  sealed model outputs of deployed models;
- simulation-before-production decision mediation
  (:class:`~src.agents.mediation.MediationEngine`): every candidate is
  simulated in a ``SIMULATION``-mode environment through
  ``src.simulation``'s public contract, a deterministic
  :class:`~src.agents.mediation.MediationPolicy` (explicit
  basis-point weights, rank points, lexicographic tie-break) selects,
  and the sealed :class:`~src.agents.mediation.MediationDecision` is
  recorded through the kernel. A decision is never an execution: it
  carries no effect intents and no authority to act. Mediation is the
  only path from proposal to decision, and the proposing agent cannot
  mediate its own proposals.

Registry discipline (documented choices): the frozen protocol registry
lists no ``model`` or ``agent`` event namespace, so none is invented —
model lifecycle and mediation decision events use the existing frozen
``governance`` namespace and simulated proposal outcomes use the
existing frozen ``simulation`` namespace; command types are internal
free-form strings (``model/register``, ``agent/propose``,
``mediation/select``) and every agents-domain object type uses the
internal non-registry ``agents/...`` format per the sibling
convention.

The domain consumes the merged dependency domains only:
``src.core`` (envelope, canonical serialization, error authority),
``src.transition`` (the real kernel), ``src.evidence`` (the frozen
epistemic vocabulary) and ``src.simulation`` (the mediation substrate).
Unmerged sibling implementations are never imported.

Determinism discipline: no wall-clock reads, no entropy sources, no
generated identifiers — every instant is explicit declared ``as_of``
data and every digest is canonical.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.evidence.contracts import EpistemicType
from src.simulation.contracts import EnvironmentMode

from .contracts import (
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
    AGENT_EVENT_TYPES,
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
    ModelLifecycleState,
    ModelRiskClass,
    ProposalKind,
)
from .models import ModelOutput, ModelRecord
from .registry import ModelRegistry
from .mandates import MandateBook, ProposalMandate
from .context import AgentContext, build_agent_context
from .proposals import ProposalBook, RouteProposal
from .mediation import (
    CandidateOutcome,
    MediationDecision,
    MediationEngine,
    MediationPolicy,
    PolicyEvaluation,
    SimulatedOutcome,
    route_evaluation_binding,
    simulate_candidate,
)
from .engine import AgentsEngine

__all__ = [
    # versioned public-boundary contracts
    "AGENTS_API_VERSION",
    "AGENTS_PROTOCOL_VERSION",
    "AGENTS_SCHEMA_VERSION",
    # frozen object types (internal non-registry formats)
    "MODEL_OBJECT_TYPE",
    "MODEL_OUTPUT_OBJECT_TYPE",
    "AGENT_CONTEXT_OBJECT_TYPE",
    "PROPOSAL_MANDATE_OBJECT_TYPE",
    "PROPOSAL_OBJECT_TYPE",
    "MEDIATION_DECISION_OBJECT_TYPE",
    "ROUTE_EVALUATION_OBJECT_TYPE",
    # frozen event namespaces and command families
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
    "ROUTE_EVALUATION_COMMAND_TYPE",
    "ROUTE_EVALUATION_EVENT_TYPE",
    "ROUTE_EVALUATION_BINDING_ID",
    # frozen vocabularies and contracts
    "MODEL_TRANSITIONS",
    "MODEL_LIFECYCLE_STATES",
    "MODEL_TERMINAL_STATES",
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
    # model registry and outputs
    "ModelRecord",
    "ModelOutput",
    "ModelRegistry",
    # bounded proposal mandates
    "ProposalMandate",
    "MandateBook",
    # agent contexts
    "AgentContext",
    "build_agent_context",
    # route proposals
    "RouteProposal",
    "ProposalBook",
    # simulation-before-production mediation
    "SimulatedOutcome",
    "CandidateOutcome",
    "MediationPolicy",
    "PolicyEvaluation",
    "MediationDecision",
    "MediationEngine",
    "route_evaluation_binding",
    "simulate_candidate",
    # the kernel binding
    "AgentsEngine",
    # re-exported owning authorities (single sources)
    "CoreValidationError",
    "EpistemicType",
    "EnvironmentMode",
    "Provenance",
]
