"""The agents-domain kernel binding: AgentsEngine (WORK-021).

:class:`AgentsEngine` binds the agents domain to the REAL transition
kernel (``src.transition.TransitionEngine``): it registers every
command of the frozen agents command families with its frozen event
type and routes the semantic gates to the typed books:

* ``model/*`` — the frozen ``Model`` command family, applied by the
  :class:`~src.agents.registry.ModelRegistry`;
* ``agent/authorize-mandate`` / ``agent/propose`` — bounded proposal
  mandates and kernel-recorded route proposals;
* ``mediation/select`` — the deterministic decision recording.

There is no second state machine and no second authority: one kernel,
one authorization discipline, one error authority
(:class:`~src.core.errors.CoreValidationError`).

The authorization discipline (constitution invariant 5 — no agent, model
or external provider receives ambient financial authority):

* governance-side commands (the model lifecycle, mandate authorization
  and mediation) require an actor whose registry authority class is a
  member of the frozen ``A``-family. An actor holding a proposal-tier
  or extension-tier class is rejected before the semantic gates;
* ``agent/propose`` requires EXACTLY the frozen ``R2`` PROPOSE tier of
  the extension authority ladder. An actor that HOLDS a registry class
  above the propose tier is escalating and is rejected at the
  authorization stage. An actor the registry authorization denies
  holds no registry class at all: the proposal authority is the
  bounded mandate, so the kernel grants the propose tier provisionally
  and the mandate gates (impersonation, scope, window, budget, deployed
  models) decide at the policy stage — every one of them fail-closed.
"""

from __future__ import annotations

from typing import Any, Callable

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import (
    AuthorizationDecision,
    Command,
    JournalEntry,
    MemoryStateStore,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)

from .contracts import (
    AGENTS_COMMANDS,
    AGENTS_EVENT_TYPES,
    GOVERNANCE_AUTHORITY_CLASSES,
    MODEL_COMMANDS,
    PROPOSAL_AUTHORITY_CLASS,
    require_agents_identifier,
)
from ._validation import require_identifier
from .mandates import MandateBook
from .mediation import DecisionBook
from .proposals import ProposalBook
from .registry import ModelRegistry

AuthorizationHook = Callable[[Command, Any], AuthorizationDecision]


class AgentsEngine:
    """The agents domain bound to one transition kernel.

    The engine owns the four typed books (models, mandates, proposals,
    decisions) and the kernel wiring (authorization wrapper, policy
    gate, validate-then-apply handlers). Every accepted command emits
    its frozen event; every rejected command is recorded as an audit
    rejection event when ``emit_rejection_events`` is enabled.
    """

    def __init__(
        self,
        environment_id: str,
        domain_id: str,
        *,
        authorization: AuthorizationHook | None = None,
        emit_rejection_events: bool = False,
        rejection_authority: str | None = None,
    ) -> None:
        require_identifier("engine environment_id", environment_id)
        require_identifier("engine domain_id", domain_id)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._store = MemoryStateStore()
        self._registry = ModelRegistry(environment_id=environment_id, domain_id=domain_id)
        self._mandates = MandateBook(environment_id=environment_id, domain_id=domain_id)
        self._proposals = ProposalBook(
            registry=self._registry,
            mandates=self._mandates,
            environment_id=environment_id,
            domain_id=domain_id,
        )
        self._decisions = DecisionBook(
            mandates=self._mandates,
            proposals=self._proposals,
            environment_id=environment_id,
            domain_id=domain_id,
        )
        self._kernel = TransitionEngine(
            environment_id,
            authorization=self._wrap_authorization(authorization),
            policy=self._policy_gate,
            store=self._store,
            emit_rejection_events=emit_rejection_events,
            rejection_authority=rejection_authority,
        )
        self._command_types: list[str] = []
        for command_type in sorted(AGENTS_EVENT_TYPES):
            event_type = AGENTS_EVENT_TYPES[command_type]
            self._kernel.register(
                command_type,
                event_type,
                self._make_handler(command_type),
            )
            self._command_types.append(command_type)

    # -- identity ------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def registry(self) -> ModelRegistry:
        return self._registry

    @property
    def mandates(self) -> MandateBook:
        return self._mandates

    @property
    def proposals(self) -> ProposalBook:
        return self._proposals

    @property
    def decisions(self) -> DecisionBook:
        return self._decisions

    # -- read-only surface ---------------------------------------------------

    def command_types(self) -> frozenset[str]:
        """Every command type registered with the kernel."""
        return frozenset(self._command_types)

    @property
    def journal(self) -> tuple[JournalEntry, ...]:
        return self._kernel.journal

    def process(self, command: Command) -> TransitionResult:
        return self._kernel.process(command)

    def get_model(self, model_id: str) -> Any | None:
        require_agents_identifier("model_id", model_id, "model/")
        return self._registry.get(model_id)

    def get_mandate(self, mandate_id: str) -> Any | None:
        require_agents_identifier("mandate_id", mandate_id, "agent-mandate/")
        return self._mandates.get(mandate_id)

    def get_proposal(self, proposal_id: str) -> Any | None:
        require_agents_identifier("proposal_id", proposal_id, "agent-proposal/")
        return self._proposals.get(proposal_id)

    def get_decision(self, decision_id: str) -> Any | None:
        require_agents_identifier("decision_id", decision_id, "mediation-decision/")
        return self._decisions.get(decision_id)

    def store_object(self, object_id: str) -> Any:
        """The kernel store's envelope for one durable object."""
        require_identifier("object_id", object_id)
        return self._store.get(object_id)

    def state_digest(self) -> str:
        """Canonical digest of the whole agents-domain state."""
        return canonical_sha256(
            {
                "models": self._registry.state_digest(),
                "mandates": self._mandates.state_digest(),
                "proposals": self._proposals.state_digest(),
                "decisions": self._decisions.state_digest(),
            }
        )

    # -- kernel wiring -----------------------------------------------------------

    def _wrap_authorization(
        self, authorization: AuthorizationHook | None
    ) -> AuthorizationHook | None:
        """Bind the per-command-family authority-class requirements."""
        if authorization is None:
            return None

        def wrapped(command: Command, view: Any) -> AuthorizationDecision:
            decision = authorization(command, view)
            if not isinstance(decision, AuthorizationDecision):
                raise CoreValidationError(
                    "authorization hook must return an AuthorizationDecision"
                )
            if not decision.granted:
                if command.command_type == "agent/propose":
                    # The actor holds no registry class: proposal
                    # authority is the bounded mandate, so the mandate
                    # gates decide at the policy stage (fail-closed).
                    return AuthorizationDecision(
                        granted=True,
                        authority=PROPOSAL_AUTHORITY_CLASS,
                        reason=None,
                    )
                return decision
            authority = decision.authority
            if command.command_type == "agent/propose":
                if authority == PROPOSAL_AUTHORITY_CLASS:
                    return decision
                return AuthorizationDecision(
                    granted=False,
                    authority=None,
                    reason=(
                        f"agent proposals require exactly the frozen "
                        f"{PROPOSAL_AUTHORITY_CLASS} PROPOSE tier: actor "
                        f"{command.actor!r} holds {authority!r} and agents "
                        "never receive authority beyond proposing"
                    ),
                )
            if authority in GOVERNANCE_AUTHORITY_CLASSES:
                return decision
            return AuthorizationDecision(
                granted=False,
                authority=None,
                reason=(
                    f"command {command.command_type!r} is a governance-side "
                    "decision and requires a registry governance authority "
                    f"class; actor {command.actor!r} holds {authority!r}"
                ),
            )

        return wrapped

    def _policy_gate(self, command: Command, view: Any) -> str | None:
        """Dispatch the semantic gates to the typed books."""
        command_type = command.command_type
        if command_type in MODEL_COMMANDS:
            return self._registry.evaluate_command(command)
        if command_type == "agent/authorize-mandate":
            return self._mandates.evaluate_command(command)
        if command_type == "agent/propose":
            return self._proposals.evaluate_command(command)
        if command_type == "mediation/select":
            return self._decisions.evaluate_command(command)
        raise CoreValidationError(
            f"agents engine policy gate received unknown command "
            f"{command_type!r}"
        )

    def _make_handler(self, command_type: str) -> Callable[[Command, Any], TransitionApplication]:
        def handler(command: Command, view: Any) -> TransitionApplication:
            if command.command_type in MODEL_COMMANDS:
                return self._registry.apply_command(command)
            if command.command_type == "agent/authorize-mandate":
                return self._mandates.apply_command(command)
            if command.command_type == "agent/propose":
                return self._proposals.apply_command(command)
            if command.command_type == "mediation/select":
                return self._decisions.apply_command(command)
            raise CoreValidationError(
                f"agents engine handler received unknown command "
                f"{command.command_type!r}"
            )

        return handler
