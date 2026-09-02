"""Route proposals: agent output, kernel-recorded (WORK-021).

A :class:`RouteProposal` is one candidate route an agent proposes under
its agent context: a declared profile (cost, latency, reliability) backed
by at least one sealed :class:`~src.agents.models.ModelOutput` from a
model in the context's deployed model set.

Proposals are PROPOSALS, never decisions: the declared profile is the
agent's claim; what mediation consumes is the SIMULATED evaluation of the
proposal inside a simulation environment (simulation-before-production),
never the claim alone.

Recording is kernel-mediated (``agent/propose``): the semantic gates —
impersonation (the command actor must be the proposal's agent), mandate
scope/kind/window/budget, deployed-model citation, and the simulation
substrate mode in the context — run at the kernel's policy stage so every
violation is a RECORDED rejection, and the handler then persists the
sealed proposal record and consumes one unit of the mandate budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import Command, TransitionApplication, payload_to_json_value

from .contracts import (
    MAX_SCALE,
    MEDIATION_REQUIRED_MODE,
    PROPOSAL_ID_PREFIX,
    PROPOSAL_OBJECT_TYPE,
    ProposalKind,
    RELIABILITY_BPS_MAX,
    RELIABILITY_BPS_MIN,
    require_agents_identifier,
)
from ._validation import (
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .context import AgentContext
from .mandates import MandateBook
from .models import ModelOutput
from .registry import ModelRegistry
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)


class ProposalState(StrEnum):
    """Closed lifecycle vocabulary of a route proposal (v0.1: PROPOSED)."""

    PROPOSED = "PROPOSED"


_PROPOSAL_SPEC_FIELDS = frozenset(
    {
        "proposal_id",
        "agent_principal",
        "mandate_id",
        "route_family",
        "rail",
        "declared_cost_minor",
        "declared_cost_scale",
        "declared_cost_asset",
        "declared_latency_ms",
        "declared_reliability_bps",
        "context",
        "model_outputs",
        "as_of",
    }
)

_PROPOSE_COMMAND_FIELDS = frozenset({"proposal"})


@dataclass(frozen=True, slots=True)
class ProposalSpec:
    """Immutable route proposal payload."""

    proposal_id: str
    agent_principal: str
    mandate_id: str
    route_family: str
    rail: str
    declared_cost_minor: int
    declared_cost_scale: int
    declared_cost_asset: str
    declared_latency_ms: int
    declared_reliability_bps: int
    context: AgentContext
    model_outputs: tuple[ModelOutput, ...]
    as_of: str

    def __post_init__(self) -> None:
        require_agents_identifier(
            "proposal.proposal_id", self.proposal_id, PROPOSAL_ID_PREFIX
        )
        require_identifier("proposal.agent_principal", self.agent_principal)
        require_agents_identifier(
            "proposal.mandate_id", self.mandate_id, "agent-mandate/"
        )
        require_text("proposal.route_family", self.route_family)
        require_text("proposal.rail", self.rail)
        require_int("proposal.declared_cost_minor", self.declared_cost_minor, minimum=0)
        require_int(
            "proposal.declared_cost_scale", self.declared_cost_scale, minimum=0, maximum=MAX_SCALE
        )
        require_identifier("proposal.declared_cost_asset", self.declared_cost_asset)
        require_int("proposal.declared_latency_ms", self.declared_latency_ms, minimum=0)
        require_int(
            "proposal.declared_reliability_bps",
            self.declared_reliability_bps,
            minimum=RELIABILITY_BPS_MIN,
            maximum=RELIABILITY_BPS_MAX,
        )
        if not isinstance(self.context, AgentContext):
            raise CoreValidationError("proposal.context must be an AgentContext")
        if not isinstance(self.model_outputs, tuple) or not self.model_outputs:
            raise CoreValidationError(
                "proposal.model_outputs must be a non-empty tuple of ModelOutput"
            )
        for output in self.model_outputs:
            if not isinstance(output, ModelOutput):
                raise CoreValidationError(
                    "proposal.model_outputs must contain ModelOutput records"
                )
        require_utc_timestamp("proposal.as_of", self.as_of)
        if self.agent_principal != self.context.spec.agent_principal:
            raise CoreValidationError(
                "proposal agent must match the agent context principal: "
                "impersonation fails closed"
            )
        if self.mandate_id != self.context.spec.mandate_id:
            raise CoreValidationError(
                "proposal must cite the agent context mandate"
            )
        context_models = set(self.context.spec.model_ids)
        for output in self.model_outputs:
            if output.model_id not in context_models:
                raise CoreValidationError(
                    f"model output {output.output_id!r} cites model "
                    f"{output.model_id!r} outside the agent context model set"
                )
            if not output.is_fresh_at(self.as_of):
                raise CoreValidationError(
                    f"model output {output.output_id!r} is not fresh at the "
                    "proposal instant: stale proposal evidence fails closed"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "agent_principal": self.agent_principal,
            "mandate_id": self.mandate_id,
            "route_family": self.route_family,
            "rail": self.rail,
            "declared_cost_minor": self.declared_cost_minor,
            "declared_cost_scale": self.declared_cost_scale,
            "declared_cost_asset": self.declared_cost_asset,
            "declared_latency_ms": self.declared_latency_ms,
            "declared_reliability_bps": self.declared_reliability_bps,
            "context": self.context.to_dict(),
            "model_outputs": [output.to_dict() for output in self.model_outputs],
            "as_of": self.as_of,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProposalSpec":
        strict_fields("proposal", value, _PROPOSAL_SPEC_FIELDS)
        context = AgentContext.from_dict(value["context"])
        outputs_raw = value["model_outputs"]
        if not isinstance(outputs_raw, list):
            raise CoreValidationError(
                "proposal.model_outputs must deserialize from an array"
            )
        return cls(
            proposal_id=value["proposal_id"],
            agent_principal=value["agent_principal"],
            mandate_id=value["mandate_id"],
            route_family=value["route_family"],
            rail=value["rail"],
            declared_cost_minor=value["declared_cost_minor"],
            declared_cost_scale=value["declared_cost_scale"],
            declared_cost_asset=value["declared_cost_asset"],
            declared_latency_ms=value["declared_latency_ms"],
            declared_reliability_bps=value["declared_reliability_bps"],
            context=context,
            model_outputs=tuple(ModelOutput.from_dict(item) for item in outputs_raw),
            as_of=value["as_of"],
        )


@dataclass(frozen=True, slots=True)
class RouteProposal:
    """Durable route proposal record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ProposalSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = PROPOSAL_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("proposal envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ProposalSpec):
            raise CoreValidationError("proposal spec must be a ProposalSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != PROPOSAL_OBJECT_TYPE:
            raise CoreValidationError(
                f"proposal object_type must be {PROPOSAL_OBJECT_TYPE!r}"
            )
        try:
            ProposalState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown proposal state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.proposal_id:
            raise CoreValidationError(
                "proposal identity mismatch: envelope and spec must name the same "
                "proposal"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.spec.proposal_id
        )

    @property
    def proposal_id(self) -> str:
        return self.spec.proposal_id

    @property
    def state(self) -> str:
        return self.envelope.state

    @property
    def digest(self) -> str:
        """Canonical digest of the sealed proposal content."""
        return canonical_sha256(self.spec.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RouteProposal":
        envelope, payload = decode_composite(
            value,
            expected_object_type=PROPOSAL_OBJECT_TYPE,
            state_type=ProposalState,
        )
        spec = ProposalSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "RouteProposal":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=PROPOSAL_OBJECT_TYPE,
            state_type=ProposalState,
        )
        spec = ProposalSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    @classmethod
    def build(
        cls,
        *,
        proposal_id: str,
        agent_principal: str,
        mandate_id: str,
        route_family: str,
        rail: str,
        declared_cost_minor: int,
        declared_cost_scale: int,
        declared_cost_asset: str,
        declared_latency_ms: int,
        declared_reliability_bps: int,
        context: AgentContext,
        model_outputs: Iterable[ModelOutput],
        as_of: str,
        provenance: Provenance | None = None,
    ) -> "RouteProposal":
        """Build one sealed proposal record (structural validation only)."""
        spec = ProposalSpec(
            proposal_id=proposal_id,
            agent_principal=agent_principal,
            mandate_id=mandate_id,
            route_family=route_family,
            rail=rail,
            declared_cost_minor=declared_cost_minor,
            declared_cost_scale=declared_cost_scale,
            declared_cost_asset=declared_cost_asset,
            declared_latency_ms=declared_latency_ms,
            declared_reliability_bps=declared_reliability_bps,
            context=context,
            model_outputs=tuple(model_outputs),
            as_of=as_of,
        )
        if provenance is None:
            provenance = Provenance(
                issuer=agent_principal,
                source="agents/agent-propose",
                recorded_at=as_of,
                evidence_refs=(mandate_id,),
            )
        envelope = build_domain_envelope(
            object_id=proposal_id,
            object_type=PROPOSAL_OBJECT_TYPE,
            state=ProposalState.PROPOSED.value,
            environment_id=context.envelope.environment_id,
            domain_id=context.envelope.domain_id,
            provenance=provenance,
        )
        return cls(
            envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
        )


class ProposalBook:
    """Typed proposal store applying ``agent/propose`` commands."""

    def __init__(
        self,
        *,
        registry: ModelRegistry,
        mandates: MandateBook,
        environment_id: str,
        domain_id: str,
    ) -> None:
        if not isinstance(registry, ModelRegistry):
            raise CoreValidationError("proposal book requires a ModelRegistry")
        if not isinstance(mandates, MandateBook):
            raise CoreValidationError("proposal book requires a MandateBook")
        require_identifier("proposal book environment_id", environment_id)
        require_identifier("proposal book domain_id", domain_id)
        self._registry = registry
        self._mandates = mandates
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._proposals: dict[str, RouteProposal] = {}

    # -- read-only surface --------------------------------------------------

    def get(self, proposal_id: str) -> RouteProposal | None:
        require_agents_identifier("proposal_id", proposal_id, PROPOSAL_ID_PREFIX)
        return self._proposals.get(proposal_id)

    def require_proposal(self, proposal_id: str) -> RouteProposal:
        proposal = self.get(proposal_id)
        if proposal is None:
            raise CoreValidationError(
                f"unknown proposal {proposal_id!r}: mediation inputs must be the "
                "kernel-recorded proposals"
            )
        return proposal

    def proposals(self) -> tuple[RouteProposal, ...]:
        return tuple(
            self._proposals[proposal_id] for proposal_id in sorted(self._proposals)
        )

    def recorded_digest(self, proposal_id: str) -> str:
        """Canonical digest of the kernel-recorded proposal content."""
        return self.require_proposal(proposal_id).digest

    def state_digest(self) -> str:
        """Canonical digest of the recorded proposal state."""
        return canonical_sha256(
            [proposal.to_dict() for proposal in self.proposals()]
        )

    # -- semantic gate (kernel policy stage) ----------------------------------

    def evaluate_command(self, command: Command) -> str | None:
        if command.command_type != "agent/propose":
            raise CoreValidationError(
                f"proposal book received command {command.command_type!r}"
            )
        try:
            proposal = self._parse_proposal(command)
            self._check_gates(command, proposal)
        except CoreValidationError as exc:
            return f"agent proposal fails closed: {exc}"
        return None

    # -- transition handler (kernel transition stage) --------------------------

    def apply_command(self, command: Command) -> TransitionApplication:
        proposal = self._parse_proposal(command)
        self._check_gates(command, proposal)
        self._proposals[proposal.proposal_id] = proposal
        self._mandates.consume_budget(proposal.spec.mandate_id)
        return TransitionApplication(
            resulting_envelopes=(proposal.envelope,),
            payload=proposal.spec.to_dict(),
        )

    # -- internals ---------------------------------------------------------------

    def _parse_proposal(self, command: Command) -> RouteProposal:
        data = payload_to_json_value(command.payload)
        if not isinstance(data, Mapping):
            raise CoreValidationError("agent proposal payload must be an object")
        strict_fields("agent proposal command", data, _PROPOSE_COMMAND_FIELDS)
        proposal_value = data["proposal"]
        if not isinstance(proposal_value, Mapping):
            raise CoreValidationError("agent proposal payload must carry the proposal")
        proposal = RouteProposal.from_dict(proposal_value)
        if command.target_refs != (proposal.proposal_id,):
            raise CoreValidationError(
                "agent proposal command must declare exactly its proposal target"
            )
        return proposal

    def _check_gates(self, command: Command, proposal: RouteProposal) -> None:
        if command.actor != proposal.spec.agent_principal:
            raise CoreValidationError(
                f"proposal {proposal.proposal_id!r} was submitted by "
                f"{command.actor!r} but belongs to agent "
                f"{proposal.spec.agent_principal!r}: impersonation fails closed"
            )
        if proposal.proposal_id in self._proposals:
            raise CoreValidationError(
                f"proposal {proposal.proposal_id!r} is already recorded"
            )
        context = proposal.spec.context
        if MEDIATION_REQUIRED_MODE not in context.spec.allowed_modes:
            raise CoreValidationError(
                "agent context must include the SIMULATION mode: every proposal "
                "is mediated simulation-first"
            )
        for output in proposal.spec.model_outputs:
            self._registry.require_deployed(output.model_id)
        self._mandates.authorize_proposal(
            mandate_id=proposal.spec.mandate_id,
            agent_principal=proposal.spec.agent_principal,
            proposal_kind=ProposalKind.ROUTE,
            route_family=proposal.spec.route_family,
            as_of=proposal.spec.as_of,
            consumed=self._mandates.budget_consumed(proposal.spec.mandate_id),
        )
