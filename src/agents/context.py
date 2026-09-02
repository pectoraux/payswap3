"""Agent contexts: derived, sealed proposal environments (WORK-021).

An :class:`AgentContext` is the typed context one agent operates under
when proposing: the agent principal, exactly one bounded proposal
mandate, the deployed model set the agent may cite, the hypothetical
environment modes it may operate in, and the explicit ``as_of`` instant.

Contexts are DERIVED records, not governance decisions: their authority
derives entirely from the kernel-recorded mandate and the kernel-recorded
model registry, both re-validated at construction time. Construction is
fail-closed:

* every cited model must be registered and currently ``DEPLOYED`` in the
  model registry (the consumption gate — undeployed models never back
  agent proposals);
* the mandate must exist, be bound to this agent and be active at
  ``as_of``;
* the environment modes must be hypothetical only
  (``SIMULATION``/``FORECAST``/``COUNTERFACTUAL``): shadow and production
  agent contexts fail closed — agents never receive live-observation
  authority (constitution invariant 5).

The context is sealed with the single canonical hash authority so
tampering fails closed on the trusted deserialization path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.simulation.contracts import EnvironmentMode

from .contracts import (
    AGENT_ALLOWED_MODES,
    AGENT_CONTEXT_ID_PREFIX,
    AGENT_CONTEXT_OBJECT_TYPE,
    MODEL_ID_PREFIX,
    require_agents_identifier,
)
from ._validation import (
    parse_enum,
    require_identifier,
    require_str_tuple,
    require_utc_timestamp,
    strict_fields,
    utc_timestamp_within,
)
from .mandates import MandateBook
from .registry import ModelRegistry
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)


class AgentContextState(StrEnum):
    """Closed lifecycle vocabulary of an agent context (v0.1: ACTIVE)."""

    ACTIVE = "ACTIVE"


_CONTEXT_SPEC_FIELDS = frozenset(
    {
        "context_id",
        "agent_principal",
        "mandate_id",
        "model_ids",
        "allowed_modes",
        "as_of",
    }
)


@dataclass(frozen=True, slots=True)
class ContextSpec:
    """Immutable agent context payload."""

    context_id: str
    agent_principal: str
    mandate_id: str
    model_ids: tuple[str, ...]
    allowed_modes: tuple[EnvironmentMode, ...]
    as_of: str

    def __post_init__(self) -> None:
        require_agents_identifier(
            "context.context_id", self.context_id, AGENT_CONTEXT_ID_PREFIX
        )
        require_identifier("context.agent_principal", self.agent_principal)
        require_agents_identifier(
            "context.mandate_id", self.mandate_id, "agent-mandate/"
        )
        object.__setattr__(
            self,
            "model_ids",
            require_str_tuple(
                "context.model_ids", self.model_ids, non_empty=True, distinct=True
            ),
        )
        for model_id in self.model_ids:
            require_agents_identifier("context model_id", model_id, MODEL_ID_PREFIX)
        object.__setattr__(
            self, "allowed_modes", self._require_modes(self.allowed_modes)
        )
        require_utc_timestamp("context.as_of", self.as_of)

    def _require_modes(self, value: Any) -> tuple[EnvironmentMode, ...]:
        if not isinstance(value, (list, tuple)) or not value:
            raise CoreValidationError(
                "context.allowed_modes must be a non-empty sequence of "
                "EnvironmentMode"
            )
        modes = tuple(
            parse_enum("context.allowed_mode", item, EnvironmentMode) for item in value
        )
        if len(set(modes)) != len(modes):
            raise CoreValidationError("context.allowed_modes must be distinct")
        for mode in modes:
            if mode not in AGENT_ALLOWED_MODES:
                raise CoreValidationError(
                    f"agent context mode {mode.value} is forbidden: agents operate "
                    "in hypothetical worlds only and never receive live-observation "
                    "or ambient financial authority"
                )
        return modes

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "agent_principal": self.agent_principal,
            "mandate_id": self.mandate_id,
            "model_ids": list(self.model_ids),
            "allowed_modes": [mode.value for mode in self.allowed_modes],
            "as_of": self.as_of,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ContextSpec":
        strict_fields("context", value, _CONTEXT_SPEC_FIELDS)
        return cls(
            context_id=value["context_id"],
            agent_principal=value["agent_principal"],
            mandate_id=value["mandate_id"],
            model_ids=tuple(value["model_ids"]),
            allowed_modes=tuple(value["allowed_modes"]),
            as_of=value["as_of"],
        )


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Durable agent context record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ContextSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = AGENT_CONTEXT_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("agent context envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ContextSpec):
            raise CoreValidationError("agent context spec must be a ContextSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != AGENT_CONTEXT_OBJECT_TYPE:
            raise CoreValidationError(
                f"agent context object_type must be {AGENT_CONTEXT_OBJECT_TYPE!r}"
            )
        try:
            AgentContextState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown agent context state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.context_id:
            raise CoreValidationError(
                "agent context identity mismatch: envelope and spec must name the "
                "same context"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.spec.context_id
        )

    @property
    def context_id(self) -> str:
        return self.spec.context_id

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
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentContext":
        envelope, payload = decode_composite(
            value,
            expected_object_type=AGENT_CONTEXT_OBJECT_TYPE,
            state_type=AgentContextState,
        )
        spec = ContextSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "AgentContext":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=AGENT_CONTEXT_OBJECT_TYPE,
            state_type=AgentContextState,
        )
        spec = ContextSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def build_agent_context(
    *,
    registry: ModelRegistry,
    mandates: MandateBook,
    context_id: str,
    agent_principal: str,
    mandate_id: str,
    model_ids: tuple[str, ...] | list[str],
    allowed_modes: tuple[EnvironmentMode, ...] | list[EnvironmentMode],
    as_of: str,
    provenance: Provenance | None = None,
) -> AgentContext:
    """Construct one sealed agent context, failing closed on every gate.

    The cited models must all be currently ``DEPLOYED`` (the registry
    consumption gate), the mandate must be bound to this agent and active
    at ``as_of``, and the modes must be hypothetical only. Mediation
    additionally requires the context to include the ``SIMULATION`` mode
    (checked where proposals are recorded and mediated).
    """
    if not isinstance(registry, ModelRegistry):
        raise CoreValidationError("agent context requires a ModelRegistry")
    if not isinstance(mandates, MandateBook):
        raise CoreValidationError("agent context requires a MandateBook")
    mandate = mandates.require_mandate(mandate_id)
    if mandate.spec.agent_principal != agent_principal:
        raise CoreValidationError(
            f"proposal mandate {mandate_id!r} is bound to agent "
            f"{mandate.spec.agent_principal!r}, not {agent_principal!r}"
        )
    require_utc_timestamp("agent context as_of", as_of)
    if not utc_timestamp_within(as_of, mandate.spec.not_before, mandate.spec.not_after):
        raise CoreValidationError(
            f"proposal mandate {mandate_id!r} is not active at {as_of}: contexts "
            "inherit the mandate expiry and expiry fails closed"
        )
    model_ids_tuple = tuple(model_ids)
    for model_id in model_ids_tuple:
        registry.require_deployed(model_id)
    spec = ContextSpec(
        context_id=context_id,
        agent_principal=agent_principal,
        mandate_id=mandate_id,
        model_ids=model_ids_tuple,
        allowed_modes=tuple(allowed_modes),
        as_of=as_of,
    )
    if provenance is None:
        provenance = Provenance(
            issuer=mandate.spec.issued_by,
            source="agents/agent-context",
            recorded_at=as_of,
            evidence_refs=(mandate_id, *model_ids_tuple),
        )
    envelope = build_domain_envelope(
        object_id=spec.context_id,
        object_type=AGENT_CONTEXT_OBJECT_TYPE,
        state=AgentContextState.ACTIVE.value,
        environment_id=registry.environment_id,
        domain_id=registry.domain_id,
        provenance=provenance,
    )
    return AgentContext(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )
