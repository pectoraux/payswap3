"""Fulfillment policy: objective ranking and hard substitution constraints.

The optimization dimensions are exactly the list frozen in the constitution
(``route, time, amount/payment shape, liquidity, credit, reliability, risk,
privacy and cost``). The policy ranks them deterministically (a strict
permutation, first = highest priority) and declares hard constraints that
the fulfillment compiler (WORK-013) must respect. Compliance is never a
policy parameter: compliance cannot be bypassed through routing, so no
policy field can weaken it.

Lifecycle (VERSIONED object): ACTIVE -> RETIRED, with in-place amendments
producing new sealed versions. Object type ``intent/policy`` is an internal
(non-registry) domain identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from .contracts import FULFILLMENT_POLICY_OBJECT_TYPE
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import require_bool, strict_fields

_POLICY_SPEC_FIELDS = frozenset(
    {"objectives", "allow_split", "allow_asset_substitution", "allow_route_substitution"}
)


class OptimizationObjective(StrEnum):
    """Closed optimization vocabulary frozen by the constitution."""

    ROUTE = "ROUTE"
    TIME = "TIME"
    AMOUNT = "AMOUNT"
    PAYMENT_SHAPE = "PAYMENT_SHAPE"
    LIQUIDITY = "LIQUIDITY"
    CREDIT = "CREDIT"
    RELIABILITY = "RELIABILITY"
    RISK = "RISK"
    PRIVACY = "PRIVACY"
    COST = "COST"


class PolicyState(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


_POLICY_COMMANDS: dict[str, dict[PolicyState, PolicyState]] = {
    "retire": {PolicyState.ACTIVE: PolicyState.RETIRED},
    "amend": {PolicyState.ACTIVE: PolicyState.ACTIVE},
}


def _convert_objective(item: Any) -> OptimizationObjective:
    if isinstance(item, OptimizationObjective):
        return item
    if isinstance(item, str):
        try:
            return OptimizationObjective(item)
        except ValueError as exc:
            raise CoreValidationError(f"unknown optimization objective {item!r}") from exc
    raise CoreValidationError(
        "policy objectives must be strings or OptimizationObjective members"
    )


@dataclass(frozen=True, slots=True)
class PolicySpec:
    """Immutable fulfillment policy payload."""

    objectives: tuple[OptimizationObjective, ...]
    allow_split: bool
    allow_asset_substitution: bool
    allow_route_substitution: bool

    def __post_init__(self) -> None:
        if not isinstance(self.objectives, tuple):
            raise CoreValidationError("policy.objectives must be a tuple")
        if not self.objectives:
            raise CoreValidationError("policy.objectives must rank at least one objective")
        seen: list[OptimizationObjective] = []
        for objective in self.objectives:
            if not isinstance(objective, OptimizationObjective):
                raise CoreValidationError(
                    "policy.objectives must use the closed OptimizationObjective vocabulary"
                )
            if objective in seen:
                raise CoreValidationError(
                    f"policy.objectives must be a strict ranking; {objective.value} repeats"
                )
            seen.append(objective)
        require_bool("policy.allow_split", self.allow_split)
        require_bool("policy.allow_asset_substitution", self.allow_asset_substitution)
        require_bool("policy.allow_route_substitution", self.allow_route_substitution)

    @classmethod
    def build(
        cls,
        *,
        objectives: Iterable[Any],
        allow_split: bool,
        allow_asset_substitution: bool,
        allow_route_substitution: bool,
    ) -> "PolicySpec":
        if not isinstance(objectives, (list, tuple)):
            raise CoreValidationError("policy objectives must be provided as a sequence")
        return cls(
            objectives=tuple(_convert_objective(item) for item in objectives),
            allow_split=allow_split,
            allow_asset_substitution=allow_asset_substitution,
            allow_route_substitution=allow_route_substitution,
        )

    def with_changes(self, changes: Mapping[str, Any]) -> "PolicySpec":
        if not isinstance(changes, Mapping):
            raise CoreValidationError("fulfillment policy changes must be a mapping")
        unknown = sorted(set(changes) - _POLICY_SPEC_FIELDS)
        if unknown:
            raise CoreValidationError(
                f"unknown fulfillment policy fields for amendment: {unknown}"
            )
        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objectives": [objective.value for objective in self.objectives],
            "allow_split": self.allow_split,
            "allow_asset_substitution": self.allow_asset_substitution,
            "allow_route_substitution": self.allow_route_substitution,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicySpec":
        strict_fields("fulfillment policy", value, _POLICY_SPEC_FIELDS)
        objectives = value["objectives"]
        if not isinstance(objectives, list):
            raise CoreValidationError("policy.objectives must deserialize from an array")
        return cls(
            objectives=tuple(_convert_objective(item) for item in objectives),
            allow_split=value["allow_split"],
            allow_asset_substitution=value["allow_asset_substitution"],
            allow_route_substitution=value["allow_route_substitution"],
        )


@dataclass(frozen=True, slots=True)
class FulfillmentPolicy:
    """Durable, versioned fulfillment policy (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: PolicySpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FULFILLMENT_POLICY_OBJECT_TYPE
    STATE_TYPE = PolicyState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("fulfillment policy envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, PolicySpec):
            raise CoreValidationError("fulfillment policy spec must be a PolicySpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != FULFILLMENT_POLICY_OBJECT_TYPE:
            raise CoreValidationError(
                f"fulfillment policy object_type must be {FULFILLMENT_POLICY_OBJECT_TYPE!r}"
            )
        try:
            PolicyState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown fulfillment policy state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: PolicySpec,
        provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "FulfillmentPolicy":
        if not isinstance(spec, PolicySpec):
            raise CoreValidationError("fulfillment policy spec must be a PolicySpec")
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=FULFILLMENT_POLICY_OBJECT_TYPE,
            state=PolicyState.ACTIVE.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> PolicyState:
        return PolicyState(self.envelope.state)

    def retire(self, *, provenance, causation_id: str | None = None) -> "FulfillmentPolicy":
        return self._command("retire", provenance=provenance, causation_id=causation_id)

    def amend(
        self,
        *,
        provenance,
        causation_id: str | None = None,
        **spec_changes: Any,
    ) -> "FulfillmentPolicy":
        return self._command(
            "amend", provenance=provenance, causation_id=causation_id,
            spec_changes=spec_changes,
        )

    def _command(
        self,
        name: str,
        *,
        provenance,
        causation_id: str | None = None,
        spec_changes: Mapping[str, Any] | None = None,
    ) -> "FulfillmentPolicy":
        current = PolicyState(self.envelope.state)
        transitions = _POLICY_COMMANDS[name]
        if current not in transitions:
            raise CoreValidationError(
                f"fulfillment policy command {name!r} is not allowed from state {current.value}"
            )
        spec = self.spec.with_changes(spec_changes or {})
        envelope = advance_envelope(
            self.envelope,
            state=transitions[current].value,
            provenance=provenance,
            causation_id=causation_id,
        )
        return type(self)(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FulfillmentPolicy":
        envelope, payload = decode_composite(
            value,
            expected_object_type=FULFILLMENT_POLICY_OBJECT_TYPE,
            state_type=PolicyState,
        )
        spec = PolicySpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "FulfillmentPolicy":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=FULFILLMENT_POLICY_OBJECT_TYPE,
            state_type=PolicyState,
        )
        spec = PolicySpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)
