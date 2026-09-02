"""Demand: the network-visible economic ask derived from an authorized intent.

The constitution's purpose — "transforms an authorized economic intent into
the best achievable fulfillment" — starts by deriving, from an authorized
intent together with the fulfillment policy and economic slack it
references, a demand signal stating what the network is being asked to
supply: destination, asset and amount window, completion window, split
bounds and substitute assets, plus the deterministic demand class.

Derivation is a pure deterministic function: same inputs, same outputs, no
wall clock, no market selection (WORK-010 owns markets) and no payment
execution (WORK-014 owns execution). Derived objects never outrank their
source of truth: the demand depends on the intent, and withdrawal follows
intent cancellation or suspension. Policy stays with the intent owner and
is deliberately not leaked onto the demand signal (selective disclosure).

Fail-closed coherence checks at derivation: the intent must be AUTHORIZED;
the supplied policy and slack must be exactly the referenced, active
objects; the amount window must use the intent amount's asset and scale and
bracket it; the completion window may not relax the intent's hard deadline;
policy constraints and slack flexibility must agree on splits and asset
substitution. Object type ``intent/demand`` is an internal (non-registry)
identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from .amount import MAX_SCALE
from .contracts import DEMAND_OBJECT_TYPE
from .demand_class import DemandShape, UrgencyClass, demand_class_id, urgency_for_window
from .intent import Intent, IntentState
from .policy import FulfillmentPolicy, PolicyState
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .slack import EconomicSlack, SlackState
from .validation import (
    parse_timestamp,
    require_bool,
    require_identifier,
    require_int,
    require_str_tuple,
    require_timestamp,
    require_timestamp_order,
    strict_fields,
)

_DEMAND_SPEC_FIELDS = frozenset(
    {
        "intent_id",
        "intent_version",
        "destination_id",
        "asset",
        "amount_min",
        "amount_max",
        "amount_scale",
        "earliest_completion",
        "latest_completion",
        "allow_split",
        "max_payment_count",
        "substitute_assets",
        "demand_class_id",
    }
)


class DemandState(StrEnum):
    OPEN = "OPEN"
    WITHDRAWN = "WITHDRAWN"


@dataclass(frozen=True, slots=True)
class DemandSpec:
    """Immutable demand payload: the derived economic ask."""

    intent_id: str
    intent_version: int
    destination_id: str
    asset: str
    amount_min: int
    amount_max: int
    amount_scale: int
    earliest_completion: str
    latest_completion: str
    allow_split: bool
    max_payment_count: int
    substitute_assets: tuple[str, ...]
    demand_class_id: str

    def __post_init__(self) -> None:
        require_identifier("demand.intent_id", self.intent_id)
        require_int("demand.intent_version", self.intent_version, minimum=1)
        require_identifier("demand.destination_id", self.destination_id)
        require_identifier("demand.asset", self.asset)
        require_int("demand.amount_min", self.amount_min, minimum=0)
        require_int("demand.amount_max", self.amount_max, minimum=0)
        if self.amount_max < self.amount_min:
            raise CoreValidationError("demand.amount_max must not be below amount_min")
        require_int("demand.amount_scale", self.amount_scale, minimum=0, maximum=MAX_SCALE)
        require_timestamp("demand.earliest_completion", self.earliest_completion)
        require_timestamp("demand.latest_completion", self.latest_completion)
        require_timestamp_order(
            "demand.earliest_completion",
            self.earliest_completion,
            "demand.latest_completion",
            self.latest_completion,
        )
        require_bool("demand.allow_split", self.allow_split)
        require_int("demand.max_payment_count", self.max_payment_count, minimum=1)
        if not self.allow_split and self.max_payment_count != 1:
            raise CoreValidationError(
                "a non-splittable demand must bound payments to exactly 1"
            )
        require_str_tuple("demand.substitute_assets", self.substitute_assets, identifier=True)
        require_identifier("demand.demand_class_id", self.demand_class_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "intent_version": self.intent_version,
            "destination_id": self.destination_id,
            "asset": self.asset,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "amount_scale": self.amount_scale,
            "earliest_completion": self.earliest_completion,
            "latest_completion": self.latest_completion,
            "allow_split": self.allow_split,
            "max_payment_count": self.max_payment_count,
            "substitute_assets": list(self.substitute_assets),
            "demand_class_id": self.demand_class_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DemandSpec":
        strict_fields("demand", value, _DEMAND_SPEC_FIELDS)
        substitutes = value["substitute_assets"]
        if not isinstance(substitutes, list):
            raise CoreValidationError(
                "demand.substitute_assets must deserialize from an array"
            )
        return cls(
            intent_id=value["intent_id"],
            intent_version=value["intent_version"],
            destination_id=value["destination_id"],
            asset=value["asset"],
            amount_min=value["amount_min"],
            amount_max=value["amount_max"],
            amount_scale=value["amount_scale"],
            earliest_completion=value["earliest_completion"],
            latest_completion=value["latest_completion"],
            allow_split=value["allow_split"],
            max_payment_count=value["max_payment_count"],
            substitute_assets=tuple(substitutes),
            demand_class_id=value["demand_class_id"],
        )


@dataclass(frozen=True, slots=True)
class Demand:
    """Durable DERIVED demand (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: DemandSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = DEMAND_OBJECT_TYPE
    STATE_TYPE = DemandState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("demand envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, DemandSpec):
            raise CoreValidationError("demand spec must be a DemandSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != DEMAND_OBJECT_TYPE:
            raise CoreValidationError(
                f"demand object_type must be {DEMAND_OBJECT_TYPE!r}"
            )
        try:
            DemandState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown demand state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> DemandState:
        return DemandState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Demand":
        envelope, payload = decode_composite(
            value,
            expected_object_type=DEMAND_OBJECT_TYPE,
            state_type=DemandState,
        )
        spec = DemandSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Demand":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=DEMAND_OBJECT_TYPE,
            state_type=DemandState,
        )
        spec = DemandSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def derive_demand(
    intent: Intent,
    *,
    slack: EconomicSlack,
    policy: FulfillmentPolicy,
    provenance,
    previous: Demand | None = None,
) -> Demand:
    """Derive the demand of an authorized intent from its policy and slack.

    Deterministic: the same intent, policy, slack and provenance always
    produce the same demand. With ``previous`` (an open demand of the same
    intent) the derivation produces the next demand version instead.
    """
    if not isinstance(intent, Intent):
        raise CoreValidationError("derive_demand requires an Intent")
    if not isinstance(slack, EconomicSlack):
        raise CoreValidationError("derive_demand requires an EconomicSlack")
    if not isinstance(policy, FulfillmentPolicy):
        raise CoreValidationError("derive_demand requires a FulfillmentPolicy")

    current = IntentState(intent.envelope.state)
    if current is not IntentState.AUTHORIZED:
        raise CoreValidationError(
            f"demand may only be derived from an authorized intent; state is {current.value}"
        )
    if slack.envelope.object_id != intent.spec.slack_id:
        raise CoreValidationError(
            f"intent references slack {intent.spec.slack_id} but "
            f"{slack.envelope.object_id} was supplied"
        )
    if policy.envelope.object_id != intent.spec.policy_id:
        raise CoreValidationError(
            f"intent references policy {intent.spec.policy_id} but "
            f"{policy.envelope.object_id} was supplied"
        )
    if policy.envelope.state != PolicyState.ACTIVE.value:
        raise CoreValidationError(
            f"fulfillment policy {policy.envelope.object_id} is not active"
        )
    if slack.envelope.state != SlackState.ACTIVE.value:
        raise CoreValidationError(
            f"economic slack {slack.envelope.object_id} is not active"
        )

    window = slack.spec
    base = intent.spec.amount
    if window.amount_min.asset != base.asset:
        raise CoreValidationError(
            "economic slack amount window must use the intent amount asset"
        )
    if window.amount_min.scale != base.scale:
        raise CoreValidationError(
            "economic slack amount window must use the intent amount scale"
        )
    if base.value < window.amount_min.value or base.value > window.amount_max.value:
        raise CoreValidationError(
            "economic slack amount window must bracket the intent amount"
        )
    if not policy.spec.allow_split and window.max_payment_count != 1:
        raise CoreValidationError(
            "fulfillment policy forbids splits but economic slack permits multiple payments"
        )
    if not policy.spec.allow_asset_substitution and window.substitute_assets:
        raise CoreValidationError(
            "fulfillment policy forbids asset substitution but economic slack "
            "declares substitute assets"
        )
    if parse_timestamp("slack.latest_completion", window.latest_completion) > parse_timestamp(
        "intent.deadline", intent.spec.deadline
    ):
        raise CoreValidationError(
            "economic slack latest completion must not relax the intent deadline"
        )

    urgency = urgency_for_window(window.earliest_completion, window.latest_completion)
    shape = DemandShape.SPLIT if policy.spec.allow_split else DemandShape.SINGLE
    spec = DemandSpec(
        intent_id=intent.envelope.object_id,
        intent_version=intent.envelope.object_version,
        destination_id=intent.spec.destination_id,
        asset=base.asset,
        amount_min=window.amount_min.value,
        amount_max=window.amount_max.value,
        amount_scale=window.amount_min.scale,
        earliest_completion=window.earliest_completion,
        latest_completion=window.latest_completion,
        allow_split=policy.spec.allow_split,
        max_payment_count=window.max_payment_count,
        substitute_assets=window.substitute_assets,
        demand_class_id=demand_class_id(base.asset, urgency, shape),
    )
    object_id = f"{intent.envelope.object_id}/demand"

    if previous is None:
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=DEMAND_OBJECT_TYPE,
            state=DemandState.OPEN.value,
            environment_id=intent.envelope.environment_id,
            domain_id=intent.envelope.domain_id,
            provenance=provenance,
            causation_id=intent.envelope.object_id,
            correlation_id=intent.envelope.correlation_id,
        )
    else:
        if not isinstance(previous, Demand):
            raise CoreValidationError("previous demand must be a Demand")
        if previous.spec.intent_id != intent.envelope.object_id:
            raise CoreValidationError(
                "previous demand belongs to a different intent"
            )
        if previous.envelope.state != DemandState.OPEN.value:
            raise CoreValidationError(
                "only an open demand can be re-derived; a withdrawn demand "
                "requires a new intent generation"
            )
        if intent.envelope.object_version < previous.spec.intent_version:
            raise CoreValidationError(
                "demand re-derivation requires an intent version at least as "
                "new as the previous derivation"
            )
        envelope = advance_envelope(
            previous.envelope,
            state=DemandState.OPEN.value,
            provenance=provenance,
            causation_id=intent.envelope.object_id,
        )
    return Demand(envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec))


def withdraw_demand(
    demand: Demand,
    *,
    provenance,
    causation_id: str | None = None,
) -> Demand:
    """Withdraw an open demand (e.g. the intent was suspended or cancelled)."""
    if not isinstance(demand, Demand):
        raise CoreValidationError("withdraw_demand requires a Demand")
    if demand.envelope.state != DemandState.OPEN.value:
        raise CoreValidationError(
            f"a withdrawn demand cannot be withdrawn again; state is {demand.envelope.state}"
        )
    envelope = advance_envelope(
        demand.envelope,
        state=DemandState.WITHDRAWN.value,
        provenance=provenance,
        causation_id=causation_id,
    )
    return Demand(
        envelope=envelope, spec=demand.spec, integrity_hash=seal_composite(envelope, demand.spec)
    )
