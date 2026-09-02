"""Economic slack: the permitted flexibility around a requested outcome.

ECON-002 freezes the idea that fulfillment optimizes time, amount, route,
liquidity and credit *within slack*. The slack object declares:

- an amount window in a single asset and scale that must bracket the
  intent amount (same-scale bound checks only; cross-scale conversion is
  money-domain work, WORK-006);
- a completion window whose latest bound may never relax an intent's hard
  deadline (validated at demand derivation);
- a payment-count bound for splitting;
- substitute assets that differ from the window's base asset.

Lifecycle (VERSIONED object): ACTIVE -> RETIRED with in-place amendments.
Object type ``intent/slack`` is an internal (non-registry) identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from .amount import Amount
from .contracts import ECONOMIC_SLACK_OBJECT_TYPE
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import (
    require_identifier,
    require_int,
    require_str_tuple,
    require_timestamp,
    require_timestamp_order,
    strict_fields,
)

_SLACK_SPEC_FIELDS = frozenset(
    {
        "amount_min",
        "amount_max",
        "earliest_completion",
        "latest_completion",
        "max_payment_count",
        "substitute_assets",
    }
)


class SlackState(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


_SLACK_COMMANDS: dict[str, dict[SlackState, SlackState]] = {
    "retire": {SlackState.ACTIVE: SlackState.RETIRED},
    "amend": {SlackState.ACTIVE: SlackState.ACTIVE},
}


@dataclass(frozen=True, slots=True)
class SlackSpec:
    """Immutable economic slack payload."""

    amount_min: Amount
    amount_max: Amount
    earliest_completion: str
    latest_completion: str
    max_payment_count: int
    substitute_assets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("amount_min", "amount_max"):
            if not isinstance(getattr(self, name), Amount):
                raise CoreValidationError(f"economic slack {name} must be an Amount")
        if self.amount_min.asset != self.amount_max.asset:
            raise CoreValidationError(
                "economic slack amount window must use a single asset"
            )
        if self.amount_min.scale != self.amount_max.scale:
            raise CoreValidationError(
                "economic slack amount window must use a single scale; "
                "cross-scale comparison is owned by the money domain"
            )
        if self.amount_min.value > self.amount_max.value:
            raise CoreValidationError(
                "economic slack amount_min must not exceed amount_max"
            )
        require_timestamp("slack.earliest_completion", self.earliest_completion)
        require_timestamp("slack.latest_completion", self.latest_completion)
        require_timestamp_order(
            "slack.earliest_completion",
            self.earliest_completion,
            "slack.latest_completion",
            self.latest_completion,
        )
        require_int("slack.max_payment_count", self.max_payment_count, minimum=1)
        if not isinstance(self.substitute_assets, tuple):
            raise CoreValidationError("slack.substitute_assets must be a tuple")
        substitutes = require_str_tuple(
            "slack.substitute_assets", self.substitute_assets, identifier=True
        )
        for asset in substitutes:
            if asset == self.amount_min.asset:
                raise CoreValidationError(
                    "substitute assets must differ from the economic slack base asset"
                )

    def with_changes(self, changes: Mapping[str, Any]) -> "SlackSpec":
        if not isinstance(changes, Mapping):
            raise CoreValidationError("economic slack changes must be a mapping")
        unknown = sorted(set(changes) - _SLACK_SPEC_FIELDS)
        if unknown:
            raise CoreValidationError(
                f"unknown economic slack fields for amendment: {unknown}"
            )
        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "amount_min": self.amount_min.to_dict(),
            "amount_max": self.amount_max.to_dict(),
            "earliest_completion": self.earliest_completion,
            "latest_completion": self.latest_completion,
            "max_payment_count": self.max_payment_count,
            "substitute_assets": list(self.substitute_assets),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SlackSpec":
        strict_fields("economic slack", value, _SLACK_SPEC_FIELDS)
        substitutes = value["substitute_assets"]
        if not isinstance(substitutes, list):
            raise CoreValidationError(
                "slack.substitute_assets must deserialize from an array"
            )
        return cls(
            amount_min=Amount.from_dict(value["amount_min"]),
            amount_max=Amount.from_dict(value["amount_max"]),
            earliest_completion=value["earliest_completion"],
            latest_completion=value["latest_completion"],
            max_payment_count=value["max_payment_count"],
            substitute_assets=tuple(substitutes),
        )


@dataclass(frozen=True, slots=True)
class EconomicSlack:
    """Durable, versioned economic slack (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: SlackSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = ECONOMIC_SLACK_OBJECT_TYPE
    STATE_TYPE = SlackState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("economic slack envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, SlackSpec):
            raise CoreValidationError("economic slack spec must be a SlackSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != ECONOMIC_SLACK_OBJECT_TYPE:
            raise CoreValidationError(
                f"economic slack object_type must be {ECONOMIC_SLACK_OBJECT_TYPE!r}"
            )
        try:
            SlackState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown economic slack state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: SlackSpec,
        provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "EconomicSlack":
        if not isinstance(spec, SlackSpec):
            raise CoreValidationError("economic slack spec must be a SlackSpec")
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=ECONOMIC_SLACK_OBJECT_TYPE,
            state=SlackState.ACTIVE.value,
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
    def state(self) -> SlackState:
        return SlackState(self.envelope.state)

    def retire(self, *, provenance, causation_id: str | None = None) -> "EconomicSlack":
        return self._command("retire", provenance=provenance, causation_id=causation_id)

    def amend(
        self,
        *,
        provenance,
        causation_id: str | None = None,
        **spec_changes: Any,
    ) -> "EconomicSlack":
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
    ) -> "EconomicSlack":
        current = SlackState(self.envelope.state)
        transitions = _SLACK_COMMANDS[name]
        if current not in transitions:
            raise CoreValidationError(
                f"economic slack command {name!r} is not allowed from state {current.value}"
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
    def from_dict(cls, value: Mapping[str, Any]) -> "EconomicSlack":
        envelope, payload = decode_composite(
            value,
            expected_object_type=ECONOMIC_SLACK_OBJECT_TYPE,
            state_type=SlackState,
        )
        spec = SlackSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "EconomicSlack":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=ECONOMIC_SLACK_OBJECT_TYPE,
            state_type=SlackState,
        )
        spec = SlackSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)
