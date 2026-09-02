"""Intent: the authorized economic outcome PaySwap is asked to fulfill.

An intent declares a requested outcome — destination, scaled-integer amount,
hard deadline, funding binding, and references to the fulfillment policy and
economic slack objects that govern how the outcome may be fulfilled. The
intent object type ``payswap/intent/v1`` is registry-listed and therefore
protocol-visible.

Lifecycle (VERSIONED object), frozen by the command families in the
command/event model — Create/Authorize/Reject/Amend/Cancel/Suspend/Resume:

    DRAFT ----authorize----> AUTHORIZED ----suspend----> SUSPENDED
      |                        |    ^                      |
      |                        |    +-------resume--------+
      +--> REJECTED (terminal) |
      |                        +--> CANCELLED (terminal)
      +--> CANCELLED (terminal)
      (amend applies from DRAFT, AUTHORIZED and SUSPENDED; rejected and
       cancelled intents are terminal)

Transitions are pure functions producing new sealed versions; identity
fields are frozen by the core envelope, provenance and causation are
carried forward per command, and no wall clock is consulted anywhere.
Market selection and payment execution are out of scope (WORK-010/WORK-014
own them); demand derivation lives in ``demand.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from .amount import Amount
from .contracts import INTENT_OBJECT_TYPE
from .funding import FundingBinding
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
    require_timestamp,
    strict_fields,
)

_INTENT_SPEC_FIELDS = frozenset(
    {
        "destination_id",
        "amount",
        "deadline",
        "funding",
        "policy_id",
        "slack_id",
    }
)


class IntentState(StrEnum):
    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    REJECTED = "REJECTED"
    SUSPENDED = "SUSPENDED"
    CANCELLED = "CANCELLED"


_INTENT_COMMANDS: dict[str, dict[IntentState, IntentState]] = {
    "authorize": {IntentState.DRAFT: IntentState.AUTHORIZED},
    "reject": {IntentState.DRAFT: IntentState.REJECTED},
    "cancel": {
        IntentState.DRAFT: IntentState.CANCELLED,
        IntentState.AUTHORIZED: IntentState.CANCELLED,
        IntentState.SUSPENDED: IntentState.CANCELLED,
    },
    "suspend": {IntentState.AUTHORIZED: IntentState.SUSPENDED},
    "resume": {IntentState.SUSPENDED: IntentState.AUTHORIZED},
    "amend": {
        IntentState.DRAFT: IntentState.DRAFT,
        IntentState.AUTHORIZED: IntentState.AUTHORIZED,
        IntentState.SUSPENDED: IntentState.SUSPENDED,
    },
}


@dataclass(frozen=True, slots=True)
class IntentSpec:
    """Immutable requested-outcome declaration carried by an intent."""

    destination_id: str
    amount: Amount
    deadline: str
    funding: FundingBinding
    policy_id: str
    slack_id: str

    def __post_init__(self) -> None:
        require_identifier("intent.destination_id", self.destination_id)
        if not isinstance(self.amount, Amount):
            raise CoreValidationError("intent.amount must be an Amount")
        if self.amount.value < 1:
            raise CoreValidationError(
                "intent.amount must declare a positive outcome value"
            )
        require_timestamp("intent.deadline", self.deadline)
        if not isinstance(self.funding, FundingBinding):
            raise CoreValidationError("intent.funding must be a FundingBinding")
        require_identifier("intent.policy_id", self.policy_id)
        require_identifier("intent.slack_id", self.slack_id)
        for ref in self.funding.sources:
            if ref.cap is None:
                continue
            if ref.cap.asset != self.amount.asset:
                raise CoreValidationError(
                    f"funding cap for {ref.source_id} must use the intent amount "
                    f"asset {self.amount.asset}"
                )
            if ref.cap.scale != self.amount.scale:
                raise CoreValidationError(
                    f"funding cap for {ref.source_id} must use the intent amount scale "
                    f"{self.amount.scale}; cross-scale conversion is owned by the money domain"
                )

    def with_changes(self, changes: Mapping[str, Any]) -> "IntentSpec":
        if not isinstance(changes, Mapping):
            raise CoreValidationError("intent spec changes must be a mapping")
        unknown = sorted(set(changes) - _INTENT_SPEC_FIELDS)
        if unknown:
            raise CoreValidationError(f"unknown intent spec fields for amendment: {unknown}")
        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination_id": self.destination_id,
            "amount": self.amount.to_dict(),
            "deadline": self.deadline,
            "funding": self.funding.to_dict(),
            "policy_id": self.policy_id,
            "slack_id": self.slack_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IntentSpec":
        strict_fields("intent spec", value, _INTENT_SPEC_FIELDS)
        return cls(
            destination_id=value["destination_id"],
            amount=Amount.from_dict(value["amount"]),
            deadline=value["deadline"],
            funding=FundingBinding.from_dict(value["funding"]),
            policy_id=value["policy_id"],
            slack_id=value["slack_id"],
        )


@dataclass(frozen=True, slots=True)
class Intent:
    """Durable, versioned intent (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: IntentSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = INTENT_OBJECT_TYPE
    STATE_TYPE = IntentState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("intent envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, IntentSpec):
            raise CoreValidationError("intent spec must be an IntentSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != INTENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"intent object_type must be {INTENT_OBJECT_TYPE!r}"
            )
        try:
            IntentState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown intent state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: IntentSpec,
        provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "Intent":
        if not isinstance(spec, IntentSpec):
            raise CoreValidationError("intent spec must be an IntentSpec")
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=INTENT_OBJECT_TYPE,
            state=IntentState.DRAFT.value,
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
    def state(self) -> IntentState:
        return IntentState(self.envelope.state)

    def authorize(self, *, provenance, causation_id: str | None = None) -> "Intent":
        return self._command("authorize", provenance=provenance, causation_id=causation_id)

    def reject(self, *, provenance, causation_id: str | None = None) -> "Intent":
        return self._command("reject", provenance=provenance, causation_id=causation_id)

    def cancel(self, *, provenance, causation_id: str | None = None) -> "Intent":
        return self._command("cancel", provenance=provenance, causation_id=causation_id)

    def suspend(self, *, provenance, causation_id: str | None = None) -> "Intent":
        return self._command("suspend", provenance=provenance, causation_id=causation_id)

    def resume(self, *, provenance, causation_id: str | None = None) -> "Intent":
        return self._command("resume", provenance=provenance, causation_id=causation_id)

    def amend(
        self,
        *,
        provenance,
        causation_id: str | None = None,
        **spec_changes: Any,
    ) -> "Intent":
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
    ) -> "Intent":
        current = IntentState(self.envelope.state)
        transitions = _INTENT_COMMANDS[name]
        if current not in transitions:
            raise CoreValidationError(
                f"intent command {name!r} is not allowed from state {current.value}"
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
    def from_dict(cls, value: Mapping[str, Any]) -> "Intent":
        envelope, payload = decode_composite(
            value,
            expected_object_type=INTENT_OBJECT_TYPE,
            state_type=IntentState,
        )
        spec = IntentSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Intent":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=INTENT_OBJECT_TYPE,
            state_type=IntentState,
        )
        spec = IntentSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)
