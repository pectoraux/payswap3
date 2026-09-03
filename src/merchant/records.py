from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.value import Amount

from ._validation import fields, identifier, timestamp
from .contracts import ACCEPTANCE_OBJECT_TYPE, CHECKOUT_OBJECT_TYPE, PROMISE_OBJECT_TYPE, REFUND_ROUTE_OBJECT_TYPE, CheckoutState, PromiseState, RefundRouteState
from .seal import build_envelope, seal, verify


def _amount(value: Any) -> Amount:
    if isinstance(value, Amount):
        return value
    if isinstance(value, Mapping):
        return Amount.from_dict(value)
    raise CoreValidationError("merchant amount must be an Amount")


@dataclass(frozen=True, slots=True)
class CheckoutSpec:
    checkout_id: str
    merchant_id: str
    customer_id: str
    intent_id: str
    amount: Amount
    expires_at: str

    def __post_init__(self) -> None:
        for name, value in (("checkout_id", self.checkout_id), ("merchant_id", self.merchant_id), ("customer_id", self.customer_id), ("intent_id", self.intent_id)):
            identifier(name, value)
        if self.amount.value <= 0:
            raise CoreValidationError("checkout amount must be positive")
        timestamp("expires_at", self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {"checkout_id": self.checkout_id, "merchant_id": self.merchant_id, "customer_id": self.customer_id, "intent_id": self.intent_id, "amount": self.amount.to_dict(), "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CheckoutSpec":
        fields("checkout spec", value, {"checkout_id", "merchant_id", "customer_id", "intent_id", "amount", "expires_at"})
        return cls(value["checkout_id"], value["merchant_id"], value["customer_id"], value["intent_id"], _amount(value["amount"]), value["expires_at"])


@dataclass(frozen=True, slots=True)
class Checkout:
    envelope: ObjectEnvelope
    spec: CheckoutSpec
    integrity_hash: str

    def __post_init__(self) -> None:
        if self.envelope.object_type != CHECKOUT_OBJECT_TYPE:
            raise CoreValidationError("checkout object type mismatch")
        verify(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def create(cls, *, spec: CheckoutSpec, environment_id: str, domain_id: str, provenance: Provenance) -> "Checkout":
        envelope = build_envelope(object_id=spec.checkout_id, object_type=CHECKOUT_OBJECT_TYPE, state=CheckoutState.DRAFT.value, environment_id=environment_id, domain_id=domain_id, provenance=provenance)
        return cls(envelope, spec, seal(envelope, spec))

    def advance(self, state: CheckoutState, provenance: Provenance, command_id: str) -> "Checkout":
        allowed = {CheckoutState.DRAFT: {CheckoutState.ACCEPTED, CheckoutState.CANCELLED}, CheckoutState.ACCEPTED: {CheckoutState.PROMISED, CheckoutState.CANCELLED}, CheckoutState.PROMISED: {CheckoutState.COMPLETED, CheckoutState.CANCELLED}, CheckoutState.COMPLETED: set(), CheckoutState.CANCELLED: set()}
        current = CheckoutState(self.envelope.state)
        if state not in allowed[current]:
            raise CoreValidationError(f"invalid checkout transition {current.value} -> {state.value}")
        envelope = self.envelope.next_version(state=state.value, provenance=provenance, causation_id=command_id).with_integrity_hash()
        return Checkout(envelope, self.spec, seal(envelope, self.spec))

    def to_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope.to_dict(), "payload": self.spec.to_dict(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Checkout":
        fields("checkout", value, {"envelope", "payload", "integrity_hash"})
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        return cls(envelope, CheckoutSpec.from_dict(value["payload"]), value["integrity_hash"])


@dataclass(frozen=True, slots=True)
class Acceptance:
    envelope: ObjectEnvelope
    checkout_id: str
    merchant_id: str
    accepted_amount: Amount
    accepted_at: str
    integrity_hash: str

    @property
    def acceptance_id(self) -> str:
        return self.envelope.object_id

    def _payload(self) -> "AcceptancePayload":
        return AcceptancePayload(self.checkout_id, self.merchant_id, self.accepted_amount, self.accepted_at)

    def __post_init__(self) -> None:
        identifier("acceptance.checkout_id", self.checkout_id)
        identifier("acceptance.merchant_id", self.merchant_id)
        _amount(self.accepted_amount)
        timestamp("acceptance.accepted_at", self.accepted_at)
        verify(self.envelope, self._payload(), self.integrity_hash)

    @classmethod
    def create(cls, *, checkout: Checkout, merchant_id: str, provenance: Provenance, accepted_at: str) -> "Acceptance":
        if checkout.spec.merchant_id != merchant_id:
            raise CoreValidationError("merchant does not own checkout")
        payload = AcceptancePayload(checkout.spec.checkout_id, merchant_id, checkout.spec.amount, accepted_at)
        envelope = build_envelope(object_id=f"{checkout.spec.checkout_id}/acceptance", object_type=ACCEPTANCE_OBJECT_TYPE, state="ACCEPTED", environment_id=checkout.envelope.environment_id, domain_id=checkout.envelope.domain_id, provenance=provenance)
        return cls(envelope, checkout.spec.checkout_id, merchant_id, checkout.spec.amount, accepted_at, seal(envelope, payload))

    def to_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope.to_dict(), "payload": self._payload().to_dict(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Acceptance":
        fields("acceptance", value, {"envelope", "payload", "integrity_hash"})
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        payload = value["payload"]
        fields("acceptance payload", payload, {"checkout_id", "merchant_id", "accepted_amount", "accepted_at"})
        return cls(envelope, payload["checkout_id"], payload["merchant_id"], _amount(payload["accepted_amount"]), payload["accepted_at"], value["integrity_hash"])


@dataclass(frozen=True, slots=True)
class AcceptancePayload:
    checkout_id: str
    merchant_id: str
    accepted_amount: Amount
    accepted_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"checkout_id": self.checkout_id, "merchant_id": self.merchant_id, "accepted_amount": self.accepted_amount.to_dict(), "accepted_at": self.accepted_at}


@dataclass(frozen=True, slots=True)
class SettlementPromiseSpec:
    promise_id: str
    checkout_id: str
    settlement_id: str
    merchant_id: str
    amount: Amount
    credit_limit: Amount | None
    expires_at: str

    def __post_init__(self) -> None:
        for name, value in (("promise_id", self.promise_id), ("checkout_id", self.checkout_id), ("settlement_id", self.settlement_id), ("merchant_id", self.merchant_id)):
            identifier(name, value)
        if self.amount.value <= 0:
            raise CoreValidationError("promise amount must be positive")
        if self.credit_limit is not None:
            if self.credit_limit.asset != self.amount.asset or self.credit_limit.scale != self.amount.scale:
                raise CoreValidationError("credit limit must use same asset and scale")
            if self.amount.value > self.credit_limit.value:
                raise CoreValidationError("merchant credit limit exceeded")
        timestamp("promise.expires_at", self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {"promise_id": self.promise_id, "checkout_id": self.checkout_id, "settlement_id": self.settlement_id, "merchant_id": self.merchant_id, "amount": self.amount.to_dict(), "credit_limit": self.credit_limit.to_dict() if self.credit_limit is not None else None, "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SettlementPromiseSpec":
        fields("settlement promise spec", value, {"promise_id", "checkout_id", "settlement_id", "merchant_id", "amount", "credit_limit", "expires_at"})
        return cls(value["promise_id"], value["checkout_id"], value["settlement_id"], value["merchant_id"], _amount(value["amount"]), _amount(value["credit_limit"]) if value["credit_limit"] is not None else None, value["expires_at"])


@dataclass(frozen=True, slots=True)
class SettlementPromise:
    envelope: ObjectEnvelope
    spec: SettlementPromiseSpec
    integrity_hash: str

    def __post_init__(self) -> None:
        if self.envelope.object_type != PROMISE_OBJECT_TYPE:
            raise CoreValidationError("settlement promise object type mismatch")
        verify(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def create(cls, *, spec: SettlementPromiseSpec, environment_id: str, domain_id: str, provenance: Provenance) -> "SettlementPromise":
        envelope = build_envelope(object_id=spec.promise_id, object_type=PROMISE_OBJECT_TYPE, state=PromiseState.PENDING.value, environment_id=environment_id, domain_id=domain_id, provenance=provenance)
        return cls(envelope, spec, seal(envelope, spec))

    def advance(self, state: PromiseState, provenance: Provenance, command_id: str) -> "SettlementPromise":
        allowed = {PromiseState.PENDING: {PromiseState.CREDITED, PromiseState.SETTLED, PromiseState.EXPIRED, PromiseState.CANCELLED}, PromiseState.CREDITED: {PromiseState.SETTLED, PromiseState.EXPIRED, PromiseState.CANCELLED}, PromiseState.SETTLED: set(), PromiseState.EXPIRED: set(), PromiseState.CANCELLED: set()}
        current = PromiseState(self.envelope.state)
        if state not in allowed[current]:
            raise CoreValidationError(f"invalid promise transition {current.value} -> {state.value}")
        envelope = self.envelope.next_version(state=state.value, provenance=provenance, causation_id=command_id).with_integrity_hash()
        return SettlementPromise(envelope, self.spec, seal(envelope, self.spec))

    def to_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope.to_dict(), "payload": self.spec.to_dict(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SettlementPromise":
        fields("settlement promise", value, {"envelope", "payload", "integrity_hash"})
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        return cls(envelope, SettlementPromiseSpec.from_dict(value["payload"]), value["integrity_hash"])


@dataclass(frozen=True, slots=True)
class RefundRoute:
    envelope: ObjectEnvelope
    checkout_id: str
    merchant_id: str
    route_id: str
    settlement_id: str
    max_refund: Amount
    integrity_hash: str

    def _payload(self) -> "RefundPayload":
        return RefundPayload(self.checkout_id, self.merchant_id, self.route_id, self.settlement_id, self.max_refund)

    def __post_init__(self) -> None:
        for name, value in (("refund.checkout_id", self.checkout_id), ("refund.merchant_id", self.merchant_id), ("refund.route_id", self.route_id), ("refund.settlement_id", self.settlement_id)):
            identifier(name, value)
        if self.max_refund.value <= 0:
            raise CoreValidationError("refund amount must be positive")
        verify(self.envelope, self._payload(), self.integrity_hash)

    @classmethod
    def create(cls, *, checkout: Checkout, route_id: str, settlement_id: str, provenance: Provenance) -> "RefundRoute":
        payload = RefundPayload(checkout.spec.checkout_id, checkout.spec.merchant_id, route_id, settlement_id, checkout.spec.amount)
        envelope = build_envelope(object_id=route_id, object_type=REFUND_ROUTE_OBJECT_TYPE, state=RefundRouteState.OPEN.value, environment_id=checkout.envelope.environment_id, domain_id=checkout.envelope.domain_id, provenance=provenance)
        return cls(envelope, checkout.spec.checkout_id, checkout.spec.merchant_id, route_id, settlement_id, checkout.spec.amount, seal(envelope, payload))

    def to_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope.to_dict(), "payload": self._payload().to_dict(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RefundRoute":
        fields("refund route", value, {"envelope", "payload", "integrity_hash"})
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        payload = value["payload"]
        fields("refund payload", payload, {"checkout_id", "merchant_id", "route_id", "settlement_id", "max_refund"})
        return cls(envelope, payload["checkout_id"], payload["merchant_id"], payload["route_id"], payload["settlement_id"], _amount(payload["max_refund"]), value["integrity_hash"])


@dataclass(frozen=True, slots=True)
class RefundPayload:
    checkout_id: str
    merchant_id: str
    route_id: str
    settlement_id: str
    max_refund: Amount

    def to_dict(self) -> dict[str, Any]:
        return {"checkout_id": self.checkout_id, "merchant_id": self.merchant_id, "route_id": self.route_id, "settlement_id": self.settlement_id, "max_refund": self.max_refund.to_dict()}
