"""Liquidity offers: bounded, windowed declarations of payment liquidity.

A :class:`LiquidityOffer` is a declarative record — provider plus a
REQUIRED opaque provider capability reference (WORK-009), optional
beneficiary, a corridor (source/target asset pair), an exact fixed-point
capacity denominated in the corridor's source asset, and a half-open
availability window. Liquidity is therefore a bounded capability/resource
model, never unbounded money creation: the capacity is an explicit
:meth:`~src.money.amount.Amount` and the provider capability reference
must be present.

The offer causes no effects and mutates no accounting state; consumption
(reservations, encumbrances, settlement) belongs to sibling domains. The
lifecycle follows the frozen ``Liquidity`` command family:
``Create/Amend/Withdraw/Suspend/Resume/Expire`` — deterministic state
machine transitions, each producing the next immutable object version.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.money import Amount

from .contracts import LIQUIDITY_OFFER_OBJECT_TYPE
from .corridors import Corridor
from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_optional_identifier,
    require_utc_timestamp,
    require_utc_window,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_OFFER_SPEC_FIELDS = frozenset(
    {
        "provider",
        "provider_capability_id",
        "beneficiary",
        "corridor",
        "capacity",
        "available_from",
        "available_until",
    }
)


class LiquidityOfferState(StrEnum):
    """Closed lifecycle vocabulary of a liquidity offer."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"


def require_capacity_matches_source_asset(
    name: str, corridor: Corridor, amount: Amount
) -> None:
    """Capacity/limits must be denominated in the corridor source asset.

    The liquidity domain references value-domain assets with the canonical
    opaque form ``asset/<CURRENCY-CODE>``; the fixed-point money authority
    (WORK-006) owns code and scale. An amount whose currency does not
    match the declared source asset fails closed instead of being silently
    coerced.
    """
    if not isinstance(amount, Amount):
        raise CoreValidationError(f"{name} must be an Amount, got {type(amount).__name__}")
    expected_asset = f"asset/{amount.currency.code}"
    if corridor.source_asset != expected_asset:
        raise CoreValidationError(
            f"{name} must be denominated in the corridor source asset "
            f"{corridor.source_asset!r}; got currency {amount.currency.code!r}"
        )


def require_positive_amount(name: str, amount: Amount) -> None:
    if not isinstance(amount, Amount):
        raise CoreValidationError(f"{name} must be an Amount, got {type(amount).__name__}")
    if not amount.is_positive():
        raise CoreValidationError(f"{name} must be positive; got {amount.to_dict()}")


@dataclass(frozen=True, slots=True)
class LiquidityOfferSpec:
    """Immutable liquidity offer payload."""

    provider: str
    provider_capability_id: str
    beneficiary: str | None
    corridor: Corridor
    capacity: Amount
    available_from: str
    available_until: str

    def __post_init__(self) -> None:
        require_identifier("offer.provider", self.provider)
        require_identifier("offer.provider_capability_id", self.provider_capability_id)
        require_optional_identifier("offer.beneficiary", self.beneficiary)
        if not isinstance(self.corridor, Corridor):
            raise CoreValidationError("offer.corridor must be a Corridor")
        require_positive_amount("offer.capacity", self.capacity)
        require_capacity_matches_source_asset("offer.capacity", self.corridor, self.capacity)
        require_utc_timestamp("offer.available_from", self.available_from)
        require_utc_timestamp("offer.available_until", self.available_until)
        require_utc_window(
            "offer.available", self.available_from, self.available_until
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_capability_id": self.provider_capability_id,
            "beneficiary": self.beneficiary,
            "corridor": self.corridor.to_dict(),
            "capacity": self.capacity.to_dict(),
            "available_from": self.available_from,
            "available_until": self.available_until,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LiquidityOfferSpec":
        strict_fields("offer", value, _OFFER_SPEC_FIELDS)
        return cls(
            provider=value["provider"],
            provider_capability_id=value["provider_capability_id"],
            beneficiary=value["beneficiary"],
            corridor=Corridor.from_dict(value["corridor"]),
            capacity=Amount.from_dict(value["capacity"]),
            available_from=value["available_from"],
            available_until=value["available_until"],
        )


@dataclass(frozen=True, slots=True)
class LiquidityOffer:
    """Durable liquidity offer record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: LiquidityOfferSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = LIQUIDITY_OFFER_OBJECT_TYPE
    STATE_TYPE = LiquidityOfferState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("offer envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, LiquidityOfferSpec):
            raise CoreValidationError("offer spec must be a LiquidityOfferSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != LIQUIDITY_OFFER_OBJECT_TYPE:
            raise CoreValidationError(
                f"offer object_type must be {LIQUIDITY_OFFER_OBJECT_TYPE!r}"
            )
        try:
            LiquidityOfferState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown offer state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> LiquidityOfferState:
        return LiquidityOfferState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LiquidityOffer":
        envelope, payload = decode_composite(
            value,
            expected_object_type=LIQUIDITY_OFFER_OBJECT_TYPE,
            state_type=LiquidityOfferState,
        )
        spec = LiquidityOfferSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "LiquidityOffer":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=LIQUIDITY_OFFER_OBJECT_TYPE,
            state_type=LiquidityOfferState,
        )
        spec = LiquidityOfferSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: LiquidityOfferState,
        *,
        provenance: Provenance,
        spec: LiquidityOfferSpec | None = None,
    ) -> "LiquidityOffer":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        payload = self.spec if spec is None else spec
        return LiquidityOffer(
            envelope=envelope, spec=payload, integrity_hash=seal_composite(envelope, payload)
        )


def create_liquidity_offer(
    *,
    offer_id: str,
    provider: str,
    provider_capability_id: str,
    beneficiary: str | None = None,
    corridor: Corridor,
    capacity: Amount,
    available_from: str,
    available_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> LiquidityOffer:
    """Create a sealed ACTIVE liquidity offer (the ``Create`` command)."""
    spec = LiquidityOfferSpec(
        provider=provider,
        provider_capability_id=provider_capability_id,
        beneficiary=beneficiary,
        corridor=corridor,
        capacity=capacity,
        available_from=available_from,
        available_until=available_until,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("offer.offer_id", offer_id),
        object_type=LIQUIDITY_OFFER_OBJECT_TYPE,
        state=LiquidityOfferState.ACTIVE.value,
        environment_id=require_identifier("offer.environment_id", environment_id),
        domain_id=require_identifier("offer.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return LiquidityOffer(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def liquidity_offer_available_at(offer: LiquidityOffer, as_of: str) -> bool:
    """Deterministic availability test: ACTIVE and inside the half-open window."""
    if not isinstance(offer, LiquidityOffer):
        raise CoreValidationError("availability test requires a LiquidityOffer")
    require_utc_timestamp("offer.as_of", as_of)
    if offer.state is not LiquidityOfferState.ACTIVE:
        return False
    return utc_timestamp_within(
        offer.spec.available_from, as_of, offer.spec.available_until
    )


def _require_offer(offer: LiquidityOffer) -> LiquidityOffer:
    if not isinstance(offer, LiquidityOffer):
        raise CoreValidationError("operation requires a LiquidityOffer")
    return offer


_AMENDABLE_FIELDS = ("capacity", "available_until")


def amend_liquidity_offer(
    offer: LiquidityOffer,
    *,
    provenance: Provenance,
    capacity: Amount | None = None,
    available_until: str | None = None,
) -> LiquidityOffer:
    """Amend economic terms of an ACTIVE offer (the ``Amend`` command).

    Identity (provider, capability reference, beneficiary, corridor,
    availability start, environment) is immutable; the amended payload is
    revalidated in full through the immutable spec constructor.
    """
    _require_offer(offer)
    if offer.state is not LiquidityOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE liquidity offer can be amended; state is "
            f"{offer.state.value}"
        )
    changes = {"capacity": capacity, "available_until": available_until}
    if all(value is None for value in changes.values()):
        raise CoreValidationError("offer amendment requires at least one new value")
    for name, value in changes.items():
        if value is not None and name not in _AMENDABLE_FIELDS:
            raise CoreValidationError(f"offer field {name} is not amendable")
    spec = replace(
        offer.spec,
        **{name: value for name, value in changes.items() if value is not None},
    )
    return offer._advance(LiquidityOfferState.ACTIVE, provenance=provenance, spec=spec)


def suspend_liquidity_offer(
    offer: LiquidityOffer, *, provenance: Provenance
) -> LiquidityOffer:
    """Suspend an ACTIVE offer (the ``Suspend`` command)."""
    _require_offer(offer)
    if offer.state is not LiquidityOfferState.ACTIVE:
        raise CoreValidationError(
            f"only an ACTIVE liquidity offer can be suspended; state is {offer.state.value}"
        )
    return offer._advance(LiquidityOfferState.SUSPENDED, provenance=provenance)


def resume_liquidity_offer(
    offer: LiquidityOffer, *, provenance: Provenance
) -> LiquidityOffer:
    """Resume a SUSPENDED offer (the ``Resume`` command)."""
    _require_offer(offer)
    if offer.state is not LiquidityOfferState.SUSPENDED:
        raise CoreValidationError(
            f"only a SUSPENDED liquidity offer can be resumed; state is {offer.state.value}"
        )
    return offer._advance(LiquidityOfferState.ACTIVE, provenance=provenance)


def withdraw_liquidity_offer(
    offer: LiquidityOffer, *, provenance: Provenance
) -> LiquidityOffer:
    """Withdraw an ACTIVE or SUSPENDED offer (the ``Withdraw`` command)."""
    _require_offer(offer)
    if offer.state not in (LiquidityOfferState.ACTIVE, LiquidityOfferState.SUSPENDED):
        raise CoreValidationError(
            "only an ACTIVE or SUSPENDED liquidity offer can be withdrawn; "
            f"state is {offer.state.value}"
        )
    return offer._advance(LiquidityOfferState.WITHDRAWN, provenance=provenance)


def expire_liquidity_offer(
    offer: LiquidityOffer, *, as_of: str, provenance: Provenance
) -> LiquidityOffer:
    """Expire an offer once its availability window has elapsed.

    System-trigger style transition driven by the explicit ``as_of``
    instant; it requires ``as_of >= available_until`` (fail closed
    otherwise).
    """
    _require_offer(offer)
    if offer.state not in (LiquidityOfferState.ACTIVE, LiquidityOfferState.SUSPENDED):
        raise CoreValidationError(
            "only an ACTIVE or SUSPENDED liquidity offer can expire; "
            f"state is {offer.state.value}"
        )
    if parse_utc_timestamp("offer.as_of", as_of) < parse_utc_timestamp(
        "offer.available_until", offer.spec.available_until
    ):
        raise CoreValidationError(
            "liquidity offer expiry requires as_of at or after available_until "
            f"({offer.spec.available_until}); got {as_of}"
        )
    return offer._advance(LiquidityOfferState.EXPIRED, provenance=provenance)
