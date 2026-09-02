"""Liquidity offers: standing, windowed quotes of liquidity supply.

A :class:`LiquidityOffer` is a declarative record — asset, amount bounds,
price in basis points, flat fee, availability window — optionally carrying
capability provenance references (opaque identifiers owned by the
capability domain, WORK-009). Offers cause no effects; they are the supply
side consumed by the RFQ default mechanism and the batch auction.

The lifecycle follows the frozen ``Liquidity`` command family:
``Create/Amend/Withdraw/Suspend/Resume/Expire`` — deterministic state
machine transitions, each producing the next immutable object version.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    LIQUIDITY_OFFER_OBJECT_TYPE,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
)
from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_int,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
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
        "asset",
        "amount_min",
        "amount_max",
        "scale",
        "price_bps",
        "flat_fee",
        "available_from",
        "available_until",
        "capability_commitment_id",
        "capability_id",
    }
)


class LiquidityOfferState(StrEnum):
    """Closed lifecycle vocabulary of a liquidity offer."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class LiquidityOfferSpec:
    """Immutable liquidity offer payload."""

    provider: str
    asset: str
    amount_min: int
    amount_max: int
    scale: int
    price_bps: int
    flat_fee: int
    available_from: str
    available_until: str
    capability_commitment_id: str | None = None
    capability_id: str | None = None

    def __post_init__(self) -> None:
        require_identifier("offer.provider", self.provider)
        require_identifier("offer.asset", self.asset)
        require_int("offer.amount_min", self.amount_min, minimum=0)
        require_int("offer.amount_max", self.amount_max, minimum=0)
        if self.amount_max < self.amount_min:
            raise CoreValidationError("offer.amount_max must not be below amount_min")
        require_int("offer.scale", self.scale, minimum=0, maximum=18)
        require_int("offer.price_bps", self.price_bps, minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS)
        require_int("offer.flat_fee", self.flat_fee, minimum=0)
        require_utc_timestamp("offer.available_from", self.available_from)
        require_utc_timestamp("offer.available_until", self.available_until)
        require_utc_timestamp_order(
            "offer.available_from", self.available_from,
            "offer.available_until", self.available_until,
        )
        if self.capability_commitment_id is not None:
            require_identifier("offer.capability_commitment_id", self.capability_commitment_id)
        if self.capability_id is not None:
            require_identifier("offer.capability_id", self.capability_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "asset": self.asset,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "scale": self.scale,
            "price_bps": self.price_bps,
            "flat_fee": self.flat_fee,
            "available_from": self.available_from,
            "available_until": self.available_until,
            "capability_commitment_id": self.capability_commitment_id,
            "capability_id": self.capability_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LiquidityOfferSpec":
        strict_fields("offer", value, _OFFER_SPEC_FIELDS)
        return cls(
            provider=value["provider"],
            asset=value["asset"],
            amount_min=value["amount_min"],
            amount_max=value["amount_max"],
            scale=value["scale"],
            price_bps=value["price_bps"],
            flat_fee=value["flat_fee"],
            available_from=value["available_from"],
            available_until=value["available_until"],
            capability_commitment_id=value["capability_commitment_id"],
            capability_id=value["capability_id"],
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
    asset: str,
    amount_min: int,
    amount_max: int,
    scale: int,
    price_bps: int,
    flat_fee: int,
    available_from: str,
    available_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    capability_commitment_id: str | None = None,
    capability_id: str | None = None,
    correlation_id: str | None = None,
) -> LiquidityOffer:
    """Create a sealed ACTIVE liquidity offer (the ``Create`` command)."""
    spec = LiquidityOfferSpec(
        provider=provider,
        asset=asset,
        amount_min=amount_min,
        amount_max=amount_max,
        scale=scale,
        price_bps=price_bps,
        flat_fee=flat_fee,
        available_from=available_from,
        available_until=available_until,
        capability_commitment_id=capability_commitment_id,
        capability_id=capability_id,
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


def _require_offer(offer: LiquidityOffer) -> LiquidityOffer:
    if not isinstance(offer, LiquidityOffer):
        raise CoreValidationError("operation requires a LiquidityOffer")
    return offer


_AMENDABLE_FIELDS = ("price_bps", "flat_fee", "amount_min", "amount_max")


def amend_liquidity_offer(
    offer: LiquidityOffer,
    *,
    provenance: Provenance,
    price_bps: int | None = None,
    flat_fee: int | None = None,
    amount_min: int | None = None,
    amount_max: int | None = None,
) -> LiquidityOffer:
    """Amend economic terms of an ACTIVE offer (the ``Amend`` command).

    Identity (provider, asset, scale, capability provenance references,
    environment) is immutable; the amended payload is revalidated in full
    through the immutable spec constructor.
    """
    _require_offer(offer)
    if offer.state is not LiquidityOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE liquidity offer can be amended; state is "
            f"{offer.state.value}"
        )
    changes = {
        "price_bps": price_bps,
        "flat_fee": flat_fee,
        "amount_min": amount_min,
        "amount_max": amount_max,
    }
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
