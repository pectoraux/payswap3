"""Firm quotes: the RFQ default mechanism's bilateral price promise.

A :class:`Quote` is a firm, windowed price promise from one maker toward
one demand: asset, amount window, price in basis points, flat fee and an
explicit validity window. The lifecycle implements the frozen ``Quote``
command family ``Create/Amend/Accept/Reject/Commit/Cancel/Expire/
Invalidate`` with fail-closed staleness and validity enforcement at every
step:

- acceptance and commitment are only possible strictly inside the
  validity window (half-open ``[valid_from, valid_until)``);
- expiry requires the window to have elapsed (``as_of >= valid_until``);
- the minimum quote validity guard rejects flicker quotes;
- the maker may never accept its own quote (self-dealing guard);
- a committed quote is terminal — commit/cancel/expire/invalidate all
  fail closed afterwards.

Committing an accepted quote produces the exact market reservation
(the ``Reservation`` record of the amount actually taken).

``request_quote`` is the RFQ default direct-accept mechanism over
standing liquidity offers: it deterministically selects the best
eligible offer (cheapest ``(price, flat fee)``) whose amount window
brackets the demand minimum and whose availability covers the default
quote validity, and issues the corresponding firm quote.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.intent import Demand, DemandState

from .contracts import (
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    LIQUIDITY_OFFER_OBJECT_TYPE,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
    MIN_QUOTE_VALIDITY_SECONDS,
    QUOTE_OBJECT_TYPE,
)
from ._validation import (
    offset_utc_timestamp,
    parse_utc_timestamp,
    require_identifier,
    require_int,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
    utc_timestamp_within,
)
from .offers import LiquidityOffer, LiquidityOfferState
from .reservations import Reservation, create_reservation
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_QUOTE_SPEC_FIELDS = frozenset(
    {
        "demand_id",
        "maker",
        "asset",
        "amount_min",
        "amount_max",
        "scale",
        "price_bps",
        "flat_fee",
        "valid_from",
        "valid_until",
        "offer_id",
        "taker",
        "reason",
    }
)

#: Reasons that may be recorded by the terminal invalidation command:
#: external causes plus the taker-side decline of a market-level
#: allocation (the maker's own cancellation and expiry use their own
#: dedicated commands).
INVALIDATION_REASONS = frozenset(
    {
        "TAKER_DECLINED",
        "OFFER_WITHDRAWN",
        "OFFER_SUSPENDED",
        "CAPABILITY_UNAVAILABLE",
    }
)


class QuoteState(StrEnum):
    """Closed lifecycle vocabulary of a firm quote."""

    FIRM = "FIRM"
    ACCEPTED = "ACCEPTED"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


class QuoteReasonCode(StrEnum):
    """Closed vocabulary of typed quote terminal reasons."""

    TAKER_DECLINED = "TAKER_DECLINED"
    MAKER_CANCELLED = "MAKER_CANCELLED"
    QUOTE_EXPIRED = "QUOTE_EXPIRED"
    OFFER_WITHDRAWN = "OFFER_WITHDRAWN"
    OFFER_SUSPENDED = "OFFER_SUSPENDED"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class QuoteSpec:
    """Immutable firm quote payload."""

    demand_id: str
    maker: str
    asset: str
    amount_min: int
    amount_max: int
    scale: int
    price_bps: int
    flat_fee: int
    valid_from: str
    valid_until: str
    offer_id: str | None = None
    taker: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        require_identifier("quote.demand_id", self.demand_id)
        require_identifier("quote.maker", self.maker)
        require_identifier("quote.asset", self.asset)
        require_int("quote.amount_min", self.amount_min, minimum=1)
        require_int("quote.amount_max", self.amount_max, minimum=1)
        if self.amount_max < self.amount_min:
            raise CoreValidationError("quote.amount_max must not be below amount_min")
        require_int("quote.scale", self.scale, minimum=0, maximum=18)
        require_int("quote.price_bps", self.price_bps, minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS)
        require_int("quote.flat_fee", self.flat_fee, minimum=0)
        require_utc_timestamp("quote.valid_from", self.valid_from)
        require_utc_timestamp("quote.valid_until", self.valid_until)
        require_utc_timestamp_order(
            "quote.valid_from", self.valid_from, "quote.valid_until", self.valid_until
        )
        if self.offer_id is not None:
            require_identifier("quote.offer_id", self.offer_id)
        if self.taker is not None:
            require_identifier("quote.taker", self.taker)
        if self.reason is not None:
            require_identifier("quote.reason", self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "demand_id": self.demand_id,
            "maker": self.maker,
            "asset": self.asset,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "scale": self.scale,
            "price_bps": self.price_bps,
            "flat_fee": self.flat_fee,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "offer_id": self.offer_id,
            "taker": self.taker,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QuoteSpec":
        strict_fields("quote", value, _QUOTE_SPEC_FIELDS)
        return cls(
            demand_id=value["demand_id"],
            maker=value["maker"],
            asset=value["asset"],
            amount_min=value["amount_min"],
            amount_max=value["amount_max"],
            scale=value["scale"],
            price_bps=value["price_bps"],
            flat_fee=value["flat_fee"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            offer_id=value["offer_id"],
            taker=value["taker"],
            reason=value["reason"],
        )


@dataclass(frozen=True, slots=True)
class Quote:
    """Durable firm quote record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: QuoteSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = QUOTE_OBJECT_TYPE
    STATE_TYPE = QuoteState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("quote envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, QuoteSpec):
            raise CoreValidationError("quote spec must be a QuoteSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != QUOTE_OBJECT_TYPE:
            raise CoreValidationError(f"quote object_type must be {QUOTE_OBJECT_TYPE!r}")
        try:
            QuoteState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown quote state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> QuoteState:
        return QuoteState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Quote":
        envelope, payload = decode_composite(
            value, expected_object_type=QUOTE_OBJECT_TYPE, state_type=QuoteState,
        )
        spec = QuoteSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Quote":
        envelope, payload, integrity_hash = decode_composite_json(
            value, expected_object_type=QUOTE_OBJECT_TYPE, state_type=QuoteState,
        )
        spec = QuoteSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self, new_state: QuoteState, *, provenance: Provenance, spec: QuoteSpec | None = None
    ) -> "Quote":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        payload = self.spec if spec is None else spec
        return Quote(
            envelope=envelope, spec=payload, integrity_hash=seal_composite(envelope, payload)
        )

    def _require_validity_window(self, as_of: str) -> None:
        if not utc_timestamp_within(self.spec.valid_from, as_of, self.spec.valid_until):
            raise CoreValidationError(
                f"quote {self.envelope.object_id} is not valid at {as_of}; "
                f"validity window is [{self.spec.valid_from}, {self.spec.valid_until})"
            )


def _require_quote_validity_window(spec: QuoteSpec) -> None:
    """Reject quotes whose validity window is shorter than the minimum."""
    valid_from = parse_utc_timestamp("quote.valid_from", spec.valid_from)
    valid_until = parse_utc_timestamp("quote.valid_until", spec.valid_until)
    if (valid_until - valid_from).total_seconds() < MIN_QUOTE_VALIDITY_SECONDS:
        raise CoreValidationError(
            f"quote validity window must span at least {MIN_QUOTE_VALIDITY_SECONDS} "
            f"seconds (flicker-quote guard); got "
            f"[{spec.valid_from}, {spec.valid_until})"
        )


def _ensure_offer_coherence(
    spec: QuoteSpec,
    *,
    offer: LiquidityOffer,
    environment_id: str,
    domain_id: str,
) -> None:
    """Fail closed when the quote is not backed by its referenced offer."""
    if offer.state is not LiquidityOfferState.ACTIVE:
        raise CoreValidationError(
            f"quote may only reference an ACTIVE liquidity offer; offer state is "
            f"{offer.state.value}"
        )
    if offer.envelope.object_type != LIQUIDITY_OFFER_OBJECT_TYPE:
        raise CoreValidationError("quote offer reference must be a LiquidityOffer")
    if offer.spec.provider != spec.maker:
        raise CoreValidationError(
            f"quote maker {spec.maker} does not own offer {offer.envelope.object_id} "
            f"(provider {offer.spec.provider})"
        )
    if offer.spec.asset != spec.asset:
        raise CoreValidationError(
            f"quote asset {spec.asset} does not match offer asset {offer.spec.asset}"
        )
    if offer.spec.scale != spec.scale:
        raise CoreValidationError(
            f"quote scale {spec.scale} does not match offer scale {offer.spec.scale}"
        )
    if offer.envelope.environment_id != environment_id:
        raise CoreValidationError(
            f"quote environment {environment_id} does not match offer environment "
            f"{offer.envelope.environment_id}"
        )
    if offer.envelope.domain_id != domain_id:
        raise CoreValidationError(
            f"quote domain {domain_id} does not match offer domain {offer.envelope.domain_id}"
        )
    if offer.spec.price_bps != spec.price_bps:
        raise CoreValidationError(
            f"quote price {spec.price_bps} does not match offer price {offer.spec.price_bps}"
        )
    if offer.spec.flat_fee != spec.flat_fee:
        raise CoreValidationError(
            f"quote flat fee {spec.flat_fee} does not match offer flat fee "
            f"{offer.spec.flat_fee}"
        )
    if spec.amount_min < offer.spec.amount_min or spec.amount_max > offer.spec.amount_max:
        raise CoreValidationError(
            f"quote amount window [{spec.amount_min}, {spec.amount_max}] is not within "
            f"offer bounds [{offer.spec.amount_min}, {offer.spec.amount_max}]"
        )
    if not (
        parse_utc_timestamp("offer.available_from", offer.spec.available_from)
        <= parse_utc_timestamp("quote.valid_from", spec.valid_from)
        and parse_utc_timestamp("quote.valid_until", spec.valid_until)
        <= parse_utc_timestamp("offer.available_until", offer.spec.available_until)
    ):
        raise CoreValidationError(
            f"quote validity window [{spec.valid_from}, {spec.valid_until}] is not "
            f"covered by offer availability "
            f"[{offer.spec.available_from}, {offer.spec.available_until}]"
        )


def create_quote(
    *,
    quote_id: str,
    demand_id: str,
    maker: str,
    asset: str,
    scale: int,
    amount_min: int,
    amount_max: int,
    price_bps: int,
    flat_fee: int,
    valid_from: str,
    valid_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    offer: LiquidityOffer | None = None,
    correlation_id: str | None = None,
) -> Quote:
    """Create a sealed FIRM quote (the ``Create`` command)."""
    spec = QuoteSpec(
        demand_id=demand_id,
        maker=maker,
        asset=asset,
        amount_min=amount_min,
        amount_max=amount_max,
        scale=scale,
        price_bps=price_bps,
        flat_fee=flat_fee,
        valid_from=valid_from,
        valid_until=valid_until,
        offer_id=None if offer is None else offer.envelope.object_id,
        taker=None,
        reason=None,
    )
    _require_quote_validity_window(spec)
    if offer is not None:
        if not isinstance(offer, LiquidityOffer):
            raise CoreValidationError("quote offer reference must be a LiquidityOffer")
        _ensure_offer_coherence(
            spec, offer=offer, environment_id=environment_id, domain_id=domain_id
        )
    envelope = build_domain_envelope(
        object_id=require_identifier("quote.quote_id", quote_id),
        object_type=QUOTE_OBJECT_TYPE,
        state=QuoteState.FIRM.value,
        environment_id=require_identifier("quote.environment_id", environment_id),
        domain_id=require_identifier("quote.domain_id", domain_id),
        provenance=provenance,
        causation_id=demand_id,
        correlation_id=correlation_id,
    )
    return Quote(envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec))


def _require_quote(quote: Quote) -> Quote:
    if not isinstance(quote, Quote):
        raise CoreValidationError("operation requires a Quote")
    return quote


def amend_quote(
    quote: Quote,
    *,
    provenance: Provenance,
    price_bps: int | None = None,
    flat_fee: int | None = None,
    amount_min: int | None = None,
    amount_max: int | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> Quote:
    """Amend a FIRM quote's economic terms (the ``Amend`` command).

    Identity (maker, demand, asset, scale, offer reference) is immutable;
    the amended payload is fully revalidated, including the minimum
    validity guard.
    """
    _require_quote(quote)
    if quote.state is not QuoteState.FIRM:
        raise CoreValidationError(
            f"only a FIRM quote can be amended; state is {quote.state.value}"
        )
    changes = {
        "price_bps": price_bps,
        "flat_fee": flat_fee,
        "amount_min": amount_min,
        "amount_max": amount_max,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    if all(value is None for value in changes.values()):
        raise CoreValidationError("quote amendment requires at least one new value")
    spec = replace(
        quote.spec,
        **{name: value for name, value in changes.items() if value is not None},
    )
    _require_quote_validity_window(spec)
    return quote._advance(QuoteState.FIRM, provenance=provenance, spec=spec)


def accept_quote(
    quote: Quote, *, taker: str, as_of: str, provenance: Provenance
) -> Quote:
    """Accept a FIRM quote inside its validity window (``Accept``).

    Fail-closed guards: the acceptance instant must lie strictly inside
    the validity window, and the maker may not accept its own quote
    (self-dealing).
    """
    _require_quote(quote)
    if quote.state is not QuoteState.FIRM:
        raise CoreValidationError(
            f"only a FIRM quote can be accepted; state is {quote.state.value}"
        )
    require_identifier("quote.taker", taker)
    if taker == quote.spec.maker:
        raise CoreValidationError(
            f"quote {quote.envelope.object_id} cannot be accepted by its own maker "
            f"({quote.spec.maker}); self-dealing is rejected"
        )
    require_utc_timestamp("quote.as_of", as_of)
    quote._require_validity_window(as_of)
    spec = replace(quote.spec, taker=taker)
    return quote._advance(QuoteState.ACCEPTED, provenance=provenance, spec=spec)


def reject_quote(quote: Quote, *, provenance: Provenance) -> Quote:
    """Reject a FIRM quote (``Reject``): the taker declined."""
    _require_quote(quote)
    if quote.state is not QuoteState.FIRM:
        raise CoreValidationError(
            f"only a FIRM quote can be rejected; state is {quote.state.value}"
        )
    spec = replace(quote.spec, reason=QuoteReasonCode.TAKER_DECLINED.value)
    return quote._advance(QuoteState.REJECTED, provenance=provenance, spec=spec)


def cancel_quote(quote: Quote, *, provenance: Provenance) -> Quote:
    """Cancel a FIRM or ACCEPTED quote (``Cancel``): the maker withdrew it.

    A COMMITTED quote is terminal and can no longer be cancelled.
    """
    _require_quote(quote)
    if quote.state not in (QuoteState.FIRM, QuoteState.ACCEPTED):
        raise CoreValidationError(
            f"only a FIRM or ACCEPTED quote can be cancelled; state is {quote.state.value}"
        )
    spec = replace(quote.spec, reason=QuoteReasonCode.MAKER_CANCELLED.value)
    return quote._advance(QuoteState.CANCELLED, provenance=provenance, spec=spec)


def expire_quote(quote: Quote, *, as_of: str, provenance: Provenance) -> Quote:
    """Expire a FIRM or ACCEPTED quote once its validity window elapsed.

    Fail-closed staleness enforcement: expiry requires
    ``as_of >= valid_until``.
    """
    _require_quote(quote)
    if quote.state not in (QuoteState.FIRM, QuoteState.ACCEPTED):
        raise CoreValidationError(
            f"only a FIRM or ACCEPTED quote can expire; state is {quote.state.value}"
        )
    if parse_utc_timestamp("quote.as_of", as_of) < parse_utc_timestamp(
        "quote.valid_until", quote.spec.valid_until
    ):
        raise CoreValidationError(
            f"quote expiry requires as_of at or after valid_until "
            f"({quote.spec.valid_until}); got {as_of}"
        )
    spec = replace(quote.spec, reason=QuoteReasonCode.QUOTE_EXPIRED.value)
    return quote._advance(QuoteState.EXPIRED, provenance=provenance, spec=spec)


def invalidate_quote(
    quote: Quote, *, reason: QuoteReasonCode, provenance: Provenance
) -> Quote:
    """Invalidate a FIRM or ACCEPTED quote for an external cause.

    Valid invalidation reasons are the external-cause codes plus the
    taker-side decline of a market-level allocation; a COMMITTED quote
    is terminal and can no longer be invalidated.
    """
    _require_quote(quote)
    if quote.state not in (QuoteState.FIRM, QuoteState.ACCEPTED):
        raise CoreValidationError(
            f"only a FIRM or ACCEPTED quote can be invalidated; state is "
            f"{quote.state.value}"
        )
    if not isinstance(reason, QuoteReasonCode):
        raise CoreValidationError("quote invalidation reason must be a QuoteReasonCode")
    if reason.value not in INVALIDATION_REASONS:
        raise CoreValidationError(
            f"quote invalidation reason {reason.value} is not an external-cause reason; "
            f"expected one of {sorted(INVALIDATION_REASONS)}"
        )
    spec = replace(quote.spec, reason=reason.value)
    return quote._advance(QuoteState.INVALIDATED, provenance=provenance, spec=spec)


@dataclass(frozen=True, slots=True)
class QuoteCommit:
    """Result of committing a quote: the terminal quote and its reservation."""

    quote: Quote
    reservation: Reservation


def commit_quote(
    quote: Quote, *, fill_value: int, as_of: str, provenance: Provenance
) -> QuoteCommit:
    """Commit an ACCEPTED quote for an exact amount (``Commit``).

    Fail-closed guards: the commitment instant must lie strictly inside
    the validity window, and the fill amount must lie inside the quote's
    amount window. The result carries the terminal COMMITTED quote and
    the exact RESERVED reservation for the amount actually taken (the
    reservation's availability horizon is the quote's validity horizon).
    """
    _require_quote(quote)
    if quote.state is not QuoteState.ACCEPTED:
        raise CoreValidationError(
            f"only an ACCEPTED quote can be committed; state is {quote.state.value}"
        )
    if quote.spec.taker is None:
        raise CoreValidationError("quote commitment requires an accepting taker")
    require_int("quote.fill_value", fill_value, minimum=1)
    if not quote.spec.amount_min <= fill_value <= quote.spec.amount_max:
        raise CoreValidationError(
            f"quote fill value {fill_value} is outside the quote amount window "
            f"[{quote.spec.amount_min}, {quote.spec.amount_max}]"
        )
    require_utc_timestamp("quote.as_of", as_of)
    quote._require_validity_window(as_of)
    committed = quote._advance(QuoteState.COMMITTED, provenance=provenance)
    reservation = _reservation_from_quote(
        committed, fill_value=fill_value, as_of=as_of, provenance=provenance
    )
    return QuoteCommit(quote=committed, reservation=reservation)


def _reservation_from_quote(
    committed_quote: Quote, *, fill_value: int, as_of: str, provenance: Provenance
) -> Reservation:
    spec = committed_quote.spec
    return create_reservation(
        reservation_id=f"{committed_quote.envelope.object_id}/reservation",
        provider=spec.maker,
        beneficiary=spec.taker,
        asset=spec.asset,
        scale=spec.scale,
        amount_value=fill_value,
        source_quote_id=committed_quote.envelope.object_id,
        reserved_from=as_of,
        reserved_until=spec.valid_until,
        environment_id=committed_quote.envelope.environment_id,
        domain_id=committed_quote.envelope.domain_id,
        provenance=provenance,
        correlation_id=committed_quote.envelope.correlation_id,
    )


# ---------------------------------------------------------------------------
# request_quote: the RFQ default mechanism over standing liquidity offers.
# ---------------------------------------------------------------------------


def _eligible_rfq_offers(
    demand: Demand, offers: Iterable[LiquidityOffer], as_of: str
) -> tuple[LiquidityOffer, ...]:
    if not isinstance(demand, Demand):
        raise CoreValidationError("request_quote requires a Demand")
    if demand.state is not DemandState.OPEN:
        raise CoreValidationError(
            f"only an OPEN demand can be quoted; state is {demand.state.value}"
        )
    valid_until = offset_utc_timestamp(
        "rfq as_of", as_of, DEFAULT_QUOTE_VALIDITY_SECONDS
    )
    eligible: list[LiquidityOffer] = []
    for offer in offers:
        if not isinstance(offer, LiquidityOffer):
            raise CoreValidationError("request_quote offers must be LiquidityOffer records")
        if offer.state is not LiquidityOfferState.ACTIVE:
            continue
        if offer.spec.asset != demand.spec.asset or offer.spec.scale != demand.spec.amount_scale:
            continue
        if (
            offer.envelope.environment_id != demand.envelope.environment_id
            or offer.envelope.domain_id != demand.envelope.domain_id
        ):
            continue
        # The offer's capacity must bracket the demand minimum.
        if offer.spec.amount_max < demand.spec.amount_min:
            continue
        if offer.spec.amount_min > demand.spec.amount_max:
            continue
        # The firm quote must stay valid for the whole default validity
        # window inside the offer's availability (flicker guard).
        if not (
            parse_utc_timestamp("offer.available_from", offer.spec.available_from)
            <= parse_utc_timestamp("rfq as_of", as_of)
            and parse_utc_timestamp("rfq valid_until", valid_until)
            <= parse_utc_timestamp("offer.available_until", offer.spec.available_until)
        ):
            continue
        eligible.append(offer)
    return tuple(eligible)


def request_quote(
    demand: Demand,
    *,
    offers: Iterable[LiquidityOffer],
    as_of: str,
    provenance: Provenance,
    quote_id: str | None = None,
) -> Quote:
    """Issue the default RFQ firm quote for a demand over standing offers.

    Deterministic selection: the cheapest ``(price_bps, flat_fee)`` offer
    whose amount window brackets the demand minimum, whose availability
    covers the default quote validity, and whose environment and domain
    match the demand. Fails closed when no offer is eligible.
    """
    if not isinstance(demand, Demand):
        raise CoreValidationError("request_quote requires a Demand")
    require_utc_timestamp("rfq.as_of", as_of)
    valid_until = offset_utc_timestamp("rfq as_of", as_of, DEFAULT_QUOTE_VALIDITY_SECONDS)
    eligible = _eligible_rfq_offers(demand, offers, as_of)
    if not eligible:
        raise CoreValidationError(
            f"no eligible liquidity offer for demand {demand.envelope.object_id} "
            f"at {as_of}; RFQ fails closed"
        )
    best = min(
        eligible, key=lambda offer: (offer.spec.price_bps, offer.spec.flat_fee)
    )
    return create_quote(
        quote_id=quote_id
        if quote_id is not None
        else f"{demand.envelope.object_id}/quote",
        demand_id=demand.envelope.object_id,
        maker=best.spec.provider,
        asset=demand.spec.asset,
        scale=demand.spec.amount_scale,
        amount_min=max(demand.spec.amount_min, best.spec.amount_min),
        amount_max=min(demand.spec.amount_max, best.spec.amount_max),
        price_bps=best.spec.price_bps,
        flat_fee=best.spec.flat_fee,
        valid_from=as_of,
        valid_until=valid_until,
        offer=best,
        environment_id=demand.envelope.environment_id,
        domain_id=demand.envelope.domain_id,
        provenance=provenance,
        correlation_id=demand.envelope.correlation_id,
    )
