"""Market mechanisms: durable market records and their phase commands.

A :class:`MarketMechanism` record declares one market session — the
mechanism kind (RFQ or batch auction), the demand it serves, the taker,
the asset and amount window, the admissible price band, the trading
window and the submission capacity. The phase commands implement the
frozen ``Market`` command family ``Create/Open/Close/Cancel``; the
``Submit/Withdraw/Accept/Reject/Allocate`` commands operate on the
session state (see :mod:`src.market.session`).

All transitions are deterministic state-machine steps over explicit
instants — never clock reads — and each produces the next immutable,
sealed object version.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    MARKET_MECHANISM_OBJECT_TYPE,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
    MechanismKind,
)
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_int,
    require_utc_timestamp,
    require_utc_timestamp_order,
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

_MARKET_SPEC_FIELDS = frozenset(
    {
        "mechanism_kind",
        "demand_id",
        "taker",
        "asset",
        "amount_min",
        "amount_max",
        "scale",
        "price_min_bps",
        "price_max_bps",
        "opens_at",
        "closes_at",
        "max_submissions",
    }
)


class MarketState(StrEnum):
    """Closed lifecycle vocabulary of a market."""

    CREATED = "CREATED"
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    ALLOCATED = "ALLOCATED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class MarketSpec:
    """Immutable market declaration payload."""

    mechanism_kind: str
    demand_id: str
    taker: str
    asset: str
    amount_min: int
    amount_max: int
    scale: int
    price_min_bps: int
    price_max_bps: int
    opens_at: str
    closes_at: str
    max_submissions: int

    def __post_init__(self) -> None:
        parse_enum("market.mechanism_kind", MechanismKind, self.mechanism_kind)
        require_identifier("market.demand_id", self.demand_id)
        require_identifier("market.taker", self.taker)
        require_identifier("market.asset", self.asset)
        require_int("market.amount_min", self.amount_min, minimum=1)
        require_int("market.amount_max", self.amount_max, minimum=1)
        if self.amount_max < self.amount_min:
            raise CoreValidationError("market.amount_max must not be below amount_min")
        require_int("market.scale", self.scale, minimum=0, maximum=18)
        require_int(
            "market.price_min_bps", self.price_min_bps,
            minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS,
        )
        require_int(
            "market.price_max_bps", self.price_max_bps,
            minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS,
        )
        if self.price_max_bps < self.price_min_bps:
            raise CoreValidationError("market.price_max_bps must not be below price_min_bps")
        require_utc_timestamp("market.opens_at", self.opens_at)
        require_utc_timestamp("market.closes_at", self.closes_at)
        require_utc_timestamp_order("market.opens_at", self.opens_at, "market.closes_at", self.closes_at)
        require_int("market.max_submissions", self.max_submissions, minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism_kind": self.mechanism_kind,
            "demand_id": self.demand_id,
            "taker": self.taker,
            "asset": self.asset,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "scale": self.scale,
            "price_min_bps": self.price_min_bps,
            "price_max_bps": self.price_max_bps,
            "opens_at": self.opens_at,
            "closes_at": self.closes_at,
            "max_submissions": self.max_submissions,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MarketSpec":
        strict_fields("market", value, _MARKET_SPEC_FIELDS)
        return cls(
            mechanism_kind=value["mechanism_kind"],
            demand_id=value["demand_id"],
            taker=value["taker"],
            asset=value["asset"],
            amount_min=value["amount_min"],
            amount_max=value["amount_max"],
            scale=value["scale"],
            price_min_bps=value["price_min_bps"],
            price_max_bps=value["price_max_bps"],
            opens_at=value["opens_at"],
            closes_at=value["closes_at"],
            max_submissions=value["max_submissions"],
        )


@dataclass(frozen=True, slots=True)
class MarketMechanism:
    """Durable market record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: MarketSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = MARKET_MECHANISM_OBJECT_TYPE
    STATE_TYPE = MarketState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("market envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, MarketSpec):
            raise CoreValidationError("market spec must be a MarketSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != MARKET_MECHANISM_OBJECT_TYPE:
            raise CoreValidationError(
                f"market object_type must be {MARKET_MECHANISM_OBJECT_TYPE!r}"
            )
        try:
            MarketState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown market state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> MarketState:
        return MarketState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MarketMechanism":
        envelope, payload = decode_composite(
            value,
            expected_object_type=MARKET_MECHANISM_OBJECT_TYPE,
            state_type=MarketState,
        )
        spec = MarketSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "MarketMechanism":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=MARKET_MECHANISM_OBJECT_TYPE,
            state_type=MarketState,
        )
        spec = MarketSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(self, new_state: MarketState, *, provenance: Provenance) -> "MarketMechanism":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        return MarketMechanism(
            envelope=envelope, spec=self.spec,
            integrity_hash=seal_composite(envelope, self.spec),
        )


def create_market(
    *,
    market_id: str,
    mechanism_kind: MechanismKind | str,
    demand_id: str,
    taker: str,
    asset: str,
    amount_min: int,
    amount_max: int,
    scale: int,
    price_min_bps: int,
    price_max_bps: int,
    opens_at: str,
    closes_at: str,
    max_submissions: int,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> MarketMechanism:
    """Create a sealed CREATED market (the ``Create`` command)."""
    if not isinstance(mechanism_kind, MechanismKind):
        mechanism_kind = parse_enum("market.mechanism_kind", MechanismKind, mechanism_kind)
    spec = MarketSpec(
        mechanism_kind=mechanism_kind.value,
        demand_id=demand_id,
        taker=taker,
        asset=asset,
        amount_min=amount_min,
        amount_max=amount_max,
        scale=scale,
        price_min_bps=price_min_bps,
        price_max_bps=price_max_bps,
        opens_at=opens_at,
        closes_at=closes_at,
        max_submissions=max_submissions,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("market.market_id", market_id),
        object_type=MARKET_MECHANISM_OBJECT_TYPE,
        state=MarketState.CREATED.value,
        environment_id=require_identifier("market.environment_id", environment_id),
        domain_id=require_identifier("market.domain_id", domain_id),
        provenance=provenance,
        causation_id=demand_id,
        correlation_id=correlation_id,
    )
    return MarketMechanism(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def _require_market(market: MarketMechanism) -> MarketMechanism:
    if not isinstance(market, MarketMechanism):
        raise CoreValidationError("operation requires a MarketMechanism")
    return market


def open_market(
    market: MarketMechanism, as_of: str = "", *, provenance: Provenance
) -> MarketMechanism:
    """Open a CREATED market inside its trading window (``Open``).

    The window is half-open: ``opens_at <= as_of < closes_at``.
    """
    _require_market(market)
    require_utc_timestamp("market.as_of", as_of)
    if market.state is not MarketState.CREATED:
        raise CoreValidationError(
            f"only a CREATED market can be opened; state is {market.state.value}"
        )
    if not utc_timestamp_within(market.spec.opens_at, as_of, market.spec.closes_at):
        raise CoreValidationError(
            "market opening requires as_of inside the trading window "
            f"[{market.spec.opens_at}, {market.spec.closes_at}); got {as_of}"
        )
    return market._advance(MarketState.OPEN, provenance=provenance)


def close_market(
    market: MarketMechanism, as_of: str = "", *, provenance: Provenance
) -> MarketMechanism:
    """Close an OPEN market once its trading window has elapsed (``Close``)."""
    _require_market(market)
    require_utc_timestamp("market.as_of", as_of)
    if market.state is not MarketState.OPEN:
        raise CoreValidationError(
            f"only an OPEN market can be closed; state is {market.state.value}"
        )
    if parse_utc_timestamp("market.as_of", as_of) < parse_utc_timestamp(
        "market.closes_at", market.spec.closes_at
    ):
        raise CoreValidationError(
            "market closing requires as_of at or after closes_at "
            f"({market.spec.closes_at}); got {as_of}"
        )
    return market._advance(MarketState.CLOSED, provenance=provenance)


def cancel_market(
    market: MarketMechanism, as_of: str = "", *, provenance: Provenance
) -> MarketMechanism:
    """Cancel a CREATED or OPEN market (``Cancel``); terminal afterwards."""
    _require_market(market)
    require_utc_timestamp("market.as_of", as_of)
    if market.state not in (MarketState.CREATED, MarketState.OPEN):
        raise CoreValidationError(
            "only a CREATED or OPEN market can be cancelled; state is "
            f"{market.state.value}"
        )
    return market._advance(MarketState.CANCELLED, provenance=provenance)
