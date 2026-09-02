"""Market-level reservations: the bounded artifact of a secured fill.

A :class:`Reservation` is a declarative record — provider, beneficiary,
asset, exact amount, availability window, and the identifier of the quote
or submission that produced it. It is intentionally bounded to the
``Create/Commit/Release/Expire`` subset of the frozen ``Reservation``
command family: encumbrance accounting, consumption and default handling
are owned by later sibling Work Orders on the execution side, so this
module declares the market's claim on future capacity and nothing more.

The record is immutable history: every command produces the next sealed
object version, and terminal records are immutable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import DEFAULT_RESERVATION_HOLD_SECONDS, RESERVATION_OBJECT_TYPE
from ._validation import (
    offset_utc_timestamp,
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

_RESERVATION_SPEC_FIELDS = frozenset(
    {
        "provider",
        "beneficiary",
        "asset",
        "amount_value",
        "scale",
        "source_quote_id",
        "reserved_from",
        "reserved_until",
    }
)


class ReservationState(StrEnum):
    """Closed lifecycle vocabulary of a market reservation."""

    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class ReservationSpec:
    """Immutable reservation payload."""

    provider: str
    beneficiary: str
    asset: str
    amount_value: int
    scale: int
    source_quote_id: str
    reserved_from: str
    reserved_until: str

    def __post_init__(self) -> None:
        require_identifier("reservation.provider", self.provider)
        require_identifier("reservation.beneficiary", self.beneficiary)
        require_identifier("reservation.asset", self.asset)
        require_int("reservation.amount_value", self.amount_value, minimum=1)
        require_int("reservation.scale", self.scale, minimum=0, maximum=18)
        require_identifier("reservation.source_quote_id", self.source_quote_id)
        require_utc_timestamp("reservation.reserved_from", self.reserved_from)
        require_utc_timestamp("reservation.reserved_until", self.reserved_until)
        require_utc_timestamp_order(
            "reservation.reserved_from", self.reserved_from,
            "reservation.reserved_until", self.reserved_until,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "beneficiary": self.beneficiary,
            "asset": self.asset,
            "amount_value": self.amount_value,
            "scale": self.scale,
            "source_quote_id": self.source_quote_id,
            "reserved_from": self.reserved_from,
            "reserved_until": self.reserved_until,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReservationSpec":
        strict_fields("reservation", value, _RESERVATION_SPEC_FIELDS)
        return cls(
            provider=value["provider"],
            beneficiary=value["beneficiary"],
            asset=value["asset"],
            amount_value=value["amount_value"],
            scale=value["scale"],
            source_quote_id=value["source_quote_id"],
            reserved_from=value["reserved_from"],
            reserved_until=value["reserved_until"],
        )


@dataclass(frozen=True, slots=True)
class Reservation:
    """Durable market reservation record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ReservationSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = RESERVATION_OBJECT_TYPE
    STATE_TYPE = ReservationState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("reservation envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ReservationSpec):
            raise CoreValidationError("reservation spec must be a ReservationSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != RESERVATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"reservation object_type must be {RESERVATION_OBJECT_TYPE!r}"
            )
        try:
            ReservationState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown reservation state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ReservationState:
        return ReservationState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Reservation":
        envelope, payload = decode_composite(
            value,
            expected_object_type=RESERVATION_OBJECT_TYPE,
            state_type=ReservationState,
        )
        spec = ReservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Reservation":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=RESERVATION_OBJECT_TYPE,
            state_type=ReservationState,
        )
        spec = ReservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(self, new_state: ReservationState, *, provenance: Provenance) -> "Reservation":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        return Reservation(
            envelope=envelope, spec=self.spec,
            integrity_hash=seal_composite(envelope, self.spec),
        )


def create_reservation(
    *,
    reservation_id: str,
    provider: str,
    beneficiary: str,
    asset: str,
    scale: int,
    amount_value: int,
    source_quote_id: str,
    reserved_from: str,
    reserved_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Reservation:
    """Create a sealed RESERVED reservation record (the ``Create`` command)."""
    spec = ReservationSpec(
        provider=provider,
        beneficiary=beneficiary,
        asset=asset,
        amount_value=amount_value,
        scale=scale,
        source_quote_id=source_quote_id,
        reserved_from=reserved_from,
        reserved_until=reserved_until,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("reservation.reservation_id", reservation_id),
        object_type=RESERVATION_OBJECT_TYPE,
        state=ReservationState.RESERVED.value,
        environment_id=require_identifier("reservation.environment_id", environment_id),
        domain_id=require_identifier("reservation.domain_id", domain_id),
        provenance=provenance,
        causation_id=source_quote_id,
        correlation_id=correlation_id,
    )
    return Reservation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def default_reserved_until(as_of: str) -> str:
    """Default reservation availability horizon from an explicit instant."""
    return offset_utc_timestamp("reservation as_of", as_of, DEFAULT_RESERVATION_HOLD_SECONDS)


def _require_reservation(reservation: Reservation) -> Reservation:
    if not isinstance(reservation, Reservation):
        raise CoreValidationError("operation requires a Reservation")
    return reservation


def commit_reservation(
    reservation: Reservation, *, as_of: str, provenance: Provenance
) -> Reservation:
    """Commit a RESERVED record inside its availability window.

    The window is half-open: ``reserved_from <= as_of < reserved_until``.
    """
    _require_reservation(reservation)
    if reservation.state is not ReservationState.RESERVED:
        raise CoreValidationError(
            "only a RESERVED reservation can be committed; state is "
            f"{reservation.state.value}"
        )
    if not (
        parse_utc_timestamp("reservation.as_of", as_of)
        >= parse_utc_timestamp("reservation.reserved_from", reservation.spec.reserved_from)
        and parse_utc_timestamp("reservation.as_of", as_of)
        < parse_utc_timestamp("reservation.reserved_until", reservation.spec.reserved_until)
    ):
        raise CoreValidationError(
            "reservation commitment requires as_of inside the availability window "
            f"[{reservation.spec.reserved_from}, {reservation.spec.reserved_until}); "
            f"got {as_of}"
        )
    return reservation._advance(ReservationState.COMMITTED, provenance=provenance)


def release_reservation(
    reservation: Reservation, *, provenance: Provenance
) -> Reservation:
    """Release a RESERVED record (the ``Release`` command)."""
    _require_reservation(reservation)
    if reservation.state is not ReservationState.RESERVED:
        raise CoreValidationError(
            "only a RESERVED reservation can be released; state is "
            f"{reservation.state.value}"
        )
    return reservation._advance(ReservationState.RELEASED, provenance=provenance)


def expire_reservation(
    reservation: Reservation, *, as_of: str, provenance: Provenance
) -> Reservation:
    """Expire a RESERVED record once its availability window has elapsed."""
    _require_reservation(reservation)
    if reservation.state is not ReservationState.RESERVED:
        raise CoreValidationError(
            "only a RESERVED reservation can expire; state is "
            f"{reservation.state.value}"
        )
    if parse_utc_timestamp("reservation.as_of", as_of) < parse_utc_timestamp(
        "reservation.reserved_until", reservation.spec.reserved_until
    ):
        raise CoreValidationError(
            "reservation expiry requires as_of at or after reserved_until "
            f"({reservation.spec.reserved_until}); got {as_of}"
        )
    return reservation._advance(ReservationState.EXPIRED, provenance=provenance)
