"""Credit exposure controls: limits, utilization, breach and concentration.

Exposure is a CONTROL model, not a financial authority: the
:class:`CreditExposure` record carries per-counterparty/per-corridor
limits and utilization accounted against offered capacity, and the
assessment/concentration functions evaluate aggregated utilization —
none of it ever posts to the value ledger (WORK-005 owns accounting);
value-domain objects are referenced only as opaque identifiers.

Two complementary fail-closed mechanisms exist:

- **gates** — :func:`draw_against_exposure` rejects a control-side draw
  that would exceed the recorded limit;
- **detection** — :func:`assess_exposure` flags BREACH when the
  per-counterparty/per-corridor aggregate of facility draws (each
  individually within its own facility limit) exceeds the exposure
  limit, and :func:`evaluate_concentration` flags concentration breaches
  with exact integer cross-multiplied basis-point shares.

All outputs are deterministically ordered by explicit sort keys
(``(counterparty, corridor_id)`` and ``(control kind, group)``), so
aggregates, checks, entries, breaches and digests are independent of
input order; ties are broken by the lexicographic group key.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money import Amount

from .contracts import (
    CONCENTRATION_DENOMINATOR_BPS,
    CREDIT_EXPOSURE_OBJECT_TYPE,
    MAX_CORRIDOR_CONCENTRATION_BPS,
    MAX_COUNTERPARTY_CONCENTRATION_BPS,
    MAX_PROVIDER_CONCENTRATION_BPS,
)
from .corridors import Corridor
from .credit import CreditOffer, CreditOfferState
from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_utc_timestamp,
    require_utc_window,
    strict_fields,
    utc_timestamp_within,
)
from .offers import LiquidityOffer, LiquidityOfferState
from .offers import require_capacity_matches_source_asset, require_positive_amount
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_EXPOSURE_SPEC_FIELDS = frozenset(
    {
        "counterparty",
        "corridor",
        "limit",
        "utilized",
        "valid_from",
        "valid_until",
    }
)


class CreditExposureState(StrEnum):
    """Closed lifecycle vocabulary of a credit exposure control record."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"


_EXPOSURE_TERMINAL_STATES = frozenset(
    {CreditExposureState.WITHDRAWN, CreditExposureState.EXPIRED}
)


class ExposureStatus(StrEnum):
    """Closed status vocabulary of an exposure limit check."""

    OK = "OK"
    BREACH = "BREACH"


class ConcentrationControlKind(StrEnum):
    """Closed vocabulary of concentration control dimensions."""

    PROVIDER = "PROVIDER"
    CORRIDOR = "CORRIDOR"
    COUNTERPARTY = "COUNTERPARTY"


@dataclass(frozen=True, slots=True)
class CreditExposureSpec:
    """Immutable credit exposure control payload."""

    counterparty: str
    corridor: Corridor
    limit: Amount
    utilized: Amount
    valid_from: str
    valid_until: str

    def __post_init__(self) -> None:
        require_identifier("exposure.counterparty", self.counterparty)
        if not isinstance(self.corridor, Corridor):
            raise CoreValidationError("exposure.corridor must be a Corridor")
        require_positive_amount("exposure.limit", self.limit)
        require_capacity_matches_source_asset("exposure.limit", self.corridor, self.limit)
        if not isinstance(self.utilized, Amount):
            raise CoreValidationError("exposure.utilized must be an Amount")
        if self.utilized < Amount.zero(self.limit.currency):
            raise CoreValidationError("exposure.utilized must not be negative")
        if self.utilized > self.limit:
            raise CoreValidationError(
                "exposure.utilized must not exceed the exposure limit; "
                f"utilized={self.utilized.to_dict()} limit={self.limit.to_dict()}"
            )
        require_utc_timestamp("exposure.valid_from", self.valid_from)
        require_utc_timestamp("exposure.valid_until", self.valid_until)
        require_utc_window("exposure.valid", self.valid_from, self.valid_until)

    def to_dict(self) -> dict[str, Any]:
        return {
            "counterparty": self.counterparty,
            "corridor": self.corridor.to_dict(),
            "limit": self.limit.to_dict(),
            "utilized": self.utilized.to_dict(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CreditExposureSpec":
        strict_fields("exposure", value, _EXPOSURE_SPEC_FIELDS)
        return cls(
            counterparty=value["counterparty"],
            corridor=Corridor.from_dict(value["corridor"]),
            limit=Amount.from_dict(value["limit"]),
            utilized=Amount.from_dict(value["utilized"]),
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
        )


@dataclass(frozen=True, slots=True)
class CreditExposure:
    """Durable credit exposure control record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: CreditExposureSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = CREDIT_EXPOSURE_OBJECT_TYPE
    STATE_TYPE = CreditExposureState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("exposure envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, CreditExposureSpec):
            raise CoreValidationError("exposure spec must be a CreditExposureSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != CREDIT_EXPOSURE_OBJECT_TYPE:
            raise CoreValidationError(
                f"exposure object_type must be {CREDIT_EXPOSURE_OBJECT_TYPE!r}"
            )
        try:
            CreditExposureState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown exposure state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> CreditExposureState:
        return CreditExposureState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CreditExposure":
        envelope, payload = decode_composite(
            value,
            expected_object_type=CREDIT_EXPOSURE_OBJECT_TYPE,
            state_type=CreditExposureState,
        )
        spec = CreditExposureSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "CreditExposure":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=CREDIT_EXPOSURE_OBJECT_TYPE,
            state_type=CreditExposureState,
        )
        spec = CreditExposureSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: CreditExposureState,
        *,
        provenance: Provenance,
        spec: CreditExposureSpec | None = None,
    ) -> "CreditExposure":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        payload = self.spec if spec is None else spec
        return CreditExposure(
            envelope=envelope, spec=payload, integrity_hash=seal_composite(envelope, payload)
        )


def create_credit_exposure(
    *,
    exposure_id: str,
    counterparty: str,
    corridor: Corridor,
    limit: Amount,
    valid_from: str,
    valid_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> CreditExposure:
    """Create a sealed ACTIVE exposure control (the ``Create`` command).

    Utilization starts at zero; control-side draws are gated by
    :func:`draw_against_exposure` and never exceed the limit.
    """
    if not isinstance(corridor, Corridor):
        raise CoreValidationError("exposure.corridor must be a Corridor")
    spec = CreditExposureSpec(
        counterparty=counterparty,
        corridor=corridor,
        limit=limit,
        utilized=Amount.zero(limit.currency),
        valid_from=valid_from,
        valid_until=valid_until,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("exposure.exposure_id", exposure_id),
        object_type=CREDIT_EXPOSURE_OBJECT_TYPE,
        state=CreditExposureState.ACTIVE.value,
        environment_id=require_identifier("exposure.environment_id", environment_id),
        domain_id=require_identifier("exposure.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return CreditExposure(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def exposure_available_capacity(exposure: CreditExposure) -> Amount:
    """Exact remaining capacity under the control limit."""
    _require_exposure(exposure)
    return exposure.spec.limit.sub(exposure.spec.utilized)


def _require_exposure(exposure: CreditExposure) -> CreditExposure:
    if not isinstance(exposure, CreditExposure):
        raise CoreValidationError("operation requires a CreditExposure")
    return exposure


def draw_against_exposure(
    exposure: CreditExposure,
    amount: Amount,
    *,
    as_of: str,
    provenance: Provenance,
) -> CreditExposure:
    """Record a control-side utilization increase (the ``Draw`` command).

    Fail-closed preconditions: ACTIVE control, ``as_of`` strictly inside
    the half-open validity window, positive amount in the limit currency
    and ``utilized + amount <= limit``. This is a control gate, not an
    accounting posting: no value-ledger state is touched.
    """
    _require_exposure(exposure)
    if exposure.state is not CreditExposureState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE exposure control can record a draw; state is "
            f"{exposure.state.value}"
        )
    require_utc_timestamp("exposure.as_of", as_of)
    if not utc_timestamp_within(
        exposure.spec.valid_from, as_of, exposure.spec.valid_until
    ):
        raise CoreValidationError(
            "exposure draw requires as_of inside the validity window "
            f"[{exposure.spec.valid_from}, {exposure.spec.valid_until}); "
            f"got {as_of}"
        )
    require_positive_amount("exposure.draw amount", amount)
    if amount.currency != exposure.spec.limit.currency:
        raise CoreValidationError(
            "exposure draw must use the limit currency "
            f"{exposure.spec.limit.currency.code}; got {amount.currency.code}"
        )
    projected = exposure.spec.utilized.add(amount)
    if projected > exposure.spec.limit:
        raise CoreValidationError(
            "exposure draw would exceed the exposure limit; "
            f"utilized={exposure.spec.utilized.to_dict()} "
            f"draw={amount.to_dict()} limit={exposure.spec.limit.to_dict()}"
        )
    spec = replace(exposure.spec, utilized=projected)
    return exposure._advance(CreditExposureState.ACTIVE, provenance=provenance, spec=spec)


def repay_against_exposure(
    exposure: CreditExposure,
    amount: Amount,
    *,
    as_of: str,
    provenance: Provenance,
) -> CreditExposure:
    """Record a control-side utilization decrease (the ``Repay`` command)."""
    _require_exposure(exposure)
    if exposure.state is not CreditExposureState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE exposure control can record a repayment; state is "
            f"{exposure.state.value}"
        )
    require_positive_amount("exposure.repay amount", amount)
    if amount.currency != exposure.spec.limit.currency:
        raise CoreValidationError(
            "exposure repayment must use the limit currency "
            f"{exposure.spec.limit.currency.code}; got {amount.currency.code}"
        )
    if parse_utc_timestamp("exposure.as_of", as_of) < parse_utc_timestamp(
        "exposure.valid_from", exposure.spec.valid_from
    ):
        raise CoreValidationError(
            "exposure repayment cannot precede the validity window "
            f"({exposure.spec.valid_from}); got {as_of}"
        )
    if amount > exposure.spec.utilized:
        raise CoreValidationError(
            "exposure repayment cannot exceed the recorded utilization; "
            f"utilized={exposure.spec.utilized.to_dict()} repay={amount.to_dict()}"
        )
    spec = replace(exposure.spec, utilized=exposure.spec.utilized.sub(amount))
    return exposure._advance(CreditExposureState.ACTIVE, provenance=provenance, spec=spec)


def amend_credit_exposure(
    exposure: CreditExposure,
    *,
    provenance: Provenance,
    limit: Amount | None = None,
    valid_until: str | None = None,
) -> CreditExposure:
    """Amend the exposure control (the ``Amend`` command).

    The new limit can never fall below the recorded utilization (the spec
    invariant is revalidated); tightening below AGGREGATE utilization is
    exactly the condition :func:`assess_exposure` reports as BREACH.
    """
    _require_exposure(exposure)
    if exposure.state is not CreditExposureState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE exposure control can be amended; state is "
            f"{exposure.state.value}"
        )
    if limit is None and valid_until is None:
        raise CoreValidationError("exposure amendment requires at least one new value")
    changes: dict[str, Any] = {}
    if limit is not None:
        changes["limit"] = limit
    if valid_until is not None:
        changes["valid_until"] = valid_until
    spec = replace(exposure.spec, **changes)
    return exposure._advance(CreditExposureState.ACTIVE, provenance=provenance, spec=spec)


def suspend_credit_exposure(
    exposure: CreditExposure, *, provenance: Provenance
) -> CreditExposure:
    """Suspend an ACTIVE exposure control (the ``Suspend`` command)."""
    _require_exposure(exposure)
    if exposure.state is not CreditExposureState.ACTIVE:
        raise CoreValidationError(
            f"only an ACTIVE exposure control can be suspended; state is {exposure.state.value}"
        )
    return exposure._advance(CreditExposureState.SUSPENDED, provenance=provenance)


def resume_credit_exposure(
    exposure: CreditExposure, *, provenance: Provenance
) -> CreditExposure:
    """Resume a SUSPENDED exposure control (the ``Resume`` command)."""
    _require_exposure(exposure)
    if exposure.state is not CreditExposureState.SUSPENDED:
        raise CoreValidationError(
            f"only a SUSPENDED exposure control can be resumed; state is {exposure.state.value}"
        )
    return exposure._advance(CreditExposureState.ACTIVE, provenance=provenance)


def withdraw_credit_exposure(
    exposure: CreditExposure, *, provenance: Provenance
) -> CreditExposure:
    """Withdraw the exposure control (the ``Withdraw`` command)."""
    _require_exposure(exposure)
    if exposure.state in _EXPOSURE_TERMINAL_STATES:
        raise CoreValidationError(
            f"a terminal exposure control cannot be withdrawn; state is {exposure.state.value}"
        )
    if not exposure.spec.utilized.is_zero():
        raise CoreValidationError(
            "an exposure control with recorded utilization cannot be withdrawn; "
            f"utilized={exposure.spec.utilized.to_dict()}"
        )
    return exposure._advance(CreditExposureState.WITHDRAWN, provenance=provenance)


def expire_credit_exposure(
    exposure: CreditExposure, *, as_of: str, provenance: Provenance
) -> CreditExposure:
    """Expire the exposure control (the ``Expire`` command).

    Requires ``as_of >= valid_until`` and zero recorded utilization.
    """
    _require_exposure(exposure)
    if exposure.state in _EXPOSURE_TERMINAL_STATES:
        raise CoreValidationError(
            f"a terminal exposure control cannot expire; state is {exposure.state.value}"
        )
    if parse_utc_timestamp("exposure.as_of", as_of) < parse_utc_timestamp(
        "exposure.valid_until", exposure.spec.valid_until
    ):
        raise CoreValidationError(
            "exposure control expiry requires as_of at or after valid_until "
            f"({exposure.spec.valid_until}); got {as_of}"
        )
    if not exposure.spec.utilized.is_zero():
        raise CoreValidationError(
            "an exposure control with recorded utilization cannot expire; "
            f"utilized={exposure.spec.utilized.to_dict()}"
        )
    return exposure._advance(CreditExposureState.EXPIRED, provenance=provenance)


# -- aggregation and assessment --------------------------------------------


@dataclass(frozen=True, slots=True)
class AggregatedExposure:
    """Aggregate utilization of all non-terminal facilities in one
    (counterparty, corridor) group."""

    counterparty: str
    corridor: Corridor
    facility_count: int
    offered_limit: Amount
    drawn: Amount

    def to_dict(self) -> dict[str, Any]:
        return {
            "counterparty": self.counterparty,
            "corridor": self.corridor.to_dict(),
            "facility_count": self.facility_count,
            "offered_limit": self.offered_limit.to_dict(),
            "drawn": self.drawn.to_dict(),
        }


def _non_terminal_credit(offers: Iterable[Any]) -> list[CreditOffer]:
    facilities: list[CreditOffer] = []
    for offer in offers:
        if not isinstance(offer, CreditOffer):
            raise CoreValidationError("aggregation requires CreditOffer values")
        if offer.state in (
            CreditOfferState.WITHDRAWN,
            CreditOfferState.EXPIRED,
            CreditOfferState.DEFAULTED,
        ):
            continue
        facilities.append(offer)
    return facilities


def aggregate_credit_utilization(
    offers: Iterable[CreditOffer],
) -> tuple[AggregatedExposure, ...]:
    """Aggregate facility limits and drawn utilization per
    (counterparty, corridor), deterministically ordered.

    Single linear pass over the offers (O(n)) with dictionary
    accumulation keyed by ``(counterparty, corridor_id)``; the corridor
    fixes the currency of every amount in a group, and the exact money
    authority rejects cross-currency sums. Terminal facilities are
    excluded; the result is sorted by the explicit key
    ``(counterparty, corridor_id)``.
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for offer in _non_terminal_credit(offers):
        key = (offer.spec.counterparty, offer.spec.corridor.corridor_id)
        group = groups.get(key)
        if group is None:
            group = {
                "counterparty": offer.spec.counterparty,
                "corridor": offer.spec.corridor,
                "facility_count": 0,
                "offered_limit": offer.spec.limit,
                "drawn": offer.spec.utilized,
            }
            groups[key] = group
        else:
            group["offered_limit"] = group["offered_limit"].add(offer.spec.limit)
            group["drawn"] = group["drawn"].add(offer.spec.utilized)
        group["facility_count"] += 1
    aggregates = [
        AggregatedExposure(
            counterparty=group["counterparty"],
            corridor=group["corridor"],
            facility_count=group["facility_count"],
            offered_limit=group["offered_limit"],
            drawn=group["drawn"],
        )
        for group in groups.values()
    ]
    aggregates.sort(key=lambda a: (a.counterparty, a.corridor.corridor_id))
    return tuple(aggregates)


@dataclass(frozen=True, slots=True)
class ExposureCheck:
    """One evaluated exposure control against aggregate facility draws."""

    exposure_id: str
    counterparty: str
    corridor: Corridor
    limit: Amount
    drawn: Amount
    status: ExposureStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "exposure_id": self.exposure_id,
            "counterparty": self.counterparty,
            "corridor": self.corridor.to_dict(),
            "limit": self.limit.to_dict(),
            "drawn": self.drawn.to_dict(),
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class ExposureAssessment:
    """Deterministic exposure assessment: aggregates, checks, breaches."""

    aggregates: tuple[AggregatedExposure, ...]
    checks: tuple[ExposureCheck, ...]

    @property
    def breaches(self) -> tuple[ExposureCheck, ...]:
        return tuple(
            check for check in self.checks if check.status is ExposureStatus.BREACH
        )

    def digest(self) -> str:
        return canonical_sha256(
            {
                "aggregates": [a.to_dict() for a in self.aggregates],
                "checks": [c.to_dict() for c in self.checks],
            }
        )


def assess_exposure(
    exposures: Iterable[CreditExposure],
    credit_offers: Iterable[CreditOffer],
) -> ExposureAssessment:
    """Assess exposure controls against aggregate facility utilization.

    For every non-terminal exposure record, the aggregate drawn amount of
    the matching ``(counterparty, corridor)`` group is compared with the
    record's limit: ``BREACH`` when the aggregate strictly exceeds the
    limit. Facility draws are each bounded by their own facility limits,
    so an aggregate breach is a legitimate, detectable control state —
    the response (suspending the control, rejecting further draws,
    restructuring) stays with the caller. Checks are ordered by
    ``(counterparty, corridor_id, exposure_id)``; the whole assessment is
    a linear pass over facilities plus a linear pass over controls, plus
    the bounded sort of the aggregate groups (O(n log n) in the group
    count).
    """
    aggregates = aggregate_credit_utilization(credit_offers)
    by_key = {
        (a.counterparty, a.corridor.corridor_id): a for a in aggregates
    }
    checks: list[ExposureCheck] = []
    for exposure in exposures:
        if not isinstance(exposure, CreditExposure):
            raise CoreValidationError("assessment requires CreditExposure values")
        if exposure.state in _EXPOSURE_TERMINAL_STATES:
            continue
        key = (exposure.spec.counterparty, exposure.spec.corridor.corridor_id)
        aggregate = by_key.get(key)
        drawn = (
            aggregate.drawn
            if aggregate is not None
            and aggregate.drawn.currency == exposure.spec.limit.currency
            else Amount.zero(exposure.spec.limit.currency)
        )
        status = (
            ExposureStatus.BREACH if drawn > exposure.spec.limit else ExposureStatus.OK
        )
        checks.append(
            ExposureCheck(
                exposure_id=exposure.envelope.object_id,
                counterparty=exposure.spec.counterparty,
                corridor=exposure.spec.corridor,
                limit=exposure.spec.limit,
                drawn=drawn,
                status=status,
            )
        )
    checks.sort(
        key=lambda c: (c.counterparty, c.corridor.corridor_id, c.exposure_id)
    )
    return ExposureAssessment(aggregates=aggregates, checks=tuple(checks))


# -- concentration controls -------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConcentrationEntry:
    """One measured concentration share against its explicit cap."""

    kind: ConcentrationControlKind
    group: tuple[str, ...]
    part: Amount
    whole: Amount
    share_bps: int
    cap_bps: int
    breach: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "group": list(self.group),
            "part": self.part.to_dict(),
            "whole": self.whole.to_dict(),
            "share_bps": self.share_bps,
            "cap_bps": self.cap_bps,
            "breach": self.breach,
        }


@dataclass(frozen=True, slots=True)
class ConcentrationReport:
    """Deterministic concentration report (entries ordered by kind+group)."""

    entries: tuple[ConcentrationEntry, ...]

    @property
    def breaches(self) -> tuple[ConcentrationEntry, ...]:
        return tuple(entry for entry in self.entries if entry.breach)

    def digest(self) -> str:
        return canonical_sha256([entry.to_dict() for entry in self.entries])


def _concentration_entry(
    kind: ConcentrationControlKind,
    group: tuple[str, ...],
    part: Amount,
    whole: Amount,
    cap_bps: int,
) -> ConcentrationEntry | None:
    """Build one entry with EXACT integer share comparison.

    The breach test is the cross-multiplied inequality
    ``part * 10000 > cap_bps * whole`` (exact integers, no rounding, no
    floating point); ``share_bps`` is the floored display value, which is
    why a share of e.g. 5000.5 bps is a breach against a 5000 bps cap
    even though its floor equals the cap.
    """
    if whole.is_zero():
        return None  # nothing measurable in this group
    breach = part.value * CONCENTRATION_DENOMINATOR_BPS > cap_bps * whole.value
    share_bps = (
        part.value * CONCENTRATION_DENOMINATOR_BPS
    ) // whole.value
    return ConcentrationEntry(
        kind=kind,
        group=group,
        part=part,
        whole=whole,
        share_bps=share_bps,
        cap_bps=cap_bps,
        breach=breach,
    )


def _accumulate(
    groups: dict[tuple[str, ...], Amount],
    key: tuple[str, ...],
    amount: Amount,
) -> None:
    existing = groups.get(key)
    if existing is None:
        groups[key] = amount
    else:
        groups[key] = existing.add(amount)


def evaluate_concentration(
    liquidity_offers: Iterable[LiquidityOffer] = (),
    credit_offers: Iterable[CreditOffer] = (),
) -> ConcentrationReport:
    """Evaluate the frozen concentration controls over offered capacity
    and drawn exposure.

    Measured dimensions (each within one currency group, because exact
    money amounts never sum across currencies):

    - ``PROVIDER`` — one provider's offered capacity share of its
      corridor's total offered capacity;
    - ``CORRIDOR`` — one corridor's offered capacity share of the total
      offered capacity denominated in that corridor's source currency;
    - ``COUNTERPARTY`` — one counterparty's drawn exposure share of the
      total drawn exposure in that currency.

    Terminal offers are excluded. Entries are ordered by
    ``(kind, group)`` — the deterministic tie-break — so the report and
    its digest are independent of input order. Single linear passes over
    the offers build the group sums (O(n)); the entries are then sorted
    (O(k log k) in the bounded group count).
    """
    provider_capacity: dict[tuple[str, ...], Amount] = {}
    corridor_capacity: dict[tuple[str, ...], Amount] = {}
    for offer in liquidity_offers:
        if not isinstance(offer, LiquidityOffer):
            raise CoreValidationError("concentration requires LiquidityOffer values")
        if offer.state in (LiquidityOfferState.WITHDRAWN, LiquidityOfferState.EXPIRED):
            continue
        corridor_id = offer.spec.corridor.corridor_id
        currency = offer.spec.capacity.currency.code
        _accumulate(
            provider_capacity,
            (corridor_id, offer.spec.provider, currency),
            offer.spec.capacity,
        )
        _accumulate(corridor_capacity, (corridor_id, currency), offer.spec.capacity)
    corridor_totals: dict[str, Amount] = {}
    for (corridor_id, currency), amount in corridor_capacity.items():
        _accumulate(corridor_totals, (currency,), amount)

    counterparty_drawn: dict[tuple[str, ...], Amount] = {}
    for offer in _non_terminal_credit(credit_offers):
        currency = offer.spec.limit.currency.code
        _accumulate(
            counterparty_drawn,
            (offer.spec.counterparty, currency),
            offer.spec.utilized,
        )
    drawn_totals: dict[str, Amount] = {}
    for (counterparty, currency), amount in counterparty_drawn.items():
        _accumulate(drawn_totals, (currency,), amount)

    entries: list[ConcentrationEntry] = []
    for (corridor_id, provider, currency), part in provider_capacity.items():
        whole = corridor_capacity[(corridor_id, currency)]
        entry = _concentration_entry(
            ConcentrationControlKind.PROVIDER,
            (corridor_id, provider),
            part,
            whole,
            MAX_PROVIDER_CONCENTRATION_BPS,
        )
        if entry is not None:
            entries.append(entry)
    for (corridor_id, currency), part in corridor_capacity.items():
        whole = corridor_totals[(currency,)]
        entry = _concentration_entry(
            ConcentrationControlKind.CORRIDOR,
            (corridor_id, currency),
            part,
            whole,
            MAX_CORRIDOR_CONCENTRATION_BPS,
        )
        if entry is not None:
            entries.append(entry)
    for (counterparty, currency), part in counterparty_drawn.items():
        whole = drawn_totals[(currency,)]
        entry = _concentration_entry(
            ConcentrationControlKind.COUNTERPARTY,
            (counterparty, currency),
            part,
            whole,
            MAX_COUNTERPARTY_CONCENTRATION_BPS,
        )
        if entry is not None:
            entries.append(entry)

    entries.sort(key=lambda entry: (entry.kind.value, entry.group))
    return ConcentrationReport(entries=tuple(entries))
