"""Credit offers: bounded facilities with utilization and collateral references.

A :class:`CreditOffer` is a declarative facility record — provider plus a
REQUIRED opaque provider capability reference (WORK-009), a counterparty
(the facility's beneficiary and debtor), a corridor whose source asset
denominates the facility, an exact fixed-point ``limit``, a half-open
utilization window, and collateral references carried as OPAQUE
value-domain identifiers (holds/accounts owned by ``src/value``,
WORK-005). This domain never touches those objects: collateral is a
reference, and encumbrance accounting is the value domain's authority.

Facility utilization is tracked as an immutable ``utilized`` amount on
each version with the invariant ``utilized <= limit`` (bounded credit,
never unbounded money creation). The lifecycle follows the frozen
``Credit`` command family: ``Create/Amend/Withdraw/Suspend/Resume/Expire``
plus ``Draw/Repay/Restructure/Default``. Withdrawal and expiry require
zero outstanding utilization (fail closed: restructure or default
instead); default requires outstanding exposure and is terminal.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.money import Amount

from .contracts import CREDIT_OFFER_OBJECT_TYPE
from .corridors import Corridor
from ._validation import (
    parse_utc_timestamp,
    require_bool,
    require_identifier,
    require_identifier_tuple,
    require_utc_timestamp,
    require_utc_window,
    strict_fields,
    utc_timestamp_within,
)
from .offers import (
    require_capacity_matches_source_asset,
    require_positive_amount,
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

_CREDIT_SPEC_FIELDS = frozenset(
    {
        "provider",
        "provider_capability_id",
        "counterparty",
        "corridor",
        "limit",
        "utilized",
        "utilization_from",
        "utilization_until",
        "collateral_refs",
        "require_collateral",
    }
)


class CreditOfferState(StrEnum):
    """Closed lifecycle vocabulary of a credit offer (facility)."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"
    DEFAULTED = "DEFAULTED"


_CREDIT_TERMINAL_STATES = frozenset(
    {CreditOfferState.WITHDRAWN, CreditOfferState.EXPIRED, CreditOfferState.DEFAULTED}
)


@dataclass(frozen=True, slots=True)
class CreditOfferSpec:
    """Immutable credit facility payload."""

    provider: str
    provider_capability_id: str
    counterparty: str
    corridor: Corridor
    limit: Amount
    utilized: Amount
    utilization_from: str
    utilization_until: str
    collateral_refs: tuple[str, ...] = ()
    require_collateral: bool = False

    def __post_init__(self) -> None:
        require_identifier("credit.provider", self.provider)
        require_identifier("credit.provider_capability_id", self.provider_capability_id)
        require_identifier("credit.counterparty", self.counterparty)
        if not isinstance(self.corridor, Corridor):
            raise CoreValidationError("credit.corridor must be a Corridor")
        require_positive_amount("credit.limit", self.limit)
        require_capacity_matches_source_asset("credit.limit", self.corridor, self.limit)
        if not isinstance(self.utilized, Amount):
            raise CoreValidationError("credit.utilized must be an Amount")
        # Same-currency comparison enforced by the money authority itself.
        if self.utilized < Amount.zero(self.limit.currency):
            raise CoreValidationError("credit.utilized must not be negative")
        if self.utilized > self.limit:
            raise CoreValidationError(
                "credit.utilized must not exceed the facility limit; "
                f"utilized={self.utilized.to_dict()} limit={self.limit.to_dict()}"
            )
        require_utc_timestamp("credit.utilization_from", self.utilization_from)
        require_utc_timestamp("credit.utilization_until", self.utilization_until)
        require_utc_window(
            "credit.utilization", self.utilization_from, self.utilization_until
        )
        require_identifier_tuple("credit.collateral_refs", self.collateral_refs)
        require_bool("credit.require_collateral", self.require_collateral)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_capability_id": self.provider_capability_id,
            "counterparty": self.counterparty,
            "corridor": self.corridor.to_dict(),
            "limit": self.limit.to_dict(),
            "utilized": self.utilized.to_dict(),
            "utilization_from": self.utilization_from,
            "utilization_until": self.utilization_until,
            "collateral_refs": list(self.collateral_refs),
            "require_collateral": self.require_collateral,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CreditOfferSpec":
        strict_fields("credit", value, _CREDIT_SPEC_FIELDS)
        refs = value["collateral_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError("credit.collateral_refs must deserialize from a list")
        return cls(
            provider=value["provider"],
            provider_capability_id=value["provider_capability_id"],
            counterparty=value["counterparty"],
            corridor=Corridor.from_dict(value["corridor"]),
            limit=Amount.from_dict(value["limit"]),
            utilized=Amount.from_dict(value["utilized"]),
            utilization_from=value["utilization_from"],
            utilization_until=value["utilization_until"],
            collateral_refs=tuple(refs),
            require_collateral=value["require_collateral"],
        )


@dataclass(frozen=True, slots=True)
class CreditOffer:
    """Durable credit facility record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: CreditOfferSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = CREDIT_OFFER_OBJECT_TYPE
    STATE_TYPE = CreditOfferState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("credit envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, CreditOfferSpec):
            raise CoreValidationError("credit spec must be a CreditOfferSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != CREDIT_OFFER_OBJECT_TYPE:
            raise CoreValidationError(
                f"credit object_type must be {CREDIT_OFFER_OBJECT_TYPE!r}"
            )
        try:
            CreditOfferState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown credit state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> CreditOfferState:
        return CreditOfferState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CreditOffer":
        envelope, payload = decode_composite(
            value,
            expected_object_type=CREDIT_OFFER_OBJECT_TYPE,
            state_type=CreditOfferState,
        )
        spec = CreditOfferSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "CreditOffer":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=CREDIT_OFFER_OBJECT_TYPE,
            state_type=CreditOfferState,
        )
        spec = CreditOfferSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: CreditOfferState,
        *,
        provenance: Provenance,
        spec: CreditOfferSpec | None = None,
    ) -> "CreditOffer":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        payload = self.spec if spec is None else spec
        return CreditOffer(
            envelope=envelope, spec=payload, integrity_hash=seal_composite(envelope, payload)
        )


def create_credit_offer(
    *,
    offer_id: str,
    provider: str,
    provider_capability_id: str,
    counterparty: str,
    corridor: Corridor,
    limit: Amount,
    utilization_from: str,
    utilization_until: str,
    collateral_refs: Iterable[str] = (),
    require_collateral: bool = False,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> CreditOffer:
    """Create a sealed ACTIVE credit facility (the ``Create`` command).

    Utilization starts at zero; ``Draw`` is the only utilization-increasing
    command and is bounded by the facility limit.
    """
    if not isinstance(corridor, Corridor):
        raise CoreValidationError("credit.corridor must be a Corridor")
    spec = CreditOfferSpec(
        provider=provider,
        provider_capability_id=provider_capability_id,
        counterparty=counterparty,
        corridor=corridor,
        limit=limit,
        utilized=Amount.zero(limit.currency),
        utilization_from=utilization_from,
        utilization_until=utilization_until,
        collateral_refs=tuple(collateral_refs),
        require_collateral=require_collateral,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("credit.offer_id", offer_id),
        object_type=CREDIT_OFFER_OBJECT_TYPE,
        state=CreditOfferState.ACTIVE.value,
        environment_id=require_identifier("credit.environment_id", environment_id),
        domain_id=require_identifier("credit.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return CreditOffer(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def credit_available_capacity(credit: CreditOffer) -> Amount:
    """Exact remaining drawable capacity of the facility."""
    _require_credit(credit)
    return credit.spec.limit.sub(credit.spec.utilized)


def _require_credit(credit: CreditOffer) -> CreditOffer:
    if not isinstance(credit, CreditOffer):
        raise CoreValidationError("operation requires a CreditOffer")
    return credit


def _require_utilization_window(credit: CreditOffer, as_of: str) -> None:
    require_utc_timestamp("credit.as_of", as_of)
    if not utc_timestamp_within(
        credit.spec.utilization_from, as_of, credit.spec.utilization_until
    ):
        raise CoreValidationError(
            "credit facility operation requires as_of inside the utilization window "
            f"[{credit.spec.utilization_from}, {credit.spec.utilization_until}); "
            f"got {as_of}"
        )


def draw_credit(
    credit: CreditOffer,
    amount: Amount,
    *,
    as_of: str,
    provenance: Provenance,
) -> CreditOffer:
    """Draw on the facility (the ``Draw`` command).

    Fail-closed preconditions: ACTIVE state, ``as_of`` strictly inside the
    half-open utilization window, a positive amount in the facility
    currency, attached collateral references when the facility requires
    them, and ``utilized + amount <= limit`` — liquidity is a bounded
    capability model, so a draw can never exceed the declared facility
    limit.
    """
    _require_credit(credit)
    if credit.state is not CreditOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE credit facility can be drawn; state is "
            f"{credit.state.value}"
        )
    _require_utilization_window(credit, as_of)
    require_positive_amount("credit.draw amount", amount)
    if amount.currency != credit.spec.limit.currency:
        raise CoreValidationError(
            "credit draw must use the facility currency "
            f"{credit.spec.limit.currency.code}; got {amount.currency.code}"
        )
    if credit.spec.require_collateral and not credit.spec.collateral_refs:
        raise CoreValidationError(
            f"credit facility {credit.envelope.object_id} requires collateral "
            "references before it can be drawn; none are attached"
        )
    projected = credit.spec.utilized.add(amount)
    if projected > credit.spec.limit:
        raise CoreValidationError(
            "credit draw would exceed the facility limit; "
            f"utilized={credit.spec.utilized.to_dict()} "
            f"draw={amount.to_dict()} limit={credit.spec.limit.to_dict()}"
        )
    spec = replace(credit.spec, utilized=projected)
    return credit._advance(CreditOfferState.ACTIVE, provenance=provenance, spec=spec)


def repay_credit(
    credit: CreditOffer,
    amount: Amount,
    *,
    as_of: str,
    provenance: Provenance,
) -> CreditOffer:
    """Repay drawn utilization (the ``Repay`` command).

    Repayment is the normal servicing path and stays legal after the
    utilization window has elapsed; it cannot precede the window start,
    cannot be non-positive, cannot be in a foreign currency and can never
    over-repay (utilization never goes negative).
    """
    _require_credit(credit)
    if credit.state is not CreditOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE credit facility can be repaid; state is "
            f"{credit.state.value}"
        )
    require_positive_amount("credit.repay amount", amount)
    if amount.currency != credit.spec.limit.currency:
        raise CoreValidationError(
            "credit repayment must use the facility currency "
            f"{credit.spec.limit.currency.code}; got {amount.currency.code}"
        )
    if parse_utc_timestamp("credit.as_of", as_of) < parse_utc_timestamp(
        "credit.utilization_from", credit.spec.utilization_from
    ):
        raise CoreValidationError(
            "credit repayment cannot precede the utilization window "
            f"({credit.spec.utilization_from}); got {as_of}"
        )
    if amount > credit.spec.utilized:
        raise CoreValidationError(
            "credit repayment cannot exceed the outstanding utilization; "
            f"utilized={credit.spec.utilized.to_dict()} repay={amount.to_dict()}"
        )
    spec = replace(credit.spec, utilized=credit.spec.utilized.sub(amount))
    return credit._advance(CreditOfferState.ACTIVE, provenance=provenance, spec=spec)


def amend_credit_offer(
    credit: CreditOffer,
    *,
    provenance: Provenance,
    limit: Amount | None = None,
    utilization_until: str | None = None,
) -> CreditOffer:
    """Amend facility terms (the ``Amend`` command).

    A clean amendment is only legal with zero outstanding utilization;
    amending a facility with outstanding exposure is a ``Restructure``.
    """
    _require_credit(credit)
    if credit.state is not CreditOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE credit facility can be amended; state is "
            f"{credit.state.value}"
        )
    if not credit.spec.utilized.is_zero():
        raise CoreValidationError(
            "a credit facility with outstanding utilization cannot be amended; "
            f"utilized={credit.spec.utilized.to_dict()}; use restructure_credit"
        )
    return _apply_term_changes(
        credit,
        provenance=provenance,
        limit=limit,
        utilization_until=utilization_until,
        collateral_refs=None,
        require_collateral=None,
        command="amend",
    )


def restructure_credit(
    credit: CreditOffer,
    *,
    provenance: Provenance,
    limit: Amount | None = None,
    utilization_until: str | None = None,
    collateral_refs: Iterable[str] | None = None,
    require_collateral: bool | None = None,
) -> CreditOffer:
    """Restructure facility terms with outstanding exposure (``Restructure``).

    Restructuring keeps utilization in place and revalidates the whole
    spec, so the new limit can never fall below the outstanding amount.
    """
    _require_credit(credit)
    if credit.state is not CreditOfferState.ACTIVE:
        raise CoreValidationError(
            "only an ACTIVE credit facility can be restructured; state is "
            f"{credit.state.value}"
        )
    return _apply_term_changes(
        credit,
        provenance=provenance,
        limit=limit,
        utilization_until=utilization_until,
        collateral_refs=collateral_refs,
        require_collateral=require_collateral,
        command="restructure",
    )


def _apply_term_changes(
    credit: CreditOffer,
    *,
    provenance: Provenance,
    limit: Amount | None,
    utilization_until: str | None,
    collateral_refs: Iterable[str] | None,
    require_collateral: bool | None,
    command: str,
) -> CreditOffer:
    if (
        limit is None
        and utilization_until is None
        and collateral_refs is None
        and require_collateral is None
    ):
        raise CoreValidationError(f"credit {command} requires at least one new value")
    changes: dict[str, Any] = {}
    if limit is not None:
        changes["limit"] = limit
    if utilization_until is not None:
        changes["utilization_until"] = utilization_until
    if collateral_refs is not None:
        if not isinstance(collateral_refs, (list, tuple)):
            raise CoreValidationError("credit collateral_refs must be a sequence")
        changes["collateral_refs"] = tuple(collateral_refs)
    if require_collateral is not None:
        changes["require_collateral"] = require_collateral
    spec = replace(credit.spec, **changes)
    return credit._advance(CreditOfferState.ACTIVE, provenance=provenance, spec=spec)


def suspend_credit_offer(
    credit: CreditOffer, *, provenance: Provenance
) -> CreditOffer:
    """Suspend an ACTIVE facility (the ``Suspend`` command).

    Suspension stops further draws; outstanding utilization persists.
    """
    _require_credit(credit)
    if credit.state is not CreditOfferState.ACTIVE:
        raise CoreValidationError(
            f"only an ACTIVE credit facility can be suspended; state is {credit.state.value}"
        )
    return credit._advance(CreditOfferState.SUSPENDED, provenance=provenance)


def resume_credit_offer(
    credit: CreditOffer, *, provenance: Provenance
) -> CreditOffer:
    """Resume a SUSPENDED facility (the ``Resume`` command)."""
    _require_credit(credit)
    if credit.state is not CreditOfferState.SUSPENDED:
        raise CoreValidationError(
            f"only a SUSPENDED credit facility can be resumed; state is {credit.state.value}"
        )
    return credit._advance(CreditOfferState.ACTIVE, provenance=provenance)


def withdraw_credit_offer(
    credit: CreditOffer, *, provenance: Provenance
) -> CreditOffer:
    """Withdraw a facility (the ``Withdraw`` command); requires zero outstanding."""
    _require_credit(credit)
    if credit.state in _CREDIT_TERMINAL_STATES:
        raise CoreValidationError(
            f"a terminal credit facility cannot be withdrawn; state is {credit.state.value}"
        )
    if not credit.spec.utilized.is_zero():
        raise CoreValidationError(
            "a credit facility with outstanding utilization cannot be withdrawn; "
            f"utilized={credit.spec.utilized.to_dict()}; restructure or default first"
        )
    return credit._advance(CreditOfferState.WITHDRAWN, provenance=provenance)


def expire_credit_offer(
    credit: CreditOffer, *, as_of: str, provenance: Provenance
) -> CreditOffer:
    """Expire a facility (the ``Expire`` command).

    Requires the utilization window to have elapsed (``as_of >=
    utilization_until``) AND zero outstanding utilization: an expiring
    facility may not silently drop outstanding exposure.
    """
    _require_credit(credit)
    if credit.state in _CREDIT_TERMINAL_STATES:
        raise CoreValidationError(
            f"a terminal credit facility cannot expire; state is {credit.state.value}"
        )
    if parse_utc_timestamp("credit.as_of", as_of) < parse_utc_timestamp(
        "credit.utilization_until", credit.spec.utilization_until
    ):
        raise CoreValidationError(
            "credit facility expiry requires as_of at or after utilization_until "
            f"({credit.spec.utilization_until}); got {as_of}"
        )
    if not credit.spec.utilized.is_zero():
        raise CoreValidationError(
            "a credit facility with outstanding utilization cannot expire; "
            f"utilized={credit.spec.utilized.to_dict()}; restructure or default first"
        )
    return credit._advance(CreditOfferState.EXPIRED, provenance=provenance)


def default_credit(
    credit: CreditOffer, *, as_of: str, provenance: Provenance
) -> CreditOffer:
    """Declare the facility defaulted (the ``Default`` command).

    Default requires outstanding exposure (a facility with zero
    outstanding cannot default) and is terminal; loss allocation and
    recourse belong to later sibling domains.
    """
    _require_credit(credit)
    if credit.state in _CREDIT_TERMINAL_STATES:
        raise CoreValidationError(
            f"a terminal credit facility cannot default; state is {credit.state.value}"
        )
    require_utc_timestamp("credit.as_of", as_of)
    if credit.spec.utilized.is_zero():
        raise CoreValidationError(
            "a credit facility with zero outstanding utilization cannot default; "
            "draw before declaring default"
        )
    return credit._advance(CreditOfferState.DEFAULTED, provenance=provenance)
