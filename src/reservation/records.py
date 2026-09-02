"""Protocol-level resource reservations: the versioned lifecycle record.

A :class:`Reservation` is the protocol-level, versioned record of reserved
capacity: a keyed resource, provider and beneficiary references, an exact
asset amount, an availability window, declared conditional-commit
conditions and the explicit lifecycle facts produced by the frozen v0.1
command family ``Create/Hold/Commit/Amend/Release/Expire/Default/Consume``.

Boundary with the market domain (WORK-010): ``src/market`` owns a bounded,
mechanism-local claim artifact restricted to the
``Create/Commit/Release/Expire`` subset. This module is the later sibling
that owns the protocol resource-reservation domain: the full command
family, encumbrance holding, amendment, conditional commit, default
handling, consumption, and the keyed concurrency contracts of the store
(:mod:`.store`) and lock manager (:mod:`.concurrency`).

Accounting boundary: a reservation RESERVES CAPACITY — it never moves
funds, never completes payments and never mutates the value ledger. The
encumbrance hold reference, funding sources and capability provenance are
referenced by opaque identifiers only; ``src/value`` (WORK-005) remains the
sole accounting authority. The reservation amount uses the value domain's
exact ``Amount`` and the availability window uses the capability domain's
``OperatingWindow`` (half-open UTC bounds, WORK-009); both are consumed,
never redefined.

Every accepted command produces the next sealed object version
(``ObjectEnvelope`` identity fields frozen, ``previous_version`` chained)
and carries explicit provenance. Terminal states
(``RELEASED/EXPIRED/DEFAULTED/CONSUMED``) are immutable.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.capability.windows import OperatingWindow
from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.value.amount import Amount

from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_utc_timestamp,
    require_utc_timestamp_at_or_after,
    strict_fields,
)
from .conditions import (
    CommitEvidence,
    ConditionSpec,
    evaluate_condition_satisfaction,
)
from .contracts import (
    RESERVATION_OBJECT_TYPE,
    RESERVATION_PROTOCOL_VERSION,
    RESERVATION_SCHEMA_VERSION,
    ReservationCommand,
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

_PAYLOAD_FIELDS = frozenset(
    {
        "resource_key",
        "provider",
        "beneficiary",
        "asset",
        "amount",
        "window",
        "conditions",
        "funding_refs",
        "source_ref",
        "hold_ref",
        "committed_at",
        "commit_evidence",
        "defaulted_reason",
        "defaulted_at",
        "consumed_at",
    }
)


class ReservationState(StrEnum):
    """Closed lifecycle vocabulary of a protocol resource reservation."""

    RESERVED = "RESERVED"
    HELD = "HELD"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    DEFAULTED = "DEFAULTED"
    CONSUMED = "CONSUMED"


class DefaultReason(StrEnum):
    """Closed vocabulary of explicit reservation default causes."""

    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE"
    CONDITION_BREACH = "CONDITION_BREACH"
    COUNTERPARTY_DEFAULT = "COUNTERPARTY_DEFAULT"


#: Terminal states: no command accepts them as a source state.
RESERVATION_TERMINAL_STATES = frozenset(
    {
        ReservationState.RELEASED,
        ReservationState.EXPIRED,
        ReservationState.DEFAULTED,
        ReservationState.CONSUMED,
    }
)

#: Allowed SOURCE states per command of the frozen family. ``Create`` has
#: no source state (it builds version 1); ``Amend`` keeps the source state;
#: every other command names its explicit target state.
RESERVATION_TRANSITIONS: Mapping[ReservationCommand, frozenset[ReservationState]] = {
    ReservationCommand.CREATE: frozenset(),
    ReservationCommand.HOLD: frozenset({ReservationState.RESERVED}),
    ReservationCommand.AMEND: frozenset(
        {ReservationState.RESERVED, ReservationState.HELD}
    ),
    ReservationCommand.COMMIT: frozenset(
        {ReservationState.RESERVED, ReservationState.HELD}
    ),
    ReservationCommand.RELEASE: frozenset(
        {ReservationState.RESERVED, ReservationState.HELD}
    ),
    ReservationCommand.EXPIRE: frozenset(
        {ReservationState.RESERVED, ReservationState.HELD}
    ),
    ReservationCommand.DEFAULT: frozenset(
        {ReservationState.HELD, ReservationState.COMMITTED}
    ),
    ReservationCommand.CONSUME: frozenset({ReservationState.COMMITTED}),
}


@dataclass(frozen=True, slots=True)
class ReservationSpec:
    """Immutable reservation payload.

    Identity fields (``resource_key``, ``provider``, ``beneficiary``,
    ``asset``, ``source_ref``, ``funding_refs``) are frozen for the object's
    whole life; the store additionally freezes the amount scale. Amount,
    window, conditions and the encumbrance reference are the amendable
    facts; the lifecycle facts (``hold_ref``, ``committed_at``,
    ``commit_evidence``, ``defaulted_reason``, ``defaulted_at``,
    ``consumed_at``) are written exactly once by their owning commands.
    """

    resource_key: str
    provider: str
    beneficiary: str
    asset: str
    amount: Amount
    window: OperatingWindow
    conditions: tuple[ConditionSpec, ...] = ()
    funding_refs: tuple[str, ...] = ()
    source_ref: str | None = None
    hold_ref: str | None = None
    committed_at: str | None = None
    commit_evidence: CommitEvidence | None = None
    defaulted_reason: DefaultReason | None = None
    defaulted_at: str | None = None
    consumed_at: str | None = None

    def __post_init__(self) -> None:
        require_identifier("reservation.resource_key", self.resource_key)
        require_identifier("reservation.provider", self.provider)
        require_identifier("reservation.beneficiary", self.beneficiary)
        require_identifier("reservation.asset", self.asset)
        if not isinstance(self.amount, Amount):
            raise CoreValidationError(
                f"reservation.amount must be a value-domain Amount, got {type(self.amount).__name__}"
            )
        if self.amount.asset != self.asset:
            raise CoreValidationError(
                f"reservation.amount asset {self.amount.asset} does not match the declared asset {self.asset}"
            )
        if not self.amount.is_positive():
            raise CoreValidationError(
                "reservation.amount must be positive: reserved capacity is a positive claim"
            )
        if not isinstance(self.window, OperatingWindow):
            raise CoreValidationError(
                f"reservation.window must be a capability-domain OperatingWindow, got {type(self.window).__name__}"
            )
        conditions = tuple(self.conditions)
        for spec in conditions:
            if not isinstance(spec, ConditionSpec):
                raise CoreValidationError(
                    f"reservation.conditions entries must be ConditionSpec values, got {type(spec).__name__}"
                )
        if len({spec.condition_key for spec in conditions}) != len(conditions):
            raise CoreValidationError(
                "reservation.conditions contain duplicate condition keys"
            )
        refs = tuple(self.funding_refs)
        if len(set(refs)) != len(refs):
            raise CoreValidationError(
                "reservation.funding_refs contain duplicate references"
            )
        for ref in refs:
            require_identifier("reservation.funding_refs entry", ref)
        if self.source_ref is not None:
            require_identifier("reservation.source_ref", self.source_ref)
        if self.hold_ref is not None:
            require_identifier("reservation.hold_ref", self.hold_ref)
        if (self.committed_at is None) != (self.commit_evidence is None):
            raise CoreValidationError(
                "reservation committed_at and commit_evidence must be present together"
            )
        if self.committed_at is not None:
            require_utc_timestamp("reservation.committed_at", self.committed_at)
        if (self.defaulted_reason is None) != (self.defaulted_at is None):
            raise CoreValidationError(
                "reservation defaulted_reason and defaulted_at must be present together"
            )
        if self.defaulted_at is not None:
            require_utc_timestamp("reservation.defaulted_at", self.defaulted_at)
        if self.consumed_at is not None:
            require_utc_timestamp("reservation.consumed_at", self.consumed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_key": self.resource_key,
            "provider": self.provider,
            "beneficiary": self.beneficiary,
            "asset": self.asset,
            "amount": self.amount.to_dict(),
            "window": self.window.to_dict(),
            "conditions": [spec.to_dict() for spec in self.conditions],
            "funding_refs": list(self.funding_refs),
            "source_ref": self.source_ref,
            "hold_ref": self.hold_ref,
            "committed_at": self.committed_at,
            "commit_evidence": (
                self.commit_evidence.to_dict() if self.commit_evidence is not None else None
            ),
            "defaulted_reason": (
                self.defaulted_reason.value
                if self.defaulted_reason is not None
                else None
            ),
            "defaulted_at": self.defaulted_at,
            "consumed_at": self.consumed_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReservationSpec":
        strict_fields("reservation payload", value, _PAYLOAD_FIELDS)
        conditions = value["conditions"]
        if not isinstance(conditions, list):
            raise CoreValidationError(
                "reservation.conditions must deserialize from a list"
            )
        funding_refs = value["funding_refs"]
        if not isinstance(funding_refs, list):
            raise CoreValidationError(
                "reservation.funding_refs must deserialize from a list"
            )
        commit_evidence = value["commit_evidence"]
        defaulted_reason = value["defaulted_reason"]
        return cls(
            resource_key=value["resource_key"],
            provider=value["provider"],
            beneficiary=value["beneficiary"],
            asset=value["asset"],
            amount=Amount.from_dict(value["amount"]),
            window=OperatingWindow.from_dict(value["window"]),
            conditions=tuple(ConditionSpec.from_dict(item) for item in conditions),
            funding_refs=tuple(funding_refs),
            source_ref=value["source_ref"],
            hold_ref=value["hold_ref"],
            committed_at=value["committed_at"],
            commit_evidence=(
                CommitEvidence.from_dict(commit_evidence)
                if commit_evidence is not None
                else None
            ),
            defaulted_reason=(
                parse_enum(
                    "reservation.defaulted_reason", DefaultReason, defaulted_reason
                )
                if defaulted_reason is not None
                else None
            ),
            defaulted_at=value["defaulted_at"],
            consumed_at=value["consumed_at"],
        )


def _validate_state_coherence(state: ReservationState, spec: ReservationSpec) -> None:
    """State-to-fact coherence: fail closed on spliced state/fact pairs."""

    def require_absent(fact: str, value: Any) -> None:
        if value is not None:
            raise CoreValidationError(
                f"a reservation in state {state.value} must not carry {fact}"
            )

    def require_present(fact: str, value: Any) -> None:
        if value is None:
            raise CoreValidationError(
                f"a reservation in state {state.value} must carry {fact}"
            )

    if state is ReservationState.RESERVED:
        # A soft claim: no encumbrance, no commit, no default, no consume.
        require_absent("hold_ref", spec.hold_ref)
        require_absent("committed_at", spec.committed_at)
        require_absent("defaulted_reason", spec.defaulted_reason)
        require_absent("consumed_at", spec.consumed_at)
    elif state is ReservationState.HELD:
        require_present("hold_ref", spec.hold_ref)
        require_absent("committed_at", spec.committed_at)
        require_absent("defaulted_reason", spec.defaulted_reason)
        require_absent("consumed_at", spec.consumed_at)
    elif state is ReservationState.COMMITTED:
        require_present("committed_at", spec.committed_at)
        require_present("commit_evidence", spec.commit_evidence)
        require_absent("defaulted_reason", spec.defaulted_reason)
        require_absent("consumed_at", spec.consumed_at)
    elif state in (ReservationState.RELEASED, ReservationState.EXPIRED):
        # Uncommitted endings: no commit, default or consume facts.
        require_absent("committed_at", spec.committed_at)
        require_absent("defaulted_reason", spec.defaulted_reason)
        require_absent("consumed_at", spec.consumed_at)
    elif state is ReservationState.DEFAULTED:
        require_present("defaulted_reason", spec.defaulted_reason)
        require_present("defaulted_at", spec.defaulted_at)
        require_absent("consumed_at", spec.consumed_at)
    elif state is ReservationState.CONSUMED:
        require_present("consumed_at", spec.consumed_at)
        require_present("committed_at", spec.committed_at)
        require_present("commit_evidence", spec.commit_evidence)
        require_absent("defaulted_reason", spec.defaulted_reason)
    else:  # pragma: no cover - closed vocabulary
        raise CoreValidationError(f"unknown reservation state: {state!r}")


@dataclass(frozen=True, slots=True)
class Reservation:
    """Durable protocol reservation record (envelope + sealed payload)."""

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
        if self.envelope.object_type != RESERVATION_OBJECT_TYPE:
            if str(self.envelope.object_type).startswith("payswap/"):
                raise CoreValidationError(
                    "reservation object_type must not claim a registry-governed "
                    "protocol-visible type; reservations use the internal type "
                    f"{RESERVATION_OBJECT_TYPE}"
                )
            raise CoreValidationError(
                f"reservation object_type must be {RESERVATION_OBJECT_TYPE!r}"
            )
        if self.envelope.schema_version != RESERVATION_SCHEMA_VERSION:
            raise CoreValidationError(
                f"reservation schema_version must be {RESERVATION_SCHEMA_VERSION}, "
                f"got {self.envelope.schema_version}"
            )
        if self.envelope.protocol_version != RESERVATION_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"reservation rejects unknown protocol version "
                f"{self.envelope.protocol_version!r}; expected "
                f"{RESERVATION_PROTOCOL_VERSION!r}"
            )
        try:
            state = ReservationState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown reservation state: {self.envelope.state!r}"
            ) from exc
        _validate_state_coherence(state, self.spec)
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ReservationState:
        return ReservationState(self.envelope.state)

    @property
    def resource_key(self) -> str:
        return self.spec.resource_key

    def is_terminal(self) -> bool:
        return self.state in RESERVATION_TERMINAL_STATES

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
        envelope, payload = decode_composite(value, state_type=ReservationState)
        spec = ReservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Reservation":
        envelope, payload, integrity_hash = decode_composite_json(
            value, state_type=ReservationState
        )
        spec = ReservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: ReservationState,
        spec: ReservationSpec,
        *,
        provenance: Provenance,
        causation_id: str | None,
        correlation_id: str | None,
    ) -> "Reservation":
        envelope = advance_envelope(
            self.envelope,
            state=new_state.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return Reservation(
            envelope=envelope,
            spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )


def _require_reservation(reservation: Reservation) -> Reservation:
    if not isinstance(reservation, Reservation):
        raise CoreValidationError("operation requires a Reservation")
    return reservation


def _require_source_state(
    reservation: Reservation,
    command: ReservationCommand,
    *,
    verb: str,
) -> None:
    allowed = RESERVATION_TRANSITIONS[command]
    if reservation.state not in allowed:
        ordered = " or ".join(
            state.value for state in sorted(allowed, key=lambda state: state.value)
        )
        raise CoreValidationError(
            f"only a {ordered} reservation can be {verb}; state is {reservation.state.value}"
        )


def _require_in_window(reservation: Reservation, command_name: str, as_of: str) -> None:
    if not reservation.spec.window.contains(as_of):
        raise CoreValidationError(
            f"{command_name} requires as_of inside the reservation window "
            f"[{reservation.spec.window.opens_at}, {reservation.spec.window.closes_at}); "
            f"got {as_of}"
        )


def create_reservation(
    *,
    reservation_id: str,
    resource_key: str,
    provider: str,
    beneficiary: str,
    asset: str,
    amount: Amount,
    window: OperatingWindow,
    conditions: Iterable[ConditionSpec] = (),
    funding_refs: Iterable[str] = (),
    source_ref: str | None = None,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Reservation:
    """Create a sealed RESERVED reservation record (the ``Create`` command)."""
    spec = ReservationSpec(
        resource_key=resource_key,
        provider=provider,
        beneficiary=beneficiary,
        asset=asset,
        amount=amount,
        window=window,
        conditions=tuple(conditions),
        funding_refs=tuple(funding_refs),
        source_ref=source_ref,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("reservation.reservation_id", reservation_id),
        state=ReservationState.RESERVED.value,
        environment_id=require_identifier("reservation.environment_id", environment_id),
        domain_id=require_identifier("reservation.domain_id", domain_id),
        provenance=provenance,
        causation_id=source_ref,
        correlation_id=correlation_id,
    )
    return Reservation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def hold_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    hold_ref: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Strengthen a RESERVED claim with an encumbrance reference (``Hold``).

    The encumbrance itself is owned by the value domain (WORK-005): the
    reservation records the opaque hold identifier only and never mutates
    the ledger.
    """
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.HOLD, verb="held")
    _require_in_window(record, "hold", as_of)
    spec = replace(record.spec, hold_ref=hold_ref)
    return record._advance(
        ReservationState.HELD,
        spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def amend_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    amount: Amount | None = None,
    window: OperatingWindow | None = None,
    conditions: Iterable[ConditionSpec] | None = None,
    hold_ref: str | None = None,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Amend the amendable facts, keeping the lifecycle state (``Amend``).

    Omitted fields are unchanged; ``conditions=()`` explicitly clears the
    declared condition set. Identity fields (resource key, parties, asset,
    source reference, funding references) cannot be amended, and the
    encumbrance reference can only be replaced — attaching one from a
    RESERVED record is the ``Hold`` command, clearing one is forbidden.
    """
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.AMEND, verb="amended")
    if not record.spec.window.contains(as_of):
        raise CoreValidationError(
            "amendment requires as_of inside the current reservation window "
            f"[{record.spec.window.opens_at}, {record.spec.window.closes_at}); got {as_of}"
        )
    if hold_ref is not None and record.spec.hold_ref is None:
        raise CoreValidationError(
            "attach the encumbrance with the Hold command instead of amending it in"
        )
    spec = record.spec
    if amount is not None:
        spec = replace(spec, amount=amount)
    if window is not None:
        spec = replace(spec, window=window)
    if conditions is not None:
        spec = replace(spec, conditions=tuple(conditions))
    if hold_ref is not None:
        spec = replace(spec, hold_ref=hold_ref)
    return record._advance(
        record.state,
        spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def commit_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    satisfied_conditions: Iterable[str] = (),
    evidence_refs: Iterable[str] = (),
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Conditionally commit the reservation (the ``Commit`` command).

    The commit succeeds only when every explicit condition holds:

    - the availability window is valid at ``as_of`` (half-open
      ``[opens_at, closes_at)``);
    - the declared condition set is fully satisfied by explicit evidence
      (no missing and no unknown keys — fail closed otherwise);
    - the writer expected the current object version (enforced by the
      reservation store's expected-version preconditions, not here).
    """
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.COMMIT, verb="committed")
    _require_in_window(record, "commit", as_of)
    satisfied = tuple(satisfied_conditions)
    evaluation = evaluate_condition_satisfaction(record.spec.conditions, satisfied)
    if not evaluation.all_satisfied:
        segments = []
        if evaluation.missing:
            segments.append(f"unsatisfied conditions {list(evaluation.missing)}")
        if evaluation.unknown:
            segments.append(f"unknown satisfied conditions {list(evaluation.unknown)}")
        raise CoreValidationError(
            "commit denied: " + "; ".join(segments)
        )
    evidence = CommitEvidence(
        satisfied_keys=tuple(sorted(set(satisfied))),
        evidence_refs=tuple(sorted(set(evidence_refs))),
        decided_at=as_of,
    )
    spec = replace(record.spec, committed_at=as_of, commit_evidence=evidence)
    return record._advance(
        ReservationState.COMMITTED,
        spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def release_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Voluntarily relinquish an uncommitted reservation (``Release``)."""
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.RELEASE, verb="released")
    closes_at = record.spec.window.closes_at
    if parse_utc_timestamp("release as_of", as_of) >= parse_utc_timestamp(
        "window closes_at", closes_at
    ):
        raise CoreValidationError(
            f"release requires as_of before the window end ({closes_at}); "
            f"use expire instead; got {as_of}"
        )
    return record._advance(
        ReservationState.RELEASED,
        record.spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def expire_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Expire an uncommitted reservation once its window elapsed (``Expire``)."""
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.EXPIRE, verb="expired")
    closes_at = record.spec.window.closes_at
    if parse_utc_timestamp("expire as_of", as_of) < parse_utc_timestamp(
        "window closes_at", closes_at
    ):
        raise CoreValidationError(
            f"expiry requires as_of at or after the window end ({closes_at}); got {as_of}"
        )
    return record._advance(
        ReservationState.EXPIRED,
        record.spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def default_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    reason: DefaultReason,
    provenance: Provenance,
    evidence_refs: Iterable[str] = (),
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Record an explicit reservation default (the ``Default`` command).

    Default is the adverse-outcome path for a claim the provider has
    affirmed (a held or committed reservation): it requires an explicit
    closed-vocabulary reason, explicit evidence references and — for a
    committed reservation — an instant at or after the recorded commit.
    """
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    if not isinstance(reason, DefaultReason):
        reason = parse_enum("reservation.default_reason", DefaultReason, reason)
    _require_source_state(record, ReservationCommand.DEFAULT, verb="defaulted")
    if record.state is ReservationState.COMMITTED:
        require_utc_timestamp_at_or_after(
            "default as_of", as_of, "recorded commit instant", record.spec.committed_at
        )
    merged_provenance = provenance
    extra_refs = tuple(evidence_refs)
    if extra_refs:
        merged_provenance = Provenance(
            issuer=provenance.issuer,
            source=provenance.source,
            recorded_at=provenance.recorded_at,
            evidence_refs=tuple(provenance.evidence_refs) + extra_refs,
        )
    spec = replace(record.spec, defaulted_reason=reason, defaulted_at=as_of)
    return record._advance(
        ReservationState.DEFAULTED,
        spec,
        provenance=merged_provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def consume_reservation(
    reservation: Reservation,
    *,
    as_of: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Reservation:
    """Consume committed reserved capacity (the ``Consume`` command)."""
    record = _require_reservation(reservation)
    require_utc_timestamp("reservation.as_of", as_of)
    _require_source_state(record, ReservationCommand.CONSUME, verb="consumed")
    require_utc_timestamp_at_or_after(
        "consume as_of", as_of, "recorded commit instant", record.spec.committed_at
    )
    spec = replace(record.spec, consumed_at=as_of)
    return record._advance(
        ReservationState.CONSUMED,
        spec,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


__all__ = [
    "DefaultReason",
    "RESERVATION_TERMINAL_STATES",
    "RESERVATION_TRANSITIONS",
    "Reservation",
    "ReservationSpec",
    "ReservationState",
    "amend_reservation",
    "commit_reservation",
    "consume_reservation",
    "create_reservation",
    "default_reservation",
    "expire_reservation",
    "hold_reservation",
    "release_reservation",
]
