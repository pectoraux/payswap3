"""Obligations: the protocol-level obligation record and its lifecycle facts.

An :class:`Obligation` is the registry-listed protocol object
(``payswap/obligation/v1``) recognized from the execution domain's
rail-reported effect results: who owes whom, exactly what amount of
which asset, inside which due window. The frozen v0.1 ``Obligation``
command family ``Create/Validate/Amend/Dispute/Restructure/MarkDue/
Default/Resolve`` drives it.

Consumed authorities (one authority per concept, never redefined here):

* the exact amount is the value domain's :class:`src.value.Amount`
  (WORK-005 — the sole accounting authority);
* the epistemic vocabulary of evidence-bearing commands is the evidence
  domain's :class:`src.evidence.EpistemicType` (WORK-018 contract): a
  dispute, restructure, default or discharge declaration must be
  ``OBSERVED`` — a simulated or predicted value can never mutate an
  obligation;
* the funding gate vocabulary is the reservation domain's
  :class:`src.reservation.ReservationState` (WORK-012): a due
  obligation may declare ``HELD`` funding evidence;
* the recognition source is the execution domain's
  :class:`src.execution.EffectResult` (WORK-014): obligations are
  recognized only from ``SUCCEEDED`` effect results, digest-bound to
  the exact evidence content (a result may never be spliced onto a
  different obligation).

Accounting boundary: an obligation is a recognized claim — it never
moves funds and never posts. Settlement and discharge belong to
WORK-016; a ``RESOLVED`` obligation is a clearing-side closure recorded
with explicit evidence, never a settlement-finality claim (constitution
invariant 11).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.evidence.contracts import EpistemicType
from src.reservation import ReservationState
from src.value.amount import Amount

from ._validation import (
    parse_enum,
    require_digest,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .contracts import (
    OBLIGATION_OBJECT_TYPE,
    ObligationSourceKind,
    ObligationState,
    ResolutionKind,
)
from .seal import (
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_OBLIGATION_SPEC_FIELDS = frozenset(
    {
        "obligation_id",
        "cycle_id",
        "obligor",
        "obligee",
        "asset",
        "amount",
        "source_kind",
        "source_ref",
        "source_digest",
        "due_window",
        "amendment",
        "dispute",
        "restructure",
        "due",
        "default",
        "resolution",
    }
)

_DUE_WINDOW_FIELDS = frozenset({"due_from", "due_until"})

_AMENDMENT_FIELDS = frozenset({"reason", "amended_at"})
_DISPUTE_FIELDS = frozenset({"evidence_ref", "epistemic_type", "reason", "disputed_at"})
_RESTRUCTURE_FIELDS = frozenset(
    {"evidence_ref", "epistemic_type", "reason", "restructured_at"}
)
_FUNDING_FIELDS = frozenset({"reservation_id", "state", "object_version"})
_DUE_FIELDS = frozenset({"marked_at", "funding"})
_DEFAULT_FIELDS = frozenset({"evidence_ref", "epistemic_type", "reason", "defaulted_at"})
_RESOLUTION_FIELDS = frozenset({"kind", "ref", "digest", "resolved_at"})


@dataclass(frozen=True, slots=True)
class DueWindow:
    """The half-open UTC window in which the obligation is claimable."""

    due_from: str
    due_until: str

    def __post_init__(self) -> None:
        require_utc_timestamp("obligation.due_window.due_from", self.due_from)
        require_utc_timestamp("obligation.due_window.due_until", self.due_until)
        require_utc_timestamp_order(
            "obligation.due_window.due_from",
            self.due_from,
            "obligation.due_window.due_until",
            self.due_until,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"due_from": self.due_from, "due_until": self.due_until}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DueWindow":
        strict_fields("obligation.due_window", value, _DUE_WINDOW_FIELDS)
        return cls(due_from=value["due_from"], due_until=value["due_until"])


@dataclass(frozen=True, slots=True)
class AmendmentRecord:
    """Marker of one ``Amend`` application (the new terms live on the spec)."""

    reason: str
    amended_at: str

    def __post_init__(self) -> None:
        require_text("obligation.amendment.reason", self.reason)
        require_utc_timestamp("obligation.amendment.amended_at", self.amended_at)

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "amended_at": self.amended_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AmendmentRecord":
        strict_fields("obligation.amendment", value, _AMENDMENT_FIELDS)
        return cls(reason=value["reason"], amended_at=value["amended_at"])


@dataclass(frozen=True, slots=True)
class EvidenceGate:
    """One ``OBSERVED`` evidence binding carried by an evidence command.

    The epistemic vocabulary is owned by ``src.evidence`` (WORK-018)
    and consumed here: only ``OBSERVED`` knowledge may back a dispute,
    restructure, default or discharge declaration — simulated or
    predicted values fail closed.
    """

    evidence_ref: str
    epistemic_type: str
    reason: str

    def __post_init__(self) -> None:
        require_identifier("obligation evidence.evidence_ref", self.evidence_ref)
        parsed = parse_enum(
            "obligation evidence.epistemic_type", self.epistemic_type, EpistemicType
        )
        if parsed is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                "obligation evidence must be OBSERVED knowledge; a "
                f"{parsed.value} value can never mutate an obligation"
            )
        require_text("obligation evidence.reason", self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "epistemic_type": self.epistemic_type.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class DisputeRecord:
    """One open dispute backed by ``OBSERVED`` evidence."""

    evidence_ref: str
    epistemic_type: str
    reason: str
    disputed_at: str

    def __post_init__(self) -> None:
        EvidenceGate(
            evidence_ref=self.evidence_ref,
            epistemic_type=self.epistemic_type,
            reason=self.reason,
        )
        require_utc_timestamp("obligation.dispute.disputed_at", self.disputed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "epistemic_type": self.epistemic_type,
            "reason": self.reason,
            "disputed_at": self.disputed_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DisputeRecord":
        strict_fields("obligation.dispute", value, _DISPUTE_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            epistemic_type=value["epistemic_type"],
            reason=value["reason"],
            disputed_at=value["disputed_at"],
        )


@dataclass(frozen=True, slots=True)
class RestructureRecord:
    """One dispute resolution with new terms (terms live on the spec)."""

    evidence_ref: str
    epistemic_type: str
    reason: str
    restructured_at: str

    def __post_init__(self) -> None:
        EvidenceGate(
            evidence_ref=self.evidence_ref,
            epistemic_type=self.epistemic_type,
            reason=self.reason,
        )
        require_utc_timestamp("obligation.restructure.restructured_at", self.restructured_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "epistemic_type": self.epistemic_type,
            "reason": self.reason,
            "restructured_at": self.restructured_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RestructureRecord":
        strict_fields("obligation.restructure", value, _RESTRUCTURE_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            epistemic_type=value["epistemic_type"],
            reason=value["reason"],
            restructured_at=value["restructured_at"],
        )


@dataclass(frozen=True, slots=True)
class FundingGate:
    """Reservation-backed funding evidence declared at ``MarkDue``.

    The state vocabulary is the closed ``ReservationState`` owned by
    ``src.reservation`` (WORK-012) and consumed here without
    re-evaluation: only a ``HELD`` reservation covers a due obligation
    (constitution invariant 8, reservation safety).
    """

    reservation_id: str
    state: str
    object_version: int

    def __post_init__(self) -> None:
        require_identifier("obligation.funding.reservation_id", self.reservation_id)
        parsed = parse_enum(
            "obligation.funding.state", self.state, ReservationState
        )
        if parsed is not ReservationState.HELD:
            raise CoreValidationError(
                f"reservation {self.reservation_id} is {parsed.value!r}; a due "
                "obligation requires HELD funding evidence"
            )
        require_int("obligation.funding.object_version", self.object_version, minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "state": self.state,
            "object_version": self.object_version,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FundingGate":
        strict_fields("obligation.funding", value, _FUNDING_FIELDS)
        return cls(
            reservation_id=value["reservation_id"],
            state=value["state"],
            object_version=value["object_version"],
        )


@dataclass(frozen=True, slots=True)
class DueRecord:
    """Marker of one ``MarkDue`` application with optional funding evidence."""

    marked_at: str
    funding: FundingGate | None

    def __post_init__(self) -> None:
        require_utc_timestamp("obligation.due.marked_at", self.marked_at)
        if self.funding is not None and not isinstance(self.funding, FundingGate):
            raise CoreValidationError("obligation.due.funding must be a FundingGate")

    def to_dict(self) -> dict[str, Any]:
        return {
            "marked_at": self.marked_at,
            "funding": self.funding.to_dict() if self.funding is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DueRecord":
        strict_fields("obligation.due", value, _DUE_FIELDS)
        raw_funding = value["funding"]
        funding = FundingGate.from_dict(raw_funding) if raw_funding is not None else None
        return cls(marked_at=value["marked_at"], funding=funding)


@dataclass(frozen=True, slots=True)
class DefaultRecord:
    """Terminal default marker backed by ``OBSERVED`` evidence."""

    evidence_ref: str
    epistemic_type: str
    reason: str
    defaulted_at: str

    def __post_init__(self) -> None:
        EvidenceGate(
            evidence_ref=self.evidence_ref,
            epistemic_type=self.epistemic_type,
            reason=self.reason,
        )
        require_utc_timestamp("obligation.default.defaulted_at", self.defaulted_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "epistemic_type": self.epistemic_type,
            "reason": self.reason,
            "defaulted_at": self.defaulted_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DefaultRecord":
        strict_fields("obligation.default", value, _DEFAULT_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            epistemic_type=value["epistemic_type"],
            reason=value["reason"],
            defaulted_at=value["defaulted_at"],
        )


@dataclass(frozen=True, slots=True)
class ResolutionRecord:
    """Terminal resolution marker.

    ``kind`` is the closed :class:`ResolutionKind` vocabulary:
    ``NETTING`` (the obligation was offset/reclassified by the
    referenced finalized netting cycle — statement digest bound) or
    ``DISCHARGE_EVIDENCE`` (externally declared discharge evidence was
    recorded — reference and digest are declared data; recording them
    never establishes settlement finality, constitution invariant 11).
    """

    kind: str
    ref: str
    digest: str
    resolved_at: str

    def __post_init__(self) -> None:
        parse_enum("obligation.resolution.kind", self.kind, ResolutionKind)
        require_identifier("obligation.resolution.ref", self.ref)
        require_digest("obligation.resolution.digest", self.digest)
        require_utc_timestamp("obligation.resolution.resolved_at", self.resolved_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "digest": self.digest,
            "resolved_at": self.resolved_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResolutionRecord":
        strict_fields("obligation.resolution", value, _RESOLUTION_FIELDS)
        return cls(
            kind=value["kind"],
            ref=value["ref"],
            digest=value["digest"],
            resolved_at=value["resolved_at"],
        )


@dataclass(frozen=True, slots=True)
class ObligationSpec:
    """Immutable obligation payload (the current terms + lifecycle facts).

    Identity fields (``obligation_id``, ``cycle_id``, ``obligor``,
    ``obligee``, ``asset``, ``source_kind``, ``source_ref``,
    ``source_digest``) are frozen for the object's whole life. The
    terms (``amount``, ``due_window``) are the amendable facts; every
    lifecycle marker is written exactly once by its owning command.
    """

    obligation_id: str
    cycle_id: str | None
    obligor: str
    obligee: str
    asset: str
    amount: Amount
    source_kind: str
    source_ref: str
    source_digest: str
    due_window: DueWindow
    amendment: AmendmentRecord | None = None
    dispute: DisputeRecord | None = None
    restructure: RestructureRecord | None = None
    due: DueRecord | None = None
    default: DefaultRecord | None = None
    resolution: ResolutionRecord | None = None

    def __post_init__(self) -> None:
        require_identifier("obligation.obligation_id", self.obligation_id)
        if self.cycle_id is not None:
            require_identifier("obligation.cycle_id", self.cycle_id)
        require_identifier("obligation.obligor", self.obligor)
        require_identifier("obligation.obligee", self.obligee)
        if self.obligor == self.obligee:
            raise CoreValidationError(
                "obligation.obligor and obligation.obligee must be distinct participants"
            )
        require_identifier("obligation.asset", self.asset)
        if not isinstance(self.amount, Amount):
            raise CoreValidationError(
                f"obligation.amount must be a value-domain Amount, got "
                f"{type(self.amount).__name__}"
            )
        if self.amount.asset != self.asset:
            raise CoreValidationError(
                f"obligation.amount asset {self.amount.asset} does not match the "
                f"declared asset {self.asset}"
            )
        if not self.amount.is_positive():
            raise CoreValidationError(
                "obligation.amount must be positive: an obligation is a positive claim"
            )
        parse_enum("obligation.source_kind", self.source_kind, ObligationSourceKind)
        require_identifier("obligation.source_ref", self.source_ref)
        require_digest("obligation.source_digest", self.source_digest)
        if not isinstance(self.due_window, DueWindow):
            raise CoreValidationError(
                f"obligation.due_window must be a DueWindow, got "
                f"{type(self.due_window).__name__}"
            )
        for name, record_type in (
            ("amendment", AmendmentRecord),
            ("dispute", DisputeRecord),
            ("restructure", RestructureRecord),
            ("due", DueRecord),
            ("default", DefaultRecord),
            ("resolution", ResolutionRecord),
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, record_type):
                raise CoreValidationError(
                    f"obligation.{name} must be a {record_type.__name__}"
                )
        if (self.default is not None) and (self.resolution is not None):
            raise CoreValidationError(
                "an obligation cannot be both defaulted and resolved"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "cycle_id": self.cycle_id,
            "obligor": self.obligor,
            "obligee": self.obligee,
            "asset": self.asset,
            "amount": self.amount.to_dict(),
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "source_digest": self.source_digest,
            "due_window": self.due_window.to_dict(),
            "amendment": self.amendment.to_dict() if self.amendment is not None else None,
            "dispute": self.dispute.to_dict() if self.dispute is not None else None,
            "restructure": (
                self.restructure.to_dict() if self.restructure is not None else None
            ),
            "due": self.due.to_dict() if self.due is not None else None,
            "default": self.default.to_dict() if self.default is not None else None,
            "resolution": self.resolution.to_dict() if self.resolution is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObligationSpec":
        strict_fields("obligation payload", value, _OBLIGATION_SPEC_FIELDS)

        def _optional(name: str, record_type):
            raw = value[name]
            return record_type.from_dict(raw) if raw is not None else None

        return cls(
            obligation_id=value["obligation_id"],
            cycle_id=value["cycle_id"],
            obligor=value["obligor"],
            obligee=value["obligee"],
            asset=value["asset"],
            amount=Amount.from_dict(value["amount"]),
            source_kind=value["source_kind"],
            source_ref=value["source_ref"],
            source_digest=value["source_digest"],
            due_window=DueWindow.from_dict(value["due_window"]),
            amendment=_optional("amendment", AmendmentRecord),
            dispute=_optional("dispute", DisputeRecord),
            restructure=_optional("restructure", RestructureRecord),
            due=_optional("due", DueRecord),
            default=_optional("default", DefaultRecord),
            resolution=_optional("resolution", ResolutionRecord),
        )


@dataclass(frozen=True, slots=True)
class Obligation:
    """Durable obligation record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ObligationSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = OBLIGATION_OBJECT_TYPE
    STATE_TYPE = ObligationState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("obligation envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ObligationSpec):
            raise CoreValidationError("obligation spec must be an ObligationSpec")
        if self.envelope.object_type != OBLIGATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"obligation object_type must be {OBLIGATION_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.obligation_id:
            raise CoreValidationError("obligation object_id must equal spec.obligation_id")
        ObligationState(self.envelope.state)
        _validate_state_facts(self.envelope.state, self.spec)
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ObligationState:
        return ObligationState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Obligation":
        envelope, payload = decode_composite(
            value, object_type=OBLIGATION_OBJECT_TYPE, state_type=ObligationState
        )
        spec = ObligationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Obligation":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=OBLIGATION_OBJECT_TYPE, state_type=ObligationState
        )
        spec = ObligationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


#: The lifecycle marker every post-recognition state must carry (its
#: owning command's fact). Earlier markers (amendment, dispute,
#: restructure, due) persist across later transitions — the envelope
#: version chain is the history; the markers are the carried facts.
_STATE_REQUIRED_FACTS: dict[str, str] = {
    ObligationState.AMENDED.value: "amendment",
    ObligationState.DISPUTED.value: "dispute",
    ObligationState.RESTRUCTURED.value: "restructure",
    ObligationState.DUE.value: "due",
    ObligationState.DEFAULTED.value: "default",
    ObligationState.RESOLVED.value: "resolution",
}

_LIFECYCLE_FACTS = (
    "amendment",
    "dispute",
    "restructure",
    "due",
    "default",
    "resolution",
)


def _validate_state_facts(state: str, spec: ObligationSpec) -> None:
    """Cross-check the envelope state against the spec's lifecycle markers.

    ``RECOGNIZED``/``VALIDATED`` carry no markers; every later state must
    carry its owning command's marker; ``default`` and ``resolution`` are
    mutually exclusive terminal facts (enforced at spec level).
    """
    carried = {
        name for name in _LIFECYCLE_FACTS if getattr(spec, name) is not None
    }
    if state in (ObligationState.RECOGNIZED.value, ObligationState.VALIDATED.value):
        if carried:
            raise CoreValidationError(
                f"obligation state {state} cannot carry lifecycle facts "
                f"{sorted(carried)}"
            )
        return
    required = _STATE_REQUIRED_FACTS[state]
    if required not in carried:
        raise CoreValidationError(
            f"obligation state {state} must carry its {required!r} lifecycle fact"
        )


def make_obligation_record(
    *,
    spec: ObligationSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Obligation:
    """Construct the version-1 sealed obligation record (state RECOGNIZED)."""
    envelope = build_domain_envelope(
        object_id=spec.obligation_id,
        object_type=OBLIGATION_OBJECT_TYPE,
        state=ObligationState.RECOGNIZED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return Obligation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


# ---------------------------------------------------------------------------
# command payload parsers (strict, fail-closed)
# ---------------------------------------------------------------------------

_CREATE_PAYLOAD_FIELDS = frozenset({"cycle_id", "effect_result", "due_window"})
_AMEND_PAYLOAD_FIELDS = frozenset({"reason", "amount", "due_window"})
_DISPUTE_PAYLOAD_FIELDS = frozenset({"evidence_ref", "epistemic_type", "reason"})
_RESTRUCTURE_PAYLOAD_FIELDS = frozenset(
    {"evidence_ref", "epistemic_type", "reason", "amount", "due_window"}
)
_MARK_DUE_PAYLOAD_FIELDS = frozenset({"funding"})
_DEFAULT_PAYLOAD_FIELDS = frozenset({"evidence_ref", "epistemic_type", "reason"})
_RESOLVE_PAYLOAD_FIELDS = frozenset({"evidence_ref", "evidence_digest", "reason"})


def parse_recognize_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``obligation.create`` payload.

    The obligation facts are NEVER trusted from this payload: the
    handler re-derives obligor/obligee/amount/asset from the carried
    execution effect result through the trusted decode path. The
    payload only declares the target clearing cycle, the binding
    evidence and the due window.
    """
    strict_fields("obligation.create payload", value, _CREATE_PAYLOAD_FIELDS)
    cycle_id = value["cycle_id"]
    if cycle_id is not None:
        require_identifier("obligation.create cycle_id", cycle_id)
    if not isinstance(value["effect_result"], Mapping):
        raise CoreValidationError("obligation.create effect_result must be an object")
    due_window = DueWindow.from_dict(value["due_window"])
    return {
        "cycle_id": cycle_id,
        "effect_result": value["effect_result"],
        "due_window": due_window,
    }


def parse_amount_or_none(name: str, value: Any) -> Amount | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an amount object or null")
    return Amount.from_dict(value)


def parse_amend_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``obligation.amend`` payload (at least one term change)."""
    strict_fields("obligation.amend payload", value, _AMEND_PAYLOAD_FIELDS)
    require_text("obligation.amend reason", value["reason"])
    amount = parse_amount_or_none("obligation.amend amount", value["amount"])
    due_window = (
        DueWindow.from_dict(value["due_window"]) if value["due_window"] is not None else None
    )
    if amount is None and due_window is None:
        raise CoreValidationError(
            "obligation.amend must restructure at least one term (amount or due window)"
        )
    return {"reason": value["reason"], "amount": amount, "due_window": due_window}


def parse_evidence_payload(
    name: str, value: Mapping[str, Any], fields: frozenset[str]
) -> EvidenceGate:
    strict_fields(name, value, fields)
    gate = EvidenceGate(
        evidence_ref=value["evidence_ref"],
        epistemic_type=value["epistemic_type"],
        reason=value["reason"],
    )
    return gate


def parse_restructure_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``obligation.restructure`` payload (new dispute terms)."""
    strict_fields("obligation.restructure payload", value, _RESTRUCTURE_PAYLOAD_FIELDS)
    gate = EvidenceGate(
        evidence_ref=value["evidence_ref"],
        epistemic_type=value["epistemic_type"],
        reason=value["reason"],
    )
    amount = parse_amount_or_none("obligation.restructure amount", value["amount"])
    due_window = (
        DueWindow.from_dict(value["due_window"]) if value["due_window"] is not None else None
    )
    if amount is None and due_window is None:
        raise CoreValidationError(
            "obligation.restructure must set new terms (amount or due window)"
        )
    return {
        "gate": gate,
        "amount": amount,
        "due_window": due_window,
    }


def parse_mark_due_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``obligation.mark-due`` payload (optional funding gate)."""
    strict_fields("obligation.mark-due payload", value, _MARK_DUE_PAYLOAD_FIELDS)
    funding = value["funding"]
    if funding is not None:
        funding = FundingGate.from_dict(funding)
    return {"funding": funding}


def parse_resolve_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``obligation.resolve`` payload (discharge evidence)."""
    strict_fields("obligation.resolve payload", value, _RESOLVE_PAYLOAD_FIELDS)
    require_identifier("obligation.resolve evidence_ref", value["evidence_ref"])
    require_digest("obligation.resolve evidence_digest", value["evidence_digest"])
    require_text("obligation.resolve reason", value["reason"])
    return {
        "evidence_ref": value["evidence_ref"],
        "evidence_digest": value["evidence_digest"],
        "reason": value["reason"],
    }
