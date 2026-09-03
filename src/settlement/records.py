"""The settlement record: discharge instructions, leg outcomes and
reconciliation facts.

A :class:`Settlement` is the registry-listed protocol object
(``payswap/settlement/v1``) driving the frozen ``Settlement`` command
family ``Create/Authorize/Submit/Cancel/Reconcile``. It carries sealed
discharge instructions — each pinned to a sealed clearing obligation
(or, for refund-linked settlements, to a compiled refund leg) with the
economic facts RE-DERIVED from the sealed source through the trusted
decode path, never trusted from the payload — the leg outcomes folded
from the execution domain's recorded rail observations, and the
reconciliation reports (constitution invariant 12 — all material
outcomes are reconcilable).

Consumed authorities (one authority per concept, never redefined here):

* the exact amount is the value domain's :class:`src.value.Amount`
  (WORK-005 — the sole accounting authority);
* the discharge source is the clearing domain's sealed
  :class:`src.clearing.Obligation` (WORK-015 — obligations are
  ``DUE``-only here; settlement discharges clearing-recognized claims,
  it never re-evaluates them);
* the rail evidence is the execution domain's recorded
  :class:`src.execution.ExternalObservation` (WORK-014 — settlement
  consumes recorded observations; it never re-evaluates a rail outcome
  and never records one itself).

Accounting boundary: a settlement moves funds only through its
balanced append-only postings (see :mod:`src.settlement.postings`);
it never edits the clearing domain's obligation lifecycle (discharge
there is an explicit clearing resolve command carrying settlement
evidence) and never edits the value domain's accounts.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from src.core.serialization import canonical_sha256
from src.value.amount import Amount
from src.core.errors import CoreValidationError

from ._validation import (
    parse_enum,
    require_identifier,
    require_identifier_tuple,
    require_int,
    require_mapping,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .contracts import (
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_SCHEMA_VERSION,
    SETTLEMENT_PROTOCOL_VERSION,
    InstructionSourceKind,
    LegState,
    SettlementState,
)
from .seal import (
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from src.core.envelope import ObjectEnvelope, Provenance

_WINDOW_FIELDS = frozenset({"submit_by", "settle_by"})
_CREATE_PAYLOAD_FIELDS = frozenset({"settlement_id", "window", "obligations"})
_CANCEL_PAYLOAD_FIELDS = frozenset({"reason"})
_RECONCILE_PAYLOAD_FIELDS = frozenset({"as_of", "observations"})

_INSTRUCTION_FIELDS = frozenset(
    {
        "instruction_id",
        "source_kind",
        "obligation_id",
        "obligation_version",
        "obligation_digest",
        "refund_case_id",
        "source_instruction_id",
        "obligor",
        "obligee",
        "amount",
    }
)

_LEG_OUTCOME_FIELDS = frozenset(
    {
        "instruction_id",
        "state",
        "native_reference",
        "observation_digest",
        "observed_at",
        "suspense",
    }
)

_RECONCILIATION_FIELDS = frozenset(
    {
        "reconciled_at",
        "settled",
        "failed",
        "unknown",
        "observation_digests",
    }
)

_CANCELLATION_FIELDS = frozenset({"reason", "cancelled_at"})

_SPEC_FIELDS = frozenset(
    {
        "settlement_id",
        "linked_ref",
        "window",
        "instructions",
        "instructions_digest",
        "submitted_at",
        "leg_outcomes",
        "reconciliations",
        "cancellation",
    }
)

#: The canonical rail-status observation content the reconcile path
#: requires: exactly a native reference and the rail outcome.
STATUS_CONTENT_FIELDS = frozenset({"native_reference", "outcome"})


@dataclass(frozen=True, slots=True)
class SettlementWindow:
    """Declared submission and settlement window (explicit UTC instants)."""

    submit_by: str
    settle_by: str

    def __post_init__(self) -> None:
        require_utc_timestamp("settlement window.submit_by", self.submit_by)
        require_utc_timestamp("settlement window.settle_by", self.settle_by)
        require_utc_timestamp_order(
            "settlement window.submit_by",
            self.submit_by,
            "settlement window.settle_by",
            self.settle_by,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"submit_by": self.submit_by, "settle_by": self.settle_by}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SettlementWindow":
        require_mapping("settlement window", value)
        strict_fields("settlement window", value, _WINDOW_FIELDS)
        return cls(submit_by=value["submit_by"], settle_by=value["settle_by"])

    @classmethod
    def parse(cls, name: str, value: Mapping[str, Any]) -> "SettlementWindow":
        require_mapping(name, value)
        return cls.from_dict(value)


@dataclass(frozen=True, slots=True)
class SettlementInstruction:
    """One sealed discharge instruction (a settlement leg).

    ``OBLIGATION`` instructions pin the exact clearing obligation
    (identifier, object version and composite digest) they discharge;
    ``REFUND_LEG`` instructions pin the compiled refund case and the
    original instruction they return funds for. The economic facts
    (obligor, obligee, amount) are re-derived from the sealed source —
    never trusted from a payload.
    """

    instruction_id: str
    source_kind: str
    obligation_id: str | None
    obligation_version: int | None
    obligation_digest: str | None
    refund_case_id: str | None
    source_instruction_id: str | None
    obligor: str
    obligee: str
    amount: Amount

    def __post_init__(self) -> None:
        require_identifier("instruction.instruction_id", self.instruction_id)
        parsed_kind = parse_enum(
            "instruction.source_kind", self.source_kind, InstructionSourceKind
        )
        require_identifier("instruction.obligor", self.obligor)
        require_identifier("instruction.obligee", self.obligee)
        if self.obligor == self.obligee:
            raise CoreValidationError(
                f"instruction {self.instruction_id} obligor and obligee must differ"
            )
        if not isinstance(self.amount, Amount):
            raise CoreValidationError("instruction.amount must be a value-domain Amount")
        if not self.amount.is_positive():
            raise CoreValidationError(
                f"instruction {self.instruction_id} amount must be positive"
            )
        if parsed_kind is InstructionSourceKind.OBLIGATION:
            if not (
                isinstance(self.obligation_id, str)
                and isinstance(self.obligation_version, int)
                and isinstance(self.obligation_digest, str)
            ):
                raise CoreValidationError(
                    "OBLIGATION instructions require obligation_id, "
                    "obligation_version and obligation_digest"
                )
            require_identifier("instruction.obligation_id", self.obligation_id)
            require_int("instruction.obligation_version", self.obligation_version, minimum=1)
            if (
                len(self.obligation_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.obligation_digest)
            ):
                raise CoreValidationError(
                    "instruction.obligation_digest must be a canonical SHA-256 digest"
                )
            if self.refund_case_id is not None or self.source_instruction_id is not None:
                raise CoreValidationError(
                    "OBLIGATION instructions must not carry refund bindings"
                )
        else:
            if not (
                isinstance(self.refund_case_id, str)
                and isinstance(self.source_instruction_id, str)
            ):
                raise CoreValidationError(
                    "REFUND_LEG instructions require refund_case_id and "
                    "source_instruction_id"
                )
            require_identifier("instruction.refund_case_id", self.refund_case_id)
            require_identifier(
                "instruction.source_instruction_id", self.source_instruction_id
            )
            if self.obligation_id is not None or self.obligation_version is not None:
                raise CoreValidationError(
                    "REFUND_LEG instructions must not carry obligation bindings"
                )

    def instruction_digest(self) -> str:
        """Canonical digest binding external evidence to this exact leg."""
        return canonical_sha256({"instruction": self.to_dict()})

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_id": self.instruction_id,
            "source_kind": self.source_kind,
            "obligation_id": self.obligation_id,
            "obligation_version": self.obligation_version,
            "obligation_digest": self.obligation_digest,
            "refund_case_id": self.refund_case_id,
            "source_instruction_id": self.source_instruction_id,
            "obligor": self.obligor,
            "obligee": self.obligee,
            "amount": self.amount.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SettlementInstruction":
        require_mapping("settlement instruction", value)
        strict_fields("settlement instruction", value, _INSTRUCTION_FIELDS)
        return cls(
            instruction_id=value["instruction_id"],
            source_kind=value["source_kind"],
            obligation_id=value["obligation_id"],
            obligation_version=value["obligation_version"],
            obligation_digest=value["obligation_digest"],
            refund_case_id=value["refund_case_id"],
            source_instruction_id=value["source_instruction_id"],
            obligor=value["obligor"],
            obligee=value["obligee"],
            amount=Amount.from_dict(value["amount"]),
        )


@dataclass(frozen=True, slots=True)
class LegOutcome:
    """The reconciliation-folded outcome of one instruction (leg)."""

    instruction_id: str
    state: str
    native_reference: str | None
    observation_digest: str | None
    observed_at: str | None
    suspense: bool

    def __post_init__(self) -> None:
        require_identifier("leg outcome.instruction_id", self.instruction_id)
        parsed = parse_enum("leg outcome.state", self.state, LegState)
        if self.native_reference is not None:
            require_identifier("leg outcome.native_reference", self.native_reference)
        if self.observed_at is not None:
            require_utc_timestamp("leg outcome.observed_at", self.observed_at)
        if parsed in (LegState.SETTLED, LegState.FAILED):
            if self.observation_digest is None or self.observed_at is None:
                raise CoreValidationError(
                    f"leg {self.instruction_id} in {parsed.value} requires the "
                    "binding observation digest and observed_at"
                )
            if self.suspense:
                raise CoreValidationError(
                    f"leg {self.instruction_id} in {parsed.value} must not sit in "
                    "suspense (the suspense pair was released)"
                )
        elif parsed is LegState.UNKNOWN:
            # An UNKNOWN leg may carry the rail observation that reported
            # the unknown outcome (digest/at) or be aged by the window;
            # it must sit in explicit suspense either way.
            if not self.suspense:
                raise CoreValidationError(
                    f"leg {self.instruction_id} UNKNOWN must sit in explicit suspense"
                )
        else:
            # PENDING / SUBMITTED legs carry no rail facts and no suspense.
            if self.observation_digest is not None or self.observed_at is not None:
                raise CoreValidationError(
                    f"leg {self.instruction_id} in {parsed.value} must not claim an "
                    "observation binding"
                )
            if self.native_reference is not None:
                raise CoreValidationError(
                    f"leg {self.instruction_id} in {parsed.value} must not claim a "
                    "rail reference"
                )
            if self.suspense:
                raise CoreValidationError(
                    f"leg {self.instruction_id} in {parsed.value} must not sit in "
                    "suspense"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_id": self.instruction_id,
            "state": self.state,
            "native_reference": self.native_reference,
            "observation_digest": self.observation_digest,
            "observed_at": self.observed_at,
            "suspense": self.suspense,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LegOutcome":
        require_mapping("leg outcome", value)
        strict_fields("leg outcome", value, _LEG_OUTCOME_FIELDS)
        return cls(
            instruction_id=value["instruction_id"],
            state=value["state"],
            native_reference=value["native_reference"],
            observation_digest=value["observation_digest"],
            observed_at=value["observed_at"],
            suspense=value["suspense"],
        )


@dataclass(frozen=True, slots=True)
class ReconciliationRecord:
    """One explicit reconciliation pass (invariant 12: material outcomes
    are reconcilable — never silently classified)."""

    reconciled_at: str
    settled: tuple[str, ...]
    failed: tuple[str, ...]
    unknown: tuple[str, ...]
    observation_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        require_utc_timestamp("reconciliation.reconciled_at", self.reconciled_at)
        for name, values in (
            ("settled", self.settled),
            ("failed", self.failed),
            ("unknown", self.unknown),
        ):
            for entry in values:
                require_identifier(f"reconciliation.{name}", entry)
        for digest in self.observation_digests:
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise CoreValidationError(
                    "reconciliation.observation_digests entries must be SHA-256 digests"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reconciled_at": self.reconciled_at,
            "settled": list(self.settled),
            "failed": list(self.failed),
            "unknown": list(self.unknown),
            "observation_digests": list(self.observation_digests),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReconciliationRecord":
        require_mapping("reconciliation record", value)
        strict_fields("reconciliation record", value, _RECONCILIATION_FIELDS)
        return cls(
            reconciled_at=value["reconciled_at"],
            settled=tuple(value["settled"]),
            failed=tuple(value["failed"]),
            unknown=tuple(value["unknown"]),
            observation_digests=tuple(value["observation_digests"]),
        )


@dataclass(frozen=True, slots=True)
class CancellationRecord:
    """Explicit cancellation fact (pre-submission only)."""

    reason: str
    cancelled_at: str

    def __post_init__(self) -> None:
        require_text("cancellation.reason", self.reason)
        require_utc_timestamp("cancellation.cancelled_at", self.cancelled_at)

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "cancelled_at": self.cancelled_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CancellationRecord":
        require_mapping("cancellation record", value)
        strict_fields("cancellation record", value, _CANCELLATION_FIELDS)
        return cls(reason=value["reason"], cancelled_at=value["cancelled_at"])


@dataclass(frozen=True, slots=True)
class SettlementSpec:
    """The immutable-identity settlement facts plus lifecycle facts."""

    settlement_id: str
    linked_ref: str | None
    window: SettlementWindow
    instructions: tuple[SettlementInstruction, ...]
    instructions_digest: str
    submitted_at: str | None
    leg_outcomes: tuple[LegOutcome, ...]
    reconciliations: tuple[ReconciliationRecord, ...]
    cancellation: CancellationRecord | None

    def __post_init__(self) -> None:
        require_identifier("settlement.settlement_id", self.settlement_id)
        if self.linked_ref is not None:
            require_identifier("settlement.linked_ref", self.linked_ref)
        if not isinstance(self.window, SettlementWindow):
            raise CoreValidationError("settlement.window must be a SettlementWindow")
        instructions = tuple(self.instructions)
        if not instructions:
            raise CoreValidationError("settlement.instructions must not be empty")
        seen: set[str] = set()
        for instruction in instructions:
            if not isinstance(instruction, SettlementInstruction):
                raise CoreValidationError(
                    "settlement.instructions entries must be SettlementInstruction records"
                )
            if instruction.instruction_id in seen:
                raise CoreValidationError(
                    f"duplicate settlement instruction {instruction.instruction_id}"
                )
            seen.add(instruction.instruction_id)
        if (
            len(self.instructions_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.instructions_digest)
        ):
            raise CoreValidationError(
                "settlement.instructions_digest must be a canonical SHA-256 digest"
            )
        if self.submitted_at is not None:
            require_utc_timestamp("settlement.submitted_at", self.submitted_at)
        outcomes = tuple(self.leg_outcomes)
        outcome_ids = {outcome.instruction_id for outcome in outcomes}
        if outcome_ids - seen:
            raise CoreValidationError(
                "leg outcomes reference unknown instructions: "
                f"{sorted(outcome_ids - seen)}"
            )
        if len(outcome_ids) != len(outcomes):
            raise CoreValidationError("leg outcomes contain duplicate instructions")
        for record in self.reconciliations:
            if not isinstance(record, ReconciliationRecord):
                raise CoreValidationError(
                    "settlement.reconciliations entries must be ReconciliationRecord records"
                )
        if self.cancellation is not None and not isinstance(
            self.cancellation, CancellationRecord
        ):
            raise CoreValidationError(
                "settlement.cancellation must be a CancellationRecord"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "settlement_id": self.settlement_id,
            "linked_ref": self.linked_ref,
            "window": self.window.to_dict(),
            "instructions": [instruction.to_dict() for instruction in self.instructions],
            "instructions_digest": self.instructions_digest,
            "submitted_at": self.submitted_at,
            "leg_outcomes": [outcome.to_dict() for outcome in self.leg_outcomes],
            "reconciliations": [
                record.to_dict() for record in self.reconciliations
            ],
            "cancellation": (
                self.cancellation.to_dict() if self.cancellation is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SettlementSpec":
        require_mapping("settlement spec", value)
        strict_fields("settlement spec", value, _SPEC_FIELDS)
        cancellation = value["cancellation"]
        return cls(
            settlement_id=value["settlement_id"],
            linked_ref=value["linked_ref"],
            window=SettlementWindow.from_dict(value["window"]),
            instructions=tuple(
                SettlementInstruction.from_dict(item) for item in value["instructions"]
            ),
            instructions_digest=value["instructions_digest"],
            submitted_at=value["submitted_at"],
            leg_outcomes=tuple(LegOutcome.from_dict(item) for item in value["leg_outcomes"]),
            reconciliations=tuple(
                ReconciliationRecord.from_dict(item) for item in value["reconciliations"]
            ),
            cancellation=(
                CancellationRecord.from_dict(cancellation)
                if cancellation is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class Settlement:
    """The sealed registry-listed settlement object (``payswap/settlement/v1``)."""

    envelope: ObjectEnvelope
    spec: SettlementSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = SETTLEMENT_OBJECT_TYPE
    STATE_TYPE = SettlementState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("settlement envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, SettlementSpec):
            raise CoreValidationError("settlement spec must be a SettlementSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.settlement_id:
            raise CoreValidationError(
                "settlement envelope and spec must agree on the settlement id"
            )
        _validate_state_facts(SettlementState(self.envelope.state), self.spec)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> SettlementState:
        return SettlementState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        from src.core.serialization import canonical_json

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Settlement":
        envelope, payload = decode_composite(
            value,
            object_type=SETTLEMENT_OBJECT_TYPE,
            state_type=SettlementState,
        )
        return cls(
            envelope=envelope,
            spec=SettlementSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "Settlement":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            object_type=SETTLEMENT_OBJECT_TYPE,
            state_type=SettlementState,
        )
        return cls(
            envelope=envelope,
            spec=SettlementSpec.from_dict(payload),
            integrity_hash=integrity_hash,
        )


def _validate_state_facts(state: SettlementState, spec: SettlementSpec) -> None:
    """State-specific coherence of the lifecycle facts (fail closed)."""
    if state in (SettlementState.DRAFT, SettlementState.AUTHORIZED):
        if spec.leg_outcomes:
            raise CoreValidationError(
                f"a {state.value} settlement must not carry leg outcomes"
            )
        if spec.submitted_at is not None:
            raise CoreValidationError(
                f"a {state.value} settlement must not carry submitted_at"
            )
        if spec.reconciliations:
            raise CoreValidationError(
                f"a {state.value} settlement must not carry reconciliation reports"
            )
    if state is SettlementState.SUBMITTED:
        if spec.submitted_at is None:
            raise CoreValidationError("a SUBMITTED settlement must carry submitted_at")
        if not spec.leg_outcomes:
            raise CoreValidationError("a SUBMITTED settlement must carry leg outcomes")
    if state is SettlementState.COMPLETED:
        _require_all_legs(state, spec, LegState.SETTLED)
    if state is SettlementState.FAILED:
        outcomes = {outcome.state for outcome in spec.leg_outcomes}
        if LegState.PENDING in outcomes or LegState.SUBMITTED in outcomes:
            raise CoreValidationError(
                "a FAILED settlement must have every leg terminal"
            )
        if LegState.FAILED not in outcomes:
            raise CoreValidationError(
                "a FAILED settlement must have at least one failed leg"
            )
    if state is SettlementState.CANCELLED:
        if spec.cancellation is None:
            raise CoreValidationError("a CANCELLED settlement must carry its reason")
        if spec.leg_outcomes:
            raise CoreValidationError(
                "a CANCELLED settlement must not carry leg outcomes (pre-submission only)"
            )
    if state not in (SettlementState.CANCELLED,) and spec.cancellation is not None:
        raise CoreValidationError(
            "a cancellation fact exists on a non-cancelled settlement"
        )


def _require_all_legs(
    state: SettlementState, spec: SettlementSpec, leg_state: LegState
) -> None:
    instruction_ids = {i.instruction_id for i in spec.instructions}
    outcome_states = {
        outcome.instruction_id: LegState(outcome.state) for outcome in spec.leg_outcomes
    }
    if set(outcome_states) != instruction_ids:
        raise CoreValidationError(
            f"a {state.value} settlement must carry outcomes for every instruction"
        )
    for instruction_id, parsed in outcome_states.items():
        if parsed is not leg_state:
            raise CoreValidationError(
                f"a {state.value} settlement requires every leg {leg_state.value}; "
                f"leg {instruction_id} is {parsed.value}"
            )


def make_settlement_record(
    *,
    settlement_id: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    window: SettlementWindow,
    instructions: tuple[SettlementInstruction, ...],
    linked_ref: str | None = None,
    state: str = SettlementState.DRAFT.value,
    submitted_at: str | None = None,
    leg_outcomes: tuple[LegOutcome, ...] = (),
    reconciliations: tuple[ReconciliationRecord, ...] = (),
    cancellation: CancellationRecord | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Settlement:
    """Build and seal a fresh settlement record (version 1)."""
    instructions_digest = compute_instructions_digest(instructions)
    spec = SettlementSpec(
        settlement_id=settlement_id,
        linked_ref=linked_ref,
        window=window,
        instructions=instructions,
        instructions_digest=instructions_digest,
        submitted_at=submitted_at,
        leg_outcomes=leg_outcomes,
        reconciliations=reconciliations,
        cancellation=cancellation,
    )
    envelope = build_domain_envelope(
        object_id=settlement_id,
        object_type=SETTLEMENT_OBJECT_TYPE,
        state=state,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return Settlement(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def compute_instructions_digest(instructions: tuple[SettlementInstruction, ...]) -> str:
    """Canonical digest over the sealed instruction set (order as created)."""
    return canonical_sha256(
        {"instructions": [instruction.to_dict() for instruction in instructions]}
    )


def advance_settlement(
    record: Settlement,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str,
    correlation_id: str | None,
    spec: SettlementSpec | None = None,
) -> Settlement:
    """Produce the next sealed settlement version (identity fields frozen)."""
    from .seal import advance_envelope

    envelope = advance_envelope(
        record.envelope,
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    new_spec = spec if spec is not None else record.spec
    return type(record)(
        envelope=envelope, spec=new_spec, integrity_hash=seal_composite(envelope, new_spec)
    )


# -- payload parsers ---------------------------------------------------------


def parse_create_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``settlement.create`` payload (sealed obligation set)."""
    strict_fields("settlement.create payload", value, _CREATE_PAYLOAD_FIELDS)
    require_identifier("settlement.create settlement_id", value["settlement_id"])
    window = SettlementWindow.parse("settlement.create window", value["window"])
    obligations = value["obligations"]
    if isinstance(obligations, (str, bytes)) or not isinstance(
        obligations, (list, tuple)
    ):
        raise CoreValidationError(
            "settlement.create obligations must be a list of sealed obligation composites"
        )
    if not obligations:
        raise CoreValidationError("settlement.create requires at least one obligation")
    for composite in obligations:
        require_mapping("settlement.create obligation composite", composite)
    return {
        "settlement_id": value["settlement_id"],
        "window": window,
        "obligations": tuple(obligations),
    }


def parse_cancel_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``settlement.cancel`` payload."""
    strict_fields("settlement.cancel payload", value, _CANCEL_PAYLOAD_FIELDS)
    require_text("settlement.cancel reason", value["reason"])
    return {"reason": value["reason"]}


def parse_reconcile_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``settlement.reconcile`` payload (recorded rail observations)."""
    strict_fields("settlement.reconcile payload", value, _RECONCILE_PAYLOAD_FIELDS)
    require_utc_timestamp("settlement.reconcile as_of", value["as_of"])
    observations = value["observations"]
    if isinstance(observations, (str, bytes)) or not isinstance(
        observations, (list, tuple)
    ):
        raise CoreValidationError(
            "settlement.reconcile observations must be a list of sealed "
            "execution observation composites"
        )
    for composite in observations:
        require_mapping("settlement.reconcile observation composite", composite)
    return {"as_of": value["as_of"], "observations": tuple(observations)}
