"""Retention: policy-driven bookkeeping over recorded data lifetimes.

A :class:`RetentionRecord` is a bookkeeping record (canonical object
model discipline): it states, for one subject's data of one declared
class, the governing policy (pinned version), the collection instant and
the computed ``retain_until`` horizon, and it advances through the
closed states ``ACTIVE -> DUE -> EXPIRED`` (or ``ARCHIVED`` as the
retention-positive alternative).

The data domain NEVER deletes or rewrites anything (constitution
invariant 17: historical financial evidence is append-only): there is
no deletion operation anywhere in this module, and every state change
is a new sealed envelope version committed through the append-only
store discipline. ``EXPIRED`` records that disposal is due — the
physical disposal itself belongs to storage operations outside this
domain (documented out of scope).

Legal holds (frozen ``ownership-lifecycle.md``: "Legal hold can suspend
deletion/retention expiry") suspend expiry: while a hold is recorded,
retention evaluation returns ``HELD`` and the DUE/EXPIRED transitions
fail closed. All instants are explicit ``as_of`` data — never clock
reads.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    HOLD_ID_PREFIX,
    LEGAL_BASIS_PREFIX,
    PRINCIPAL_PREFIX,
    RETENTION_ID_PREFIX,
    RETENTION_OBJECT_TYPE,
    DataClass,
    RetentionState,
)
from .policy import DataPolicy, require_active_policy
from ._validation import (
    offset_utc_timestamp,
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)


@dataclass(frozen=True, slots=True)
class LegalHold:
    """A declared legal hold that suspends retention expiry.

    ``basis_ref`` is an opaque typed reference to the declared legal
    basis — recorded, never interpreted (no legal-policy invention).
    """

    hold_id: str
    declared_by: str
    declared_at: str
    basis_ref: str
    case_ref: str | None = None

    def __post_init__(self) -> None:
        require_identifier("hold.hold_id", self.hold_id, prefix=HOLD_ID_PREFIX)
        require_identifier("hold.declared_by", self.declared_by, prefix=PRINCIPAL_PREFIX)
        require_utc_timestamp("hold.declared_at", self.declared_at)
        require_identifier("hold.basis_ref", self.basis_ref, prefix=LEGAL_BASIS_PREFIX)
        if self.case_ref is not None:
            require_identifier("hold.case_ref", self.case_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "declared_by": self.declared_by,
            "declared_at": self.declared_at,
            "basis_ref": self.basis_ref,
            "case_ref": self.case_ref,
        }

    @classmethod
    def from_dict(cls, value: object) -> "LegalHold":
        strict_fields(
            "legal hold", value, {"hold_id", "declared_by", "declared_at", "basis_ref", "case_ref"}
        )
        return cls(
            hold_id=value["hold_id"],
            declared_by=value["declared_by"],
            declared_at=value["declared_at"],
            basis_ref=value["basis_ref"],
            case_ref=value["case_ref"],
        )


_RETENTION_PAYLOAD_FIELDS = frozenset(
    {
        "retention_id",
        "subject_ref",
        "data_class",
        "policy_id",
        "policy_version",
        "collected_at",
        "retain_until",
        "legal_hold",
        "archive_ref",
    }
)


@dataclass(frozen=True, slots=True)
class RetentionPayload:
    """Immutable retention payload: the recorded retention state."""

    retention_id: str
    subject_ref: str
    data_class: Any
    policy_id: str
    policy_version: int
    collected_at: str
    retain_until: str
    legal_hold: LegalHold | None = None
    archive_ref: str | None = None

    def __post_init__(self) -> None:
        require_identifier("retention.retention_id", self.retention_id, prefix=RETENTION_ID_PREFIX)
        require_identifier("retention.subject_ref", self.subject_ref)
        object.__setattr__(
            self, "data_class", parse_enum("retention.data_class", DataClass, self.data_class)
        )
        require_identifier("retention.policy_id", self.policy_id)
        if not isinstance(self.policy_version, int) or isinstance(self.policy_version, bool):
            raise CoreValidationError("retention.policy_version must be an integer")
        require_utc_timestamp("retention.collected_at", self.collected_at)
        require_utc_timestamp("retention.retain_until", self.retain_until)
        require_utc_timestamp_order(
            "retention.collected_at", self.collected_at,
            "retention.retain_until", self.retain_until,
        )
        if self.legal_hold is not None and not isinstance(self.legal_hold, LegalHold):
            raise CoreValidationError("retention.legal_hold must be a LegalHold")
        if self.archive_ref is not None:
            require_identifier("retention.archive_ref", self.archive_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "retention_id": self.retention_id,
            "subject_ref": self.subject_ref,
            "data_class": self.data_class.value,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "collected_at": self.collected_at,
            "retain_until": self.retain_until,
            "legal_hold": self.legal_hold.to_dict() if self.legal_hold is not None else None,
            "archive_ref": self.archive_ref,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RetentionPayload":
        strict_fields("retention", value, _RETENTION_PAYLOAD_FIELDS)
        return cls(
            retention_id=value["retention_id"],
            subject_ref=value["subject_ref"],
            data_class=value["data_class"],
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            collected_at=value["collected_at"],
            retain_until=value["retain_until"],
            legal_hold=(
                LegalHold.from_dict(value["legal_hold"])
                if value["legal_hold"] is not None
                else None
            ),
            archive_ref=value["archive_ref"],
        )


def _validate_retention_state(envelope: ObjectEnvelope, payload: RetentionPayload) -> None:
    state = RetentionState(envelope.state)
    if state is RetentionState.EXPIRED:
        if payload.legal_hold is not None:
            raise CoreValidationError("an EXPIRED retention record cannot carry a legal hold")
        if payload.archive_ref is not None:
            raise CoreValidationError("an EXPIRED retention record is not archived")
    if state is RetentionState.ARCHIVED:
        if payload.archive_ref is None:
            raise CoreValidationError("an ARCHIVED retention record must reference its archive")
    else:
        if payload.archive_ref is not None:
            raise CoreValidationError(
                f"a {state.value} retention record cannot carry an archive reference"
            )


@dataclass(frozen=True, slots=True)
class RetentionRecord:
    """Immutable durable retention record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: RetentionPayload
    integrity_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.payload, RetentionPayload):
            raise CoreValidationError("retention payload must be a RetentionPayload")
        decode_composite(
            composite_to_dict(self.envelope, self.payload, self.integrity_hash),
            expected_object_type=RETENTION_OBJECT_TYPE,
            state_type=RetentionState,
        )
        if self.envelope.object_id != self.payload.retention_id:
            raise CoreValidationError("retention object id must equal the retention identifier")
        _validate_retention_state(self.envelope, self.payload)
        verify_composite(
            self.envelope, self.payload, self.integrity_hash, self.envelope.object_id
        )

    @property
    def retention_id(self) -> str:
        return self.payload.retention_id

    @property
    def state(self) -> RetentionState:
        return RetentionState(self.envelope.state)

    @property
    def subject_ref(self) -> str:
        return self.payload.subject_ref

    @property
    def data_class(self) -> DataClass:
        return self.payload.data_class

    @property
    def policy_id(self) -> str:
        return self.payload.policy_id

    @property
    def policy_version(self) -> int:
        return self.payload.policy_version

    @property
    def retain_until(self) -> str:
        return self.payload.retain_until

    @property
    def legal_hold(self) -> LegalHold | None:
        return self.payload.legal_hold

    @property
    def archive_ref(self) -> str | None:
        return self.payload.archive_ref

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "RetentionRecord":
        envelope, payload = decode_composite(
            value, expected_object_type=RETENTION_OBJECT_TYPE, state_type=RetentionState
        )
        return cls(
            envelope=envelope,
            payload=RetentionPayload.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "RetentionRecord":
        decoded = decode_composite_json(
            value, expected_object_type=RETENTION_OBJECT_TYPE, state_type=RetentionState
        )
        return cls.from_dict(
            {"envelope": decoded[0].to_dict(), "payload": decoded[1], "integrity_hash": decoded[2]}
        )


def create_retention_record(
    *,
    retention_id: str,
    subject_ref: str,
    data_class: Any,
    collected_at: str,
    policy: DataPolicy,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> RetentionRecord:
    """Record a retention entry: policy-driven horizon from the collection instant."""
    data_class = parse_enum("retention.data_class", DataClass, data_class)
    require_active_policy(policy, collected_at)
    retain_seconds = policy.spec.retain_seconds_for(data_class)  # fail closed on unknown class
    retain_until = offset_utc_timestamp("retention.collected_at", collected_at, retain_seconds)
    payload = RetentionPayload(
        retention_id=retention_id,
        subject_ref=subject_ref,
        data_class=data_class,
        policy_id=policy.policy_id,
        policy_version=policy.envelope.object_version,
        collected_at=collected_at,
        retain_until=retain_until,
    )
    envelope = build_domain_envelope(
        object_id=retention_id,
        object_type=RETENTION_OBJECT_TYPE,
        state=RetentionState.ACTIVE.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return RetentionRecord(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )


def evaluate_retention_state(record: RetentionRecord, as_of: str) -> Any:
    """Pure evaluation: RETAINED / DUE / HELD at an explicit instant.

    A recorded legal hold dominates: expiry is suspended while the hold
    is recorded (frozen ownership-lifecycle rule).
    """
    if not isinstance(record, RetentionRecord):
        raise CoreValidationError("evaluate_retention_state requires a RetentionRecord")
    from .contracts import RetentionOutcome

    moment = parse_utc_timestamp("as_of", as_of)
    if record.legal_hold is not None:
        return RetentionOutcome.HELD
    if moment < parse_utc_timestamp("retention.retain_until", record.retain_until):
        return RetentionOutcome.RETAINED
    return RetentionOutcome.DUE


def _require_no_hold(record: RetentionRecord, action: str) -> None:
    if record.legal_hold is not None:
        raise CoreValidationError(
            f"retention {record.retention_id} is under legal hold "
            f"{record.legal_hold.hold_id}; {action} is suspended"
        )


def _advance(
    record: RetentionRecord, payload: RetentionPayload, state: RetentionState, provenance: Provenance
) -> RetentionRecord:
    envelope = advance_envelope(record.envelope, state=state.value, provenance=provenance)
    return RetentionRecord(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )


def mark_retention_due(
    record: RetentionRecord, *, as_of: str, provenance: Provenance
) -> RetentionRecord:
    """ACTIVE -> DUE, only when the window has elapsed and no hold is recorded."""
    from .contracts import RetentionOutcome

    if record.state is not RetentionState.ACTIVE:
        raise CoreValidationError(
            f"retention {record.retention_id} cannot become DUE from state {record.state.value}"
        )
    _require_no_hold(record, "the DUE transition")
    if evaluate_retention_state(record, as_of) is not RetentionOutcome.DUE:
        raise CoreValidationError(
            f"retention {record.retention_id} has not reached its retain_until horizon at {as_of}"
        )
    return _advance(record, record.payload, RetentionState.DUE, provenance)


def mark_retention_expired(
    record: RetentionRecord, *, as_of: str, provenance: Provenance
) -> RetentionRecord:
    """DUE -> EXPIRED: disposal bookkeeping (never a deletion of history)."""
    if record.state is not RetentionState.DUE:
        raise CoreValidationError(
            f"retention {record.retention_id} cannot expire from state {record.state.value}"
        )
    _require_no_hold(record, "the EXPIRED transition")
    return _advance(record, record.payload, RetentionState.EXPIRED, provenance)


def archive_retention_record(
    record: RetentionRecord,
    *,
    as_of: str,
    provenance: Provenance,
    archive_ref: str,
) -> RetentionRecord:
    """ACTIVE/DUE -> ARCHIVED: the retention-positive terminal alternative."""
    if record.state not in (RetentionState.ACTIVE, RetentionState.DUE):
        raise CoreValidationError(
            f"retention {record.retention_id} cannot be archived from state {record.state.value}"
        )
    require_identifier("retention.archive_ref", archive_ref)
    require_utc_timestamp("as_of", as_of)
    payload = replace(record.payload, archive_ref=archive_ref)
    return _advance(record, payload, RetentionState.ARCHIVED, provenance)


def declare_retention_hold(
    record: RetentionRecord, *, hold: LegalHold, provenance: Provenance
) -> RetentionRecord:
    """Record a legal hold on an ACTIVE/DUE retention record (suspends expiry)."""
    if record.state not in (RetentionState.ACTIVE, RetentionState.DUE):
        raise CoreValidationError(
            f"retention {record.retention_id} cannot take a legal hold from state "
            f"{record.state.value}"
        )
    if record.legal_hold is not None:
        raise CoreValidationError(
            f"retention {record.retention_id} already carries legal hold "
            f"{record.legal_hold.hold_id}"
        )
    if not isinstance(hold, LegalHold):
        raise CoreValidationError("declare_retention_hold requires a LegalHold")
    payload = replace(record.payload, legal_hold=hold)
    return _advance(record, payload, record.state, provenance)


def release_retention_hold(
    record: RetentionRecord, *, as_of: str, provenance: Provenance
) -> RetentionRecord:
    """Release a recorded legal hold (expiry bookkeeping may resume)."""
    if record.state not in (RetentionState.ACTIVE, RetentionState.DUE):
        raise CoreValidationError(
            f"retention {record.retention_id} cannot release a hold from state "
            f"{record.state.value}"
        )
    if record.legal_hold is None:
        raise CoreValidationError(
            f"retention {record.retention_id} carries no legal hold to release"
        )
    if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
        "hold.declared_at", record.legal_hold.declared_at
    ):
        raise CoreValidationError(
            f"hold {record.legal_hold.hold_id} cannot be released at {as_of} before it was "
            f"declared at {record.legal_hold.declared_at}"
        )
    payload = replace(record.payload, legal_hold=None)
    return _advance(record, payload, record.state, provenance)
