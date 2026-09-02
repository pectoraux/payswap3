"""Market submissions: sealed offers of liquidity inside one market.

A :class:`MarketSubmission` is the record of one provider's bid into a
market session — the referenced offer, the submitted amount, the copied
price and flat fee, the explicit submission instant and the deterministic
sequence number. Submission rejection at the session boundary is a typed,
explicit outcome (:class:`SubmissionResult` +
:class:`SubmissionRejectionReason`) rather than a raised error, so
anti-gaming guards are observable and auditable.

The state vocabulary implements the submission side of the frozen
``Market`` command family: ``Submit`` (SUBMITTED), ``Accept``
(ACCEPTED), ``Reject`` (REJECTED), ``Withdraw`` (WITHDRAWN) and the
allocation outcomes (ALLOCATED_FULL / ALLOCATED_PARTIAL / UNALLOCATED).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import MARKET_SUBMISSION_OBJECT_TYPE
from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_utc_timestamp,
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

_SUBMISSION_SPEC_FIELDS = frozenset(
    {
        "market_id",
        "provider",
        "offer_id",
        "amount",
        "price_bps",
        "flat_fee",
        "submitted_at",
        "sequence",
        "reason",
    }
)


class SubmissionState(StrEnum):
    """Closed lifecycle vocabulary of a market submission."""

    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"
    ALLOCATED_FULL = "ALLOCATED_FULL"
    ALLOCATED_PARTIAL = "ALLOCATED_PARTIAL"
    UNALLOCATED = "UNALLOCATED"


class SubmissionRejectionReason(StrEnum):
    """Closed vocabulary of typed submission rejection reasons."""

    MARKET_NOT_OPEN = "MARKET_NOT_OPEN"
    WINDOW_CLOSED = "WINDOW_CLOSED"
    SELF_DEALING = "SELF_DEALING"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    OFFER_MISMATCH = "OFFER_MISMATCH"
    OFFER_INACTIVE = "OFFER_INACTIVE"
    PRICE_OUT_OF_BAND = "PRICE_OUT_OF_BAND"
    AMOUNT_OUT_OF_OFFER_BOUNDS = "AMOUNT_OUT_OF_OFFER_BOUNDS"
    DUPLICATE_SUBMISSION = "DUPLICATE_SUBMISSION"
    MARKET_AT_CAPACITY = "MARKET_AT_CAPACITY"
    NOT_ADMITTED = "NOT_ADMITTED"
    COLLUSION_SUSPECTED = "COLLUSION_SUSPECTED"
    OPERATOR_POLICY = "OPERATOR_POLICY"
    SUBMISSION_LOCKED = "SUBMISSION_LOCKED"
    ALLOCATION_FINAL = "ALLOCATION_FINAL"


@dataclass(frozen=True, slots=True)
class MarketSubmissionSpec:
    """Immutable submission payload."""

    market_id: str
    provider: str
    offer_id: str
    amount: int
    price_bps: int
    flat_fee: int
    submitted_at: str
    sequence: int
    reason: str | None = None

    def __post_init__(self) -> None:
        require_identifier("submission.market_id", self.market_id)
        require_identifier("submission.provider", self.provider)
        require_identifier("submission.offer_id", self.offer_id)
        require_int("submission.amount", self.amount, minimum=1)
        require_int("submission.price_bps", self.price_bps, minimum=1, maximum=10000)
        require_int("submission.flat_fee", self.flat_fee, minimum=0)
        require_utc_timestamp("submission.submitted_at", self.submitted_at)
        require_int("submission.sequence", self.sequence, minimum=1)
        if self.reason is not None:
            require_identifier("submission.reason", self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "market_id": self.market_id,
            "provider": self.provider,
            "offer_id": self.offer_id,
            "amount": self.amount,
            "price_bps": self.price_bps,
            "flat_fee": self.flat_fee,
            "submitted_at": self.submitted_at,
            "sequence": self.sequence,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MarketSubmissionSpec":
        strict_fields("submission", value, _SUBMISSION_SPEC_FIELDS)
        return cls(
            market_id=value["market_id"],
            provider=value["provider"],
            offer_id=value["offer_id"],
            amount=value["amount"],
            price_bps=value["price_bps"],
            flat_fee=value["flat_fee"],
            submitted_at=value["submitted_at"],
            sequence=value["sequence"],
            reason=value["reason"],
        )


@dataclass(frozen=True, slots=True)
class MarketSubmission:
    """Durable market submission record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: MarketSubmissionSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = MARKET_SUBMISSION_OBJECT_TYPE
    STATE_TYPE = SubmissionState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("submission envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, MarketSubmissionSpec):
            raise CoreValidationError("submission spec must be a MarketSubmissionSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != MARKET_SUBMISSION_OBJECT_TYPE:
            raise CoreValidationError(
                f"submission object_type must be {MARKET_SUBMISSION_OBJECT_TYPE!r}"
            )
        try:
            SubmissionState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown submission state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> SubmissionState | None:
        """Current submission state; ``None`` for unsealed crafted records.

        Sealed submissions always resolve to a closed-vocabulary state.
        An unsealed (crafted) record — only constructible by bypassing
        validation — reports no state and fails admission downstream
        (fail closed).
        """
        if self.envelope is None:
            return None
        return SubmissionState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MarketSubmission":
        envelope, payload = decode_composite(
            value,
            expected_object_type=MARKET_SUBMISSION_OBJECT_TYPE,
            state_type=SubmissionState,
        )
        spec = MarketSubmissionSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "MarketSubmission":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=MARKET_SUBMISSION_OBJECT_TYPE,
            state_type=SubmissionState,
        )
        spec = MarketSubmissionSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: SubmissionState,
        *,
        provenance: Provenance,
        reason: str | None = None,
    ) -> "MarketSubmission":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.spec.market_id,
        )
        spec = self.spec if reason is None else replace(self.spec, reason=reason)
        return MarketSubmission(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )


def submission_object_id(market_id: str, sequence: int) -> str:
    """Deterministic submission identifier: ``<market_id>/sub/<NNNNNN>``."""
    require_identifier("submission.market_id", market_id)
    require_int("submission.sequence", sequence, minimum=1)
    return f"{market_id}/sub/{sequence:06d}"


def build_submission(
    *,
    market_id: str,
    provider: str,
    offer_id: str,
    amount: int,
    price_bps: int,
    flat_fee: int,
    submitted_at: str,
    sequence: int,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> MarketSubmission:
    """Create a sealed SUBMITTED submission (the ``Submit`` command)."""
    spec = MarketSubmissionSpec(
        market_id=market_id,
        provider=provider,
        offer_id=offer_id,
        amount=amount,
        price_bps=price_bps,
        flat_fee=flat_fee,
        submitted_at=submitted_at,
        sequence=sequence,
        reason=None,
    )
    envelope = build_domain_envelope(
        object_id=submission_object_id(market_id, sequence),
        object_type=MARKET_SUBMISSION_OBJECT_TYPE,
        state=SubmissionState.SUBMITTED.value,
        environment_id=require_identifier("submission.environment_id", environment_id),
        domain_id=require_identifier("submission.domain_id", domain_id),
        provenance=provenance,
        causation_id=market_id,
        correlation_id=correlation_id,
    )
    return MarketSubmission(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def parse_rejection_reason(name: str, value: Any) -> SubmissionRejectionReason:
    """Parse a closed-vocabulary rejection reason, failing closed."""
    return parse_enum(name, SubmissionRejectionReason, value)


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """Typed outcome of a submission command.

    ``reason`` is ``None`` if and only if the command was accepted, in
    which case ``submission`` carries the new immutable record.
    """

    reason: SubmissionRejectionReason | None
    submission: MarketSubmission | None = None

    def __post_init__(self) -> None:
        if self.reason is None:
            if not isinstance(self.submission, MarketSubmission):
                raise CoreValidationError(
                    "accepted submission results must carry the submission record"
                )
        else:
            if not isinstance(self.reason, SubmissionRejectionReason):
                raise CoreValidationError(
                    "submission rejection reason must use the closed vocabulary"
                )
