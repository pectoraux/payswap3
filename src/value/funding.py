"""Funding sources: explicit binding of payment intent to a ledger account.

The intent domain (WORK-008) references funding sources as the ordered
binding of opaque refs to spendable positions; this module owns the
funding-source object itself: an immutable, integrity-sealed record that
DEPENDS_ON exactly one ledger account and carries an explicit cap in the
account's asset and scale. Lifecycle: ``ACTIVE → RETIRED`` (retirement is
terminal). Object type ``value/funding-source/v1`` is internal
(non-registry).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.relationships import Relationship, RelationshipType
from src.core.serialization import canonical_json, loads_canonical

from .amount import Amount
from .contracts import FUNDING_SOURCE_OBJECT_TYPE
from .seal import (
    advance_domain_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import require_identifier, strict_fields

FUNDING_SOURCE_PAYLOAD_FIELDS = frozenset({"account_id", "cap"})


class FundingSourceState(StrEnum):
    """Closed funding-source lifecycle."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass(frozen=True, slots=True)
class FundingSourcePayload:
    """Immutable funding-source data: bound account and explicit cap."""

    account_id: str
    cap: Amount

    def __post_init__(self) -> None:
        require_identifier("funding source.account_id", self.account_id)
        if not isinstance(self.cap, Amount):
            raise CoreValidationError(
                f"funding source.cap must be an Amount, got {type(self.cap).__name__}"
            )
        if not self.cap.is_positive():
            raise CoreValidationError(
                "funding source.cap must be positive; a non-positive cap cannot fund anything"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "cap": self.cap.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FundingSourcePayload":
        strict_fields("funding source payload", value, FUNDING_SOURCE_PAYLOAD_FIELDS)
        return cls(
            account_id=value["account_id"],
            cap=Amount.from_dict(value["cap"]),
        )


@dataclass(frozen=True, slots=True)
class FundingSource:
    """Durable, integrity-sealed funding-source record."""

    envelope: ObjectEnvelope
    payload: FundingSourcePayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"funding source envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != FUNDING_SOURCE_OBJECT_TYPE:
            raise CoreValidationError(
                f"funding source object_type must be {FUNDING_SOURCE_OBJECT_TYPE!r}, "
                f"got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"funding source schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"funding source rejects unknown protocol version {self.envelope.protocol_version!r}"
            )
        try:
            FundingSourceState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"funding source state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, FundingSourcePayload):
            raise CoreValidationError(
                f"funding source payload must be a FundingSourcePayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError(
                "funding source integrity hash must be a non-empty string or null"
            )

    @classmethod
    def create(
        cls,
        *,
        object_id: str,
        account_id: str,
        cap: Amount,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "FundingSource":
        payload = FundingSourcePayload(account_id=account_id, cap=cap)
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=FUNDING_SOURCE_OBJECT_TYPE,
            state=FundingSourceState.ACTIVE.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def retire(
        self,
        *,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "FundingSource":
        if self.envelope.state != FundingSourceState.ACTIVE.value:
            raise CoreValidationError(
                f"funding source {self.envelope.object_id} cannot retire from state "
                f"{self.envelope.state}; retirement is terminal and only ACTIVE sources may retire"
            )
        envelope = advance_domain_envelope(
            self.envelope,
            state=FundingSourceState.RETIRED.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return FundingSource(envelope=envelope, payload=self.payload).with_integrity_hash()

    def relationships(self) -> tuple[Relationship, ...]:
        """A funding source depends on exactly one ledger account."""
        return (
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                self.envelope.object_id,
                self.payload.account_id,
            ),
        )

    def with_integrity_hash(self) -> "FundingSource":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                "funding source envelope must be sealed before the payload hash of "
                f"{self.envelope.object_id}"
            )
        return FundingSource(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"funding source {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FundingSource":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = FundingSourcePayload.from_dict(payload_value)
        record = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        record.verify_integrity()
        return record

    @classmethod
    def from_json(cls, value: str) -> "FundingSource":
        return cls.from_dict(decode_composite_json(value))
