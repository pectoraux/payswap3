"""Journals: append-only containers of postings.

A journal is the authoritative accounting journal of the frozen
ledger/posting model. The lifecycle uses the frozen command family
``Create/Post/Reverse/Adjust/ReconcileJournal``:

```text
ACTIVE → RECONCILED
```

Postings are accepted only while the journal is ``ACTIVE``.
Reconciliation transitions the journal to ``RECONCILED`` (and may run
again to re-issue evidence): a reconciled journal is sealed for
postings — corrections belong to a governed successor journal. Every
posting carries a per-journal monotonic sequence; the ledger derives
posting and reconciliation record ids from the journal identity plus
the sequence so replay is deterministic. Object type
``value/journal/v1`` is internal (non-registry).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .contracts import JOURNAL_OBJECT_TYPE
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
from .validation import require_identifier, require_text, strict_fields

JOURNAL_PAYLOAD_FIELDS = frozenset({"custodian_id", "description"})


class JournalState(StrEnum):
    ACTIVE = "ACTIVE"
    RECONCILED = "RECONCILED"


@dataclass(frozen=True, slots=True)
class JournalPayload:
    """Immutable journal data: custodian and description."""

    custodian_id: str
    description: str

    def __post_init__(self) -> None:
        require_identifier("journal.custodian_id", self.custodian_id)
        require_text("journal.description", self.description)

    def to_dict(self) -> dict[str, Any]:
        return {"custodian_id": self.custodian_id, "description": self.description}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "JournalPayload":
        strict_fields("journal payload", value, JOURNAL_PAYLOAD_FIELDS)
        return cls(custodian_id=value["custodian_id"], description=value["description"])


@dataclass(frozen=True, slots=True)
class Journal:
    """Durable, integrity-sealed journal record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: JournalPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"journal envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != JOURNAL_OBJECT_TYPE:
            raise CoreValidationError(
                f"journal object_type must be {JOURNAL_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"journal schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"journal rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        try:
            JournalState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"journal state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, JournalPayload):
            raise CoreValidationError(
                f"journal payload must be a JournalPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("journal integrity hash must be a non-empty string or null")

    @classmethod
    def open(
        cls,
        *,
        object_id: str,
        custodian_id: str,
        description: str,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Journal":
        payload = JournalPayload(custodian_id=custodian_id, description=description)
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=JOURNAL_OBJECT_TYPE,
            state=JournalState.ACTIVE.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def reconcile(
        self,
        *,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Journal":
        """Record a reconciliation run; re-reconciliation re-issues evidence."""
        if self.envelope.state not in (JournalState.ACTIVE.value, JournalState.RECONCILED.value):
            raise CoreValidationError(
                f"journal {self.envelope.object_id} cannot reconcile from state {self.envelope.state}"
            )
        envelope = advance_domain_envelope(
            self.envelope,
            state=JournalState.RECONCILED.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return Journal(envelope=envelope, payload=self.payload).with_integrity_hash()

    def with_integrity_hash(self) -> "Journal":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"journal envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return Journal(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"journal {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Journal":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = JournalPayload.from_dict(payload_value)
        journal = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        journal.verify_integrity()
        return journal

    @classmethod
    def from_json(cls, value: str) -> "Journal":
        return cls.from_dict(decode_composite_json(value))
