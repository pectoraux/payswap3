"""Value instruments: issued, transferable and redeemable value claims.

A value instrument is a specific issued claim of a positive amount of
one asset by an issuer in favor of a holder. The lifecycle follows the
frozen value command family ``Issue/Redeem/TransferInstrument``:

```text
ISSUED → (transfer: new holder, same state) → REDEEMED
```

Transfers produce a new immutable version with the new holder (the
frozen architecture's explicit-relationship model keeps holder identity
as declared data; ``relationships()`` exposes ISSUES/OWNS pairs).
Redemption is terminal. The instrument record conserves its value by
construction: the amount is positive and immutable across versions, so
issuance and redemption of ledger positions are journal postings posted
by the caller with ``source_refs`` linking to the instrument. Object
type ``value/instrument/v1`` is internal (non-registry).
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
from .contracts import INSTRUMENT_OBJECT_TYPE, MAX_SCALE
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
from .validation import require_identifier, require_int, strict_fields

INSTRUMENT_PAYLOAD_FIELDS = frozenset({"asset", "scale", "amount", "issuer_id", "holder_id"})


class InstrumentState(StrEnum):
    ISSUED = "ISSUED"
    REDEEMED = "REDEEMED"


@dataclass(frozen=True, slots=True)
class InstrumentPayload:
    """Immutable instrument data: asset, positive amount, issuer, holder."""

    asset: str
    scale: int
    amount: Amount
    issuer_id: str
    holder_id: str

    def __post_init__(self) -> None:
        require_identifier("instrument.asset", self.asset)
        require_int("instrument.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        if not isinstance(self.amount, Amount):
            raise CoreValidationError(
                f"instrument.amount must be an Amount, got {type(self.amount).__name__}"
            )
        if not self.amount.is_positive():
            raise CoreValidationError("instrument.amount must be positive; a value instrument cannot issue zero or negative value")
        if self.amount.asset != self.asset:
            raise CoreValidationError(
                f"instrument.amount asset {self.amount.asset} does not match the declared asset {self.asset}"
            )
        if self.amount.scale != self.scale:
            raise CoreValidationError(
                f"instrument.amount scale {self.amount.scale} does not match the declared scale {self.scale}"
            )
        require_identifier("instrument.issuer_id", self.issuer_id)
        require_identifier("instrument.holder_id", self.holder_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "scale": self.scale,
            "amount": self.amount.to_dict(),
            "issuer_id": self.issuer_id,
            "holder_id": self.holder_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InstrumentPayload":
        strict_fields("instrument payload", value, INSTRUMENT_PAYLOAD_FIELDS)
        return cls(
            asset=value["asset"],
            scale=value["scale"],
            amount=Amount.from_dict(value["amount"]),
            issuer_id=value["issuer_id"],
            holder_id=value["holder_id"],
        )


@dataclass(frozen=True, slots=True)
class ValueInstrument:
    """Durable, integrity-sealed value instrument (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: InstrumentPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"instrument envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != INSTRUMENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"instrument object_type must be {INSTRUMENT_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"instrument schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"instrument rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        try:
            InstrumentState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"instrument state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, InstrumentPayload):
            raise CoreValidationError(
                f"instrument payload must be an InstrumentPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("instrument integrity hash must be a non-empty string or null")

    @classmethod
    def issue(
        cls,
        *,
        object_id: str,
        asset: str,
        scale: int,
        amount: Amount,
        issuer_id: str,
        holder_id: str,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "ValueInstrument":
        payload = InstrumentPayload(
            asset=asset, scale=scale, amount=amount, issuer_id=issuer_id, holder_id=holder_id
        )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=INSTRUMENT_OBJECT_TYPE,
            state=InstrumentState.ISSUED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def transfer(
        self,
        *,
        new_holder_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "ValueInstrument":
        if self.envelope.state != InstrumentState.ISSUED.value:
            raise CoreValidationError(
                f"instrument {self.envelope.object_id} cannot transfer from state {self.envelope.state}"
            )
        require_identifier("instrument.new_holder_id", new_holder_id)
        if new_holder_id == self.payload.holder_id:
            raise CoreValidationError(
                f"instrument {self.envelope.object_id} cannot transfer to its current holder"
            )
        payload = InstrumentPayload(
            asset=self.payload.asset,
            scale=self.payload.scale,
            amount=self.payload.amount,
            issuer_id=self.payload.issuer_id,
            holder_id=new_holder_id,
        )
        envelope = advance_domain_envelope(
            self.envelope,
            state=InstrumentState.ISSUED.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return ValueInstrument(envelope=envelope, payload=payload).with_integrity_hash()

    def redeem(
        self,
        *,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "ValueInstrument":
        if self.envelope.state != InstrumentState.ISSUED.value:
            raise CoreValidationError(
                f"instrument {self.envelope.object_id} cannot redeem from state {self.envelope.state}"
            )
        envelope = advance_domain_envelope(
            self.envelope,
            state=InstrumentState.REDEEMED.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return ValueInstrument(envelope=envelope, payload=self.payload).with_integrity_hash()

    def relationships(self) -> tuple[Relationship, ...]:
        """The issuer issues the claim; the holder owns it."""
        return (
            Relationship.build(
                RelationshipType.ISSUES,
                self.payload.issuer_id,
                self.envelope.object_id,
            ),
            Relationship.build(
                RelationshipType.OWNS,
                self.payload.holder_id,
                self.envelope.object_id,
            ),
        )

    def with_integrity_hash(self) -> "ValueInstrument":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"instrument envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return ValueInstrument(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"instrument {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ValueInstrument":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = InstrumentPayload.from_dict(payload_value)
        instrument = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        instrument.verify_integrity()
        return instrument

    @classmethod
    def from_json(cls, value: str) -> "ValueInstrument":
        return cls.from_dict(decode_composite_json(value))
