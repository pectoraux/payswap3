"""Holds: reservation records with their encumbrance postings.

A hold reserves a positive amount of one asset on one account. The
lifecycle follows the frozen value command family
``Create/Release/Expire/Increase/DecreaseHold``:

```text
ACTIVE → RELEASED | EXPIRED      (terminal)
```

Invariant: a hold's amount is positive if and only if its state is
``ACTIVE`` — full release, full consumption (decrease to zero) and
expiry all leave the amount at zero with the history preserved in the
version chain.

Holds are the reservation-safety authority of the ledger: the ledger
service refuses to create or increase a hold beyond the account's
available view, posts an encumbrance posting (class ``HOLD``, legs
moving value between the AVAILABLE and ENCUMBERED views) at every
encumbering transition, and posts a compensation posting at release and
expiry. ``decrease`` reduces the record without a posting: it is the
reconciliation step after other postings (executions consuming encumbered
value) have already reduced the ENCUMBERED view. The reconciliation
record verifies the hold invariant ``HELD == ENCUMBERED`` per account.
Object type ``value/hold/v1`` is internal (non-registry).
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
from .contracts import HOLD_OBJECT_TYPE
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
from .validation import require_identifier, require_text, require_timestamp, strict_fields

HOLD_PAYLOAD_FIELDS = frozenset({"account_id", "asset", "amount", "purpose", "expires_at"})


class HoldState(StrEnum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class HoldPayload:
    """Immutable hold data: account, asset, amount, purpose, expiry."""

    account_id: str
    asset: str
    amount: Amount
    purpose: str | None = None
    expires_at: str | None = None

    def __post_init__(self) -> None:
        require_identifier("hold.account_id", self.account_id)
        require_identifier("hold.asset", self.asset)
        if not isinstance(self.amount, Amount):
            raise CoreValidationError(
                f"hold.amount must be an Amount, got {type(self.amount).__name__}"
            )
        if self.amount.asset != self.asset:
            raise CoreValidationError(
                f"hold.amount asset {self.amount.asset} does not match the declared asset {self.asset}"
            )
        if self.purpose is not None:
            require_text("hold.purpose", self.purpose)
        if self.expires_at is not None:
            require_timestamp("hold.expires_at", self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "asset": self.asset,
            "amount": self.amount.to_dict(),
            "purpose": self.purpose,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HoldPayload":
        strict_fields("hold payload", value, HOLD_PAYLOAD_FIELDS)
        return cls(
            account_id=value["account_id"],
            asset=value["asset"],
            amount=Amount.from_dict(value["amount"]),
            purpose=value["purpose"],
            expires_at=value["expires_at"],
        )


def _validate_state_amount_pair(state: str, amount: Amount) -> None:
    if state == HoldState.ACTIVE.value and not amount.is_positive():
        raise CoreValidationError(
            "an active hold must hold a positive amount; use release, decrease or expire "
            "instead of zeroing an active hold"
        )
    if state in (HoldState.RELEASED.value, HoldState.EXPIRED.value) and not amount.is_zero():
        raise CoreValidationError(
            f"a hold in state {state} holds nothing; its final amount must be zero "
            "(the version chain preserves the held history)"
        )


@dataclass(frozen=True, slots=True)
class Hold:
    """Durable, integrity-sealed hold record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: HoldPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"hold envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != HOLD_OBJECT_TYPE:
            raise CoreValidationError(
                f"hold object_type must be {HOLD_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"hold schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"hold rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        try:
            HoldState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"hold state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, HoldPayload):
            raise CoreValidationError(
                f"hold payload must be a HoldPayload, got {type(self.payload).__name__}"
            )
        _validate_state_amount_pair(self.envelope.state, self.payload.amount)
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("hold integrity hash must be a non-empty string or null")

    @classmethod
    def create(
        cls,
        *,
        object_id: str,
        account_id: str,
        asset: str,
        amount: Amount,
        purpose: str | None = None,
        expires_at: str | None = None,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Hold":
        payload = HoldPayload(
            account_id=account_id, asset=asset, amount=amount, purpose=purpose, expires_at=expires_at
        )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=HOLD_OBJECT_TYPE,
            state=HoldState.ACTIVE.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def _require_active(self, operation: str) -> None:
        if self.envelope.state != HoldState.ACTIVE.value:
            raise CoreValidationError(
                f"hold {self.envelope.object_id} cannot {operation} from state {self.envelope.state}"
            )

    def _require_delta(self, delta: Amount, operation: str) -> None:
        if not isinstance(delta, Amount):
            raise CoreValidationError(
                f"hold {operation} delta must be an Amount, got {type(delta).__name__}"
            )
        if delta.asset != self.payload.asset:
            raise CoreValidationError(
                f"hold {operation} delta asset {delta.asset} does not match the hold asset {self.payload.asset}"
            )
        if delta.scale != self.payload.amount.scale:
            raise CoreValidationError(
                f"hold {operation} delta scale {delta.scale} does not match the hold scale {self.payload.amount.scale}"
            )
        if not delta.is_positive():
            raise CoreValidationError(f"hold {operation} delta must be positive")

    def _advance(
        self,
        amount: Amount,
        state: str,
        *,
        provenance: Provenance,
        causation_id: str | None,
        correlation_id: str | None,
    ) -> "Hold":
        payload = HoldPayload(
            account_id=self.payload.account_id,
            asset=self.payload.asset,
            amount=amount,
            purpose=self.payload.purpose,
            expires_at=self.payload.expires_at,
        )
        envelope = advance_domain_envelope(
            self.envelope,
            state=state,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return Hold(envelope=envelope, payload=payload).with_integrity_hash()

    def increase(
        self,
        *,
        delta: Amount,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Hold":
        self._require_active("increase")
        self._require_delta(delta, "increase")
        return self._advance(
            self.payload.amount.add(delta),
            HoldState.ACTIVE.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def decrease(
        self,
        *,
        delta: Amount,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Hold":
        self._require_active("decrease")
        self._require_delta(delta, "decrease")
        remaining = self.payload.amount.sub(delta)
        if remaining.is_negative():
            raise CoreValidationError(
                f"hold {self.envelope.object_id} cannot decrease below zero; current amount "
                f"{self.payload.amount.value}, delta {delta.value}"
            )
        state = HoldState.ACTIVE.value if remaining.is_positive() else HoldState.RELEASED.value
        return self._advance(
            remaining,
            state,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def release(
        self,
        *,
        amount: Amount | None = None,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Hold":
        self._require_active("release")
        if amount is None:
            return self._advance(
                Amount.zero(self.payload.asset, self.payload.amount.scale),
                HoldState.RELEASED.value,
                provenance=provenance,
                causation_id=causation_id,
                correlation_id=correlation_id,
            )
        self._require_delta(amount, "release")
        remaining = self.payload.amount.sub(amount)
        if remaining.is_negative():
            raise CoreValidationError(
                f"hold {self.envelope.object_id} cannot release more than it holds; current "
                f"amount {self.payload.amount.value}, requested {amount.value}"
            )
        state = HoldState.ACTIVE.value if remaining.is_positive() else HoldState.RELEASED.value
        return self._advance(
            remaining,
            state,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def expire(
        self,
        *,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Hold":
        self._require_active("expire")
        return self._advance(
            Amount.zero(self.payload.asset, self.payload.amount.scale),
            HoldState.EXPIRED.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def relationships(self) -> tuple[Relationship, ...]:
        """A hold depends on the account it reserves value on."""
        return (
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                self.envelope.object_id,
                self.payload.account_id,
            ),
        )

    def with_integrity_hash(self) -> "Hold":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"hold envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return Hold(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"hold {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Hold":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = HoldPayload.from_dict(payload_value)
        hold = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        hold.verify_integrity()
        return hold

    @classmethod
    def from_json(cls, value: str) -> "Hold":
        return cls.from_dict(decode_composite_json(value))
