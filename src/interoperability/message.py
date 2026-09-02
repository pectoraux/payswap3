from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .endpoint import Destination
from .records import (
    DOMAIN_PROTOCOL_VERSION,
    DOMAIN_SCHEMA_VERSION,
    OBJECT_TYPE_PAYMENT_MESSAGE,
    _require_text,
    decode_record,
    payload_binding_hash,
    require_object_identity,
    require_payload_keys,
    verify_payload_binding,
)
from .status import (
    CanonicalPaymentStatus,
    coerce_payment_status,
    is_retry_safe_payment_status,
    is_terminal_payment_status,
    requires_reconciliation,
)

_AMOUNT_KEYS = frozenset({"value", "scale", "currency"})
_MESSAGE_PAYLOAD_KEYS = frozenset(
    {"destination", "instructed_amount", "end_to_end_id"}
)

_CURRENCY = re.compile(r"[A-Z]{3}")
_MAX_SCALE = 18


@dataclass(frozen=True, slots=True)
class InstructedAmount:
    """Wire-level instructed amount in the frozen fixed-point form.

    The canonical amount form mirrors the frozen monetary semantics
    (Amount = integer_value + scale + asset) without performing any money
    arithmetic: rounding, quantization, FX and every authoritative monetary
    calculation remain the exclusive authority of the money domain.
    """

    value: int
    scale: int
    currency: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or isinstance(self.value, bool) or self.value < 0:
            raise CoreValidationError(
                f"amount.value must be a non-negative integer, got {self.value!r}"
            )
        if (
            not isinstance(self.scale, int)
            or isinstance(self.scale, bool)
            or not 0 <= self.scale <= _MAX_SCALE
        ):
            raise CoreValidationError(
                f"amount.scale must be an integer between 0 and {_MAX_SCALE}, got {self.scale!r}"
            )
        _require_text("amount.currency", self.currency)
        if not _CURRENCY.fullmatch(self.currency):
            raise CoreValidationError(
                f"amount.currency must be an uppercase 3-letter currency code, "
                f"got {self.currency!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "scale": self.scale, "currency": self.currency}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InstructedAmount":
        if not isinstance(value, Mapping):
            raise CoreValidationError("amount must be an object")
        if set(value) != _AMOUNT_KEYS:
            missing = sorted(_AMOUNT_KEYS - set(value))
            extra = sorted(set(value) - _AMOUNT_KEYS)
            raise CoreValidationError(
                f"non-canonical amount fields; missing={missing}, extra={extra}"
            )
        return cls(
            value=value["value"], scale=value["scale"], currency=value["currency"]
        )


@dataclass(frozen=True, slots=True)
class CanonicalPaymentMessage:
    """A canonical payment message in the semantic layer above external rails.

    The message is a sealed envelope record whose envelope state carries the
    canonical payment lifecycle status and whose version chain records status
    progression. The payload binding ties destination, instructed amount and
    end-to-end reference to one exact sealed envelope version.
    """

    envelope: Any
    destination: Destination
    instructed_amount: InstructedAmount
    end_to_end_id: str
    payload_hash: str

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def object_version(self) -> int:
        return self.envelope.object_version

    @property
    def status(self) -> CanonicalPaymentStatus:
        return coerce_payment_status(self.envelope.state)

    def payload_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination.to_dict(),
            "instructed_amount": self.instructed_amount.to_dict(),
            "end_to_end_id": self.end_to_end_id,
        }

    def __post_init__(self) -> None:
        require_object_identity(self.envelope, OBJECT_TYPE_PAYMENT_MESSAGE)
        status = coerce_payment_status(self.envelope.state)
        if self.envelope.object_version == 1 and status is not CanonicalPaymentStatus.INITIATED:
            raise CoreValidationError(
                "payment message version 1 must start in INITIATED state"
            )
        if not isinstance(self.destination, Destination):
            raise CoreValidationError("message.destination must be a Destination")
        if not isinstance(self.instructed_amount, InstructedAmount):
            raise CoreValidationError("message.instructed_amount must be an InstructedAmount")
        _require_text("message.end_to_end_id", self.end_to_end_id)
        verify_payload_binding(self.envelope, self.payload_dict(), self.payload_hash)

    @classmethod
    def create(
        cls,
        *,
        message_id: str,
        destination: Destination,
        instructed_amount: InstructedAmount,
        end_to_end_id: str,
        environment_id: str,
        domain_id: str,
        provenance: Any,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        state: str = "INITIATED",
    ) -> "CanonicalPaymentMessage":
        from src.core import ObjectEnvelope

        status = coerce_payment_status(state)
        envelope = ObjectEnvelope(
            object_id=message_id,
            object_type=OBJECT_TYPE_PAYMENT_MESSAGE,
            object_version=1,
            environment_id=environment_id,
            domain_id=domain_id,
            schema_version=DOMAIN_SCHEMA_VERSION,
            protocol_version=DOMAIN_PROTOCOL_VERSION,
            state=status.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        ).with_integrity_hash()
        return cls(
            envelope=envelope,
            destination=destination,
            instructed_amount=instructed_amount,
            end_to_end_id=end_to_end_id,
            payload_hash=payload_binding_hash(envelope, {
                "destination": destination.to_dict(),
                "instructed_amount": instructed_amount.to_dict(),
                "end_to_end_id": end_to_end_id,
            }),
        )

    def with_status(
        self,
        status: Any,
        *,
        provenance: Any = None,
        causation_id: str | None = None,
    ) -> "CanonicalPaymentMessage":
        """Record a canonical status transition as the next immutable version.

        Transition legality of the lifecycle chain is enforced by the command/
        event transition kernel authority, not by the adapter boundary; this
        method only applies a canonical-vocabulary status to a new sealed
        version of the same message identity.
        """
        canonical = coerce_payment_status(status)
        changes: dict[str, Any] = {"state": canonical.value}
        if provenance is not None:
            changes["provenance"] = provenance
        if causation_id is not None:
            changes["causation_id"] = causation_id
        envelope = self.envelope.next_version(**changes).with_integrity_hash()
        return CanonicalPaymentMessage(
            envelope=envelope,
            destination=self.destination,
            instructed_amount=self.instructed_amount,
            end_to_end_id=self.end_to_end_id,
            payload_hash=payload_binding_hash(envelope, self.payload_dict()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.payload_dict(),
            "payload_hash": self.payload_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanonicalPaymentMessage":
        envelope, payload, payload_hash = decode_record(value)
        require_payload_keys(payload, _MESSAGE_PAYLOAD_KEYS)
        return cls(
            envelope=envelope,
            destination=Destination.from_dict(payload["destination"]),
            instructed_amount=InstructedAmount.from_dict(payload["instructed_amount"]),
            end_to_end_id=payload["end_to_end_id"],
            payload_hash=payload_hash,
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "CanonicalPaymentMessage":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("payment message JSON must decode to an object")
        return cls.from_dict(decoded)


def ensure_safe_for_resubmission(message: CanonicalPaymentMessage) -> None:
    """Fail closed unless the message outcome authorizes a resubmission decision.

    Per the frozen unknown-outcome rule, an ambiguous external response must
    enter reconciliation/investigation before any unsafe retry: messages in
    UNKNOWN state, in-flight states, disputes and success outcomes never
    authorize resubmission. Only definitive negative outcomes do.
    """
    if not isinstance(message, CanonicalPaymentMessage):
        raise CoreValidationError("resubmission guard requires a CanonicalPaymentMessage")
    status = message.status
    if requires_reconciliation(status):
        raise CoreValidationError(
            f"message {message.object_id} is in ambiguous state UNKNOWN; "
            "reconciliation is required before any retry"
        )
    if not is_terminal_payment_status(status):
        raise CoreValidationError(
            f"message {message.object_id} is in non-terminal state {status.value}; "
            "resubmission is not safe while the payment is in flight"
        )
    if not is_retry_safe_payment_status(status):
        raise CoreValidationError(
            f"message {message.object_id} is in terminal state {status.value}; "
            "this outcome does not authorize resubmission"
        )


__all__ = [
    "CanonicalPaymentMessage",
    "InstructedAmount",
    "ensure_safe_for_resubmission",
]
