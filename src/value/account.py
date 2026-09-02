"""Accounts: segregated single-asset ledger positions.

Every account denominates exactly one registered asset, carries a
segregation class from the frozen ledger/posting model (customer,
network, participant, collateral, merchant receivables, suspense), an
owner and a custodian (ownership and custody are distinct
relationships), a debit/credit normal side, and an explicit
safeguarding policy flag.

The lifecycle follows the frozen value command family
``Create/Activate/Restrict/CloseAccount``:

```text
CREATED → ACTIVE → RESTRICTED → CLOSED
```

Restriction is one-way (the family has no un-restrict command): it is
the quarantine state on the path to closure. Closure is refused while
any balance view is non-zero or any hold is active (ledger-enforced).
Object type ``value/account/v1`` is internal (non-registry).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.relationships import Relationship, RelationshipType
from src.core.serialization import canonical_json, loads_canonical

from .contracts import ACCOUNT_OBJECT_TYPE, MAX_SCALE, EntrySide
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
from .validation import require_identifier, require_int, require_text, strict_fields

ACCOUNT_PAYLOAD_FIELDS = frozenset(
    {"asset", "scale", "segregation_class", "owner_id", "custodian_id", "normal_side", "enforce_non_negative", "name"}
)


class SegregationClass(StrEnum):
    """Closed accounting classes for customer-fund segregation.

    Customer assets, network assets, participant assets, collateral and
    merchant receivables use distinct accounting classes and
    safeguarding policies; suspense is the controlled position for
    uncertain external outcomes — a state, never a silent loss or
    success classification.
    """

    CUSTOMER = "CUSTOMER"
    NETWORK = "NETWORK"
    PARTICIPANT = "PARTICIPANT"
    COLLATERAL = "COLLATERAL"
    MERCHANT_RECEIVABLE = "MERCHANT_RECEIVABLE"
    SUSPENSE = "SUSPENSE"


#: Segregation classes whose safeguarding policy forbids negative
#: positions: these classes hold other parties' value, so the ledger may
#: never create claims on them through postings.
NON_NEGATIVE_CLASSES = frozenset(
    {
        SegregationClass.CUSTOMER,
        SegregationClass.MERCHANT_RECEIVABLE,
        SegregationClass.COLLATERAL,
    }
)


class AccountState(StrEnum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    RESTRICTED = "RESTRICTED"
    CLOSED = "CLOSED"


_ACCOUNT_TRANSITIONS: dict[str, str] = {
    "activate": AccountState.ACTIVE.value,
    "restrict": AccountState.RESTRICTED.value,
    "close": AccountState.CLOSED.value,
}

_ALLOWED_SOURCES: dict[str, frozenset[str]] = {
    "activate": frozenset({AccountState.CREATED.value}),
    "restrict": frozenset({AccountState.ACTIVE.value}),
    "close": frozenset({AccountState.RESTRICTED.value}),
}


@dataclass(frozen=True, slots=True)
class AccountPayload:
    """Immutable account data: asset, segregation, ownership, custody, policy."""

    asset: str
    scale: int
    segregation_class: SegregationClass
    owner_id: str
    custodian_id: str
    normal_side: EntrySide
    enforce_non_negative: bool | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        require_identifier("account.asset", self.asset)
        require_int("account.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        if not isinstance(self.segregation_class, SegregationClass):
            raise CoreValidationError(
                "account.segregation_class must use the closed SegregationClass vocabulary"
            )
        require_identifier("account.owner_id", self.owner_id)
        require_identifier("account.custodian_id", self.custodian_id)
        if not isinstance(self.normal_side, EntrySide):
            raise CoreValidationError("account.normal_side must use the closed EntrySide vocabulary")
        if self.enforce_non_negative is None:
            object.__setattr__(
                self, "enforce_non_negative", default_enforce_non_negative(self.segregation_class)
            )
        elif not isinstance(self.enforce_non_negative, bool):
            raise CoreValidationError("account.enforce_non_negative must be a boolean")
        if self.segregation_class in NON_NEGATIVE_CLASSES and not self.enforce_non_negative:
            raise CoreValidationError(
                f"accounts of segregation class {self.segregation_class.value} safeguard "
                "other parties' value and cannot opt out of the non-negative position policy"
            )
        if self.name is not None:
            require_text("account.name", self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "scale": self.scale,
            "segregation_class": self.segregation_class.value,
            "owner_id": self.owner_id,
            "custodian_id": self.custodian_id,
            "normal_side": self.normal_side.value,
            "enforce_non_negative": self.enforce_non_negative,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AccountPayload":
        strict_fields("account payload", value, ACCOUNT_PAYLOAD_FIELDS)
        try:
            segregation_class = SegregationClass(value["segregation_class"])
        except ValueError as exc:
            raise CoreValidationError(
                f"account.segregation_class must use the closed vocabulary, got {value['segregation_class']!r}"
            ) from exc
        try:
            normal_side = EntrySide(value["normal_side"])
        except ValueError as exc:
            raise CoreValidationError(
                f"account.normal_side must use the closed vocabulary, got {value['normal_side']!r}"
            ) from exc
        return cls(
            asset=value["asset"],
            scale=value["scale"],
            segregation_class=segregation_class,
            owner_id=value["owner_id"],
            custodian_id=value["custodian_id"],
            normal_side=normal_side,
            enforce_non_negative=value["enforce_non_negative"],
            name=value["name"],
        )


def default_enforce_non_negative(segregation_class: SegregationClass) -> bool:
    """Safeguarding policy default: segregated customer-side funds never go negative."""
    return segregation_class in NON_NEGATIVE_CLASSES


@dataclass(frozen=True, slots=True)
class Account:
    """Durable, integrity-sealed account record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: AccountPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"account envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != ACCOUNT_OBJECT_TYPE:
            raise CoreValidationError(
                f"account object_type must be {ACCOUNT_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"account schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"account rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        try:
            AccountState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"account state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, AccountPayload):
            raise CoreValidationError(
                f"account payload must be an AccountPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("account integrity hash must be a non-empty string or null")

    @classmethod
    def create(
        cls,
        *,
        object_id: str,
        asset: str,
        scale: int,
        segregation_class: SegregationClass,
        owner_id: str,
        custodian_id: str,
        normal_side: EntrySide,
        enforce_non_negative: bool | None = None,
        name: str | None = None,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Account":
        if enforce_non_negative is None:
            enforce_non_negative = default_enforce_non_negative(segregation_class)
        payload = AccountPayload(
            asset=asset,
            scale=scale,
            segregation_class=segregation_class,
            owner_id=owner_id,
            custodian_id=custodian_id,
            normal_side=normal_side,
            enforce_non_negative=enforce_non_negative,
            name=name,
        )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=ACCOUNT_OBJECT_TYPE,
            state=AccountState.CREATED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def _transition(
        self,
        operation: str,
        *,
        provenance: Provenance,
        causation_id: str | None,
        correlation_id: str | None,
    ) -> "Account":
        target = _ACCOUNT_TRANSITIONS[operation]
        allowed = _ALLOWED_SOURCES[operation]
        if self.envelope.state not in allowed:
            raise CoreValidationError(
                f"account {self.envelope.object_id} cannot {operation} from state "
                f"{self.envelope.state}; allowed source states are {sorted(allowed)}"
            )
        envelope = advance_domain_envelope(
            self.envelope,
            state=target,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return Account(envelope=envelope, payload=self.payload).with_integrity_hash()

    def activate(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Account":
        return self._transition(
            "activate", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def restrict(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Account":
        return self._transition(
            "restrict", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def close(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Account":
        return self._transition(
            "close", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def ownership_relationships(self) -> tuple[Relationship, ...]:
        """Ownership and custody are distinct explicit relationships."""
        return (
            Relationship.build(
                RelationshipType.OWNS,
                self.payload.owner_id,
                self.envelope.object_id,
            ),
            Relationship.build(
                RelationshipType.CUSTODIES,
                self.payload.custodian_id,
                self.envelope.object_id,
            ),
        )

    def with_integrity_hash(self) -> "Account":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"account envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return Account(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"account {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Account":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = AccountPayload.from_dict(payload_value)
        account = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        account.verify_integrity()
        return account

    @classmethod
    def from_json(cls, value: str) -> "Account":
        return cls.from_dict(decode_composite_json(value))
