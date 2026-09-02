"""Reconciliation evidence: trial balance, account holds and asset sheets.

The reconciliation record is the frozen ledger/posting model's conservation
proof: it derives per-asset trial-balance totals over journal postings,
compares the hold-derived ``HELD`` totals against the ledger-mirrored
``ENCUMBERED`` view, and compares normal-side asset sheets. Every
disagreement must be carried explicitly as a discrepancy string; building a
reconciliation whose evidence is unbalanced while declaring no discrepancies
fails closed. Object type ``value/reconciliation/v1`` is internal
(non-registry).

``AccountHolds`` and ``AssetSheet`` are plain immutable evidence dataclasses
(they carry derived integers, not durable objects), mirroring
``AssetTotals``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .contracts import RECONCILIATION_OBJECT_TYPE
from .seal import (
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .posting import AssetTotals
from .validation import require_identifier, require_int, require_text, strict_fields

ACCOUNT_HOLDS_FIELDS = frozenset({"account_id", "held", "encumbered"})
ASSET_SHEET_FIELDS = frozenset({"asset", "scale", "debit_normal_total", "credit_normal_total"})
RECONCILIATION_PAYLOAD_FIELDS = frozenset(
    {"journal_id", "as_of_ordinal", "trial_balance", "account_holds", "asset_sheets", "discrepancies"}
)


class ReconciliationState(StrEnum):
    """Closed reconciliation lifecycle."""

    BALANCED = "BALANCED"
    DISCREPANCY = "DISCREPANCY"


@dataclass(frozen=True, slots=True)
class AccountHolds:
    """Hold-derived totals for one account at reconciliation time.

    ``ok`` is the hold reconciliation invariant: the total held by active
    hold records must equal the account's ``ENCUMBERED`` view exactly.
    """

    account_id: str
    held: int
    encumbered: int

    def __post_init__(self) -> None:
        require_identifier("account holds.account_id", self.account_id)
        require_int("account holds.held", self.held, minimum=0)
        require_int("account holds.encumbered", self.encumbered, minimum=0)

    @property
    def ok(self) -> bool:
        return self.held == self.encumbered

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "held": self.held,
            "encumbered": self.encumbered,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AccountHolds":
        strict_fields("account holds", value, ACCOUNT_HOLDS_FIELDS)
        return cls(
            account_id=value["account_id"],
            held=value["held"],
            encumbered=value["encumbered"],
        )


@dataclass(frozen=True, slots=True)
class AssetSheet:
    """Normal-side asset sheet: debit-normal vs credit-normal positions.

    Value conservation per asset requires the signed positions of
    debit-normal accounts to equal those of credit-normal accounts, so a
    balanced sheet proves the segregation map conserves value exactly.
    """

    asset: str
    scale: int
    debit_normal_total: int
    credit_normal_total: int

    def __post_init__(self) -> None:
        require_identifier("asset sheet.asset", self.asset)
        require_int("asset sheet.scale", self.scale, minimum=0)
        require_int("asset sheet.debit_normal_total", self.debit_normal_total)
        require_int("asset sheet.credit_normal_total", self.credit_normal_total)

    @property
    def balanced(self) -> bool:
        return self.debit_normal_total == self.credit_normal_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "scale": self.scale,
            "debit_normal_total": self.debit_normal_total,
            "credit_normal_total": self.credit_normal_total,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetSheet":
        strict_fields("asset sheet", value, ASSET_SHEET_FIELDS)
        return cls(
            asset=value["asset"],
            scale=value["scale"],
            debit_normal_total=value["debit_normal_total"],
            credit_normal_total=value["credit_normal_total"],
        )


@dataclass(frozen=True, slots=True)
class ReconciliationPayload:
    """Immutable reconciliation evidence bound to one journal."""

    journal_id: str
    as_of_ordinal: int
    trial_balance: tuple[AssetTotals, ...]
    account_holds: tuple[AccountHolds, ...]
    asset_sheets: tuple[AssetSheet, ...]
    discrepancies: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier("reconciliation.journal_id", self.journal_id)
        require_int("reconciliation.as_of_ordinal", self.as_of_ordinal, minimum=1)
        if not isinstance(self.trial_balance, tuple):
            raise CoreValidationError("reconciliation.trial_balance must be a tuple")
        for totals in self.trial_balance:
            if not isinstance(totals, AssetTotals):
                raise CoreValidationError(
                    f"reconciliation.trial_balance entries must be AssetTotals, got {type(totals).__name__}"
                )
        if not isinstance(self.account_holds, tuple):
            raise CoreValidationError("reconciliation.account_holds must be a tuple")
        for holds in self.account_holds:
            if not isinstance(holds, AccountHolds):
                raise CoreValidationError(
                    f"reconciliation.account_holds entries must be AccountHolds, got {type(holds).__name__}"
                )
        if not isinstance(self.asset_sheets, tuple):
            raise CoreValidationError("reconciliation.asset_sheets must be a tuple")
        for sheet in self.asset_sheets:
            if not isinstance(sheet, AssetSheet):
                raise CoreValidationError(
                    f"reconciliation.asset_sheets entries must be AssetSheet, got {type(sheet).__name__}"
                )
        if not isinstance(self.discrepancies, tuple):
            raise CoreValidationError("reconciliation.discrepancies must be a tuple")
        for item in self.discrepancies:
            require_text("reconciliation.discrepancy", item)

    def to_dict(self) -> dict[str, Any]:
        return {
            "journal_id": self.journal_id,
            "as_of_ordinal": self.as_of_ordinal,
            "trial_balance": [totals.to_dict() for totals in self.trial_balance],
            "account_holds": [holds.to_dict() for holds in self.account_holds],
            "asset_sheets": [sheet.to_dict() for sheet in self.asset_sheets],
            "discrepancies": list(self.discrepancies),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReconciliationPayload":
        strict_fields("reconciliation payload", value, RECONCILIATION_PAYLOAD_FIELDS)
        return cls(
            journal_id=value["journal_id"],
            as_of_ordinal=value["as_of_ordinal"],
            trial_balance=tuple(AssetTotals.from_dict(item) for item in value["trial_balance"]),
            account_holds=tuple(AccountHolds.from_dict(item) for item in value["account_holds"]),
            asset_sheets=tuple(AssetSheet.from_dict(item) for item in value["asset_sheets"]),
            discrepancies=tuple(value["discrepancies"]),
        )


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """Durable, integrity-sealed reconciliation evidence record."""

    envelope: ObjectEnvelope
    payload: ReconciliationPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"reconciliation envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != RECONCILIATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"reconciliation object_type must be {RECONCILIATION_OBJECT_TYPE!r}, "
                f"got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"reconciliation schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"reconciliation rejects unknown protocol version {self.envelope.protocol_version!r}"
            )
        try:
            ReconciliationState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"reconciliation state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, ReconciliationPayload):
            raise CoreValidationError(
                f"reconciliation payload must be a ReconciliationPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError(
                "reconciliation integrity hash must be a non-empty string or null"
            )

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        journal_id: str,
        as_of_ordinal: int,
        trial_balance: Iterable[AssetTotals],
        account_holds: Iterable[AccountHolds],
        asset_sheets: Iterable[AssetSheet],
        discrepancies: Iterable[str],
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Reconciliation":
        """Derive the lifecycle state from the evidence, fail-closed.

        Unbalanced trial totals, hold divergence or unbalanced sheets must
        be acknowledged by at least one explicit discrepancy string;
        declaring a clean BALANCED reconciliation over contradictory
        evidence is rejected. Explicit discrepancies always force the
        DISCREPANCY state.
        """
        payload = ReconciliationPayload(
            journal_id=journal_id,
            as_of_ordinal=as_of_ordinal,
            trial_balance=tuple(trial_balance),
            account_holds=tuple(account_holds),
            asset_sheets=tuple(asset_sheets),
            discrepancies=tuple(discrepancies),
        )
        evidence_contradicted = any(
            not totals.balanced for totals in payload.trial_balance
        ) or any(not holds.ok for holds in payload.account_holds) or any(
            not sheet.balanced for sheet in payload.asset_sheets
        )
        if evidence_contradicted and not payload.discrepancies:
            raise CoreValidationError(
                "reconciliation evidence is unbalanced while no discrepancies are declared; "
                "contradictory evidence must be acknowledged explicitly"
            )
        state = (
            ReconciliationState.DISCREPANCY.value
            if payload.discrepancies
            else ReconciliationState.BALANCED.value
        )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=RECONCILIATION_OBJECT_TYPE,
            state=state,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def with_integrity_hash(self) -> "Reconciliation":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                "reconciliation envelope must be sealed before the payload hash of "
                f"{self.envelope.object_id}"
            )
        return Reconciliation(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"reconciliation {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Reconciliation":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = ReconciliationPayload.from_dict(payload_value)
        record = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        record.verify_integrity()
        return record

    @classmethod
    def from_json(cls, value: str) -> "Reconciliation":
        return cls.from_dict(decode_composite_json(value))
