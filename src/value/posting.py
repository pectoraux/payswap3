"""Postings: the immutable, exactly-balanced journal entries.

A posting is the frozen architecture's ``LedgerEntry`` (the Work Order
names it "posting"; the command family is ``Create/Post/Reverse/
Adjust/ReconcileJournal``). Postings are IMMUTABLE lifecycle objects:
they exist only at envelope version 1, carry state ``POSTED`` forever,
and corrections are new reversal/compensation postings — never edits.

Conservation contract enforced at construction and re-verified on every
deserialization:

```text
for every asset: Σ debits == Σ credits        (per posting, hence per journal)
```

Balance views are carried by the legs. A leg classifies value into one
of ``AVAILABLE``, ``PENDING``, ``ENCUMBERED``, ``RESTRICTED`` or
``SETTLED``; ``HELD`` is reserved for the hold-derived view and rejected
on legs (holds enter the ledger as ENCUMBERED legs). Because the views
only classify — they never change the debit/credit arithmetic — every
posting conserves value exactly across views as well: the sum of the
per-view position deltas equals the posting's total position delta.

Posting classes are the frozen source-mapping vocabulary (Hold,
Execution, Fee, FX, Clearing, Netting, Settlement, Refund, Reversal,
Default, Collateral, Credit) plus the explicit ADJUSTMENT class implied
by the ``AdjustJournal`` command. A reversal posting links to the exact
posting it reverses via ``reverses_posting_id``; the ledger enforces
that each posting is reversed at most once and that reversals are never
themselves reversed. Object type ``value/posting/v1`` is internal
(non-registry).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .amount import Amount
from .contracts import LEDGER_VIEWS, POSTING_OBJECT_TYPE, BalanceView, EntrySide
from .seal import (
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import require_identifier, require_int, require_str_tuple, require_text, strict_fields

POSTING_PAYLOAD_FIELDS = frozenset(
    {"journal_id", "sequence", "posting_class", "legs", "description", "reverses_posting_id", "source_refs"}
)
POSTING_LEG_FIELDS = frozenset({"account_id", "side", "amount", "view"})


class PostingClass(StrEnum):
    """Closed posting vocabulary from the frozen source mapping."""

    HOLD = "HOLD"
    EXECUTION = "EXECUTION"
    FEE = "FEE"
    FX = "FX"
    CLEARING = "CLEARING"
    NETTING = "NETTING"
    SETTLEMENT = "SETTLEMENT"
    REFUND = "REFUND"
    REVERSAL = "REVERSAL"
    DEFAULT = "DEFAULT"
    COLLATERAL = "COLLATERAL"
    CREDIT = "CREDIT"
    ADJUSTMENT = "ADJUSTMENT"


class PostingState(StrEnum):
    """Ledger entries are posted once and never change (single state)."""

    POSTED = "POSTED"


@dataclass(frozen=True, slots=True)
class PostingLeg:
    """One debit or credit of a posting against one account in one view."""

    account_id: str
    side: EntrySide
    amount: Amount
    view: BalanceView

    def __post_init__(self) -> None:
        require_identifier("posting leg.account_id", self.account_id)
        if not isinstance(self.side, EntrySide):
            raise CoreValidationError("posting leg.side must use the closed EntrySide vocabulary")
        if not isinstance(self.amount, Amount):
            raise CoreValidationError(
                f"posting leg.amount must be an Amount, got {type(self.amount).__name__}"
            )
        if not isinstance(self.view, BalanceView):
            raise CoreValidationError("posting leg.view must use the closed BalanceView vocabulary")
        if self.view not in LEDGER_VIEWS:
            raise CoreValidationError(
                f"posting legs may not carry the {self.view.value} view; {BalanceView.HELD.value} "
                "is derived exclusively from active hold records and its ledger mirror is "
                f"{BalanceView.ENCUMBERED.value}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "side": self.side.value,
            "amount": self.amount.to_dict(),
            "view": self.view.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PostingLeg":
        strict_fields("posting leg", value, POSTING_LEG_FIELDS)
        try:
            side = EntrySide(value["side"])
        except ValueError as exc:
            raise CoreValidationError(
                f"posting leg.side must use the closed vocabulary, got {value['side']!r}"
            ) from exc
        try:
            view = BalanceView(value["view"])
        except ValueError as exc:
            raise CoreValidationError(
                f"posting leg.view must use the closed vocabulary, got {value['view']!r}"
            ) from exc
        return cls(
            account_id=value["account_id"],
            side=side,
            amount=Amount.from_dict(value["amount"]),
            view=view,
        )


@dataclass(frozen=True, slots=True)
class AssetTotals:
    """Per-asset debit/credit totals; ``balanced`` is exact integer equality."""

    asset: str
    scale: int
    debit_total: int
    credit_total: int

    def __post_init__(self) -> None:
        require_identifier("asset totals.asset", self.asset)
        require_int("asset totals.scale", self.scale, minimum=0)
        require_int("asset totals.debit_total", self.debit_total)
        require_int("asset totals.credit_total", self.credit_total)

    @property
    def balanced(self) -> bool:
        return self.debit_total == self.credit_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "scale": self.scale,
            "debit_total": self.debit_total,
            "credit_total": self.credit_total,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetTotals":
        strict_fields("asset totals", value, {"asset", "scale", "debit_total", "credit_total"})
        return cls(
            asset=value["asset"],
            scale=value["scale"],
            debit_total=value["debit_total"],
            credit_total=value["credit_total"],
        )


def compute_asset_totals(legs: tuple[PostingLeg, ...]) -> tuple[AssetTotals, ...]:
    """Compute per-asset debit/credit totals, sorted by asset."""
    debits: dict[str, int] = {}
    credits: dict[str, int] = {}
    scales: dict[str, int] = {}
    for leg in legs:
        asset = leg.amount.asset
        scales[asset] = leg.amount.scale
        if leg.side == EntrySide.DEBIT:
            debits[asset] = debits.get(asset, 0) + leg.amount.value
        else:
            credits[asset] = credits.get(asset, 0) + leg.amount.value
    return tuple(
        AssetTotals(
            asset=asset,
            scale=scales[asset],
            debit_total=debits.get(asset, 0),
            credit_total=credits.get(asset, 0),
        )
        for asset in sorted(debits)
    )


@dataclass(frozen=True, slots=True)
class PostingPayload:
    """Immutable posting data: journal, sequence, class, legs, linkage."""

    journal_id: str
    sequence: int
    posting_class: PostingClass
    legs: tuple[PostingLeg, ...]
    description: str | None = None
    reverses_posting_id: str | None = None
    source_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("posting.journal_id", self.journal_id)
        require_int("posting.sequence", self.sequence, minimum=1)
        if not isinstance(self.posting_class, PostingClass):
            raise CoreValidationError("posting.posting_class must use the closed PostingClass vocabulary")
        if not isinstance(self.legs, tuple):
            raise CoreValidationError("posting.legs must be a tuple")
        if len(self.legs) < 2:
            raise CoreValidationError(
                "posting.legs must contain at least two legs; a single leg can never balance"
            )
        for leg in self.legs:
            if not isinstance(leg, PostingLeg):
                raise CoreValidationError(
                    f"posting.legs entries must be PostingLeg, got {type(leg).__name__}"
                )
            if not leg.amount.is_positive():
                raise CoreValidationError(
                    "posting leg amounts must be positive; zero or negative legs hide "
                    "conservation errors"
                )
        for totals in compute_asset_totals(self.legs):
            if not totals.balanced:
                raise CoreValidationError(
                    f"posting must balance per asset; asset {totals.asset} has "
                    f"debits {totals.debit_total} != credits {totals.credit_total}"
                )
        if self.description is not None:
            require_text("posting.description", self.description)
        if self.reverses_posting_id is not None:
            require_identifier("posting.reverses_posting_id", self.reverses_posting_id)
        if not isinstance(self.source_refs, tuple):
            raise CoreValidationError("posting.source_refs must be a tuple")
        require_str_tuple("posting.source_refs", list(self.source_refs), identifier=True)

    def asset_totals(self) -> tuple[AssetTotals, ...]:
        return compute_asset_totals(self.legs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "journal_id": self.journal_id,
            "sequence": self.sequence,
            "posting_class": self.posting_class.value,
            "legs": [leg.to_dict() for leg in self.legs],
            "description": self.description,
            "reverses_posting_id": self.reverses_posting_id,
            "source_refs": list(self.source_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PostingPayload":
        strict_fields("posting payload", value, POSTING_PAYLOAD_FIELDS)
        try:
            posting_class = PostingClass(value["posting_class"])
        except ValueError as exc:
            raise CoreValidationError(
                f"posting.posting_class must use the closed vocabulary, got {value['posting_class']!r}"
            ) from exc
        legs_value = value["legs"]
        if not isinstance(legs_value, list):
            raise CoreValidationError("posting.legs must deserialize from an array")
        return cls(
            journal_id=value["journal_id"],
            sequence=value["sequence"],
            posting_class=posting_class,
            legs=tuple(PostingLeg.from_dict(item) for item in legs_value),
            description=value["description"],
            reverses_posting_id=value["reverses_posting_id"],
            source_refs=tuple(value["source_refs"]),
        )

    @classmethod
    def build(
        cls,
        *,
        journal_id: str,
        sequence: int,
        posting_class: PostingClass | str,
        legs: Iterable[PostingLeg],
        description: str | None = None,
        reverses_posting_id: str | None = None,
        source_refs: Iterable[str] | tuple[str, ...] = (),
    ) -> "PostingPayload":
        if not isinstance(legs, (list, tuple)):
            raise CoreValidationError("posting legs must be provided as a sequence")
        if not isinstance(source_refs, (list, tuple)):
            raise CoreValidationError("posting source_refs must be provided as a sequence")
        try:
            resolved_class = PostingClass(posting_class)
        except ValueError as exc:
            raise CoreValidationError(
                f"posting_class must use the closed vocabulary, got {posting_class!r}"
            ) from exc
        return cls(
            journal_id=journal_id,
            sequence=sequence,
            posting_class=resolved_class,
            legs=tuple(legs),
            description=description,
            reverses_posting_id=reverses_posting_id,
            source_refs=tuple(source_refs),
        )


@dataclass(frozen=True, slots=True)
class Posting:
    """Durable, integrity-sealed posting (envelope + payload + seal).

    Ledger entries are append-only history: the class exposes no version
    transition API and rejects any envelope above version 1, because a
    correction is always a new posting, never an edit.
    """

    envelope: ObjectEnvelope
    payload: PostingPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"posting envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != POSTING_OBJECT_TYPE:
            raise CoreValidationError(
                f"posting object_type must be {POSTING_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"posting schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"posting rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        if self.envelope.state != PostingState.POSTED.value:
            raise CoreValidationError(
                f"posting state must be {PostingState.POSTED.value}; ledger entries never change state"
            )
        if self.envelope.object_version != 1 or self.envelope.previous_version is not None:
            raise CoreValidationError(
                "ledger entries are immutable and exist only at version 1; corrections are "
                "new reversal or compensation postings"
            )
        if not isinstance(self.payload, PostingPayload):
            raise CoreValidationError(
                f"posting payload must be a PostingPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("posting integrity hash must be a non-empty string or null")

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        journal_id: str,
        sequence: int,
        posting_class: PostingClass | str,
        legs: Iterable[PostingLeg],
        environment_id: str,
        domain_id: str,
        description: str | None = None,
        reverses_posting_id: str | None = None,
        source_refs: Iterable[str] | tuple[str, ...] = (),
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Posting":
        payload = PostingPayload.build(
            journal_id=journal_id,
            sequence=sequence,
            posting_class=posting_class,
            legs=legs,
            description=description,
            reverses_posting_id=reverses_posting_id,
            source_refs=source_refs,
        )
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=POSTING_OBJECT_TYPE,
            state=PostingState.POSTED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def asset_totals(self) -> tuple[AssetTotals, ...]:
        return self.payload.asset_totals()

    def with_integrity_hash(self) -> "Posting":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"posting envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return Posting(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"posting {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Posting":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = PostingPayload.from_dict(payload_value)
        posting = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        posting.verify_integrity()
        return posting

    @classmethod
    def from_json(cls, value: str) -> "Posting":
        return cls.from_dict(decode_composite_json(value))
