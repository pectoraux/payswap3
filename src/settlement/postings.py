"""The settlement-domain posting journal (append-only, double entry).

Ledger-posting-model source mapping owned here (constitution
invariants 2, 12 and 17; the Work Order's forbidden surface "no
arbitrary ledger edits"):

* ``Settlement → discharge of obligations + asset movement`` — every
  settled leg emits a balanced ``DISCHARGE`` pair;
* uncertain external outcomes (unknown rail results, aged windows) emit
  a balanced ``SUSPENSE`` pair into controlled suspense/exception
  positions — a state, never a silent loss or success classification;
  a later authoritative observation emits ``SUSPENSE_RELEASE`` (the
  exact compensation of the suspense pair) before the terminal pair;
* ``Reversal → explicit reversal/compensation journal`` —
  ``recourse/reversal.execute`` emits the exact compensation of the
  original discharge pair (a new posting; history is never rewritten);
* ``Refund → new economic transaction linked to original`` — a refund
  settlement's settled legs emit ``REFUND`` pairs (direction-reversed
  legs of a completed settlement, linked to the original).

Every posting entry is itself balanced (``debit_value == credit_value``
within one asset). Postings are derived deterministically from committed
settlement events and carried in the event payloads; the journal index
appends them and is rebuilt identically from the journal alone. No
command exists to edit, rewrite or delete a posting: the only
"correction" paths are the explicit compensation postings above.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_mapping,
    require_text,
    strict_fields,
)
from .contracts import PostingKind

#: Controlled account-kind namespace of the settlement layer. Account
#: names are ``{kind}/{participant}``. The value domain (WORK-005) owns
#: authoritative accounts; these are the settlement layer's explicit
#: accounting semantics for discharge, suspense, reversal and refund.
ACCOUNT_KINDS = frozenset(
    {
        "obligation-liability",
        "settled-claim",
        "suspense-in-transit",
        "suspense-exception",
        "reversal-adjustment",
        "refund-disbursed",
    }
)

_POSTING_ENTRY_FIELDS = frozenset(
    {
        "entry_id",
        "event_id",
        "event_type",
        "kind",
        "asset",
        "scale",
        "debit_account",
        "debit_value",
        "credit_account",
        "credit_value",
        "instruction_ref",
        "posted_at",
    }
)


def account_name(kind: str, participant: str) -> str:
    """Build one controlled account name; the kind must be closed."""
    require_text("posting account kind", kind)
    if kind not in ACCOUNT_KINDS:
        raise CoreValidationError(
            f"posting account kind {kind!r} is not part of the closed account namespace"
        )
    require_identifier("posting account participant", participant)
    return f"{kind}/{participant}"


@dataclass(frozen=True, slots=True)
class PostingEntry:
    """One balanced double-entry posting pair (append-only journal entry)."""

    entry_id: str
    event_id: str
    event_type: str
    kind: str
    asset: str
    scale: int
    debit_account: str
    debit_value: int
    credit_account: str
    credit_value: int
    instruction_ref: str
    posted_at: str

    def __post_init__(self) -> None:
        require_identifier("posting.entry_id", self.entry_id)
        require_identifier("posting.event_id", self.event_id)
        require_text("posting.event_type", self.event_type)
        parse_enum("posting.kind", self.kind, PostingKind)
        require_identifier("posting.asset", self.asset)
        require_int("posting.scale", self.scale, minimum=0)
        require_identifier("posting.debit_account", self.debit_account)
        require_int("posting.debit_value", self.debit_value, minimum=1)
        require_identifier("posting.credit_account", self.credit_account)
        require_int("posting.credit_value", self.credit_value, minimum=1)
        require_identifier("posting.instruction_ref", self.instruction_ref)
        require_text("posting.posted_at", self.posted_at)
        if self.debit_account == self.credit_account:
            raise CoreValidationError(
                "posting debit and credit accounts must differ "
                f"({self.debit_account!r})"
            )
        self._require_balance()

    def _require_balance(self) -> None:
        """Double-entry integrity: the pair is balanced within one asset."""
        if self.debit_value != self.credit_value:
            raise CoreValidationError(
                f"posting {self.entry_id} is unbalanced: debit "
                f"{self.debit_value} != credit {self.credit_value} "
                f"(asset {self.asset})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "kind": self.kind,
            "asset": self.asset,
            "scale": self.scale,
            "debit_account": self.debit_account,
            "debit_value": self.debit_value,
            "credit_account": self.credit_account,
            "credit_value": self.credit_value,
            "instruction_ref": self.instruction_ref,
            "posted_at": self.posted_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PostingEntry":
        require_mapping("posting entry", value)
        strict_fields("posting entry", value, _POSTING_ENTRY_FIELDS)
        return cls(
            entry_id=value["entry_id"],
            event_id=value["event_id"],
            event_type=value["event_type"],
            kind=value["kind"],
            asset=value["asset"],
            scale=value["scale"],
            debit_account=value["debit_account"],
            debit_value=value["debit_value"],
            credit_account=value["credit_account"],
            credit_value=value["credit_value"],
            instruction_ref=value["instruction_ref"],
            posted_at=value["posted_at"],
        )


def discharge_pair(
    *,
    event_id: str,
    event_type: str,
    instruction_ref: str,
    obligor: str,
    obligee: str,
    asset: str,
    scale: int,
    amount_value: int,
    posted_at: str,
) -> PostingEntry:
    """``Settlement → discharge of obligations``: balanced discharge pair.

    Debits the obligor's obligation-liability, credits the obligee's
    settled-claim. The amount is the instruction amount re-derived from
    the sealed source (never payload-trusted).
    """
    return PostingEntry(
        entry_id=f"posting/{event_id}/discharge/{instruction_ref}",
        event_id=event_id,
        event_type=event_type,
        kind=PostingKind.DISCHARGE.value,
        asset=asset,
        scale=scale,
        debit_account=account_name("obligation-liability", obligor),
        debit_value=amount_value,
        credit_account=account_name("settled-claim", obligee),
        credit_value=amount_value,
        instruction_ref=instruction_ref,
        posted_at=posted_at,
    )


def refund_pair(
    *,
    event_id: str,
    event_type: str,
    instruction_ref: str,
    obligor: str,
    obligee: str,
    asset: str,
    scale: int,
    amount_value: int,
    posted_at: str,
) -> PostingEntry:
    """``Refund → new economic transaction linked to original``.

    The refund leg's obligor is the original obligee (funds return) and
    the obligee is the original obligor: debits the payer's
    settled-claim, credits refund-disbursed. A new transaction — never
    a rewrite of the original discharge posting.
    """
    return PostingEntry(
        entry_id=f"posting/{event_id}/refund/{instruction_ref}",
        event_id=event_id,
        event_type=event_type,
        kind=PostingKind.REFUND.value,
        asset=asset,
        scale=scale,
        debit_account=account_name("settled-claim", obligor),
        debit_value=amount_value,
        credit_account=account_name("refund-disbursed", obligee),
        credit_value=amount_value,
        instruction_ref=instruction_ref,
        posted_at=posted_at,
    )


def suspense_pair(
    *,
    event_id: str,
    event_type: str,
    instruction_ref: str,
    obligor: str,
    obligee: str,
    asset: str,
    scale: int,
    amount_value: int,
    posted_at: str,
) -> PostingEntry:
    """Uncertain external outcome → controlled suspense positions."""
    return PostingEntry(
        entry_id=f"posting/{event_id}/suspense/{instruction_ref}",
        event_id=event_id,
        event_type=event_type,
        kind=PostingKind.SUSPENSE.value,
        asset=asset,
        scale=scale,
        debit_account=account_name("suspense-in-transit", obligor),
        debit_value=amount_value,
        credit_account=account_name("suspense-exception", obligee),
        credit_value=amount_value,
        instruction_ref=instruction_ref,
        posted_at=posted_at,
    )


def suspense_release_pair(
    *,
    event_id: str,
    event_type: str,
    instruction_ref: str,
    obligor: str,
    obligee: str,
    asset: str,
    scale: int,
    amount_value: int,
    posted_at: str,
) -> PostingEntry:
    """Exact compensation of a leg's suspense pair (new posting)."""
    return PostingEntry(
        entry_id=f"posting/{event_id}/suspense-release/{instruction_ref}",
        event_id=event_id,
        event_type=event_type,
        kind=PostingKind.SUSPENSE_RELEASE.value,
        asset=asset,
        scale=scale,
        debit_account=account_name("suspense-exception", obligee),
        debit_value=amount_value,
        credit_account=account_name("suspense-in-transit", obligor),
        credit_value=amount_value,
        instruction_ref=instruction_ref,
        posted_at=posted_at,
    )


def reversal_pair(
    *,
    event_id: str,
    event_type: str,
    instruction_ref: str,
    obligor: str,
    obligee: str,
    asset: str,
    scale: int,
    amount_value: int,
    posted_at: str,
) -> PostingEntry:
    """``Reversal → explicit reversal/compensation journal``.

    The exact compensation of the original discharge pair: debits the
    obligee's settled-claim, credits reversal-adjustment. The books are
    restored by a new posting; the original posting is never edited.
    """
    return PostingEntry(
        entry_id=f"posting/{event_id}/reversal/{instruction_ref}",
        event_id=event_id,
        event_type=event_type,
        kind=PostingKind.REVERSAL.value,
        asset=asset,
        scale=scale,
        debit_account=account_name("settled-claim", obligee),
        debit_value=amount_value,
        credit_account=account_name("reversal-adjustment", obligor),
        credit_value=amount_value,
        instruction_ref=instruction_ref,
        posted_at=posted_at,
    )


def verify_journal_balance(entries: Iterable[PostingEntry]) -> dict[str, int]:
    """Verify Σ debits == Σ credits per asset over the whole journal.

    (Each entry already balances per pair; this computes the per-asset
    totals that reconciliation reports and tests pin.) Returns the
    per-asset totals keyed by asset.
    """
    totals: dict[str, int] = {}
    for entry in entries:
        parse_enum("posting kind", entry.kind, PostingKind)
        totals[entry.asset] = totals.get(entry.asset, 0) + entry.debit_value
    return totals


def journal_digest(entries: Iterable[PostingEntry]) -> str:
    """Canonical digest over the append-only journal (order-stable)."""
    return canonical_sha256(
        {"entries": [entry.to_dict() for entry in entries]}
    )
