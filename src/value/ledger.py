"""The value ledger: one authoritative in-memory facade per environment+domain.

``ValueLedger`` owns the current version of every value-domain record for
exactly one environment and domain (no dual authority interval) and applies
the frozen ledger/posting model's operational guards fail-closed:

* postings require an ACTIVE journal, ACTIVE accounts and an ACTIVE asset,
  exact asset/scale agreement, per-asset balance (enforced by the posting
  payload) and the safeguarding policy: accounts that hold other parties'
  value may never reach a negative total position;
* holds reserve value by posting it from AVAILABLE to ENCUMBERED; the
  hold-derived ``HELD`` total and the ``ENCUMBERED`` view are kept
  reconcilable — release/expire return encumbered value to AVAILABLE
  (allowed even on a RESTRICTED account: releasing trapped value is the
  sanctioned exception path), decrease re-aligns the record with a consumed
  encumbered view, and reservation safety always requires AVAILABLE cover;
* reconciliation derives per-asset trial totals, normal-side asset sheets
  and hold evidence, refuses to certify contradictory evidence, and seals
  the journal (postings then fail closed until a new journal version).

All records are immutable sealed composites (envelope + payload + domain
seal); history stays append-only at the posting level while versioned
records advance through governed transitions. Deterministic identifiers:
postings ``<journal>/p%06d``, reconciliations ``<journal>/r%06d``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256

from .account import Account, AccountState, SegregationClass
from .amount import Amount
from .asset import Asset, AssetKind, AssetState
from .balances import Balance, BalanceView
from .contracts import (
    LEDGER_VIEWS,
    TOTAL_VIEWS,
    EntrySide,
)
from .funding import FundingSource, FundingSourceState
from .hold import Hold, HoldState
from .instrument import InstrumentState, ValueInstrument
from .journal import Journal, JournalState
from .posting import (
    AssetTotals,
    EntrySide as _EntrySide,
    Posting,
    PostingClass,
    PostingLeg,
    PostingState,
)
from .reconciliation import AccountHolds, AssetSheet, Reconciliation, ReconciliationState
from .seal import advance_domain_envelope
from .validation import require_identifier, require_text


def _mirror(side: EntrySide) -> EntrySide:
    return EntrySide.CREDIT if side is EntrySide.DEBIT else EntrySide.DEBIT


def _hold_movement_legs(
    account: Account, amount: Amount, *, direction: str
) -> tuple[PostingLeg, ...]:
    """Legs moving value between AVAILABLE and ENCUMBERED on one account.

    ``direction="encumber"`` reserves value (AVAILABLE → ENCUMBERED);
    ``direction="release"`` returns it (ENCUMBERED → AVAILABLE). The leg
    sides follow the account's normal side so the normal-oriented views
    move as intended for both credit-normal and debit-normal accounts.
    """
    if direction not in ("encumber", "release"):
        raise CoreValidationError(f"unknown hold movement direction {direction!r}")
    if account.payload.normal_side is EntrySide.CREDIT:
        available_side, encumbered_side = EntrySide.DEBIT, EntrySide.CREDIT
    else:
        available_side, encumbered_side = EntrySide.CREDIT, EntrySide.DEBIT
    if direction == "release":
        available_side, encumbered_side = _mirror(available_side), _mirror(encumbered_side)
    return (
        PostingLeg(
            account_id=account.envelope.object_id,
            side=available_side,
            amount=amount,
            view=BalanceView.AVAILABLE,
        ),
        PostingLeg(
            account_id=account.envelope.object_id,
            side=encumbered_side,
            amount=amount,
            view=BalanceView.ENCUMBERED,
        ),
    )


class ValueLedger:
    """Authoritative in-memory ledger state for one environment and domain."""

    def __init__(self, *, environment_id: str, domain_id: str) -> None:
        require_text("ledger.environment_id", environment_id)
        require_text("ledger.domain_id", domain_id)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._assets: dict[str, Asset] = {}
        self._asset_by_code: dict[str, str] = {}
        self._accounts: dict[str, Account] = {}
        self._journals: dict[str, Journal] = {}
        self._postings: dict[str, Posting] = {}
        self._journal_posting_ids: dict[str, list[str]] = {}
        self._holds: dict[str, Hold] = {}
        self._instruments: dict[str, ValueInstrument] = {}
        self._funding_sources: dict[str, FundingSource] = {}
        self._reconciliations: dict[str, Reconciliation] = {}

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _require_new(self, store: Mapping[str, Any], object_id: str, kind: str) -> None:
        if object_id in store:
            raise CoreValidationError(f"{kind} {object_id} already exists in this ledger")

    def _asset_for_code(self, asset_code: str) -> Asset:
        require_identifier("asset_code", asset_code)
        object_id = self._asset_by_code.get(asset_code)
        if object_id is None:
            raise CoreValidationError(f"unknown asset code {asset_code} in this ledger")
        return self._assets[object_id]

    def _account(self, account_id: str) -> Account:
        require_identifier("account_id", account_id)
        account = self._accounts.get(account_id)
        if account is None:
            raise CoreValidationError(f"unknown account {account_id} in this ledger")
        return account

    def _journal(self, journal_id: str) -> Journal:
        require_identifier("journal_id", journal_id)
        journal = self._journals.get(journal_id)
        if journal is None:
            raise CoreValidationError(f"unknown journal {journal_id} in this ledger")
        return journal

    def _hold(self, hold_id: str) -> Hold:
        require_identifier("hold_id", hold_id)
        hold = self._holds.get(hold_id)
        if hold is None:
            raise CoreValidationError(f"unknown hold {hold_id} in this ledger")
        return hold

    # ------------------------------------------------------------------
    # view derivation
    # ------------------------------------------------------------------

    def _ordered_postings(self) -> tuple[Posting, ...]:
        ordered: list[Posting] = []
        for journal_id in sorted(self._journal_posting_ids):
            for posting_id in self._journal_posting_ids[journal_id]:
                ordered.append(self._postings[posting_id])
        return tuple(ordered)

    def _account_views(self, account_id: str) -> dict[str, int]:
        """Normal-oriented per-view positions of one account over all postings."""
        account = self._account(account_id)
        views = {view.value: 0 for view in LEDGER_VIEWS}
        credit_normal = account.payload.normal_side is EntrySide.CREDIT
        for posting in self._ordered_postings():
            for leg in posting.payload.legs:
                if leg.account_id != account_id:
                    continue
                normal_credit = (leg.side is EntrySide.CREDIT) == credit_normal
                views[leg.view.value] += leg.amount.value if normal_credit else -leg.amount.value
        return views

    def _held_total(self, account_id: str) -> int:
        held = 0
        for hold_id in sorted(self._holds):
            hold = self._holds[hold_id]
            if hold.envelope.state == HoldState.ACTIVE.value and hold.payload.account_id == account_id:
                held += hold.payload.amount.value
        return held

    def _as_of_ordinal(self) -> int:
        return len(self._postings) + 1

    def derive_balances(self, *, account_id: str) -> Balance:
        account = self._account(account_id)
        views = self._account_views(account_id)
        return Balance.derive(
            account_id=account_id,
            as_of_ordinal=self._as_of_ordinal(),
            asset=account.payload.asset,
            scale=account.payload.scale,
            available=views[BalanceView.AVAILABLE.value],
            pending=views[BalanceView.PENDING.value],
            encumbered=views[BalanceView.ENCUMBERED.value],
            restricted=views[BalanceView.RESTRICTED.value],
            settled=views[BalanceView.SETTLED.value],
            held=self._held_total(account_id),
        )

    # ------------------------------------------------------------------
    # assets
    # ------------------------------------------------------------------

    def register_asset(
        self,
        *,
        object_id: str,
        code: str,
        scale: int,
        kind: AssetKind,
        issuer_id: str,
        provenance: Provenance,
        name: str | None = None,
    ) -> Asset:
        self._require_new(self._assets, object_id, "asset")
        if code in self._asset_by_code:
            raise CoreValidationError(f"asset code {code} is already registered in this ledger")
        asset = Asset.register(
            object_id=object_id,
            code=code,
            scale=scale,
            kind=kind,
            issuer_id=issuer_id,
            name=name,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._assets[object_id] = asset
        self._asset_by_code[code] = object_id
        return asset

    def _advance_asset(self, object_id: str, operation: str, provenance: Provenance) -> Asset:
        asset = self._assets.get(object_id)
        if asset is None:
            raise CoreValidationError(f"unknown asset {object_id} in this ledger")
        advanced = getattr(asset, operation)(provenance=provenance)
        self._assets[object_id] = advanced
        return advanced

    def activate_asset(self, *, object_id: str, provenance: Provenance) -> Asset:
        return self._advance_asset(object_id, "activate", provenance)

    def suspend_asset(self, *, object_id: str, provenance: Provenance) -> Asset:
        return self._advance_asset(object_id, "suspend", provenance)

    def retire_asset(self, *, object_id: str, provenance: Provenance) -> Asset:
        return self._advance_asset(object_id, "retire", provenance)

    def get_asset(self, asset_code: str) -> Asset:
        return self._asset_for_code(asset_code)

    # ------------------------------------------------------------------
    # accounts
    # ------------------------------------------------------------------

    def create_account(
        self,
        *,
        object_id: str,
        asset_code: str,
        segregation_class: SegregationClass,
        owner_id: str,
        custodian_id: str,
        normal_side: EntrySide,
        provenance: Provenance,
        scale: int | None = None,
        name: str | None = None,
        enforce_non_negative: bool | None = None,
    ) -> Account:
        self._require_new(self._accounts, object_id, "account")
        asset = self._asset_for_code(asset_code)
        if asset.envelope.state != AssetState.ACTIVE.value:
            raise CoreValidationError(
                f"asset {asset_code} is {asset.envelope.state}; accounts may only be created "
                "on ACTIVE assets"
            )
        if scale is not None and scale != asset.payload.scale:
            raise CoreValidationError(
                f"account {object_id} scale {scale} does not match asset {asset_code} scale "
                f"{asset.payload.scale}"
            )
        account = Account.create(
            object_id=object_id,
            asset=asset_code,
            scale=asset.payload.scale,
            segregation_class=segregation_class,
            owner_id=owner_id,
            custodian_id=custodian_id,
            normal_side=normal_side,
            enforce_non_negative=enforce_non_negative,
            name=name,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._accounts[object_id] = account
        return account

    def _advance_account(self, object_id: str, operation: str, provenance: Provenance) -> Account:
        account = self._account(object_id)
        advanced = getattr(account, operation)(provenance=provenance)
        self._accounts[object_id] = advanced
        return advanced

    def activate_account(self, *, object_id: str, provenance: Provenance) -> Account:
        return self._advance_account(object_id, "activate", provenance)

    def restrict_account(self, *, object_id: str, provenance: Provenance) -> Account:
        return self._advance_account(object_id, "restrict", provenance)

    def close_account(self, *, object_id: str, provenance: Provenance) -> Account:
        account = self._account(object_id)
        if account.envelope.state != AccountState.RESTRICTED.value:
            raise CoreValidationError(
                f"account {object_id} is {account.envelope.state}; closure requires RESTRICTED"
            )
        for hold_id in sorted(self._holds):
            hold = self._holds[hold_id]
            if hold.payload.account_id == object_id and hold.envelope.state == HoldState.ACTIVE.value:
                raise CoreValidationError(
                    f"account {object_id} cannot close with active hold {hold_id}"
                )
        views = self._account_views(object_id)
        total = sum(views[view.value] for view in TOTAL_VIEWS)
        if total != 0 or any(views[view.value] != 0 for view in LEDGER_VIEWS):
            raise CoreValidationError(
                f"account {object_id} cannot close with a non-zero position; every ledger view "
                "must be zero"
            )
        return self._advance_account(object_id, "close", provenance)

    def get_account(self, object_id: str) -> Account:
        return self._account(object_id)

    # ------------------------------------------------------------------
    # journals and postings
    # ------------------------------------------------------------------

    def open_journal(
        self,
        *,
        object_id: str,
        custodian_id: str,
        description: str,
        provenance: Provenance,
    ) -> Journal:
        self._require_new(self._journals, object_id, "journal")
        journal = Journal.open(
            object_id=object_id,
            custodian_id=custodian_id,
            description=description,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._journals[object_id] = journal
        self._journal_posting_ids.setdefault(object_id, [])
        return journal

    def get_journal(self, journal_id: str) -> Journal:
        return self._journal(journal_id)

    def _check_posting_guards(
        self,
        *,
        legs: Iterable[PostingLeg],
        allowed_restricted: frozenset[str] = frozenset(),
    ) -> None:
        for leg in legs:
            account = self._account(leg.account_id)
            if account.envelope.state != AccountState.ACTIVE.value:
                if leg.account_id in allowed_restricted and account.envelope.state == AccountState.RESTRICTED.value:
                    continue
                raise CoreValidationError(
                    f"account {leg.account_id} is {account.envelope.state}; postings require "
                    "ACTIVE accounts"
                )
            asset = self._asset_for_code(leg.amount.asset)
            if asset.envelope.state != AssetState.ACTIVE.value:
                raise CoreValidationError(
                    f"asset {leg.amount.asset} is {asset.envelope.state}; postings require an "
                    "ACTIVE asset"
                )
            if leg.amount.asset != account.payload.asset:
                raise CoreValidationError(
                    f"leg amount asset {leg.amount.asset} does not match account "
                    f"{leg.account_id} asset {account.payload.asset}"
                )
            if leg.amount.scale != account.payload.scale:
                raise CoreValidationError(
                    f"leg amount scale {leg.amount.scale} does not match account {leg.account_id} "
                    f"scale {account.payload.scale}"
                )
        # safeguarding: accounts holding other parties' value never go negative in total
        deltas: dict[str, int] = {}
        for leg in legs:
            account = self._account(leg.account_id)
            credit_normal = account.payload.normal_side is EntrySide.CREDIT
            normal_credit = (leg.side is EntrySide.CREDIT) == credit_normal
            deltas[leg.account_id] = deltas.get(leg.account_id, 0) + (
                leg.amount.value if normal_credit else -leg.amount.value
            )
        for account_id, delta in deltas.items():
            account = self._account(account_id)
            if not account.payload.enforce_non_negative:
                continue
            views = self._account_views(account_id)
            total = sum(views[view.value] for view in TOTAL_VIEWS) + delta
            if total < 0:
                raise CoreValidationError(
                    f"account {account_id} safeguards other parties' value; its total position "
                    f"would go negative ({total}) under this posting"
                )

    def _record_posting(
        self,
        *,
        journal_id: str,
        posting_class: PostingClass,
        legs: tuple[PostingLeg, ...],
        provenance: Provenance,
        description: str | None = None,
        reverses_posting_id: str | None = None,
        source_refs: tuple[str, ...] = (),
        allowed_restricted: frozenset[str] = frozenset(),
    ) -> Posting:
        journal = self._journal(journal_id)
        if journal.envelope.state != JournalState.ACTIVE.value:
            raise CoreValidationError(
                f"journal {journal_id} is {journal.envelope.state}; postings require the "
                "journal to be ACTIVE"
            )
        self._check_posting_guards(legs=legs, allowed_restricted=allowed_restricted)
        sequence = len(self._journal_posting_ids[journal_id]) + 1
        object_id = f"{journal_id}/p{sequence:06d}"
        posting = Posting.build(
            object_id=object_id,
            journal_id=journal_id,
            sequence=sequence,
            posting_class=posting_class,
            legs=legs,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            description=description,
            reverses_posting_id=reverses_posting_id,
            source_refs=source_refs,
            provenance=provenance,
        )
        self._postings[object_id] = posting
        self._journal_posting_ids[journal_id].append(object_id)
        return posting

    def post(
        self,
        *,
        journal_id: str,
        posting_class: PostingClass,
        legs: Iterable[PostingLeg],
        provenance: Provenance,
        description: str | None = None,
    ) -> Posting:
        leg_tuple = tuple(legs)
        if not isinstance(posting_class, PostingClass):
            raise CoreValidationError("posting_class must use the closed PostingClass vocabulary")
        return self._record_posting(
            journal_id=journal_id,
            posting_class=posting_class,
            legs=leg_tuple,
            provenance=provenance,
            description=description,
        )

    def adjust(
        self,
        *,
        journal_id: str,
        legs: Iterable[PostingLeg],
        provenance: Provenance,
        description: str | None = None,
    ) -> Posting:
        return self.post(
            journal_id=journal_id,
            posting_class=PostingClass.ADJUSTMENT,
            legs=legs,
            provenance=provenance,
            description=description,
        )

    def reverse_posting(
        self,
        *,
        journal_id: str,
        posting_id: str,
        provenance: Provenance,
        description: str | None = None,
    ) -> Posting:
        original = self._postings.get(posting_id)
        if original is None:
            raise CoreValidationError(f"unknown posting {posting_id} in this ledger")
        if original.payload.journal_id != journal_id:
            raise CoreValidationError(
                f"posting {posting_id} does not belong to journal {journal_id}"
            )
        if original.payload.reverses_posting_id is not None:
            raise CoreValidationError(
                f"posting {posting_id} is a reversal; reversals are never themselves reversed"
            )
        for existing_id in self._journal_posting_ids[journal_id]:
            existing = self._postings[existing_id]
            if existing.payload.reverses_posting_id == posting_id:
                raise CoreValidationError(
                    f"posting {posting_id} is already reversed by {existing_id}"
                )
        mirrored = tuple(
            PostingLeg(
                account_id=leg.account_id,
                side=_mirror(leg.side),
                amount=leg.amount,
                view=leg.view,
            )
            for leg in original.payload.legs
        )
        return self._record_posting(
            journal_id=journal_id,
            posting_class=PostingClass.REVERSAL,
            legs=mirrored,
            provenance=provenance,
            description=description,
            reverses_posting_id=posting_id,
        )

    def journal_postings(self, journal_id: str) -> tuple[Posting, ...]:
        self._journal(journal_id)
        return tuple(self._postings[posting_id] for posting_id in self._journal_posting_ids[journal_id])

    def get_posting(self, posting_id: str) -> Posting:
        posting = self._postings.get(posting_id)
        if posting is None:
            raise CoreValidationError(f"unknown posting {posting_id} in this ledger")
        return posting

    # ------------------------------------------------------------------
    # holds
    # ------------------------------------------------------------------

    def _require_active_account(self, account_id: str) -> Account:
        account = self._account(account_id)
        if account.envelope.state != AccountState.ACTIVE.value:
            raise CoreValidationError(
                f"account {account_id} is {account.envelope.state}; hold operations that "
                "consume available value require ACTIVE accounts"
            )
        return account

    def _require_reservation_cover(self, account_id: str, amount: Amount) -> None:
        views = self._account_views(account_id)
        if views[BalanceView.AVAILABLE.value] < amount.value:
            raise CoreValidationError(
                f"reservation safety: account {account_id} available "
                f"{views[BalanceView.AVAILABLE.value]} cannot cover a hold of {amount.value}"
            )

    def _require_encumbered_cover(self, account_id: str, amount: Amount, operation: str) -> None:
        views = self._account_views(account_id)
        if views[BalanceView.ENCUMBERED.value] < amount.value:
            raise CoreValidationError(
                f"hold {operation} for account {account_id}: the requested {amount.value} "
                f"exceeds the account's encumbered view "
                f"{views[BalanceView.ENCUMBERED.value]}"
            )

    def hold_create(
        self,
        *,
        journal_id: str,
        hold_id: str,
        account_id: str,
        amount: Amount,
        provenance: Provenance,
        purpose: str | None = None,
        expires_at: str | None = None,
    ) -> Hold:
        self._require_new(self._holds, hold_id, "hold")
        account = self._require_active_account(account_id)
        if not isinstance(amount, Amount) or not amount.is_positive():
            raise CoreValidationError("hold amount must be a positive Amount")
        if amount.asset != account.payload.asset or amount.scale != account.payload.scale:
            raise CoreValidationError(
                f"hold amount must use account {account_id} asset {account.payload.asset} "
                f"at scale {account.payload.scale}"
            )
        self._require_reservation_cover(account_id, amount)
        hold = Hold.create(
            object_id=hold_id,
            account_id=account_id,
            asset=amount.asset,
            amount=amount,
            purpose=purpose,
            expires_at=expires_at,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._holds[hold_id] = hold
        self._record_posting(
            journal_id=journal_id,
            posting_class=PostingClass.HOLD,
            legs=_hold_movement_legs(account, amount, direction="encumber"),
            provenance=provenance,
            description=f"hold encumbrance for {hold_id}",
            source_refs=(hold_id,),
        )
        return hold

    def hold_increase(
        self,
        *,
        journal_id: str,
        hold_id: str,
        delta: Amount,
        provenance: Provenance,
    ) -> Hold:
        hold = self._hold(hold_id)
        account = self._require_active_account(hold.payload.account_id)
        if not isinstance(delta, Amount) or not delta.is_positive():
            raise CoreValidationError("hold increase delta must be a positive Amount")
        self._require_reservation_cover(hold.payload.account_id, delta)
        advanced = hold.increase(delta=delta, provenance=provenance)
        self._holds[hold_id] = advanced
        self._record_posting(
            journal_id=journal_id,
            posting_class=PostingClass.HOLD,
            legs=_hold_movement_legs(account, delta, direction="encumber"),
            provenance=provenance,
            description=f"hold increase for {hold_id}",
            source_refs=(hold_id,),
        )
        return advanced

    def hold_release(
        self,
        *,
        journal_id: str,
        hold_id: str,
        provenance: Provenance,
        amount: Amount | None = None,
    ) -> Hold:
        hold = self._hold(hold_id)
        account_id = hold.payload.account_id
        account = self._account(account_id)
        release_amount = amount if amount is not None else hold.payload.amount
        if not isinstance(release_amount, Amount) or not release_amount.is_positive():
            raise CoreValidationError("hold release amount must be a positive Amount")
        if release_amount.value > hold.payload.amount.value:
            raise CoreValidationError(
                f"hold {hold_id} cannot release {release_amount.value}; it only holds "
                f"{hold.payload.amount.value}"
            )
        # Releasing trapped value is the sanctioned exception path on a
        # RESTRICTED account: the account may be RESTRICTED, but the
        # encumbered view must still cover the release exactly.
        self._require_encumbered_cover(account_id, release_amount, "release")
        advanced = hold.release(amount=amount, provenance=provenance)
        self._holds[hold_id] = advanced
        self._record_posting(
            journal_id=journal_id,
            posting_class=PostingClass.HOLD,
            legs=_hold_movement_legs(account, release_amount, direction="release"),
            provenance=provenance,
            description=f"hold release for {hold_id}",
            source_refs=(hold_id,),
            allowed_restricted=frozenset({account_id}),
        )
        return advanced

    def hold_decrease(
        self,
        *,
        hold_id: str,
        delta: Amount,
        provenance: Provenance,
    ) -> Hold:
        hold = self._hold(hold_id)
        account_id = hold.payload.account_id
        self._account(account_id)
        if not isinstance(delta, Amount) or not delta.is_positive():
            raise CoreValidationError("hold decrease delta must be a positive Amount")
        held_after = hold.payload.amount.value - delta.value
        views = self._account_views(account_id)
        if held_after < views[BalanceView.ENCUMBERED.value]:
            raise CoreValidationError(
                f"hold decrease for {hold_id}: held would fall to {held_after}, below the "
                f"account's encumbered view {views[BalanceView.ENCUMBERED.value]}; use release "
                "to move value back instead"
            )
        advanced = hold.decrease(delta=delta, provenance=provenance)
        self._holds[hold_id] = advanced
        return advanced

    def hold_expire(
        self,
        *,
        journal_id: str,
        hold_id: str,
        provenance: Provenance,
    ) -> Hold:
        hold = self._hold(hold_id)
        account_id = hold.payload.account_id
        account = self._account(account_id)
        amount = hold.payload.amount
        if amount.is_positive():
            self._require_encumbered_cover(account_id, amount, "expire")
        advanced = hold.expire(provenance=provenance)
        self._holds[hold_id] = advanced
        if amount.is_positive():
            self._record_posting(
                journal_id=journal_id,
                posting_class=PostingClass.HOLD,
                legs=_hold_movement_legs(account, amount, direction="release"),
                provenance=provenance,
                description=f"hold expiry release for {hold_id}",
                source_refs=(hold_id,),
                allowed_restricted=frozenset({account_id}),
            )
        return advanced

    # ------------------------------------------------------------------
    # instruments and funding sources
    # ------------------------------------------------------------------

    def issue_instrument(
        self,
        *,
        object_id: str,
        asset_code: str,
        amount: Amount,
        issuer_id: str,
        holder_id: str,
        provenance: Provenance,
    ) -> ValueInstrument:
        self._require_new(self._instruments, object_id, "instrument")
        asset = self._asset_for_code(asset_code)
        if asset.envelope.state != AssetState.ACTIVE.value:
            raise CoreValidationError(
                f"asset {asset_code} is {asset.envelope.state}; instruments may only be issued "
                "on ACTIVE assets"
            )
        if not isinstance(amount, Amount) or not amount.is_positive():
            raise CoreValidationError("instrument amount must be a positive Amount")
        if amount.asset != asset_code or amount.scale != asset.payload.scale:
            raise CoreValidationError(
                f"instrument amount must use asset {asset_code} at scale {asset.payload.scale}"
            )
        instrument = ValueInstrument.issue(
            object_id=object_id,
            asset=asset_code,
            scale=asset.payload.scale,
            amount=amount,
            issuer_id=issuer_id,
            holder_id=holder_id,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._instruments[object_id] = instrument
        return instrument

    def transfer_instrument(
        self,
        *,
        object_id: str,
        new_holder_id: str,
        provenance: Provenance,
    ) -> ValueInstrument:
        instrument = self._instruments.get(object_id)
        if instrument is None:
            raise CoreValidationError(f"unknown instrument {object_id} in this ledger")
        advanced = instrument.transfer(new_holder_id=new_holder_id, provenance=provenance)
        self._instruments[object_id] = advanced
        return advanced

    def redeem_instrument(self, *, object_id: str, provenance: Provenance) -> ValueInstrument:
        instrument = self._instruments.get(object_id)
        if instrument is None:
            raise CoreValidationError(f"unknown instrument {object_id} in this ledger")
        advanced = instrument.redeem(provenance=provenance)
        self._instruments[object_id] = advanced
        return advanced

    def create_funding_source(
        self,
        *,
        object_id: str,
        account_id: str,
        cap: Amount,
        provenance: Provenance,
    ) -> FundingSource:
        self._require_new(self._funding_sources, object_id, "funding source")
        account = self._require_active_account(account_id)
        if not isinstance(cap, Amount):
            raise CoreValidationError("funding source cap must be an Amount")
        if cap.asset != account.payload.asset or cap.scale != account.payload.scale:
            raise CoreValidationError(
                f"funding source cap must use account {account_id} asset "
                f"{account.payload.asset} at scale {account.payload.scale}"
            )
        source = FundingSource.create(
            object_id=object_id,
            account_id=account_id,
            cap=cap,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        self._funding_sources[object_id] = source
        return source

    def retire_funding_source(self, *, object_id: str, provenance: Provenance) -> FundingSource:
        source = self._funding_sources.get(object_id)
        if source is None:
            raise CoreValidationError(f"unknown funding source {object_id} in this ledger")
        advanced = source.retire(provenance=provenance)
        self._funding_sources[object_id] = advanced
        return advanced

    # ------------------------------------------------------------------
    # reconciliation
    # ------------------------------------------------------------------

    def _trial_balance(self, journal_id: str) -> tuple[AssetTotals, ...]:
        totals: dict[str, AssetTotals] = {}
        for posting in self.journal_postings(journal_id):
            for asset_totals in posting.payload.asset_totals():
                existing = totals.get(asset_totals.asset)
                if existing is None:
                    totals[asset_totals.asset] = asset_totals
                else:
                    totals[asset_totals.asset] = AssetTotals(
                        asset=asset_totals.asset,
                        scale=asset_totals.scale,
                        debit_total=existing.debit_total + asset_totals.debit_total,
                        credit_total=existing.credit_total + asset_totals.credit_total,
                    )
        return tuple(totals[asset] for asset in sorted(totals))

    def _asset_sheets(self) -> tuple[AssetSheet, ...]:
        totals: dict[str, dict[str, int]] = {}
        scales: dict[str, int] = {}
        for account_id in sorted(self._accounts):
            account = self._accounts[account_id]
            asset = account.payload.asset
            bucket = totals.setdefault(asset, {"debit": 0, "credit": 0})
            scales.setdefault(asset, account.payload.scale)
            views = self._account_views(account_id)
            total = sum(views[view.value] for view in TOTAL_VIEWS)
            if account.payload.normal_side is EntrySide.DEBIT:
                bucket["debit"] += total
            else:
                bucket["credit"] += total
        return tuple(
            AssetSheet(
                asset=asset,
                scale=scales[asset],
                debit_normal_total=totals[asset]["debit"],
                credit_normal_total=totals[asset]["credit"],
            )
            for asset in sorted(totals)
        )

    def _account_holds_evidence(self) -> tuple[AccountHolds, ...]:
        evidence: dict[str, AccountHolds] = {}
        for hold_id in sorted(self._holds):
            account_id = self._holds[hold_id].payload.account_id
            if account_id in evidence:
                continue
            views = self._account_views(account_id)
            evidence[account_id] = AccountHolds(
                account_id=account_id,
                held=self._held_total(account_id),
                encumbered=views[BalanceView.ENCUMBERED.value],
            )
        for account_id in sorted(self._accounts):
            if account_id in evidence:
                continue
            views = self._account_views(account_id)
            if views[BalanceView.ENCUMBERED.value] != 0:
                evidence[account_id] = AccountHolds(
                    account_id=account_id,
                    held=self._held_total(account_id),
                    encumbered=views[BalanceView.ENCUMBERED.value],
                )
        return tuple(evidence[account_id] for account_id in sorted(evidence))

    def reconcile(self, *, journal_id: str, provenance: Provenance) -> Reconciliation:
        journal = self._journal(journal_id)
        trial_balance = self._trial_balance(journal_id)
        account_holds = self._account_holds_evidence()
        asset_sheets = self._asset_sheets()
        discrepancies: list[str] = []
        for totals in trial_balance:
            if not totals.balanced:
                discrepancies.append(
                    f"asset {totals.asset} journal trial balance is off by "
                    f"{totals.debit_total - totals.credit_total}"
                )
        for holds in account_holds:
            if not holds.ok:
                discrepancies.append(
                    f"account {holds.account_id} held {holds.held} != encumbered "
                    f"{holds.encumbered}"
                )
        for sheet in asset_sheets:
            if not sheet.balanced:
                discrepancies.append(
                    f"asset {sheet.asset} normal-side sheet is off by "
                    f"{sheet.debit_normal_total - sheet.credit_normal_total}"
                )
        ordinal = self._as_of_ordinal()
        object_id = f"{journal_id}/r{ordinal:06d}"
        built = Reconciliation.build(
            object_id=object_id,
            journal_id=journal_id,
            as_of_ordinal=ordinal,
            trial_balance=trial_balance,
            account_holds=account_holds,
            asset_sheets=asset_sheets,
            discrepancies=discrepancies,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=provenance,
        )
        existing = self._reconciliations.get(object_id)
        if existing is not None:
            # Re-reconciliation with unchanged evidence re-issues the record
            # as its next immutable version (same identity, new version).
            envelope = advance_domain_envelope(
                existing.envelope,
                state=built.envelope.state,
                provenance=provenance,
            )
            built = Reconciliation(
                envelope=envelope,
                payload=built.payload,
            ).with_integrity_hash()
        self._reconciliations[object_id] = built
        advanced_journal = journal.reconcile(provenance=provenance)
        self._journals[journal_id] = advanced_journal
        return built

    # ------------------------------------------------------------------
    # deterministic state projection
    # ------------------------------------------------------------------

    def canonical_state(self) -> dict[str, Any]:
        """Deterministic canonical projection of the whole ledger state."""
        return {
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "assets": [self._assets[key].to_dict() for key in sorted(self._assets)],
            "accounts": [self._accounts[key].to_dict() for key in sorted(self._accounts)],
            "journals": [self._journals[key].to_dict() for key in sorted(self._journals)],
            "postings": [self._postings[key].to_dict() for key in sorted(self._postings)],
            "holds": [self._holds[key].to_dict() for key in sorted(self._holds)],
            "instruments": [
                self._instruments[key].to_dict() for key in sorted(self._instruments)
            ],
            "funding_sources": [
                self._funding_sources[key].to_dict() for key in sorted(self._funding_sources)
            ],
            "reconciliations": [
                self._reconciliations[key].to_dict() for key in sorted(self._reconciliations)
            ],
        }

    def state_digest(self) -> str:
        return canonical_sha256(self.canonical_state())
