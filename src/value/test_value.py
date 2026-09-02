"""Contract and discrimination suite for the PaySwap value domain (WORK-005).

This suite was written red-first against the declared public boundary of
``src.value`` before any implementation module existed. The captured red
run failed with ImportError for every declared export, i.e. the public
contract was absent, which is the required failing reason.

The suite encodes the frozen v0.1 ledger/posting contract:

* ``Amount = integer value + scale + asset`` — exact fixed-point minors,
  no floats, same-asset arithmetic only (rounding/FX are WORK-006);
* every posting balances per asset (``Σ debits = Σ credits``), so every
  journal operation conserves value exactly;
* balance views (AVAILABLE/HELD/PENDING/ENCUMBERED/RESTRICTED/SETTLED)
  are derived from posting legs and hold records; HELD is derived only
  from active hold records and must reconcile with the ENCUMBERED view;
* customer-fund segregation classes carry a safeguarding policy that
  forbids negative positions;
* ledger history is append-only: postings are immutable version-1
  objects and corrections are new reversal/compensation postings;
* provenance is explicit on every durable record and all operations are
  deterministic (no wall-clock reads, no randomness).
"""

from __future__ import annotations

import unittest

from src.core import ObjectEnvelope, ObjectGraph, Provenance, RelationshipType
from src.core.serialization import canonical_json, canonical_sha256
from src.value import (
    ACCOUNT_OBJECT_TYPE,
    ASSET_OBJECT_TYPE,
    BALANCE_OBJECT_TYPE,
    CoreValidationError,
    EntrySide,
    FUNDING_SOURCE_OBJECT_TYPE,
    Balance,
    BalanceView,
    HOLD_OBJECT_TYPE,
    INSTRUMENT_OBJECT_TYPE,
    JOURNAL_OBJECT_TYPE,
    LEDGER_VIEWS,
    MAX_SCALE,
    NON_NEGATIVE_CLASSES,
    POSTING_OBJECT_TYPE,
    Account,
    AccountHolds,
    AccountState,
    Amount,
    Asset,
    AssetKind,
    AssetSheet,
    AssetState,
    AssetTotals,
    FundingSource,
    FundingSourceState,
    Hold,
    HoldState,
    InstrumentState,
    Journal,
    JournalState,
    Posting,
    PostingClass,
    PostingLeg,
    Reconciliation,
    ReconciliationState,
    SegregationClass,
    ValueInstrument,
    ValueLedger,
)

STAMP = "2026-09-02T00:00:00Z"
ENV = "env/test"
DOMAIN = "domain/value-test"


def provenance(issuer: str = "principal/treasury") -> Provenance:
    return Provenance(issuer=issuer, source="dogfood", recorded_at=STAMP)


def make_ledger() -> ValueLedger:
    ledger = ValueLedger(environment_id=ENV, domain_id=DOMAIN)
    ledger.register_asset(
        object_id="value/asset/usd",
        code="USD",
        scale=2,
        kind=AssetKind.FIAT,
        issuer_id="principal/treasury",
        provenance=provenance(),
    )
    ledger.activate_asset(object_id="value/asset/usd", provenance=provenance())
    for object_id, segregation, normal, owner in (
        ("value/account/customer-1", SegregationClass.CUSTOMER, EntrySide.CREDIT, "principal/customer-1"),
        ("value/account/merchant-1", SegregationClass.MERCHANT_RECEIVABLE, EntrySide.CREDIT, "principal/merchant-1"),
        ("value/account/cash-vault", SegregationClass.NETWORK, EntrySide.DEBIT, "principal/treasury"),
        ("value/account/suspense-1", SegregationClass.SUSPENSE, EntrySide.CREDIT, "principal/treasury"),
    ):
        ledger.create_account(
            object_id=object_id,
            asset_code="USD",
            segregation_class=segregation,
            owner_id=owner,
            custodian_id="principal/custodian-1",
            normal_side=normal,
            provenance=provenance(),
        )
        ledger.activate_account(object_id=object_id, provenance=provenance())
    ledger.open_journal(
        object_id="value/journal/ops-1",
        custodian_id="principal/custodian-1",
        description="operations journal",
        provenance=provenance(),
    )
    return ledger


def deposit(ledger: ValueLedger, value: int = 12500) -> Posting:
    return ledger.post(
        journal_id="value/journal/ops-1",
        posting_class=PostingClass.EXECUTION,
        legs=(
            PostingLeg(
                account_id="value/account/cash-vault",
                side=EntrySide.DEBIT,
                amount=Amount(value, 2, "USD"),
                view=BalanceView.AVAILABLE,
            ),
            PostingLeg(
                account_id="value/account/customer-1",
                side=EntrySide.CREDIT,
                amount=Amount(value, 2, "USD"),
                view=BalanceView.AVAILABLE,
            ),
        ),
        description="customer deposit",
        provenance=provenance(),
    )


def re_seal(composite: dict) -> dict:
    """Recompute both seals of a composite record so semantic validations are hit."""
    envelope_core = {k: v for k, v in composite["envelope"].items() if k != "integrity_hash"}
    composite["envelope"]["integrity_hash"] = canonical_sha256(envelope_core)
    composite["integrity_hash"] = canonical_sha256(
        {"envelope": composite["envelope"], "payload": composite["payload"]}
    )
    return composite


class AmountTests(unittest.TestCase):
    def test_construction_and_fields(self) -> None:
        amount = Amount(10000, 2, "USD")
        self.assertEqual(amount.value, 10000)
        self.assertEqual(amount.scale, 2)
        self.assertEqual(amount.asset, "USD")

    def test_rejects_non_integer_values(self) -> None:
        for bad in (True, 1.5, "100", None, object()):
            with self.assertRaises(CoreValidationError):
                Amount(bad, 2, "USD")

    def test_rejects_out_of_range_scale(self) -> None:
        for bad in (-1, MAX_SCALE + 1, True, "2"):
            with self.assertRaises(CoreValidationError):
                Amount(10000, bad, "USD")
        self.assertEqual(Amount(10000, 0, "USD").scale, 0)
        self.assertEqual(Amount(10000, MAX_SCALE, "USD").scale, MAX_SCALE)

    def test_rejects_invalid_asset_identifiers(self) -> None:
        for bad in ("", "   ", "USD X", "USD\n", "x" * 201):
            with self.assertRaises(CoreValidationError):
                Amount(10000, 2, bad)

    def test_supports_signed_values_and_zero_factory(self) -> None:
        negative = Amount(-500, 2, "USD")
        self.assertTrue(negative.is_negative())
        self.assertFalse(negative.is_positive())
        self.assertTrue(Amount(0, 2, "USD").is_zero())
        self.assertEqual(Amount.zero("USD", 2), Amount(0, 2, "USD"))

    def test_exact_arithmetic_within_asset_and_scale(self) -> None:
        first = Amount(10000, 2, "USD")
        second = Amount(2550, 2, "USD")
        self.assertEqual(first.add(second), Amount(12550, 2, "USD"))
        self.assertEqual(first.sub(second), Amount(7450, 2, "USD"))
        self.assertEqual(first.negate(), Amount(-10000, 2, "USD"))
        self.assertEqual(first.add(second).sub(second), first)

    def test_rejects_cross_asset_and_cross_scale_arithmetic(self) -> None:
        usd = Amount(10000, 2, "USD")
        with self.assertRaises(CoreValidationError):
            usd.add(Amount(10000, 2, "EUR"))
        with self.assertRaises(CoreValidationError):
            usd.sub(Amount(100, 1, "USD"))
        # sanity: negate is total and double negation round-trips exactly
        self.assertEqual(Amount(100, 2, "USD").negate().negate(), Amount(100, 2, "USD"))
        self.assertEqual(usd.add(Amount(100, 2, "USD").negate().negate()), Amount(10100, 2, "USD"))

    def test_round_trip_is_lossless_and_byte_stable(self) -> None:
        amount = Amount(12550, 2, "USD")
        encoded = amount.to_json()
        self.assertEqual(Amount.from_json(encoded), amount)
        self.assertEqual(Amount.from_json(encoded).to_json(), encoded)
        self.assertEqual(Amount.from_dict(amount.to_dict()), amount)

    def test_rejects_unknown_fields(self) -> None:
        data = Amount(12550, 2, "USD").to_dict()
        data["extra"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            Amount.from_dict(data)


class AssetTests(unittest.TestCase):
    def build_asset(self) -> Asset:
        return Asset.register(
            object_id="value/asset/usd",
            code="USD",
            scale=2,
            kind=AssetKind.FIAT,
            issuer_id="principal/treasury",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )

    def test_register_creates_version_one_in_registered_state(self) -> None:
        asset = self.build_asset()
        self.assertEqual(asset.envelope.object_id, "value/asset/usd")
        self.assertEqual(asset.envelope.object_type, ASSET_OBJECT_TYPE)
        self.assertEqual(asset.envelope.object_version, 1)
        self.assertEqual(asset.envelope.state, AssetState.REGISTERED.value)
        self.assertEqual(asset.envelope.schema_version, 1)
        self.assertEqual(asset.envelope.protocol_version, "v0.1")
        self.assertEqual(asset.payload.code, "USD")
        self.assertEqual(asset.payload.scale, 2)

    def test_lifecycle_follows_register_activate_suspend_retire(self) -> None:
        asset = self.build_asset()
        active = asset.activate(provenance=provenance())
        self.assertEqual(active.envelope.state, AssetState.ACTIVE.value)
        self.assertEqual(active.envelope.object_version, 2)
        self.assertEqual(active.envelope.previous_version, 1)
        suspended = active.suspend(provenance=provenance())
        self.assertEqual(suspended.envelope.state, AssetState.SUSPENDED.value)
        retired = suspended.retire(provenance=provenance())
        self.assertEqual(retired.envelope.state, AssetState.RETIRED.value)
        self.assertEqual(asset.envelope.state, AssetState.REGISTERED.value)

    def test_reactivation_from_suspended_is_allowed_but_not_from_retired(self) -> None:
        asset = self.build_asset()
        suspended = asset.activate(provenance=provenance()).suspend(provenance=provenance())
        self.assertEqual(suspended.activate(provenance=provenance()).envelope.state, AssetState.ACTIVE.value)
        retired = suspended.retire(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            retired.activate(provenance=provenance())

    def test_illegal_transitions_fail_closed(self) -> None:
        asset = self.build_asset()
        with self.assertRaises(CoreValidationError):
            asset.suspend(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            asset.retire(provenance=provenance())
        active = asset.activate(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            active.retire(provenance=provenance())

    def test_payload_validation_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.build_asset().payload.__class__(code="USD", scale=MAX_SCALE + 1, kind=AssetKind.FIAT, issuer_id="p/t")
        with self.assertRaises(CoreValidationError):
            self.build_asset().payload.__class__(code="US D", scale=2, kind=AssetKind.FIAT, issuer_id="p/t")
        with self.assertRaises(CoreValidationError):
            self.build_asset().payload.__class__(code="USD", scale=2, kind="WEIRD", issuer_id="p/t")

    def test_round_trip_is_lossless_and_byte_stable(self) -> None:
        asset = self.build_asset().activate(provenance=provenance())
        encoded = asset.to_json()
        self.assertEqual(Asset.from_json(encoded), asset)
        self.assertEqual(Asset.from_json(encoded).to_json(), encoded)

    def test_tampered_and_unsealed_assets_are_rejected(self) -> None:
        asset = self.build_asset()
        with self.assertRaises(CoreValidationError):
            Asset.from_json(asset.to_json().replace('"code":"USD"', '"code":"EUR"'))
        data = asset.to_dict()
        data["integrity_hash"] = None
        with self.assertRaises(CoreValidationError):
            Asset.from_dict(data)
        forged = asset.to_dict()
        forged["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            Asset.from_dict(forged)

    def test_state_must_use_the_closed_vocabulary(self) -> None:
        asset = self.build_asset()
        data = re_seal(asset.to_dict())
        data["envelope"]["state"] = "BOGUS"
        re_seal(data)
        with self.assertRaises(CoreValidationError) as ctx:
            Asset.from_dict(data)
        self.assertIn("closed vocabulary", str(ctx.exception))

    def test_wrong_object_type_and_protocol_are_rejected(self) -> None:
        asset = self.build_asset()
        data = re_seal(asset.to_dict())
        data["envelope"]["object_type"] = "payswap/intent/v1"
        re_seal(data)
        with self.assertRaises(CoreValidationError) as ctx:
            Asset.from_dict(data)
        self.assertIn(ASSET_OBJECT_TYPE, str(ctx.exception))
        data = re_seal(asset.to_dict())
        data["envelope"]["protocol_version"] = "v0.2"
        re_seal(data)
        with self.assertRaises(CoreValidationError):
            Asset.from_dict(data)


class AccountTests(unittest.TestCase):
    def build_account(self, segregation: SegregationClass = SegregationClass.CUSTOMER) -> Account:
        return Account.create(
            object_id="value/account/customer-1",
            asset="USD",
            scale=2,
            segregation_class=segregation,
            owner_id="principal/customer-1",
            custodian_id="principal/custodian-1",
            normal_side=EntrySide.CREDIT,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )

    def test_create_yields_created_state_with_segregation_policy(self) -> None:
        account = self.build_account()
        self.assertEqual(account.envelope.object_type, ACCOUNT_OBJECT_TYPE)
        self.assertEqual(account.envelope.state, AccountState.CREATED.value)
        self.assertEqual(account.payload.segregation_class, SegregationClass.CUSTOMER)
        self.assertEqual(account.payload.normal_side, EntrySide.CREDIT)
        self.assertTrue(account.payload.enforce_non_negative)

    def test_lifecycle_create_activate_restrict_close(self) -> None:
        account = self.build_account()
        active = account.activate(provenance=provenance())
        restricted = active.restrict(provenance=provenance())
        closed = restricted.close(provenance=provenance())
        self.assertEqual(active.envelope.state, AccountState.ACTIVE.value)
        self.assertEqual(restricted.envelope.state, AccountState.RESTRICTED.value)
        self.assertEqual(closed.envelope.state, AccountState.CLOSED.value)
        self.assertEqual(closed.envelope.object_version, 4)

    def test_illegal_transitions_fail_closed(self) -> None:
        account = self.build_account()
        with self.assertRaises(CoreValidationError):
            account.restrict(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            account.close(provenance=provenance())
        active = account.activate(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            active.close(provenance=provenance())
        restricted = active.restrict(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            restricted.activate(provenance=provenance())
        closed = restricted.close(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            closed.restrict(provenance=provenance())

    def test_customer_funds_cannot_opt_out_of_safeguarding(self) -> None:
        for segregation in (SegregationClass.CUSTOMER, SegregationClass.MERCHANT_RECEIVABLE, SegregationClass.COLLATERAL):
            with self.assertRaises(CoreValidationError) as ctx:
                Account.create(
                    object_id="value/account/x",
                    asset="USD",
                    scale=2,
                    segregation_class=segregation,
                    owner_id="principal/x",
                    custodian_id="principal/custodian-1",
                    normal_side=EntrySide.CREDIT,
                    enforce_non_negative=False,
                    environment_id=ENV,
                    domain_id=DOMAIN,
                    provenance=provenance(),
                )
            self.assertIn("non-negative", str(ctx.exception))
        self.assertEqual(NON_NEGATIVE_CLASSES, frozenset({SegregationClass.CUSTOMER, SegregationClass.MERCHANT_RECEIVABLE, SegregationClass.COLLATERAL}))

    def test_control_accounts_may_opt_into_safeguarding(self) -> None:
        network = Account.create(
            object_id="value/account/float",
            asset="USD",
            scale=2,
            segregation_class=SegregationClass.NETWORK,
            owner_id="principal/treasury",
            custodian_id="principal/custodian-1",
            normal_side=EntrySide.DEBIT,
            enforce_non_negative=True,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        self.assertTrue(network.payload.enforce_non_negative)
        suspense = Account.create(
            object_id="value/account/suspense-x",
            asset="USD",
            scale=2,
            segregation_class=SegregationClass.SUSPENSE,
            owner_id="principal/treasury",
            custodian_id="principal/custodian-1",
            normal_side=EntrySide.CREDIT,
            enforce_non_negative=False,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        self.assertFalse(suspense.payload.enforce_non_negative)

    def test_payload_validations_fail_closed(self) -> None:
        base = dict(asset="USD", scale=2, segregation_class=SegregationClass.CUSTOMER,
                    owner_id="principal/c", custodian_id="principal/k", normal_side=EntrySide.CREDIT)
        for mutation in (
            {"asset": "US D"}, {"scale": -1}, {"scale": "2"},
            {"segregation_class": "MIXED"}, {"normal_side": "BOTH"},
            {"owner_id": ""}, {"custodian_id": "principal/k", "enforce_non_negative": "yes"},
        ):
            with self.assertRaises(CoreValidationError):
                self.build_account().payload.__class__(**{**base, **mutation})

    def test_ownership_relationships_use_the_core_vocabulary(self) -> None:
        account = self.build_account()
        relationships = account.ownership_relationships()
        self.assertEqual(
            [(rel.relationship_type, rel.subject_id, rel.object_id) for rel in relationships],
            [
                (RelationshipType.OWNS, "principal/customer-1", "value/account/customer-1"),
                (RelationshipType.CUSTODIES, "principal/custodian-1", "value/account/customer-1"),
            ],
        )

    def test_round_trip_and_tamper_rejection(self) -> None:
        account = self.build_account().activate(provenance=provenance())
        encoded = account.to_json()
        self.assertEqual(Account.from_json(encoded), account)
        self.assertEqual(Account.from_json(encoded).to_json(), encoded)
        with self.assertRaises(CoreValidationError):
            Account.from_json(encoded.replace('"owner_id":"principal/customer-1"', '"owner_id":"principal/attacker"'))
        data = re_seal(account.to_dict())
        data["envelope"]["state"] = "FROZEN"
        re_seal(data)
        with self.assertRaises(CoreValidationError):
            Account.from_dict(data)


class ValueInstrumentTests(unittest.TestCase):
    def build_instrument(self) -> ValueInstrument:
        return ValueInstrument.issue(
            object_id="value/instrument/prepaid-1",
            asset="USD",
            scale=2,
            amount=Amount(5000, 2, "USD"),
            issuer_id="principal/treasury",
            holder_id="principal/customer-1",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )

    def test_issue_creates_issued_instrument(self) -> None:
        instrument = self.build_instrument()
        self.assertEqual(instrument.envelope.object_type, INSTRUMENT_OBJECT_TYPE)
        self.assertEqual(instrument.envelope.state, InstrumentState.ISSUED.value)
        self.assertEqual(instrument.payload.amount, Amount(5000, 2, "USD"))
        self.assertEqual(instrument.payload.holder_id, "principal/customer-1")

    def test_transfer_moves_holder_and_advances_version(self) -> None:
        instrument = self.build_instrument()
        transferred = instrument.transfer(new_holder_id="principal/merchant-1", provenance=provenance())
        self.assertEqual(transferred.envelope.object_version, 2)
        self.assertEqual(transferred.envelope.state, InstrumentState.ISSUED.value)
        self.assertEqual(transferred.payload.holder_id, "principal/merchant-1")
        self.assertEqual(instrument.payload.holder_id, "principal/customer-1")
        with self.assertRaises(CoreValidationError):
            transferred.transfer(new_holder_id="principal/merchant-1", provenance=provenance())

    def test_redeem_is_terminal(self) -> None:
        instrument = self.build_instrument()
        redeemed = instrument.redeem(provenance=provenance())
        self.assertEqual(redeemed.envelope.state, InstrumentState.REDEEMED.value)
        with self.assertRaises(CoreValidationError):
            redeemed.redeem(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            redeemed.transfer(new_holder_id="principal/merchant-1", provenance=provenance())

    def test_amounts_must_be_positive_and_consistent(self) -> None:
        for bad in (Amount(0, 2, "USD"), Amount(-500, 2, "USD")):
            with self.assertRaises(CoreValidationError):
                self.build_instrument().payload.__class__(
                    asset="USD", scale=2, amount=bad,
                    issuer_id="principal/treasury", holder_id="principal/customer-1",
                )
        with self.assertRaises(CoreValidationError):
            self.build_instrument().payload.__class__(
                asset="USD", scale=2, amount=Amount(5000, 2, "EUR"),
                issuer_id="principal/treasury", holder_id="principal/customer-1",
            )
        with self.assertRaises(CoreValidationError):
            self.build_instrument().payload.__class__(
                asset="USD", scale=1, amount=Amount(5000, 2, "USD"),
                issuer_id="principal/treasury", holder_id="principal/customer-1",
            )

    def test_relationships_use_issues_and_owns(self) -> None:
        instrument = self.build_instrument()
        pairs = [(rel.relationship_type, rel.subject_id, rel.object_id) for rel in instrument.relationships()]
        self.assertEqual(
            pairs,
            [
                (RelationshipType.ISSUES, "principal/treasury", "value/instrument/prepaid-1"),
                (RelationshipType.OWNS, "principal/customer-1", "value/instrument/prepaid-1"),
            ],
        )

    def test_round_trip_and_tamper_rejection(self) -> None:
        instrument = self.build_instrument()
        encoded = instrument.to_json()
        self.assertEqual(ValueInstrument.from_json(encoded), instrument)
        self.assertEqual(ValueInstrument.from_json(encoded).to_json(), encoded)
        with self.assertRaises(CoreValidationError):
            ValueInstrument.from_json(encoded.replace('"value":5000', '"value":9999'))


class PostingTests(unittest.TestCase):
    def build_posting(self, legs=None) -> Posting:
        if legs is None:
            legs = (
                PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
                PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
            )
        return Posting.build(
            object_id="value/journal/ops-1/p000001",
            journal_id="value/journal/ops-1",
            sequence=1,
            posting_class=PostingClass.EXECUTION,
            legs=legs,
            environment_id=ENV,
            domain_id=DOMAIN,
            description="customer deposit",
            provenance=provenance(),
        )

    def test_balanced_posting_builds_and_reports_asset_totals(self) -> None:
        posting = self.build_posting()
        self.assertEqual(posting.envelope.object_type, POSTING_OBJECT_TYPE)
        self.assertEqual(posting.envelope.state, "POSTED")
        totals = posting.asset_totals()
        self.assertEqual(len(totals), 1)
        self.assertEqual((totals[0].asset, totals[0].scale, totals[0].debit_total, totals[0].credit_total), ("USD", 2, 12500, 12500))
        self.assertTrue(totals[0].balanced)
        self.assertTrue(all(total.balanced for total in totals))

    def test_unbalanced_posting_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError) as ctx:
            self.build_posting(
                legs=(
                    PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE),
                    PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(9000, 2, "USD"), BalanceView.AVAILABLE),
                )
            )
        self.assertIn("must balance per asset", str(ctx.exception))

    def test_multi_asset_posting_balances_each_asset(self) -> None:
        legs = (
            PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE),
            PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE),
            PostingLeg("value/account/liquidity", EntrySide.DEBIT, Amount(9200, 2, "EUR"), BalanceView.AVAILABLE),
            PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(9200, 2, "EUR"), BalanceView.AVAILABLE),
        )
        posting = self.build_posting(legs)
        totals = {total.asset: total for total in posting.asset_totals()}
        self.assertEqual(set(totals), {"USD", "EUR"})
        self.assertTrue(all(total.balanced for total in totals.values()))
        unbalanced = legs[:-1] + (PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(9100, 2, "EUR"), BalanceView.AVAILABLE),)
        with self.assertRaises(CoreValidationError):
            self.build_posting(unbalanced)

    def test_degenerate_legs_fail_closed(self) -> None:
        for legs in (
            (),
            (PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE),),
            (PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(0, 2, "USD"), BalanceView.AVAILABLE),
             PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(0, 2, "USD"), BalanceView.AVAILABLE)),
            (PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(-100, 2, "USD"), BalanceView.AVAILABLE),
             PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(-100, 2, "USD"), BalanceView.AVAILABLE)),
        ):
            with self.assertRaises(CoreValidationError):
                self.build_posting(legs)

    def test_held_view_is_reserved_for_derived_holds(self) -> None:
        with self.assertRaises(CoreValidationError) as ctx:
            self.build_posting(
                legs=(
                    PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(6000, 2, "USD"), BalanceView.HELD),
                    PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(6000, 2, "USD"), BalanceView.HELD),
                )
            )
        self.assertIn("HELD", str(ctx.exception))
        self.assertEqual(
            LEDGER_VIEWS,
            frozenset({BalanceView.AVAILABLE, BalanceView.PENDING, BalanceView.ENCUMBERED, BalanceView.RESTRICTED, BalanceView.SETTLED}),
        )

    def test_unknown_class_view_and_side_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.build_posting().payload.__class__(
                journal_id="value/journal/ops-1", sequence=1, posting_class="MYSTERY",
                legs=(PostingLeg("a/1", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("a/2", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
            )
        with self.assertRaises(CoreValidationError):
            self.build_posting().payload.__class__(
                journal_id="value/journal/ops-1", sequence=1, posting_class=PostingClass.FEE,
                legs=(PostingLeg("a/1", "BOTH", Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("a/2", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
            )
        with self.assertRaises(CoreValidationError):
            self.build_posting().payload.__class__(
                journal_id="value/journal/ops-1", sequence=1, posting_class=PostingClass.FEE,
                legs=(PostingLeg("a/1", EntrySide.DEBIT, Amount(1, 2, "USD"), "FROZEN"),
                      PostingLeg("a/2", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
            )

    def test_source_refs_must_be_unique_identifiers(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.build_posting().payload.__class__(
                journal_id="value/journal/ops-1", sequence=1, posting_class=PostingClass.FEE,
                legs=(PostingLeg("a/1", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("a/2", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
                source_refs=("value/hold/h1", "value/hold/h1"),
            )
        with self.assertRaises(CoreValidationError):
            self.build_posting().payload.__class__(
                journal_id="value/journal/ops-1", sequence=1, posting_class=PostingClass.FEE,
                legs=(PostingLeg("a/1", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("a/2", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
                reverses_posting_id="not an identifier!",
            )

    def test_legs_are_normalized_to_tuples(self) -> None:
        legs = [
            PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
            PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
        ]
        from_list = self.build_posting(legs)
        from_tuple = self.build_posting(tuple(legs))
        self.assertIsInstance(from_list.payload.legs, tuple)
        self.assertEqual(from_list, from_tuple)
        self.assertEqual(from_list.to_json(), from_tuple.to_json())

    def test_ledger_entries_exist_only_at_version_one(self) -> None:
        posting = self.build_posting()
        data = posting.to_dict()
        data["envelope"]["object_version"] = 2
        data["envelope"]["previous_version"] = 1
        re_seal(data)
        with self.assertRaises(CoreValidationError) as ctx:
            Posting.from_dict(data)
        self.assertIn("version 1", str(ctx.exception))

    def test_round_trip_is_lossless_and_byte_stable(self) -> None:
        posting = self.build_posting()
        encoded = posting.to_json()
        self.assertEqual(Posting.from_json(encoded), posting)
        self.assertEqual(Posting.from_json(encoded).to_json(), encoded)

    def test_tampered_payload_and_duplicate_keys_are_rejected(self) -> None:
        posting = self.build_posting()
        with self.assertRaises(CoreValidationError):
            Posting.from_json(posting.to_json().replace('"value":12500', '"value":9'))
        duplicated = posting.to_json().replace('"legs":[', '"legs":[],"legs":[')
        with self.assertRaises(CoreValidationError):
            Posting.from_json(duplicated)

    def test_spliced_payload_is_rejected(self) -> None:
        first = self.build_posting()
        second = Posting.build(
            object_id="value/journal/ops-1/p000002",
            journal_id="value/journal/ops-1",
            sequence=2,
            posting_class=PostingClass.FEE,
            legs=(
                PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(75, 2, "USD"), BalanceView.AVAILABLE),
                PostingLeg("value/account/fee-income", EntrySide.CREDIT, Amount(75, 2, "USD"), BalanceView.AVAILABLE),
            ),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        spliced = first.to_dict()
        spliced["payload"] = second.to_dict()["payload"]
        with self.assertRaises(CoreValidationError):
            Posting.from_dict(spliced)


class HoldTests(unittest.TestCase):
    def build_hold(self, value: int = 6000) -> Hold:
        return Hold.create(
            object_id="value/hold/h1",
            account_id="value/account/customer-1",
            asset="USD",
            amount=Amount(value, 2, "USD"),
            purpose="payment reservation",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )

    def test_create_yields_active_positive_hold(self) -> None:
        hold = self.build_hold()
        self.assertEqual(hold.envelope.object_type, HOLD_OBJECT_TYPE)
        self.assertEqual(hold.envelope.state, HoldState.ACTIVE.value)
        self.assertEqual(hold.payload.amount, Amount(6000, 2, "USD"))
        self.assertEqual(hold.payload.account_id, "value/account/customer-1")
        self.assertEqual(hold.payload.purpose, "payment reservation")

    def test_increase_and_decrease_adjust_amounts_with_versions(self) -> None:
        hold = self.build_hold()
        increased = hold.increase(delta=Amount(500, 2, "USD"), provenance=provenance())
        self.assertEqual(increased.payload.amount, Amount(6500, 2, "USD"))
        self.assertEqual(increased.envelope.object_version, 2)
        decreased = increased.decrease(delta=Amount(1500, 2, "USD"), provenance=provenance())
        self.assertEqual(decreased.payload.amount, Amount(5000, 2, "USD"))
        self.assertEqual(decreased.envelope.state, HoldState.ACTIVE.value)
        with self.assertRaises(CoreValidationError):
            decreased.increase(delta=Amount(0, 2, "USD"), provenance=provenance())
        with self.assertRaises(CoreValidationError):
            decreased.decrease(delta=Amount(5001, 2, "USD"), provenance=provenance())

    def test_partial_and_full_release(self) -> None:
        hold = self.build_hold()
        partial = hold.release(amount=Amount(1500, 2, "USD"), provenance=provenance())
        self.assertEqual(partial.payload.amount, Amount(4500, 2, "USD"))
        self.assertEqual(partial.envelope.state, HoldState.ACTIVE.value)
        full = partial.release(amount=None, provenance=provenance())
        self.assertEqual(full.payload.amount, Amount(0, 2, "USD"))
        self.assertEqual(full.envelope.state, HoldState.RELEASED.value)
        with self.assertRaises(CoreValidationError):
            full.release(amount=None, provenance=provenance())
        with self.assertRaises(CoreValidationError):
            self.build_hold().release(amount=Amount(6001, 2, "USD"), provenance=provenance())

    def test_decrease_to_zero_releases(self) -> None:
        hold = self.build_hold(2000)
        consumed = hold.decrease(delta=Amount(2000, 2, "USD"), provenance=provenance())
        self.assertEqual(consumed.envelope.state, HoldState.RELEASED.value)
        self.assertEqual(consumed.payload.amount, Amount(0, 2, "USD"))

    def test_expire_is_terminal_from_active(self) -> None:
        hold = self.build_hold()
        expired = hold.expire(provenance=provenance())
        self.assertEqual(expired.envelope.state, HoldState.EXPIRED.value)
        self.assertEqual(expired.payload.amount, Amount(0, 2, "USD"))
        with self.assertRaises(CoreValidationError):
            expired.expire(provenance=provenance())
        with self.assertRaises(CoreValidationError):
            expired.decrease(delta=Amount(1, 2, "USD"), provenance=provenance())

    def test_active_holds_hold_positive_value_only(self) -> None:
        hold = self.build_hold()
        data = hold.to_dict()
        data["payload"]["amount"]["value"] = 0
        re_seal(data)
        with self.assertRaises(CoreValidationError):
            Hold.from_dict(data)
        released = hold.release(amount=None, provenance=provenance())
        data = released.to_dict()
        data["payload"]["amount"]["value"] = 5
        re_seal(data)
        with self.assertRaises(CoreValidationError):
            Hold.from_dict(data)

    def test_expires_at_requires_explicit_offset_timestamp(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.build_hold().payload.__class__(
                account_id="value/account/customer-1", asset="USD",
                amount=Amount(6000, 2, "USD"), expires_at="2026-12-31T23:59:59",
            )
        hold = Hold.create(
            object_id="value/hold/h2",
            account_id="value/account/customer-1",
            asset="USD",
            amount=Amount(100, 2, "USD"),
            expires_at="2026-12-31T23:59:59Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        self.assertEqual(hold.payload.expires_at, "2026-12-31T23:59:59Z")

    def test_amount_must_match_declared_asset(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.build_hold().payload.__class__(
                account_id="value/account/customer-1", asset="USD", amount=Amount(6000, 2, "EUR"),
            )

    def test_relationships_reference_the_account(self) -> None:
        hold = self.build_hold()
        pairs = [(rel.relationship_type, rel.subject_id, rel.object_id) for rel in hold.relationships()]
        self.assertEqual(pairs, [(RelationshipType.DEPENDS_ON, "value/hold/h1", "value/account/customer-1")])

    def test_round_trip_and_tamper_rejection(self) -> None:
        hold = self.build_hold()
        encoded = hold.to_json()
        self.assertEqual(Hold.from_json(encoded), hold)
        self.assertEqual(Hold.from_json(encoded).to_json(), encoded)
        with self.assertRaises(CoreValidationError):
            Hold.from_json(encoded.replace('"value":6000', '"value":1'))


class JournalTests(unittest.TestCase):
    def build_journal(self) -> Journal:
        return Journal.open(
            object_id="value/journal/ops-1",
            custodian_id="principal/custodian-1",
            description="operations journal",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )

    def test_open_yields_active_journal(self) -> None:
        journal = self.build_journal()
        self.assertEqual(journal.envelope.object_type, JOURNAL_OBJECT_TYPE)
        self.assertEqual(journal.envelope.state, JournalState.ACTIVE.value)
        self.assertEqual(journal.payload.custodian_id, "principal/custodian-1")

    def test_reconcile_advances_state_and_can_re_reconcile(self) -> None:
        journal = self.build_journal()
        reconciled = journal.reconcile(provenance=provenance())
        self.assertEqual(reconciled.envelope.state, JournalState.RECONCILED.value)
        self.assertEqual(reconciled.envelope.object_version, 2)
        again = reconciled.reconcile(provenance=provenance())
        self.assertEqual(again.envelope.state, JournalState.RECONCILED.value)
        self.assertEqual(again.envelope.object_version, 3)

    def test_round_trip_and_tamper_rejection(self) -> None:
        journal = self.build_journal()
        encoded = journal.to_json()
        self.assertEqual(Journal.from_json(encoded), journal)
        self.assertEqual(Journal.from_json(encoded).to_json(), encoded)
        with self.assertRaises(CoreValidationError):
            Journal.from_json(encoded.replace('"description":"operations journal"', '"description":"evil"'))


class BalanceTests(unittest.TestCase):
    def derive(self, **overrides) -> Balance:
        fields = dict(
            account_id="value/account/customer-1",
            asset="USD",
            scale=2,
            as_of_ordinal=4,
            available=6500,
            pending=0,
            encumbered=6000,
            restricted=0,
            settled=0,
            held=6000,
        )
        fields.update(overrides)
        return Balance.derive(**fields)

    def test_derivation_computes_total_and_hash(self) -> None:
        balance = self.derive()
        self.assertEqual(balance.total, 12500)
        self.assertEqual(balance.account_id, "value/account/customer-1")
        self.assertEqual(len(balance.derivation_hash), 64)
        self.assertEqual(balance.derivation_hash, self.derive().derivation_hash)

    def test_view_value_accessor_covers_all_six_views(self) -> None:
        balance = self.derive()
        self.assertEqual(balance.view_value(BalanceView.AVAILABLE), 6500)
        self.assertEqual(balance.view_value(BalanceView.ENCUMBERED), 6000)
        self.assertEqual(balance.view_value(BalanceView.HELD), 6000)
        self.assertEqual(balance.view_value(BalanceView.PENDING), 0)
        self.assertEqual(balance.view_value(BalanceView.RESTRICTED), 0)
        self.assertEqual(balance.view_value(BalanceView.SETTLED), 0)

    def test_conservation_is_enforced_at_construction(self) -> None:
        # total must equal the five ledger views exactly; a total that
        # disagrees with the views (e.g. a stale projection) fails closed
        with self.assertRaises(CoreValidationError) as ctx:
            Balance(
                account_id="value/account/customer-1",
                as_of_ordinal=4,
                asset="USD",
                scale=2,
                available=7000,
                pending=0,
                encumbered=6000,
                restricted=0,
                settled=0,
                held=6000,
                total=12500,
                derivation_hash="0" * 64,
            )
        self.assertIn("conservation", str(ctx.exception))

    def test_held_may_diverge_from_encumbered_mid_flight(self) -> None:
        balance = self.derive(held=9000, encumbered=2000, available=10500)
        self.assertEqual(balance.total, 12500)
        self.assertEqual(balance.view_value(BalanceView.HELD), 9000)

    def test_round_trip_is_lossless_and_tamper_evident(self) -> None:
        balance = self.derive()
        encoded = balance.to_json()
        self.assertEqual(Balance.from_json(encoded), balance)
        self.assertEqual(Balance.from_json(encoded).to_json(), encoded)
        tampered = balance.to_dict()
        tampered["available"] = 9999
        with self.assertRaises(CoreValidationError):
            Balance.from_dict(tampered)

    def test_object_type_is_declared_for_the_derived_projection(self) -> None:
        self.assertEqual(self.derive().to_dict()["object_type"], BALANCE_OBJECT_TYPE)


class ReconciliationTests(unittest.TestCase):
    def test_totals_and_holds_are_dataclasses_with_derived_flags(self) -> None:
        totals = AssetTotals(asset="USD", scale=2, debit_total=100, credit_total=100)
        self.assertTrue(totals.balanced)
        self.assertFalse(AssetTotals(asset="USD", scale=2, debit_total=100, credit_total=99).balanced)
        holds = AccountHolds(account_id="value/account/customer-1", held=10, encumbered=10)
        self.assertTrue(holds.ok)
        self.assertFalse(AccountHolds(account_id="value/account/customer-1", held=10, encumbered=9).ok)
        sheet = AssetSheet(asset="USD", scale=2, debit_normal_total=100, credit_normal_total=100)
        self.assertTrue(sheet.balanced)

    def test_balanced_reconciliation_round_trips(self) -> None:
        reconciliation = Reconciliation.build(
            object_id="value/journal/ops-1/r000004",
            journal_id="value/journal/ops-1",
            as_of_ordinal=4,
            trial_balance=(AssetTotals(asset="USD", scale=2, debit_total=24500, credit_total=24500),),
            account_holds=(AccountHolds(account_id="value/account/customer-1", held=0, encumbered=0),),
            asset_sheets=(AssetSheet(asset="USD", scale=2, debit_normal_total=12500, credit_normal_total=12500),),
            discrepancies=(),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        self.assertEqual(reconciliation.envelope.state, ReconciliationState.BALANCED.value)
        encoded = reconciliation.to_json()
        self.assertEqual(Reconciliation.from_json(encoded), reconciliation)
        self.assertEqual(Reconciliation.from_json(encoded).to_json(), encoded)

    def test_discrepancies_force_discrepancy_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            Reconciliation.build(
                object_id="value/journal/ops-1/r000004",
                journal_id="value/journal/ops-1",
                as_of_ordinal=4,
                trial_balance=(AssetTotals(asset="USD", scale=2, debit_total=100, credit_total=99),),
                account_holds=(),
                asset_sheets=(),
                discrepancies=(),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=provenance(),
            )
        reconciliation = Reconciliation.build(
            object_id="value/journal/ops-1/r000004",
            journal_id="value/journal/ops-1",
            as_of_ordinal=4,
            trial_balance=(AssetTotals(asset="USD", scale=2, debit_total=100, credit_total=99),),
            account_holds=(AccountHolds(account_id="value/account/customer-1", held=60, encumbered=20),),
            asset_sheets=(AssetSheet(asset="USD", scale=2, debit_normal_total=100, credit_normal_total=100),),
            discrepancies=(
                "asset USD journal trial balance is off by 1",
                "account value/account/customer-1 held 60 != encumbered 20",
            ),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        self.assertEqual(reconciliation.envelope.state, ReconciliationState.DISCREPANCY.value)

    def test_tamper_rejection(self) -> None:
        reconciliation = Reconciliation.build(
            object_id="value/journal/ops-1/r000004",
            journal_id="value/journal/ops-1",
            as_of_ordinal=4,
            trial_balance=(AssetTotals(asset="USD", scale=2, debit_total=100, credit_total=100),),
            account_holds=(),
            asset_sheets=(),
            discrepancies=(),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError):
            Reconciliation.from_json(reconciliation.to_json().replace('"debit_total":100', '"debit_total":101'))


class LedgerAssetAndAccountTests(unittest.TestCase):
    def test_duplicate_asset_codes_and_ids_are_rejected(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.register_asset(
                object_id="value/asset/usd-copy", code="USD", scale=2,
                kind=AssetKind.FIAT, issuer_id="principal/treasury", provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.register_asset(
                object_id="value/asset/usd", code="EUR", scale=2,
                kind=AssetKind.FIAT, issuer_id="principal/treasury", provenance=provenance(),
            )

    def test_unknown_asset_operations_fail_closed(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.activate_asset(object_id="value/asset/missing", provenance=provenance())
        self.assertEqual(ledger.get_asset("USD").envelope.state, AssetState.ACTIVE.value)

    def test_account_creation_validates_asset_state_and_scale(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.create_account(
                object_id="value/account/bad", asset_code="EUR", segregation_class=SegregationClass.NETWORK,
                owner_id="principal/treasury", custodian_id="principal/custodian-1",
                normal_side=EntrySide.DEBIT, provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.create_account(
                object_id="value/account/bad", asset_code="USD", scale=3,
                segregation_class=SegregationClass.NETWORK,
                owner_id="principal/treasury", custodian_id="principal/custodian-1",
                normal_side=EntrySide.DEBIT, provenance=provenance(),
            )
        suspended = ledger.get_asset("USD").suspend(provenance=provenance())
        ledger._assets["value/asset/usd"] = suspended
        with self.assertRaises(CoreValidationError):
            ledger.create_account(
                object_id="value/account/bad", asset_code="USD",
                segregation_class=SegregationClass.NETWORK,
                owner_id="principal/treasury", custodian_id="principal/custodian-1",
                normal_side=EntrySide.DEBIT, provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.create_account(
                object_id="value/account/customer-1", asset_code="USD",
                segregation_class=SegregationClass.CUSTOMER,
                owner_id="principal/customer-1", custodian_id="principal/custodian-1",
                normal_side=EntrySide.CREDIT, provenance=provenance(),
            )

    def test_duplicate_account_ids_are_rejected(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.create_account(
                object_id="value/account/customer-1", asset_code="USD",
                segregation_class=SegregationClass.CUSTOMER,
                owner_id="principal/customer-1", custodian_id="principal/custodian-1",
                normal_side=EntrySide.CREDIT, provenance=provenance(),
            )

    def test_close_requires_restriction_zero_balance_and_no_holds(self) -> None:
        ledger = make_ledger()
        ledger.create_account(
            object_id="value/account/zero", asset_code="USD",
            segregation_class=SegregationClass.NETWORK,
            owner_id="principal/treasury", custodian_id="principal/custodian-1",
            normal_side=EntrySide.DEBIT, provenance=provenance(),
        )
        ledger.activate_account(object_id="value/account/zero", provenance=provenance())
        ledger.restrict_account(object_id="value/account/zero", provenance=provenance())
        closed = ledger.close_account(object_id="value/account/zero", provenance=provenance())
        self.assertEqual(closed.envelope.state, AccountState.CLOSED.value)

        deposit(ledger)
        ledger.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.close_account(object_id="value/account/customer-1", provenance=provenance())
        self.assertIn("non-zero", str(ctx.exception))

        ledger2 = make_ledger()
        deposit(ledger2)
        ledger2.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        ledger2.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        with self.assertRaises(CoreValidationError) as ctx:
            ledger2.close_account(object_id="value/account/customer-1", provenance=provenance())
        self.assertIn("active hold", str(ctx.exception))


class LedgerPostingTests(unittest.TestCase):
    def test_posting_ids_are_deterministic_and_sequential(self) -> None:
        ledger = make_ledger()
        first = deposit(ledger)
        self.assertEqual(first.envelope.object_id, "value/journal/ops-1/p000001")
        second = deposit(ledger, value=100)
        self.assertEqual(second.envelope.object_id, "value/journal/ops-1/p000002")
        self.assertEqual(len(ledger.journal_postings("value/journal/ops-1")), 2)

    def test_posting_requires_active_journal_and_active_accounts(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.post(
                journal_id="value/journal/missing", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        self.assertIn("journal", str(ctx.exception))

        with self.assertRaises(CoreValidationError) as ctx:
            ledger.post(
                journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/missing", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        self.assertIn("unknown", str(ctx.exception).lower())

        ledger.create_account(
            object_id="value/account/dormant", asset_code="USD",
            segregation_class=SegregationClass.NETWORK,
            owner_id="principal/treasury", custodian_id="principal/custodian-1",
            normal_side=EntrySide.DEBIT, provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.post(
                journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/dormant", EntrySide.DEBIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(1, 2, "USD"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        self.assertIn("ACTIVE", str(ctx.exception))

    def test_posting_to_restricted_account_and_reconciled_journal_fails_closed(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        with self.assertRaises(CoreValidationError) as ctx:
            deposit(ledger, value=100)
        self.assertIn("ACTIVE", str(ctx.exception))
        ledger2 = make_ledger()
        deposit(ledger2)
        ledger2.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        with self.assertRaises(CoreValidationError) as ctx:
            deposit(ledger2, value=100)
        self.assertIn("ACTIVE", str(ctx.exception))

    def test_posting_rejects_foreign_asset_and_scale_mismatch(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.post(
                journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(1, 2, "EUR"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(1, 2, "EUR"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.post(
                journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/cash-vault", EntrySide.DEBIT, Amount(1, 1, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(1, 1, "USD"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        self.assertIn("scale", str(ctx.exception))

    def test_suspended_asset_blocks_postings(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.suspend_asset(object_id="value/asset/usd", provenance=provenance())
        with self.assertRaises(CoreValidationError) as ctx:
            deposit(ledger, value=100)
        self.assertIn("asset", str(ctx.exception))

    def test_customer_overdraft_is_rejected_but_control_accounts_may_swing(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.post(
                journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
                legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(13000, 2, "USD"), BalanceView.AVAILABLE),
                      PostingLeg("value/account/merchant-1", EntrySide.CREDIT, Amount(13000, 2, "USD"), BalanceView.AVAILABLE)),
                provenance=provenance(),
            )
        self.assertIn("negative", str(ctx.exception))
        swing = ledger.post(
            journal_id="value/journal/ops-1", posting_class=PostingClass.ADJUSTMENT,
            legs=(PostingLeg("value/account/suspense-1", EntrySide.DEBIT, Amount(3000, 2, "USD"), BalanceView.AVAILABLE),
                  PostingLeg("value/account/cash-vault", EntrySide.CREDIT, Amount(3000, 2, "USD"), BalanceView.AVAILABLE)),
            provenance=provenance(),
        )
        self.assertEqual(swing.payload.posting_class, PostingClass.ADJUSTMENT)

    def test_reverse_posting_mirrors_legs_exactly_once(self) -> None:
        ledger = make_ledger()
        original = deposit(ledger)
        reversal = ledger.reverse_posting(
            journal_id="value/journal/ops-1", posting_id="value/journal/ops-1/p000001",
            description="reversal of erroneous deposit", provenance=provenance(),
        )
        self.assertEqual(reversal.payload.posting_class, PostingClass.REVERSAL)
        self.assertEqual(reversal.payload.reverses_posting_id, "value/journal/ops-1/p000001")
        mirrored = [
            (leg.account_id, leg.side, leg.amount, leg.view)
            for leg in (
                PostingLeg("value/account/cash-vault", EntrySide.CREDIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
                PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(12500, 2, "USD"), BalanceView.AVAILABLE),
            )
        ]
        self.assertEqual([(leg.account_id, leg.side, leg.amount, leg.view) for leg in reversal.payload.legs], mirrored)
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.available, 0)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.reverse_posting(
                journal_id="value/journal/ops-1", posting_id="value/journal/ops-1/p000001",
                provenance=provenance(),
            )
        self.assertIn("already reversed", str(ctx.exception))
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.reverse_posting(
                journal_id="value/journal/ops-1", posting_id=reversal.envelope.object_id,
                provenance=provenance(),
            )
        self.assertIn("reversal", str(ctx.exception))

    def test_reversal_that_would_overdraft_fails_closed(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.post(
            journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
            legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE),
                  PostingLeg("value/account/merchant-1", EntrySide.CREDIT, Amount(10000, 2, "USD"), BalanceView.AVAILABLE)),
            provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError):
            ledger.reverse_posting(
                journal_id="value/journal/ops-1", posting_id="value/journal/ops-1/p000001",
                provenance=provenance(),
            )

    def test_adjust_posts_explicit_adjustment_class(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        adjustment = ledger.adjust(
            journal_id="value/journal/ops-1",
            legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(5000, 2, "USD"), BalanceView.SETTLED),
                  PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(5000, 2, "USD"), BalanceView.AVAILABLE)),
            description="settled value released to available",
            provenance=provenance(),
        )
        self.assertEqual(adjustment.payload.posting_class, PostingClass.ADJUSTMENT)
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.settled, -5000)
        self.assertEqual(balance.available, 17500)
        self.assertEqual(balance.total, 12500)


class LedgerHoldTests(unittest.TestCase):
    def test_hold_create_posts_encumbrance_and_reduces_available(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        hold = ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            purpose="payment reservation", provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.ACTIVE.value)
        encumbrance = ledger.journal_postings("value/journal/ops-1")[1]
        self.assertEqual(encumbrance.payload.posting_class, PostingClass.HOLD)
        self.assertEqual(encumbrance.payload.source_refs, ("value/hold/h1",))
        self.assertEqual(
            [(leg.account_id, leg.side, leg.amount.value, leg.view) for leg in encumbrance.payload.legs],
            [
                ("value/account/customer-1", EntrySide.DEBIT, 6000, BalanceView.AVAILABLE),
                ("value/account/customer-1", EntrySide.CREDIT, 6000, BalanceView.ENCUMBERED),
            ],
        )
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.available, 6500)
        self.assertEqual(balance.encumbered, 6000)
        self.assertEqual(balance.held, 6000)
        self.assertEqual(balance.total, 12500)

    def test_reservation_safety_rejects_unbacked_holds(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(12501, 2, "USD"),
                provenance=provenance(),
            )
        self.assertIn("reservation", str(ctx.exception))
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError):
            ledger.hold_increase(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                delta=Amount(6501, 2, "USD"), provenance=provenance(),
            )

    def test_hold_create_validations_fail_closed(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        with self.assertRaises(CoreValidationError):
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/missing", amount=Amount(6000, 2, "USD"),
                provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(0, 2, "USD"),
                provenance=provenance(),
            )
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError):
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(1, 2, "USD"),
                provenance=provenance(),
            )
        ledger.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        with self.assertRaises(CoreValidationError):
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h2",
                account_id="value/account/customer-1", amount=Amount(1, 2, "USD"),
                provenance=provenance(),
            )

    def test_release_expire_and_decrease_keep_held_equal_to_encumbered(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        ledger.hold_increase(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            delta=Amount(500, 2, "USD"), provenance=provenance(),
        )
        hold = ledger.hold_release(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            amount=Amount(1500, 2, "USD"), provenance=provenance(),
        )
        self.assertEqual(hold.payload.amount, Amount(5000, 2, "USD"))
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.held, 5000)
        self.assertEqual(balance.encumbered, 5000)
        self.assertEqual(balance.available, 7500)

        ledger.post(
            journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
            legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(3000, 2, "USD"), BalanceView.ENCUMBERED),
                  PostingLeg("value/account/merchant-1", EntrySide.CREDIT, Amount(3000, 2, "USD"), BalanceView.AVAILABLE)),
            provenance=provenance(),
        )
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.encumbered, 2000)
        self.assertEqual(balance.held, 5000)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_release(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                amount=Amount(3000, 2, "USD"), provenance=provenance(),
            )
        self.assertIn("encumbered view", str(ctx.exception))
        hold = ledger.hold_decrease(
            hold_id="value/hold/h1", delta=Amount(3000, 2, "USD"), provenance=provenance(),
        )
        self.assertEqual(hold.payload.amount, Amount(2000, 2, "USD"))
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual(balance.held, 2000)
        self.assertEqual(balance.encumbered, 2000)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_decrease(
                hold_id="value/hold/h1", delta=Amount(2001, 2, "USD"), provenance=provenance(),
            )
        self.assertIn("encumbered view", str(ctx.exception))
        hold = ledger.hold_release(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1", provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.RELEASED.value)
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (0, 0, 9500))

    def test_hold_expire_releases_encumbered_value(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(2000, 2, "USD"),
            expires_at="2026-12-31T23:59:59Z", provenance=provenance(),
        )
        hold = ledger.hold_expire(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1", provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.EXPIRED.value)
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (0, 0, 12500))

    def test_hold_ops_on_debit_normal_account_mirror_directions(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        hold = ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/vault-1",
            account_id="value/account/cash-vault", amount=Amount(3000, 2, "USD"),
            provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.ACTIVE.value)
        encumbrance = ledger.journal_postings("value/journal/ops-1")[1]
        self.assertEqual(
            [(leg.side, leg.view) for leg in encumbrance.payload.legs],
            [(EntrySide.CREDIT, BalanceView.AVAILABLE), (EntrySide.DEBIT, BalanceView.ENCUMBERED)],
        )
        balance = ledger.derive_balances(account_id="value/account/cash-vault")
        self.assertEqual((balance.available, balance.encumbered, balance.held), (9500, 3000, 3000))
        ledger.hold_expire(
            journal_id="value/journal/ops-1", hold_id="value/hold/vault-1", provenance=provenance(),
        )
        balance = ledger.derive_balances(account_id="value/account/cash-vault")
        self.assertEqual((balance.available, balance.encumbered, balance.held), (12500, 0, 0))

    def test_hold_release_on_restricted_account_is_the_exception_path(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        ledger.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        hold = ledger.hold_release(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1", provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.RELEASED.value)
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (0, 0, 12500))


class LedgerHoldPostingAtomicityTests(unittest.TestCase):
    """WORK-005 correction regressions: hold mutations are atomic with their
    coupled encumbrance postings.

    ``hold_create``, ``hold_increase``, ``hold_release`` and ``hold_expire``
    each publish an advanced hold projection and post the coupled
    AVAILABLE<->ENCUMBERED movement. The posting must be fully recorded
    BEFORE the advanced hold is published: when the coupled posting fails
    after the hold transition was prepared (missing journal, sealed
    RECONCILED journal, or a posting-guard failure such as a suspended
    asset), the authoritative hold projection must remain at its exact
    prior state, no posting may be added, and the whole-ledger canonical
    state and digest must be unchanged.
    """

    def _snapshot(self, ledger: ValueLedger) -> tuple[str, str]:
        return ledger.state_digest(), canonical_json(ledger.canonical_state())

    def _assert_unchanged(self, ledger: ValueLedger, snapshot: tuple[str, str]) -> None:
        digest, state = snapshot
        self.assertEqual(ledger.state_digest(), digest)
        self.assertEqual(canonical_json(ledger.canonical_state()), state)

    def _hold_projection(self, ledger: ValueLedger, hold_id: str) -> dict:
        for hold in ledger.canonical_state()["holds"]:
            if hold["envelope"]["object_id"] == hold_id:
                return hold
        self.fail(f"hold {hold_id} is not registered in the ledger projection")

    def _assert_prior_hold(
        self, ledger: ValueLedger, hold_id: str, amount: int, state: str, version: int
    ) -> None:
        hold = self._hold_projection(ledger, hold_id)
        self.assertEqual(hold["payload"]["amount"]["value"], amount)
        self.assertEqual(hold["envelope"]["state"], state)
        self.assertEqual(hold["envelope"]["object_version"], version)

    def _open_second_journal(self, ledger: ValueLedger) -> None:
        ledger.open_journal(
            object_id="value/journal/ops-2",
            custodian_id="principal/custodian-1",
            description="secondary operations journal",
            provenance=provenance(),
        )

    def _seed_hold(self, ledger: ValueLedger) -> None:
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )

    def test_failed_hold_create_publishes_no_hold_and_no_posting(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        self._open_second_journal(ledger)

        # missing journal: the coupled posting fails at the journal lookup,
        # after the hold transition was fully prepared
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_create(
                journal_id="value/journal/missing", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
                provenance=provenance(),
            )
        self.assertIn("unknown journal", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self.assertEqual(ledger.canonical_state()["holds"], [])

        # sealed journal: the coupled posting fails at the ACTIVE-journal guard
        ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
                provenance=provenance(),
            )
        self.assertIn("RECONCILED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self.assertEqual(ledger.canonical_state()["holds"], [])

        # suspended asset: the coupled posting fails inside the posting guards
        ledger.suspend_asset(object_id="value/asset/usd", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_create(
                journal_id="value/journal/ops-2", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
                provenance=provenance(),
            )
        self.assertIn("SUSPENDED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self.assertEqual(ledger.canonical_state()["holds"], [])
        self.assertEqual(ledger.journal_postings("value/journal/ops-2"), ())

        # recovery: the failed attempts left no residual registration, so the
        # same hold id creates cleanly with exactly one encumbrance posting
        ledger.activate_asset(object_id="value/asset/usd", provenance=provenance())
        hold = ledger.hold_create(
            journal_id="value/journal/ops-2", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        self.assertEqual(hold.envelope.state, HoldState.ACTIVE.value)
        postings = ledger.journal_postings("value/journal/ops-2")
        self.assertEqual([p.payload.posting_class for p in postings], [PostingClass.HOLD])
        self.assertEqual(postings[0].payload.source_refs, ("value/hold/h1",))

    def test_failed_hold_increase_leaves_the_prior_hold_and_no_posting(self) -> None:
        ledger = make_ledger()
        self._seed_hold(ledger)
        self._open_second_journal(ledger)
        baseline = len(ledger.journal_postings("value/journal/ops-1"))
        self.assertEqual(baseline, 2)

        # sealed journal: the increase posting fails after it was prepared
        ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_increase(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                delta=Amount(500, 2, "USD"), provenance=provenance(),
            )
        self.assertIn("RECONCILED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(len(ledger.journal_postings("value/journal/ops-1")), baseline)

        # suspended asset: posting-guard failure after the increase was prepared
        ledger.suspend_asset(object_id="value/asset/usd", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_increase(
                journal_id="value/journal/ops-2", hold_id="value/hold/h1",
                delta=Amount(500, 2, "USD"), provenance=provenance(),
            )
        self.assertIn("SUSPENDED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(ledger.journal_postings("value/journal/ops-2"), ())

        # recovery: the untouched hold increases cleanly on a working journal
        ledger.activate_asset(object_id="value/asset/usd", provenance=provenance())
        advanced = ledger.hold_increase(
            journal_id="value/journal/ops-2", hold_id="value/hold/h1",
            delta=Amount(500, 2, "USD"), provenance=provenance(),
        )
        self.assertEqual(advanced.payload.amount, Amount(6500, 2, "USD"))
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (6500, 6500, 6000))

    def test_failed_hold_release_leaves_the_prior_hold_and_no_posting(self) -> None:
        ledger = make_ledger()
        self._seed_hold(ledger)
        self._open_second_journal(ledger)
        baseline = len(ledger.journal_postings("value/journal/ops-1"))
        self.assertEqual(baseline, 2)

        # sealed journal: the partial-release posting fails after it was prepared
        ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_release(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                amount=Amount(1500, 2, "USD"), provenance=provenance(),
            )
        self.assertIn("RECONCILED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(len(ledger.journal_postings("value/journal/ops-1")), baseline)

        # suspended asset: the full-release posting fails inside the guards
        ledger.suspend_asset(object_id="value/asset/usd", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_release(
                journal_id="value/journal/ops-2", hold_id="value/hold/h1",
                provenance=provenance(),
            )
        self.assertIn("SUSPENDED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(ledger.journal_postings("value/journal/ops-2"), ())

        # recovery: partial release still works and keeps held == encumbered
        ledger.activate_asset(object_id="value/asset/usd", provenance=provenance())
        released = ledger.hold_release(
            journal_id="value/journal/ops-2", hold_id="value/hold/h1",
            amount=Amount(1500, 2, "USD"), provenance=provenance(),
        )
        self.assertEqual(released.envelope.state, HoldState.ACTIVE.value)
        self.assertEqual(released.payload.amount, Amount(4500, 2, "USD"))
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (4500, 4500, 8000))

    def test_failed_hold_expire_leaves_the_prior_hold_and_no_posting(self) -> None:
        ledger = make_ledger()
        self._seed_hold(ledger)
        self._open_second_journal(ledger)
        baseline = len(ledger.journal_postings("value/journal/ops-1"))
        self.assertEqual(baseline, 2)

        # sealed journal: the expiry release posting fails after it was prepared
        ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_expire(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                provenance=provenance(),
            )
        self.assertIn("RECONCILED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(len(ledger.journal_postings("value/journal/ops-1")), baseline)

        # suspended asset: posting-guard failure after expiry was prepared
        ledger.suspend_asset(object_id="value/asset/usd", provenance=provenance())
        snapshot = self._snapshot(ledger)
        with self.assertRaises(CoreValidationError) as ctx:
            ledger.hold_expire(
                journal_id="value/journal/ops-2", hold_id="value/hold/h1",
                provenance=provenance(),
            )
        self.assertIn("SUSPENDED", str(ctx.exception))
        self._assert_unchanged(ledger, snapshot)
        self._assert_prior_hold(ledger, "value/hold/h1", 6000, HoldState.ACTIVE.value, 1)
        self.assertEqual(ledger.journal_postings("value/journal/ops-2"), ())

        # recovery: expiry still works and returns the encumbered value
        ledger.activate_asset(object_id="value/asset/usd", provenance=provenance())
        expired = ledger.hold_expire(
            journal_id="value/journal/ops-2", hold_id="value/hold/h1",
            provenance=provenance(),
        )
        self.assertEqual(expired.envelope.state, HoldState.EXPIRED.value)
        self.assertEqual(expired.payload.amount, Amount(0, 2, "USD"))
        balance = ledger.derive_balances(account_id="value/account/customer-1")
        self.assertEqual((balance.held, balance.encumbered, balance.available), (0, 0, 12500))


class LedgerInstrumentAndFundingTests(unittest.TestCase):
    def test_instrument_lifecycle_via_ledger(self) -> None:
        ledger = make_ledger()
        instrument = ledger.issue_instrument(
            object_id="value/instrument/prepaid-1", asset_code="USD",
            amount=Amount(5000, 2, "USD"), issuer_id="principal/treasury",
            holder_id="principal/customer-1", provenance=provenance(),
        )
        self.assertEqual(instrument.envelope.state, InstrumentState.ISSUED.value)
        transferred = ledger.transfer_instrument(
            object_id="value/instrument/prepaid-1", new_holder_id="principal/merchant-1",
            provenance=provenance(),
        )
        self.assertEqual(transferred.payload.holder_id, "principal/merchant-1")
        redeemed = ledger.redeem_instrument(
            object_id="value/instrument/prepaid-1", provenance=provenance(),
        )
        self.assertEqual(redeemed.envelope.state, InstrumentState.REDEEMED.value)
        with self.assertRaises(CoreValidationError):
            ledger.issue_instrument(
                object_id="value/instrument/prepaid-1", asset_code="USD",
                amount=Amount(5000, 2, "USD"), issuer_id="principal/treasury",
                holder_id="principal/customer-1", provenance=provenance(),
            )
        ledger.register_asset(
            object_id="value/asset/eur", code="EUR", scale=2,
            kind=AssetKind.FIAT, issuer_id="principal/treasury", provenance=provenance(),
        )
        with self.assertRaises(CoreValidationError):
            ledger.issue_instrument(
                object_id="value/instrument/euro-1", asset_code="EUR",
                amount=Amount(5000, 2, "EUR"), issuer_id="principal/treasury",
                holder_id="principal/customer-1", provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.issue_instrument(
                object_id="value/instrument/bad-scale", asset_code="USD",
                amount=Amount(5000, 1, "USD"), issuer_id="principal/treasury",
                holder_id="principal/customer-1", provenance=provenance(),
            )

    def test_funding_source_requires_active_matching_account(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        source = ledger.create_funding_source(
            object_id="value/funding-source/fs-1", account_id="value/account/customer-1",
            cap=Amount(2500, 2, "USD"), provenance=provenance(),
        )
        self.assertEqual(source.envelope.state, FundingSourceState.ACTIVE.value)
        self.assertEqual(source.payload.cap, Amount(2500, 2, "USD"))
        with self.assertRaises(CoreValidationError):
            ledger.create_funding_source(
                object_id="value/funding-source/fs-2", account_id="value/account/customer-1",
                cap=Amount(2500, 2, "EUR"), provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            ledger.create_funding_source(
                object_id="value/funding-source/fs-3", account_id="value/account/missing",
                cap=Amount(2500, 2, "USD"), provenance=provenance(),
            )
        retired = ledger.retire_funding_source(object_id="value/funding-source/fs-1", provenance=provenance())
        self.assertEqual(retired.envelope.state, FundingSourceState.RETIRED.value)
        with self.assertRaises(CoreValidationError):
            ledger.retire_funding_source(object_id="value/funding-source/fs-1", provenance=provenance())
        ledger.restrict_account(object_id="value/account/customer-1", provenance=provenance())
        with self.assertRaises(CoreValidationError):
            ledger.create_funding_source(
                object_id="value/funding-source/fs-4", account_id="value/account/customer-1",
                cap=Amount(2500, 2, "USD"), provenance=provenance(),
            )

    def test_funding_source_round_trips_and_references_account(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        source = ledger.create_funding_source(
            object_id="value/funding-source/fs-1", account_id="value/account/customer-1",
            cap=Amount(2500, 2, "USD"), provenance=provenance(),
        )
        encoded = source.to_json()
        self.assertEqual(FundingSource.from_json(encoded), source)
        self.assertEqual(FundingSource.from_json(encoded).to_json(), encoded)
        self.assertEqual(source.envelope.object_type, FUNDING_SOURCE_OBJECT_TYPE)
        pairs = [(rel.relationship_type, rel.subject_id, rel.object_id) for rel in source.relationships()]
        self.assertEqual(pairs, [(RelationshipType.DEPENDS_ON, "value/funding-source/fs-1", "value/account/customer-1")])
        with self.assertRaises(CoreValidationError):
            FundingSource.from_json(encoded.replace('"value":2500', '"value":9'))


class LedgerReconciliationTests(unittest.TestCase):
    def test_reconcile_produces_balanced_evidence_and_seals_journal(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        ledger.hold_release(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1", provenance=provenance(),
        )
        reconciliation = ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        self.assertEqual(reconciliation.envelope.state, ReconciliationState.BALANCED.value)
        self.assertEqual(reconciliation.payload.journal_id, "value/journal/ops-1")
        self.assertEqual(reconciliation.payload.discrepancies, ())
        totals = {total.asset: total for total in reconciliation.payload.trial_balance}
        self.assertEqual((totals["USD"].debit_total, totals["USD"].credit_total), (24500, 24500))
        sheets = {sheet.asset: sheet for sheet in reconciliation.payload.asset_sheets}
        self.assertEqual((sheets["USD"].debit_normal_total, sheets["USD"].credit_normal_total), (12500, 12500))
        holds = {entry.account_id: entry for entry in reconciliation.payload.account_holds}
        self.assertEqual((holds["value/account/customer-1"].held, holds["value/account/customer-1"].encumbered), (0, 0))
        journal = ledger.get_journal("value/journal/ops-1")
        self.assertEqual(journal.envelope.state, JournalState.RECONCILED.value)
        again = ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        self.assertEqual(again.envelope.object_version, 2)

    def test_reconcile_detects_hold_divergence_as_discrepancy(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.hold_create(
            journal_id="value/journal/ops-1", hold_id="value/hold/h1",
            account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
            provenance=provenance(),
        )
        ledger.post(
            journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
            legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(4000, 2, "USD"), BalanceView.ENCUMBERED),
                  PostingLeg("value/account/merchant-1", EntrySide.CREDIT, Amount(4000, 2, "USD"), BalanceView.AVAILABLE)),
            provenance=provenance(),
        )
        reconciliation = ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        self.assertEqual(reconciliation.envelope.state, ReconciliationState.DISCREPANCY.value)
        self.assertTrue(reconciliation.payload.discrepancies)
        self.assertTrue(any("held" in item for item in reconciliation.payload.discrepancies))
        encoded = reconciliation.to_json()
        self.assertEqual(Reconciliation.from_json(encoded), reconciliation)

    def test_suspense_lifecycle_through_pending_and_resolution(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        ledger.post(
            journal_id="value/journal/ops-1", posting_class=PostingClass.EXECUTION,
            legs=(PostingLeg("value/account/customer-1", EntrySide.DEBIT, Amount(500, 2, "USD"), BalanceView.AVAILABLE),
                  PostingLeg("value/account/suspense-1", EntrySide.CREDIT, Amount(500, 2, "USD"), BalanceView.PENDING)),
            description="uncertain external outcome parked in suspense",
            provenance=provenance(),
        )
        suspense = ledger.derive_balances(account_id="value/account/suspense-1")
        self.assertEqual(suspense.pending, 500)
        ledger.adjust(
            journal_id="value/journal/ops-1",
            legs=(PostingLeg("value/account/suspense-1", EntrySide.DEBIT, Amount(500, 2, "USD"), BalanceView.PENDING),
                  PostingLeg("value/account/customer-1", EntrySide.CREDIT, Amount(500, 2, "USD"), BalanceView.AVAILABLE)),
            description="suspense resolved back to customer",
            provenance=provenance(),
        )
        suspense = ledger.derive_balances(account_id="value/account/suspense-1")
        self.assertEqual((suspense.pending, suspense.total), (0, 0))
        reconciliation = ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
        self.assertEqual(reconciliation.envelope.state, ReconciliationState.BALANCED.value)

    def test_full_state_digest_is_deterministic(self) -> None:
        def build() -> ValueLedger:
            ledger = make_ledger()
            deposit(ledger)
            ledger.hold_create(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                account_id="value/account/customer-1", amount=Amount(6000, 2, "USD"),
                provenance=provenance(),
            )
            ledger.hold_release(
                journal_id="value/journal/ops-1", hold_id="value/hold/h1",
                amount=Amount(1000, 2, "USD"), provenance=provenance(),
            )
            ledger.reconcile(journal_id="value/journal/ops-1", provenance=provenance())
            return ledger

        first, second = build(), build()
        self.assertEqual(first.state_digest(), second.state_digest())
        self.assertEqual(canonical_json(first.canonical_state()), canonical_json(second.canonical_state()))
        self.assertEqual(
            first.derive_balances(account_id="value/account/customer-1").derivation_hash,
            second.derive_balances(account_id="value/account/customer-1").derivation_hash,
        )

    def test_unknown_lookups_fail_closed(self) -> None:
        ledger = make_ledger()
        with self.assertRaises(CoreValidationError):
            ledger.derive_balances(account_id="value/account/missing")
        with self.assertRaises(CoreValidationError):
            ledger.get_posting("value/journal/ops-1/p999999")
        with self.assertRaises(CoreValidationError):
            ledger.journal_postings("value/journal/missing")


class ValueGraphTests(unittest.TestCase):
    def test_representative_value_graph_round_trips(self) -> None:
        ledger = make_ledger()
        deposit(ledger)
        account = ledger.get_account("value/account/customer-1")
        source = ledger.create_funding_source(
            object_id="value/funding-source/fs-1", account_id="value/account/customer-1",
            cap=Amount(2500, 2, "USD"), provenance=provenance(),
        )
        owner = ObjectEnvelope(
            object_id="principal/customer-1",
            object_type="value/principal/v1",
            object_version=1,
            environment_id=ENV,
            domain_id=DOMAIN,
            schema_version=1,
            protocol_version="v0.1",
            state="ACTIVE",
            provenance=provenance("principal/registry"),
        ).with_integrity_hash()
        custodian = ObjectEnvelope(
            object_id="principal/custodian-1",
            object_type="value/principal/v1",
            object_version=1,
            environment_id=ENV,
            domain_id=DOMAIN,
            schema_version=1,
            protocol_version="v0.1",
            state="ACTIVE",
            provenance=provenance("principal/registry"),
        ).with_integrity_hash()
        relationships = [*account.ownership_relationships(), *source.relationships()]
        graph = ObjectGraph.build([account.envelope, source.envelope, owner, custodian], relationships)
        encoded = graph.to_json()
        self.assertEqual(ObjectGraph.from_json(encoded), graph)
        self.assertEqual(ObjectGraph.from_json(encoded).to_json(), encoded)
        with self.assertRaises(CoreValidationError):
            ObjectGraph.from_json(encoded.replace('"state":"ACTIVE"', '"state":"TAMPERED"'))


class DogfoodingTests(unittest.TestCase):
    def test_dogfooding_run_classifies_pass(self) -> None:
        from src.value.dogfooding import run

        record = run()
        self.assertEqual(record["workOrder"], "WORK-005")
        self.assertEqual(record["classification"], "PASS")
        self.assertTrue(all(check["ok"] for check in record["checks"]))
        self.assertIn("stateDigest", record)

    def test_dogfooding_run_is_deterministic(self) -> None:
        from src.value.dogfooding import run

        self.assertEqual(canonical_json(run()), canonical_json(run()))


if __name__ == "__main__":
    unittest.main()
