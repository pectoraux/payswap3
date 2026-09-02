"""DOGFOOD-005: simulated balanced journal lifecycle with hold/release/reconciliation.

Runs the Work Order's conformance experiment against the real ledger in a
sandboxed in-memory environment and returns a deterministic evidence
record. Every check is a real invariant of the frozen ledger/posting model;
the record is JSON-canonical so repeated runs are byte-identical.
"""

from __future__ import annotations

from typing import Any

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json

from .account import SegregationClass
from .amount import Amount
from .asset import AssetKind
from .contracts import BalanceView, EntrySide
from .ledger import ValueLedger
from .posting import PostingClass, PostingLeg
from .reconciliation import ReconciliationState

ENV = "env/dogfood-value"
DOMAIN = "domain/value-dogfood"
STAMP = "2026-09-02T00:00:00Z"
ASSET_ID = "value/asset/usd"
JOURNAL_ID = "value/journal/ops-1"
CUSTOMER = "value/account/customer-1"
MERCHANT = "value/account/merchant-1"
VAULT = "value/account/cash-vault"


def _provenance(issuer: str = "principal/treasury"):
    from src.core.envelope import Provenance

    return Provenance(issuer=issuer, source="dogfood", recorded_at=STAMP)


def _build_ledger() -> ValueLedger:
    ledger = ValueLedger(environment_id=ENV, domain_id=DOMAIN)
    ledger.register_asset(
        object_id=ASSET_ID,
        code="USD",
        scale=2,
        kind=AssetKind.FIAT,
        issuer_id="principal/treasury",
        provenance=_provenance(),
    )
    ledger.activate_asset(object_id=ASSET_ID, provenance=_provenance())
    for object_id, segregation, normal, owner in (
        (CUSTOMER, SegregationClass.CUSTOMER, EntrySide.CREDIT, "principal/customer-1"),
        (MERCHANT, SegregationClass.MERCHANT_RECEIVABLE, EntrySide.CREDIT, "principal/merchant-1"),
        (VAULT, SegregationClass.NETWORK, EntrySide.DEBIT, "principal/treasury"),
    ):
        ledger.create_account(
            object_id=object_id,
            asset_code="USD",
            segregation_class=segregation,
            owner_id=owner,
            custodian_id="principal/custodian-1",
            normal_side=normal,
            provenance=_provenance(),
        )
        ledger.activate_account(object_id=object_id, provenance=_provenance())
    ledger.open_journal(
        object_id=JOURNAL_ID,
        custodian_id="principal/custodian-1",
        description="dogfood operations journal",
        provenance=_provenance(),
    )
    return ledger


def _deposit(ledger: ValueLedger, value: int) -> None:
    ledger.post(
        journal_id=JOURNAL_ID,
        posting_class=PostingClass.EXECUTION,
        legs=(
            PostingLeg(VAULT, EntrySide.DEBIT, Amount(value, 2, "USD"), BalanceView.AVAILABLE),
            PostingLeg(CUSTOMER, EntrySide.CREDIT, Amount(value, 2, "USD"), BalanceView.AVAILABLE),
        ),
        description="customer deposit",
        provenance=_provenance(),
    )


def run() -> dict[str, Any]:
    """Execute the WORK-005 dogfooding experiment and return the evidence record."""
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    ledger = _build_ledger()

    # 1. balanced deposit conserves value exactly
    _deposit(ledger, 12500)
    customer = ledger.derive_balances(account_id=CUSTOMER)
    vault = ledger.derive_balances(account_id=VAULT)
    check(
        "deposit-conserves-value",
        customer.total == 12500 and vault.total == 12500 and customer.available == 12500,
        f"customer={customer.total} vault={vault.total}",
    )

    # 2. hold reserves value: available drops, encumbered rises, total unchanged
    ledger.hold_create(
        journal_id=JOURNAL_ID,
        hold_id="value/hold/d1",
        account_id=CUSTOMER,
        amount=Amount(6000, 2, "USD"),
        purpose="payment reservation",
        provenance=_provenance(),
    )
    held = ledger.derive_balances(account_id=CUSTOMER)
    check(
        "hold-encumbers-without-creating-value",
        held.available == 6500 and held.encumbered == 6000 and held.held == 6000 and held.total == 12500,
        f"available={held.available} encumbered={held.encumbered} held={held.held}",
    )

    # 3. partial release returns value to available
    ledger.hold_release(
        journal_id=JOURNAL_ID,
        hold_id="value/hold/d1",
        amount=Amount(1500, 2, "USD"),
        provenance=_provenance(),
    )
    released = ledger.derive_balances(account_id=CUSTOMER)
    check(
        "partial-release-restores-available",
        released.available == 8000 and released.encumbered == 4500 and released.held == 4500,
        f"available={released.available} encumbered={released.encumbered}",
    )

    # 4. unbacked reservation is rejected fail-closed
    reservation_rejected = False
    try:
        ledger.hold_create(
            journal_id=JOURNAL_ID,
            hold_id="value/hold/d2",
            account_id=CUSTOMER,
            amount=Amount(12501, 2, "USD"),
            provenance=_provenance(),
        )
    except CoreValidationError:
        reservation_rejected = True
    check("unbacked-hold-rejected", reservation_rejected)

    # 5. overdraft of safeguarded customer funds is rejected
    overdraft_rejected = False
    try:
        ledger.post(
            journal_id=JOURNAL_ID,
            posting_class=PostingClass.EXECUTION,
            legs=(
                PostingLeg(CUSTOMER, EntrySide.DEBIT, Amount(20000, 2, "USD"), BalanceView.AVAILABLE),
                PostingLeg(MERCHANT, EntrySide.CREDIT, Amount(20000, 2, "USD"), BalanceView.AVAILABLE),
            ),
            provenance=_provenance(),
        )
    except CoreValidationError:
        overdraft_rejected = True
    check("customer-overdraft-rejected", overdraft_rejected)

    # 6. reconciliation certifies the balanced lifecycle and seals the journal
    ledger.hold_release(
        journal_id=JOURNAL_ID,
        hold_id="value/hold/d1",
        provenance=_provenance(),
    )
    reconciliation = ledger.reconcile(journal_id=JOURNAL_ID, provenance=_provenance())
    check(
        "reconciliation-is-balanced",
        reconciliation.envelope.state == ReconciliationState.BALANCED.value,
        reconciliation.envelope.state,
    )
    check(
        "reconciliation-certifies-hold-evidence",
        all(entry.ok for entry in reconciliation.payload.account_holds),
    )

    # 7. sealed journal fails closed for further postings
    sealed_rejects = False
    try:
        _deposit(ledger, 100)
    except CoreValidationError:
        sealed_rejects = True
    check("reconciled-journal-rejects-postings", sealed_rejects)

    # 8. tampered ledger state is rejected on the trusted deserialization path
    tamper_rejected = False
    try:
        from .account import Account as _Account

        encoded = ledger.get_account(CUSTOMER).to_json()
        _Account.from_json(encoded.replace('"owner_id":"principal/customer-1"', '"owner_id":"principal/attacker"'))
    except CoreValidationError:
        tamper_rejected = True
    check("tampered-record-rejected", tamper_rejected)

    classification = "PASS" if all(item["ok"] for item in checks) else "FAIL"
    return {
        "workOrder": "WORK-005",
        "experiment": "simulated balanced journal lifecycle with hold/release/reconciliation",
        "architecture": "v0.1",
        "environment": ENV,
        "checks": checks,
        "classification": classification,
        "stateDigest": ledger.state_digest(),
    }


if __name__ == "__main__":
    print(canonical_json(run()))
