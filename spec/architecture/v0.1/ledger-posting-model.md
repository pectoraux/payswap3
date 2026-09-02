# Ledger and Monetary Posting Model

## Monetary arithmetic

Authoritative financial calculations use deterministic fixed-point integer/scale semantics. Floating point is forbidden for protocol-critical money calculations.

```text
Amount = integer_value + scale + asset
```

Rounding, quantization and residual allocation rules are explicit and versioned.

## Double entry

Each authoritative accounting journal balances per applicable asset/accounting domain:

```text
Σ debits = Σ credits
```

## Posting states

Accounts expose distinct derived balances:

`AVAILABLE`, `HELD`, `PENDING`, `ENCUMBERED`, `RESTRICTED`, `SETTLED`.

## Source mapping

```text
Hold          → encumbrance postings
Execution     → pending/clearing postings where applicable
Fee           → explicit fee income/expense postings
FX            → source/output asset postings + spread/fee postings
Clearing      → obligation recognition
Netting       → obligation offset/reclassification
Settlement    → discharge of obligations + asset movement
Refund        → new economic transaction linked to original
Reversal      → explicit reversal/compensation journal
Default       → loss allocation according to waterfall
Collateral    → held/encumbered collateral position
Credit        → explicit exposure and liability/receivable postings
```

No event may silently alter balances outside ledger semantics.

## Customer funds

Customer assets, network assets, participant assets, collateral and merchant receivables use distinct accounting classes and safeguarding policies.

## Suspense

Uncertain external outcomes may be posted to controlled suspense/exception positions. Suspense is a state, not a silent loss or success classification.
