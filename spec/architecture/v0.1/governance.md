# Governance and Institutional Architecture

## Source of truth

The repository is the durable source of truth for protocol architecture and development governance.

## Roles

```text
Human / institution → consequential governance decisions
Architect → architecture interpretation, Work Orders, review, merge, governance state
Implementation agents → bounded workers
Validation agents → bounded observation/execution workers
```

## Federated state

PaySwap uses authoritative domains rather than requiring a single global mutable ledger. A domain has a governed StateAuthority and publishes state commitments/finality evidence.

## Neutrality

The network must not secretly privilege its own capabilities, operators, liquidity or extensions.

## Protocol change

Frozen architecture changes require an Architecture Change Request and a new immutable architecture version. Proposed versions must be simulated and shadowed before activation when applicable.

## Emergency authority

Emergency actions are narrowly scoped, time-bounded, heavily audited, and cannot rewrite history, erase liabilities, manufacture value or override genuine settlement finality.

## Wind-down

Participants and the network itself require explicit exit/wind-down procedures protecting customer funds, outstanding obligations, collateral and evidence.
