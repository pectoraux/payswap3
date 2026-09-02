# Ownership and Lifecycle

PaySwap distinguishes:

```text
OWNERSHIP ≠ CONTROL ≠ CUSTODY ≠ AUTHORITY ≠ OBSERVATION
```

One object may therefore have several explicit relationship holders.

## Lifecycle classes

- `IMMUTABLE` — events, ledger entries, receipts, finality certificates, attestations.
- `VERSIONED` — intents, policies, extensions, models, quotes.
- `STATEFUL` — reservations, executions, obligations, cases, participants.
- `DERIVED` — balances, demand classes, risk/reputation scores.
- `EPHEMERAL` — route candidates, cache/worker state.

## General lifecycle

```text
CREATED → ACTIVE → DEGRADED/SUSPENDED → CLOSED/EXPIRED → ARCHIVED
```

The exact machine is object-specific.

## Core rules

- An authoritative object has exactly one authoritative state domain at a time.
- Domain transfer is explicit and leaves no dual-authority interval.
- Financial history is append-only.
- An object may not terminate while active dependent obligations require it unless a governed successor exists.
- Customer funds remain customer-owned even when an intermediary has custody or execution authority.
- Simulation/shadow objects never acquire production authority.
- Physical deletion is exceptional; logical closure and archival are preferred.
- Legal hold can suspend deletion/retention expiry.
