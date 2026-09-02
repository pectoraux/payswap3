# PaySwap Architecture Lock v0.1

## Status

**FROZEN**

This file is authoritative for the frozen v0.1 architecture rules.

## Frozen rules

- One PaySwap protocol state machine.
- One canonical semantic object model.
- One command/event transition mechanism.
- One authoritative value/accounting model.
- Federated authoritative domains; no mandatory universal global ledger.
- Simulation/replay/forecast/counterfactual/shadow/production are environments of the same protocol.
- Non-production environments cannot mutate production financial state.
- Extensions and agents are bounded capability consumers/providers, not alternate financial authorities.
- Customer funds are distinct from participant/network funds and collateral.
- Clearing, netting, settlement and finality are separate concepts.
- Fixed-point monetary arithmetic.
- Optimistic concurrency with conditional resource commit.
- Canonical interoperability semantics above external rails.
- Fraud, risk, compliance and privacy are distinct policy/evidence domains.
- Repository-resident governance is the source of truth for implementation state.
- One Architect/reviewer is the merge authority.
- Parallel work requires dependency eligibility and disjoint protected authoritative surfaces.
- No-rebase sibling rule.
- Dogfooding is mandatory at user/execution boundaries.

## Architecture change mechanism

Any change to a frozen rule requires:

```text
Architecture Change Request
→ Architect review
→ new immutable ArchitectureVersion
→ governed implementation Work Order(s)
```

Implementation agents must not modify this file as part of ordinary feature work.
