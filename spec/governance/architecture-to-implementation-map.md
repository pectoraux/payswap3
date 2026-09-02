# Architecture → Implementation Map

## Purpose

This is the Architect's compact semantic map from the frozen PaySwap architecture to the implementation Work Orders. It is a navigation artifact, not a competing authority. The frozen architecture remains normative; the Work Orders define implementation scope.

## Frozen semantic areas

| Semantic area | Frozen authority | Primary implementation | Integration |
|---|---|---|---|
| canonical identities/envelopes/versions | `canonical-object-model.md` | WORK-002 | IG-001 |
| command/event transition kernel | `command-event-model.md` | WORK-003 | IG-001 |
| identity/authority/mandates | `ownership-lifecycle.md`, `command-event-model.md` | WORK-004 | IG-002 |
| assets/accounts/ledger/postings/holds | `ledger-posting-model.md` | WORK-005 | IG-001 |
| fixed-point money/FX | `ledger-posting-model.md`, `constitution.md` | WORK-006 | IG-001 |
| interoperability/endpoints/adapters | `interoperability.md` | WORK-007 | IG-005 |
| intents/policy/slack/demand | `canonical-object-model.md`, `constitution.md` | WORK-008 | IG-002 |
| capability/commitment/windows | `canonical-object-model.md` | WORK-009 | IG-002 |
| markets/quotes/allocation | `constitution.md`, `canonical-object-model.md` | WORK-010 | IG-002 |
| liquidity/credit/exposure/collateral | `constitution.md`, `security-risk.md` | WORK-011 | IG-001/IG-002 |
| reservations/concurrency | `command-event-model.md`, `security-risk.md` | WORK-012 | IG-001/IG-002 |
| fulfillment compilation/optimization | `constitution.md`, `canonical-object-model.md` | WORK-013 | IG-002/IG-003 |
| external effects/execution/retry | `command-event-model.md`, `interoperability.md` | WORK-014 | IG-002/IG-005 |
| clearing/obligations/netting | `ledger-posting-model.md` | WORK-015 | IG-001/IG-002 |
| settlement/finality/reconciliation | `ledger-posting-model.md`, `command-event-model.md` | WORK-016 | IG-002/IG-005 |
| risk/fraud/compliance/policy | `security-risk.md` | WORK-017 | IG-002 |
| evidence/attestation/uncertainty | `command-event-model.md`, `security-risk.md` | WORK-018 | IG-002/IG-003 |
| simulation/replay/forecast/shadow | `simulation.md` | WORK-019 | IG-003 |
| extensions/marketplace/resources/reputation | `extensions.md` | WORK-020 | IG-004 |
| agents/models/mediation | `extensions.md`, `simulation.md` | WORK-021 | IG-004 |
| data/privacy/recourse | `security-risk.md`, `command-event-model.md` | WORK-022 | IG-006 |
| domains/federation/finality binding | `interoperability.md`, `ownership-lifecycle.md` | WORK-023 | IG-005 |
| resilience/recovery/operations | `security-risk.md`, `simulation.md` | WORK-024 | IG-006 |
| merchant checkout/settlement promise | `constitution.md` | WORK-025 | IG-006 |

## Implementation-order rule

The implementation graph is not a serialization of the architecture. It is a dependency graph. A Work Order may start as soon as its declared hard dependencies and contracts are satisfied and its protected surfaces are conflict-free.

`contract` means the dependency's required public semantics are already frozen or merged and consumable; it does not permit consuming unmerged sibling implementation code.

`implementation` means the dependency's implementation must be merged and available on `main`.

`integration` means the item is a composition/acceptance gate that consumes independently merged capabilities.

## If architecture and repository disagree

Workers do not resolve architectural disagreement by intuition.

```text
repository appears inconsistent with frozen architecture
        ↓
stop implementation at the contradiction
        ↓
record exact evidence
        ↓
Architect decides
        ├── implementation interpretation → continue
        ├── Work Order correction → governed state update
        └── architecture change → ACR + new immutable version
```
