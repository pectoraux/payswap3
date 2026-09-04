# PaySwap Product UI Work Items

One product work item per branch/PR. Start only when dependencies are satisfied. Acceptance evidence is mandatory.

These are product-layer work items, not new protocol Work Orders. The protocol Work Orders `WORK-001` through `WORK-033` are complete and remain governed by `spec/work-orders/`.

| ID | Work item | Depends on |
|---|---|---|
| `UI-001` | shared product shell and navigation grammar | — |
| `UI-002` | Home and Ask PaySwap outcome-first entry | `UI-001` |
| `UI-003` | customer Pay / Track / Resolve journey | `UI-002`,`UI-005` |
| `UI-004` | merchant checkout / fulfillment journey | `UI-002`,`UI-005` |
| `UI-005` | shared object/task detail pattern | `UI-002` |
| `UI-006` | Activity, state, waiting, exception, and recovery UX | `UI-003`,`UI-004`,`UI-005` |
| `UI-007` | trust, evidence, authority, and progressive disclosure | `UI-006` |
| `UI-008` | provider, liquidity, developer, agent, operator, and admin surfaces | `UI-007` |
| `UI-009` | responsive, accessibility, and interaction polish | `UI-008` |
| `UI-010` | final UX dogfood, acceptance, and product closure | `UI-009` |

## Process

For every active item:

1. The Architect activates exactly one branch/PR for that work item.
2. The worker reads the matching work order and repository state first.
3. The worker implements only the owned product surface and does not merge.
4. CI and objective UX evidence are required before review.
5. The Architect reviews the exact PR head and either requests changes or approves/merges.
6. After merge, the Architect reconciles `spec/development-state/product-program-state.json` and recomputes eligibility.

A status claim without repository evidence does not advance the ledger.

## Authority boundary

The product layer may orchestrate and present protocol state. It must not create a second financial authority, ledger, settlement/finality authority, or silently elevate UI roles into protocol authority.

See `spec/product/implementation-roadmap.md` for the frozen human-readable sequence and `spec/product/work-orders/` for acceptance contracts.