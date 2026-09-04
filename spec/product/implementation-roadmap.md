# PAYSWAP PRODUCT UI IMPLEMENTATION ROADMAP

**Status:** FROZEN
**Authority:** human-readable product/UI implementation sequencing and progress
**Machine state:** `spec/development-state/product-program-state.json`
**Detailed contracts:** `spec/product/work-orders/`
**Dependency ledger:** `spec/product/work-items.md`

## Purpose

This roadmap is the implementation plan for closing the PaySwap product/UI work. It is deliberately separate from the frozen protocol Work Order program (`WORK-001` through `WORK-033`). The protocol program is complete. Product work must not reopen or refactor protocol architecture unless a separately governed architecture change is required.

## Roadmap graph

```text
PAYSWAP PRODUCT / UI

UI-001 Product shell completion
   │
   ▼
UI-002 Home + Ask PaySwap
   │
   ├───────────────┬───────────────┐
   ▼               ▼               ▼
UI-003           UI-004          UI-005
Customer         Merchant        Shared object /
journey          journey         task detail
   │               │               │
   └───────────────┼───────────────┘
                   ▼
               UI-006
          Activity / state /
        waiting / recovery
                   │
                   ▼
               UI-007
          Trust + evidence /
         progressive disclosure
                   │
                   ▼
               UI-008
           Role surfaces
 Provider / Liquidity / Developer /
 Agent / Operator / Administrator
                   │
                   ▼
               UI-009
       Responsive + accessibility +
             interaction polish
                   │
                   ▼
               UI-010
        UX acceptance / dogfood /
             closure gate
                   │
                   ▼
            UI PROGRAM CLOSED
```

## Status semantics

- `READY` — all declared product dependencies are complete and the Architect may activate the item.
- `BLOCKED` — at least one declared dependency is incomplete.
- `IN_PROGRESS` — explicitly activated for implementation on one branch/PR.
- `FINAL` — implementation, objective evidence, Architect acceptance, merge, and post-merge reconciliation are complete.

## Work item ledger

| Work item | Objective | Depends on | Status | Primary proof |
|---|---|---|---|---|
| `UI-001` | Complete the shared product shell and navigation grammar | — | READY | shell/navigation UX + tests |
| `UI-002` | Make Home + Ask PaySwap the clear outcome-first entry | UI-001 | BLOCKED | task creation + UX flow |
| `UI-003` | Polish the customer Pay/Track/Resolve journey | UI-002, UI-005 | BLOCKED | customer dogfood |
| `UI-004` | Polish the merchant checkout/fulfillment journey | UI-002, UI-005 | BLOCKED | merchant dogfood |
| `UI-005` | Implement the reusable object/task detail pattern | UI-002 | BLOCKED | shared detail conformance |
| `UI-006` | Make activity, state, waiting, exceptions, and recovery legible | UI-003, UI-004, UI-005 | BLOCKED | state/recovery discrimination |
| `UI-007` | Make trust, evidence, authority, and uncertainty inspectable | UI-006 | BLOCKED | evidence/progressive-disclosure checks |
| `UI-008` | Complete the remaining role-aware product surfaces | UI-007 | BLOCKED | role-by-role acceptance |
| `UI-009` | Complete responsive, accessibility, and interaction quality | UI-008 | BLOCKED | cross-device/a11y evidence |
| `UI-010` | Run final UX dogfood and close the product program | UI-009 | BLOCKED | Architect closure decision |

## Product milestones already complete

The product foundation preceding this roadmap is already merged and recorded in machine state:

```text
PR #38 → UX architecture + authentication / waitlist
PR #39 → first outcome workflow vertical slice
PR #40 → workflow decisions bound to protocol drafts
PR #41 → governed execution-handoff preparation
PR #43 → sandbox execution through the existing ExecutionEngine
```

These are historical completed milestones, not remaining Work Items. PR #42 was closed as a stale/replaced implementation path and is retained only as historical context.

## Closure criteria

UI work is closed only when all of the following are true:

1. The shared product grammar is coherent across roles.
2. The core customer and merchant journeys are usable end-to-end in the available product environment.
3. State, uncertainty, waiting, exceptions, recovery, and next action are explicit.
4. Evidence and technical depth are available without overwhelming normal users.
5. Role surfaces use one navigation grammar rather than eight unrelated applications.
6. Responsive and accessibility acceptance passes are recorded.
7. Objective dogfooding demonstrates the stated UX success criteria in `spec/product/ux-architecture-v0.2.md`.
8. Every completed item has repository evidence and machine-state reconciliation.
9. The Architect records the final `UI-010` acceptance and marks the product program closed.

## Freeze rule

This document is frozen as the sequencing authority for the product/UI program. Changes require a governed repository change that records why scope or sequencing changed. It never overrides `spec/architecture/v0.1/` or the completed protocol Work Orders.
