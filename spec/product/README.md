# PaySwap Product Program

## Authority

This directory governs the product/UI program only. The frozen PaySwap v0.1 protocol architecture and the completed protocol Work Orders remain authoritative and are not reopened by this program.

The repository is the sole source of truth. Conversation history is non-authoritative.

### Product governance artifacts

- `spec/product/implementation-roadmap.md` — frozen, human-readable product sequencing and progress.
- `spec/product/work-items.md` — compact product dependency and status ledger.
- `spec/product/work-orders/` — detailed acceptance contracts; one product work item per branch/PR.
- `spec/development-state/product-program-state.json` — machine-readable product state and acceptance evidence.
- `spec/product/ux-architecture-v0.2.md` — UX contract and product design direction.

## Operating loop

```text
READ → VALIDATE → COMPUTE ELIGIBILITY → ACTIVATE ONE WORK ITEM
→ IMPLEMENT → TEST/VERIFY → ARCHITECT REVIEW → MERGE → RECONCILE
→ UPDATE ROADMAP + WORK-ITEM LEDGER + MACHINE STATE
```

A product work item is complete only after implementation, tests/evidence, Architect review, merge, and post-merge reconciliation are recorded in repository state.

## Scope boundary

Product work may improve presentation, interaction, workflows, accessibility, responsive behavior, evidence presentation, and task orchestration.

Product work must not:

- change frozen protocol semantics;
- create a second financial authority, ledger, settlement, or finality authority;
- silently grant protocol authority from UI roles;
- turn sandbox/demo behavior into a production financial claim;
- invent new protocol Work Orders merely to support UI work.

Any required semantic protocol change is an architecture/governance matter outside this product roadmap.

## Completed product foundation

The current product foundation was established through merged PRs #38, #39, #40, #41, and #43. These provide authentication/waitlist, the first outcome workflow, protocol draft binding, governed execution-handoff preparation, and sandbox execution through the existing ExecutionEngine. The sandbox remains explicitly non-production; settlement/finality are not claimed by the product shell.

PR #42 was a stale-base implementation attempt and was closed/replaced by the reconciled PR #43 path. It is historical context, not an outstanding task.
