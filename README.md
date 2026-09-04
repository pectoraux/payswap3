# PaySwap

PaySwap is an open financial coordination protocol that fulfills economic intents across heterogeneous financial capabilities.

**Repository is the source of truth.** Architecture, governance, work orders, dependencies, proof requirements, dogfooding rules, product UX contracts, and operational development state live under `spec/`. The implementation is intentionally driven from repository-resident contracts rather than chat instructions.

## Frozen architecture

`spec/architecture/v0.1/architecture-lock.md` is the frozen architectural contract. The constitution and supporting specifications are immutable once frozen; changes require an Architecture Change Request and a new architecture version.

## Development model

- One Architect/reviewer is the consequential architecture, review, merge, and governance authority.
- Multiple implementation workers may execute in parallel when dependency and protected-surface rules permit it.
- Z.ai workers are the intended implementation-agent pool; provider details remain behind the worker gateway boundary.
- One active Work Item maps to one implementation branch/PR.
- Parallel siblings start from the same stable `main` SHA and do not consume each other's unmerged branches.
- Integration gates combine independently merged capabilities only after their hard dependencies complete.
- Tests prove correctness; real-product dogfooding proves integrated usefulness.
- Findings are durable evidence and become targeted Work Items through governed intake; workers do not silently expand scope.
- Architect merge is the completion event. Post-merge finalization records the authoritative Git fact.

## Protocol program state

The original protocol Work Order program is complete through `WORK-033`. The product/UI program is tracked separately and does not imply new protocol Work Orders.

## Product/UI program

The product/UI roadmap is governed by:

- `spec/product/implementation-roadmap.md` — frozen human-readable sequencing and progress.
- `spec/product/work-items.md` — product dependency/status ledger.
- `spec/product/work-orders/` — detailed product acceptance contracts.
- `spec/development-state/product-program-state.json` — machine-readable UI program state and evidence.
- `spec/product/ux-architecture-v0.2.md` — UX contract.

Start product implementation by reading those artifacts together. The current next eligible item is `UI-001`.

## Repository navigation

```text
spec/
  architecture/v0.1/      frozen constitution and protocol design
  governance/             development control-plane contracts
  development-state/      canonical protocol and product machine state
  work-orders/            atomic protocol implementation units
  product/                product UX contract, roadmap, work items, and UI work orders
  architecture-change-requests/

agents/                   worker/architect protocols and role contracts
scripts/                  fail-closed governance validators

tests/                    repository-level governance tests
```

## Fresh architect bootstrap

A new Architect should start with:

1. `spec/governance/fresh-architect-bootstrap.md`
2. `spec/architecture/v0.1/architecture-lock.md`
3. `spec/development-state/program-state.json`
4. `spec/development-state/governance-model.json`
5. `spec/development-state/dependency-state.json`
6. `spec/development-state/frontier-state.json`
7. `spec/product/implementation-roadmap.md`
8. `spec/product/work-items.md`
9. `spec/development-state/product-program-state.json`
10. the eligible protocol Work Order(s) or product work order in the corresponding directory

Do not rely on prior conversation state.

## Validate governance

```bash
python3 scripts/validate_governance.py
```

A non-zero result means the repository is not a valid governed implementation state.

## Target repository

The canonical target repository is `pectoraux/payswap3`. The repository is designed to be self-describing so a fresh Architect can take over without chat history.

## Architect and worker bootstrap

A fresh Architect may use [`agents/architect-prompt.md`](agents/architect-prompt.md) as the operating contract. Worker execution is governed by [`agents/zai-worker-prompt.md`](agents/zai-worker-prompt.md) and [`agents/schemas/execution-context.schema.json`](agents/schemas/execution-context.schema.json).

The Architect should dispatch the largest dependency-eligible, protected-surface-disjoint set of protocol Work Orders or product work items. A worker's implementation freedom is deliberately broad inside its assigned contract and deliberately narrow across semantic boundaries.
