# Fresh Architect Bootstrap

A fresh Architect with zero conversation history must be able to direct the entire PaySwap implementation program from the repository alone.

## Read in order

1. `spec/governance/source-of-truth.md`
2. `spec/architecture/v0.1/architecture-lock.md`
3. `spec/architecture/v0.1/constitution.md`
4. `spec/architecture/v0.1/canonical-object-model.md`
5. `spec/architecture/v0.1/command-event-model.md`
6. `spec/architecture/v0.1/ownership-lifecycle.md`
7. `spec/architecture/v0.1/ledger-posting-model.md`
8. `spec/architecture/v0.1/simulation.md`
9. `spec/architecture/v0.1/extensions.md`
10. `spec/architecture/v0.1/security-risk.md`
11. `spec/governance/architecture-to-implementation-map.md`
12. `spec/governance/governance-model.json`
13. `spec/governance/architect.json`
14. `spec/governance/worker-protocol.json`
15. `spec/governance/implementation-protocol.md`
16. `spec/governance/drift-control.md`
17. `spec/governance/parallel-execution.md`
18. `spec/governance/dogfooding-protocol.md`
19. `spec/registry/protocol-registry.json`
20. `spec/development-state/program-state.json`
21. `spec/development-state/dependency-state.json`
22. `spec/development-state/frontier-state.json`
23. `spec/development-state/checkpoint-state.json`
24. `spec/development-state/future-roadmap.json`
25. the current eligible protocol Work Order(s).

## Product/UI takeover

When the protocol Work Orders are complete, or when the current task is product/UI implementation, also read:

26. `spec/product/README.md`
27. `spec/product/ux-architecture-v0.2.md`
28. `spec/product/implementation-roadmap.md`
29. `spec/product/work-items.md`
30. `spec/development-state/product-program-state.json`
31. the current eligible product work order in `spec/product/work-orders/`.

The protocol program currently ends at `WORK-033` and is complete. Product/UI work is a separate bounded program. Do not create `WORK-034+` merely to advance UI implementation.

## Takeover

Verify repository identity, current `main`, clean/dirty state, frozen architecture, validators, Work Order/work-item identities and state. Recompute eligibility from authoritative facts.

## Eligibility

For protocol work:

```text
hard dependencies complete
AND governing architecture matches
AND contracts consumable
AND no active protected-surface conflict
AND stable current base
AND no architecture contradiction
```

For product/UI work, use the same control model against `spec/product/work-items.md` and `spec/development-state/product-program-state.json`.

## Parallelism

Prefer the largest eligible antichain of protocol Work Orders or product work items with disjoint authoritative change surfaces. Never consume an unmerged sibling. Use an integration item for composition.

## Dispatch

Give each worker exactly one protocol Work Order or product work item and one branch/PR. The execution context includes repository, current main SHA, assigned contract, dependency facts, owned/forbidden surfaces, assurance, required proofs, dogfooding/UX evidence, checkpoint contract, registry, and stop conditions.

## Review

Review the exact head against the relevant repository contract. For protocol work, review scope, public contracts, authority boundaries, failure/retry/reconciliation, accounting, simulation parity, extension isolation, proofs and dogfooding. For UI work, review UX contract conformance, state/next-action clarity, progressive disclosure, role/access correctness, responsive/accessibility quality, and evidence of useful journeys.

## Completion

Only Architect merge establishes completion. Post-merge reconciliation records the actual merge and recomputes protocol frontier or product eligibility. The corresponding human-readable roadmap and machine state must remain synchronized.

## Interruption

Resume from the relevant protocol or product program state, active handoff, current PR, last verified revision, assigned contract and evidence. Never reconstruct authority from conversation history.
