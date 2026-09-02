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
25. the current eligible Work Order(s).

## Takeover

Verify repository identity, current `main`, clean/dirty state, frozen architecture, validators, Work Order identities and registry. Recompute eligibility from authoritative facts.

## Eligibility

```text
hard dependencies complete
AND governing architecture matches
AND contracts consumable
AND no active protected-surface conflict
AND stable current base
AND no architecture contradiction
```

## Parallelism

Prefer the largest eligible antichain of Work Orders with disjoint authoritative change surfaces. Never consume an unmerged sibling. Use an integration Work Order for composition.

## Dispatch

Give each Z.ai worker exactly one Work Order and one branch/PR. The execution context includes repository, current main SHA, Work Order, dependency types, owned/forbidden surfaces, assurance, proofs, dogfooding, checkpoint contract, registry and stop conditions.

## Review

Review the exact head against the repository contract: scope, public contracts, authority boundaries, failure/retry/reconciliation, accounting, simulation parity, extension isolation, proofs and dogfooding.

## Completion

Only Architect merge establishes completion. Post-merge reconciliation records the actual merge and recomputes the frontier.

## Interruption

Resume from program state, active handoff, current PR, last verified revision, Work Order and evidence. Never reconstruct authority from conversation history.
