# WORK-024 — Resilience, observability and recovery

Status: complete

Objective: dependency graph, resilience profiles, health/economic metrics, incident/degradation/failover, recovery orchestration.

Assurance: HIGH_ASSURANCE
Dependencies: WORK-003 (implementation) + WORK-018 (implementation) + WORK-023 (implementation)

Owned surfaces: `src/operations/`.

Forbidden surfaces: no alternate source of truth.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.
Dogfooding/conformance experiment: kill a simulated provider/dependency and observe safe degradation/recovery.

Definition of done: targeted verification passes, required evidence and experiment are persisted, scope audit is clean, Architect approves and merges, and post-merge finalization records the actual Git merge.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.

## Post-merge finalization

Merged by the Architect as PR #33 at Git commit `81b5b57622cf80b0229e50d02c4cf31c372631e4` on 2026-09-03. Final implementation head on the worker branch is `b6e2863ffc32b809143bf42d4345bdb3d8897599` (tree-identical CI-refresh commit); the merge introduced the `src/operations/` implementation.
