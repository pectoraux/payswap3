# WORK-029 — Extension/agent economic integration gate

Status: complete

Objective: prove agent + extension composition, authority containment, simulation-first decision and economic contribution.

Assurance: CRITICAL
Dependencies: WORK-020 (implementation) + WORK-021 (implementation) + WORK-028 (implementation)

Owned surfaces: `IG-004`.

Forbidden surfaces: no core bypass.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.
Dogfooding/conformance experiment: real extension + real agent proposal on a merchant demand scenario.

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

Merged by the Architect as PR #34 at Git commit `9dc4b2f67d2ac87693f513814c60ae915ea5ee7c` on 2026-09-03. Final implementation head on the worker branch is `3da39515f68f3ebe6e23f50afb08bd8e4b3cd5be` (tree-identical CI-refresh commit); the merge introduced `src/integration/economics/`.
