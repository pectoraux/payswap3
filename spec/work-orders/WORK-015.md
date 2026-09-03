# WORK-015 — Clearing, obligations and netting

Status: complete

Objective: clearing cycles, obligations, bilateral/multilateral netting, gross/net calculations.

Assurance: CRITICAL
Dependencies: WORK-005 (implementation) + WORK-006 (implementation) + WORK-012 (implementation) + WORK-014 (implementation) + WORK-018 (contract)

Owned surfaces: `src/clearing/`.

Forbidden surfaces: no external settlement effects.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, transformation-completeness.

Dogfooding/conformance experiment: run reciprocal cross-border demand through clearing and prove gross-to-net capital reduction.

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

- Architect decision: ACCEPTED and merged.
- Pull request: #26.
- Implementation revision: `433484eeb067dc7ebcd92def83c23b4aa6a9449c`.
- Merge commit: `3044a06cc77d5dbb4a865953460710ff880c7f8a`.
- Merge date: 2026-09-03.
