# WORK-016 — Settlement, finality and reconciliation

Status: complete

Objective: settlement lifecycle, finality certificates, settlement reconciliation, reversals/returns boundaries.

Assurance: CRITICAL
Dependencies: WORK-005 (implementation) + WORK-006 (implementation) + WORK-014 (implementation) + WORK-015 (implementation) + WORK-018 (implementation)

Owned surfaces: `src/settlement/`.

Forbidden surfaces: no false finality; no arbitrary ledger edits.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.

Dogfooding/conformance experiment: complete a sandbox settlement, with unknown/failure/reversal and finality evidence paths.

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

Merged PR: #27
Implementation commit: `1fcc00f8556a0705aa0dfe313e89282d88b737d0`
Merge commit: `4862b85d003d455cdb8f230029c4431deabd09ce`
Architect decision: accepted and merged after review of the required proof battery and owned-surface audit.
