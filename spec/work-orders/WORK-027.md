# WORK-027 — Fulfillment lifecycle integration gate

Status: planned

Objective: prove intent through finality across the compiled lifecycle.

Assurance: CRITICAL
Dependencies: WORK-007 (implementation) + WORK-009 (implementation) + WORK-010 (implementation) + WORK-011 (implementation) + WORK-012 (implementation) + WORK-013 (implementation) + WORK-014 (implementation) + WORK-015 (implementation) + WORK-016 (implementation) + WORK-017 (implementation) + WORK-018 (implementation)

Owned surfaces: `IG-002`.

Forbidden surfaces: no redesign of underlying modules.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.

Dogfooding/conformance experiment: real supported sandbox payment end-to-end.

Definition of done: targeted verification passes, required evidence and experiment are persisted, scope audit is clean, Architect approves and merges, and post-merge finalization records the actual Git merge.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
