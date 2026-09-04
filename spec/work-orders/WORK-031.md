# WORK-031 — Merchant/end-to-end global fulfillment dogfood

Status: complete

Objective: prove a real user-facing merchant outcome through the complete network, including delay/credit, recovery and evidence.

Assurance: CRITICAL
Dependencies: WORK-024 (implementation) + WORK-025 (implementation) + WORK-028 (implementation) + WORK-030 (implementation)

Owned surfaces: `IG-006`.

Forbidden surfaces: no new authority.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.

Dogfooding/conformance experiment: real merchant/customer sandbox journey; document cost, time, reliability and findings.

Definition of done: targeted verification passes, required evidence and experiment are persisted, scope audit is clean, Architect approves and merges, and post-merge finalization records the actual Git merge.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.

## Activation

Activated by the Architect on 2026-09-03 after WORK-024, WORK-025, WORK-028 and WORK-030 were verified complete and merged. Starting implementation frontier: `9dc4b2f67d2ac87693f513814c60ae915ea5ee7c`. Owned integration surface: `IG-006`. Next action: implement and prove the merchant/end-to-end global fulfillment dogfood without introducing a new authority.

## Post-merge finalization

Merged by the Architect as PR #35 at Git commit `05feb8fd0553f35533ff7e53a75a048d6f90dc00` on 2026-09-04. The merge was performed from the reviewed worker head `2392e215b66524007680b3684892167a25026872`; GitHub reported the pull request successfully merged. Required W031 evidence remains persisted in `spec/dogfooding/DOGFOOD-031.md` and `src/integration/flywheel/`.
