# WORK-019 — Simulation, replay, forecast and shadow

Status: in_flight

Objective: one environment runtime abstraction shared by simulation, replay, forecast, counterfactual, shadow and production-compatible execution; snapshots, checkpoints, deterministic replay, world adapters and forecast/counterfactual state branching.

Assurance: CRITICAL
Dependencies: WORK-003 (implementation) + WORK-005 (implementation)

Owned surfaces: `src/simulation/`.

Forbidden surfaces: no production mutation; no second protocol semantics.

Acceptance criteria:
- implementation matches the frozen v0.1 architecture;
- public boundary is typed and versioned;
- all required failure paths are explicit;
- no second authority is introduced;
- scope is isolated from sibling Work Orders wherever feasible.

Required proofs: static, dynamic, discrimination, quality-attribute.

Dogfooding/conformance experiment: run the same protocol scenario through simulation, shadow and a production-compatible harness; compare canonical transitions and prove only the effect policy/environment changes, never business semantics.

Definition of done: targeted verification passes, required evidence and experiment are persisted, scope audit is clean, Architect approves and merges, and post-merge finalization records the actual Git merge.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
