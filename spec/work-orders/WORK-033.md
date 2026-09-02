# WORK-033 — Governance revision-binding remediation

Status: planned

Objective: Close the W001 governance gap so repository validation detects stale program/base revisions and malformed dependency declarations fail closed.

Assurance: HIGH_ASSURANCE
Dependencies: WORK-001 (implementation)

Owned surfaces: `scripts/`, `tests/governance/`.

Forbidden surfaces: `spec/architecture/`, protocol runtime, protocol registry authority, Work Order domain semantics, external credentials, sibling implementation surfaces.

Acceptance criteria:
- governance validation binds authoritative `program-state.json.currentMain` to the actual `main` ref;
- active Work Orders are rejected when their recorded baseRevision is stale relative to the authoritative main revision according to the repository governance contract;
- stale revision state produces a deterministic fail-closed diagnostic;
- malformed or partially parseable dependency declarations are rejected instead of silently ignored;
- discrimination tests cover stale main/currentMain, stale active Work Order baseRevision, malformed dependency syntax and unknown dependency type;
- validation remains compatible with bootstrap, active, blocked, ready_for_merge and complete lifecycle states;
- no new governance authority or alternate state source is introduced.

Required proofs: static, dynamic, discrimination.
Dogfooding/conformance experiment: run the governance validator from a clean checkout while mutating only repository control-plane revisions/declarations; prove stale or malformed control-plane state is rejected and valid reconciled state passes.

Definition of done: targeted verification passes, discrimination evidence is persisted, scope audit is clean, Architect independently reviews the exact PR head and merges, and post-merge finalization records the actual Git merge.

## Findings addressed

- W001-1: stale main/program-state revision drift was not detected.
- W001-2: dependency parsing can silently ignore malformed dependency declarations.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
