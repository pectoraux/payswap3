# WORK-001 — Governance/bootstrap validator

Status: complete

Objective: Make repository governance mechanically self-validating before runtime implementation begins.

Assurance: STANDARD
Dependencies: none

Owned surfaces: `scripts/`, `tests/governance/`.

Forbidden surfaces: `spec/architecture/`, authoritative governance-model/state artifacts, protocol runtime, Work Order scope, external credentials.

Acceptance criteria:
- validates Work Order identity and roadmap↔futureGeneration equality;
- validates dependency DAG acyclicity and known-node references;
- validates parallel waves have disjoint protected surfaces;
- validates no active Work Order exists at bootstrap;
- validates architecture lock and source-of-truth rules;
- fails closed on unknown schema/status/dependency values.

Required proofs: static, dynamic, discrimination.

Dogfooding: fresh-checkout bootstrap by a new Architect process using only repository files.

Definition of done: `python3 scripts/validate_governance.py` passes and a deliberate invalid fixture is rejected.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
