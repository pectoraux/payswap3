# WORK-002 — Canonical protocol primitives

Status: complete

Objective: Implement the shared immutable object identities, envelopes, identifiers, versions, provenance, relationships and common schema utilities.

Assurance: STANDARD
Dependencies: WORK-001 (implementation)

Owned surfaces: `src/core/`.

Forbidden surfaces: domain transition engines, ledger behavior, external adapters.

Acceptance criteria:
- canonical ObjectEnvelope;
- environment/domain identity;
- version/causation/correlation fields;
- typed relationship model;
- closed protocol vocabularies;
- schema versioning;
- immutable object identity semantics.

Required proofs: static, dynamic, transformation-completeness.
Dogfooding: construct a representative intent lifecycle object graph and serialize/deserialize losslessly.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
