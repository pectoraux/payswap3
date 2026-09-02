# WORK-032 — Canonical core integrity remediation

Status: in_flight

Objective: Remediate W002 canonical-core weaknesses identified by independent Architect review so the shared object/envelope layer is safe to consume as protocol foundation.

Assurance: HIGH_ASSURANCE
Dependencies: WORK-002 (implementation)

Owned surfaces: `src/core/`, `tests/core/`.

Forbidden surfaces: `spec/architecture/`, `spec/governance/`, protocol registry authority, domain transition engines, ledger/accounting semantics, external adapters, sibling Work Order scope.

Acceptance criteria:
- nested protocol values are deeply immutable after construction;
- relationship attributes cannot contain duplicate keys and round-trip losslessly;
- canonical JSON accepts only an explicit protocol-safe JSON value domain and rejects non-finite numeric values;
- integrity hashes are recomputed and verified during trusted deserialization/conformance paths;
- version transitions preserve immutable identity fields and reject changes to object type, domain, environment or protocol/schema identity unless an explicitly governed migration mechanism exists;
- adversarial tests cover tampering, mutability, duplicate-key loss, invalid canonical values and illegal identity transitions;
- implementation introduces no second authority and remains compatible with the frozen canonical ObjectEnvelope model.

Required proofs: static, dynamic, discrimination, transformation-completeness.
Dogfooding/conformance experiment: construct, serialize, tamper, deserialize and version a representative intent object graph; prove tampering and illegal mutations are rejected while valid round-trips remain lossless and byte-stable.

Definition of done: targeted verification passes, required adversarial/conformance evidence is persisted, scope audit is clean, Architect independently reviews the exact PR head and merges, and post-merge finalization records the actual Git merge.

## Findings addressed

- W002-1: shallow immutability can permit semantic mutation and duplicate attribute-key collapse.
- W002-2: integrity_hash is generated but not verified on deserialization.
- W002-3: canonical JSON does not explicitly constrain the protocol-safe JSON value domain.
- W002-4: next_version permits identity-domain fields to change across an ordinary version transition.
- W002-5: the existing six-test suite lacks discrimination coverage for these failure modes.

## Architect execution contract

- Authority: frozen `spec/architecture/v0.1/` plus this Work Order.
- Internal implementation choices are free inside owned surfaces when semantic behavior, safety, accounting, provenance, and public contracts remain equivalent.
- A dependency marked `implementation` must be merged on `main` before activation. A dependency marked `contract` means its public contract is consumable without using an unmerged sibling implementation.
- Any need to edit a forbidden authoritative surface, create a second authority, weaken a required invariant, or change protocol-visible semantics is an `ARCHITECTURE_BLOCKER`; stop and report it.
- The worker must verify exact base revision, dependency state, owned surfaces, required proofs, and dogfooding/conformance before PR.

## Required context

The worker context must include the exact current `main` revision, all dependency identities/types, this Work Order's owned and forbidden surfaces, the governing architecture version, assurance profile, required proofs, dogfooding/conformance contract, and protocol-registry reference.
