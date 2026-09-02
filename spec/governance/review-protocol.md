# Architect Review Protocol

There is one consequential reviewer: the Architect.

## Review order

1. Verify exact repository base, branch and head.
2. Verify Work Order identity and status.
3. Verify architecture version and relevant frozen contract.
4. Verify dependency eligibility.
5. Verify owned/forbidden/change surfaces.
6. Inspect public contracts and authority boundaries.
7. Inspect state transitions, failure, retry, timeout and reconciliation semantics.
8. Inspect accounting/conservation where value is affected.
9. Inspect simulation/replay/shadow/production parity where applicable.
10. Verify required proofs, including discrimination proofs where required.
11. Verify exact dogfooding/conformance evidence and provenance.
12. Audit the diff for unrelated scope.
13. Decide `APPROVE`, `CHANGES_REQUESTED`, or `ARCHITECTURE_CHANGE_REQUIRED`.

## Semantic equivalence rule

The Architect should not prescribe internal implementation style when multiple implementations satisfy the same frozen contract with equal or stronger safety.

## Mandatory CRITICAL scrutiny

CRITICAL work receives explicit scrutiny for:

- authority and delegation;
- monetary arithmetic and conservation;
- ledger/posting integrity;
- concurrency/idempotency;
- external effect reconciliation;
- settlement/finality;
- security/tenant/data isolation;
- federation/cross-domain state;
- simulation/production parity;
- extension isolation and economic exposure;
- evidence/provenance completeness;
- loss/default/recovery semantics.

A green test suite never substitutes for contract review.

## Review output

Every review records the exact head reviewed, verdict, findings, required evidence, and whether an architecture-change request is required.
