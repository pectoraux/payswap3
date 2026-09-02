# Implementation Drift Control

Keep Z.ai workers autonomous inside their Work Order while making semantic drift difficult to introduce and easy to detect. Governance is intentionally small: one Architect, one Work Order contract, machine-checkable boundaries and feature-boundary evidence.

## Non-negotiable controls

1. Workers cannot change frozen architecture without an ACR.
2. Work Order scope is explicit and machine-checked.
3. Architectural contradictions stop implementation; they are never solved by worker intuition.
4. Critical boundaries require discrimination proofs, not only happy-path tests.
5. Real behavior is exercised through the supported product/protocol path.

## Semantic implementation freedom

Internal choices are free when they preserve the same public contract, authority boundaries, state-machine semantics, failure semantics, accounting, provenance, simulation/production semantics, security strength and dependency shape.

## Stop conditions

Report `IMPLEMENTATION_BLOCKED` when a contract is missing/ambiguous; an implementation dependency is unmerged; protected surfaces conflict; a forbidden authority must be edited; a registry name is missing; a second authority would be introduced; simulation/test could cause production financial effects; required provenance/authorization cannot be preserved; or frozen architecture semantics would need to change.

## Findings outside scope

Record them. The Architect decides whether to fix within scope, create a corrective Work Order, create an ACR, or record a non-blocking observation.

## Control loop

`READ → VALIDATE → DERIVE ELIGIBILITY → ACTIVATE → DISPATCH → REVIEW → MERGE → RECONCILE → RECOMPUTE`
