# Implementation Principles

1. Repository source of truth; never depend on conversation memory.
2. Architecture is consumed, not reinterpreted by workers.
3. One authority per concept; no shadow authority.
4. Ports over providers; external dependencies remain replaceable.
5. Same semantics across simulation, replay, shadow and production.
6. Fail closed on unknown policy, identity, evidence, version or state.
7. Financial calculations use deterministic fixed-point arithmetic.
8. External effects are idempotent where possible and reconciled before unsafe retry.
9. Immutable history; corrections are new events/postings.
10. Parallelism requires dependency eligibility plus disjoint protected authoritative surfaces.
11. Parallel siblings start from the same stable base and never rebase onto one another.
12. Integration work happens only after required siblings merge.
13. Every user-facing or execution-facing feature has a real-product dogfooding experiment.
14. Mutation/discrimination tests are required for critical authority boundaries.
15. Findings are persisted and routed to owned follow-up work; scope does not silently expand.
16. Architect is the sole merge gate.
17. Completion requires verified implementation + required dogfooding/conformance + architect merge + post-merge reconciliation.
