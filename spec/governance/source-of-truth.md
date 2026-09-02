# PaySwap Source of Truth

## Authority hierarchy

1. Frozen architecture version currently governing.
2. Architect-approved Work Orders and architecture-change records.
3. Repository Git history for implementation/merge facts.
4. Verification and dogfooding evidence for empirical facts.
5. Machine-readable development-state projections.
6. Agent reports and chat messages are non-authoritative summaries.

## Practical rule

When two artifacts disagree, do not average them.

Identify the owning authority and reconcile the weaker artifact to the stronger one.

## Implementation truth

A worker's prose never proves that a change exists. The exact Git revision and repository contents do.

A roadmap projection never proves that work is eligible. Dependencies, status and protected surfaces do.

A test report never proves architectural conformance by itself. The Architect checks the exact revision against the frozen architecture and Work Order.

A simulation result never proves that production is authorized to execute the same action. It proves behavior under a stated environment and policy; production requires fresh authority and fresh validation.
