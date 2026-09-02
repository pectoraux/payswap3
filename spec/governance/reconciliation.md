# Governance Reconciliation

Reconciliation is a deterministic comparison between repository-resident state and authoritative Git facts.

## Red conditions

- Git shows a merged Work Order while program-state says `in_flight`.
- active handoff references a completed Work Order.
- a future Work Order disappears from the roadmap/identity surface.
- a Work Order depends on unknown or incomplete implementation work.
- derived frontier disagrees with authoritative state.

## Resolution

Reconciliation records the real fact; it does not create approval, alter scope or lower assurance.

Historical records remain intact. Current truth is recomputed rather than rewritten into history.
