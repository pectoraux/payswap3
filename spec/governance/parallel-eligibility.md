# Parallel Eligibility

Parallel eligibility is derived, never declared solely by a worker.

A candidate Work Order is eligible when:

```text
all hard dependencies COMPLETE
AND
no forbidden-surface conflict
AND
owned authoritative surface is unclaimed by another active Work Order
AND
base revision satisfies current governance expectation
AND
required architecture version is governing
```

Parallel siblings may share contracts, types or read-only APIs, but they may not concurrently own the same authoritative mutation surface.

When composition requires shared editing, create an integration Work Order rather than relaxing the conflict rule.
