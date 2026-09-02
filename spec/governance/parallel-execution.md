# Parallel Execution Protocol

Parallelism is the default where safe.

## Parallel-safe conditions

Two Work Orders may execute concurrently when:

1. all hard dependencies are complete;
2. neither consumes the other's unmerged implementation;
3. their protected authoritative surfaces are disjoint;
4. they do not compete for the same migration/schema/registry ownership;
5. both use the same stable main base;
6. neither requires an unmerged shared application composition surface to make its own contract true.

## No-rebase sibling rule

Parallel siblings never rebase onto one another. A sibling may only consume merged mainline contracts.

## Integration

When capabilities must be combined, use an `IG-*` integration gate after the required Work Orders merge. The integration gate owns the composition change and its cross-feature proof.

## Conflict model

Protected surfaces may be:

- `exclusive` — one Work Order only;
- `shared-read` — many readers, one owner;
- `integration-only` — siblings do not edit; an integration gate owns changes;
- `governance-shared` — may be reconciled by the Architect after independent implementation.

## Quality invariant

Parallelism may reduce elapsed time, but it may not reduce assurance, verification, dogfooding or review depth.
