# PaySwap Agent Operating Model

PaySwap implementation uses one Architect/reviewer and a pool of bounded Z.ai implementation workers.

The Architect is consequentially authoritative. Workers execute Work Orders; they do not redefine architecture, activate other Work Orders, merge, or approve themselves.

## Roles

- `architect` — sole architecture/review/merge authority.
- `implementation-worker` — bounded Z.ai worker implementing exactly one Work Order.
- `integration-worker` — bounded worker for an `IG-*` Work Order after dependencies merge.
- `dogfooding-worker` — executes an authorized real-product experiment without acquiring code/architecture authority.

See `roles.json`, `zai-worker-prompt.md`, and `schemas/execution-context.schema.json`.
