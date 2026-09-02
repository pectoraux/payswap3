# Proof Matrix

Every Work Order must map its acceptance criteria to at least one proof class.

## Proof classes

- `static` — source/architecture boundary checks.
- `dynamic` — runtime behavior tests.
- `discrimination` — remove/bypass the claimed protection and prove the test fails.
- `transformation-completeness` — prove no semantic loss across representation boundaries.
- `quality-attribute` — measured performance/reliability/capacity/security property.
- `dogfooding` — real supported product path.
- `real-system` — actual PostgreSQL, crypto, rail sandbox, browser or other real dependency where the Work Order calls for it.

## Mandatory rules

CRITICAL Work Orders require static + dynamic + discrimination and the declared integration/dogfooding evidence. Any skipped proof requires an explicit Architect-recorded disposition.

A green unit suite without the required integration/dogfooding proof does not satisfy completion.
