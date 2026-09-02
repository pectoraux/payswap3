# Dogfooding Protocol

Tests prove implementation correctness. Dogfooding proves the integrated product/capability works through the real supported path.

## Lifecycle

```text
tests green → real supported surface executable → DOGFOODING RUN → record evidence → classify
```

Classifications: `PASS`, `CONTRACT_FAILURE`, `UX_FAILURE`, `OPERATIONAL_FAILURE`, `ENVIRONMENT_BLOCKED`.

## Required experiment record

Record Work Order, exact revision, architecture version, environment/surface, task, starting state, expected outcome, observed outcome, evidence, relevant duration/cost, limitations and resulting action.

## Safety

Production destructive effects are forbidden merely to prove correctness. Use isolated tenants, test accounts, sandbox rails, explicit human confirmation or simulated effects.

## Finding discipline

A finding is evidence, not scope authority. Fix it only when owned; otherwise create targeted follow-up work.

## Anti-repeat

A milestone cannot advance solely because tests are green. Each user-facing/execution-facing boundary requires a real-product experiment or equivalent conformance evidence.
