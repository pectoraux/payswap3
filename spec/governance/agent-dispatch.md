# Agent Dispatch Protocol

## Principle

The Architect dispatches work from repository-derived eligibility. A worker receives a scope contract, not architectural authority.

## Dispatch context

Every dispatch contains:

```text
repository
currentMainRevision
workOrderId
architectureVersion
hardDependencies
contractDependencies
ownedSurfaces
forbiddenSurfaces
assuranceProfile
checkpointContract
requiredProofs
dogfoodingContract
protocolRegistry
stopConditions
```

The authoritative context schema is `agents/schemas/execution-context.schema.json`.

## Dispatch lifecycle

```text
ELIGIBLE
 → ACTIVATED
 → DISPATCHED
 → WORKING
 → READY_FOR_MERGE
 → ARCHITECT_REVIEW
 → MERGED
 → FINALIZED
```

A worker interruption does not lose authority or require chat reconstruction. The active resumption handoff belongs in `program-state.json` when the governance workflow chooses to use one.

## Parallel dispatch

Dispatch as many eligible Z.ai workers as the dependency graph safely permits.

For each candidate, prove:

```text
hard dependencies complete
AND
same stable base
AND
no unmerged sibling dependency
AND
no protected authoritative surface conflict
AND
no registry/architecture contradiction
```

## Failure handling

Worker findings are categorized as:

```text
WITHIN_SCOPE
OUT_OF_SCOPE
CONTRACT_BLOCKER
ARCHITECTURE_BLOCKER
ENVIRONMENT_BLOCKER
```

Only `WITHIN_SCOPE` findings may be fixed without a new governance decision.
