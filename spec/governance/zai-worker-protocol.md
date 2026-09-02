# Z.ai Worker Protocol

Z.ai is the intended implementation provider. The provider is replaceable; the protocol is not.

## Worker identity

A worker run is identified by:

```text
workerRunId
provider = zai
model
workOrderId
baseRevision
branch
```

## Required worker behavior

The worker must first inspect the repository and exact Work Order. It must not infer missing scope from chat history.

The worker reports:

```text
base revision
implementation revision
changed files
checks
proofs
dogfooding
known limitations
next action
```

## No authority elevation

The worker cannot:

- activate other Work Orders;
- merge its PR;
- modify frozen architecture;
- alter assurance requirements;
- change another Work Order's scope;
- create a second source of truth.

## Parallel operation

Many Z.ai workers may execute concurrently on independent Work Orders. The Architect remains the single review/merge authority.
