# PaySwap product execution handoff v0.2

## Purpose

This defines the product boundary after a selected workflow has been bound to a sealed sandbox `Intent`.

The product shell may prepare a governed execution handoff, but it must not become the execution authority. The existing execution domain remains the sole owner of execution commands, external effects, retry/reconciliation, and observations.

## User model

`Outcome → Options → Decision → Protocol draft → Execution handoff → Waiting`

After a protocol draft exists, the product can prepare a protocol-visible execution plan in `DRAFT` plus a `PENDING` step. This is a proposal for the governed execution path, not evidence that execution has started.

## Handoff object

The product prepares:

- `payswap/execution-plan/v1` in `DRAFT` state;
- one internal `execution/step/v1` in `PENDING` state;
- the bound intent id as the plan `source_ref`;
- opaque adapter and reservation references that must be resolved by governed execution infrastructure before authorization.

The step payload contains protocol references and the product workflow id. Human-readable customer/recipient fields remain in the product projection.

## Authority boundary

The product must not authorize the execution plan, pin an exercised financial-effect authority class, invent fraud/compliance approval, reserve funds, select a real route or adapter, submit an external effect, interpret `UNKNOWN` as success/failure, or assert clearing, settlement, or finality.

The execution domain owns the command pipeline and its own authorization and safety gates. External effect submission requires a configured typed adapter and covering authorization.

## Failure semantics

Failed preparation leaves the product task unchanged and reports an explicit preparation error. A prepared execution plan is never presented as running or completed.

This is intentionally a thin handoff adapter. A subsequent deployment integration can replace its opaque placeholders with governed capability, reservation, authorization, and adapter bindings without changing the user-facing workflow.
