# PaySwap product execution handoff v0.2

This defines the product boundary after a selected workflow has been bound to a sealed sandbox `Intent`. The product may prepare a governed execution handoff, but the existing execution domain remains the sole owner of execution commands, external effects, retry/reconciliation, and observations.

## User model

`Outcome → Options → Decision → Protocol draft → Execution handoff → Waiting`

The handoff is a proposal for execution. It is not proof that execution has started.

## Handoff object

The product prepares a protocol-visible `payswap/execution-plan/v1` in `DRAFT` plus one internal `execution/step/v1` in `PENDING`. The plan references the bound intent. Adapter and reservation references remain opaque placeholders until governed execution infrastructure resolves them.

Human-readable recipient/customer fields stay in the product projection; the protocol receives canonical references.

## Authority boundary

The product must not authorize the execution plan, pin an exercised financial-effect authority class, invent fraud/compliance approval, reserve funds, select a real route or adapter, submit an external effect, interpret `UNKNOWN` as success/failure, or assert clearing, settlement, or finality.

The execution domain owns the command pipeline and its safety gates. External effect submission requires a configured typed adapter and covering authorization.

## Failure semantics

Failed preparation leaves the product task unchanged and reports an explicit preparation error. A prepared execution plan is never presented as running or completed.

This is intentionally a thin handoff adapter. A subsequent deployment integration can replace its opaque placeholders with governed capability, reservation, authorization, and adapter bindings without changing the user-facing workflow.
