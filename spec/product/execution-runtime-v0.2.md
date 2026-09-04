# PaySwap product execution runtime v0.2

## Purpose

This slice closes the gap between a persisted execution handoff and a runnable governed execution path while keeping the product shell outside financial authority.

The product workflow remains:

`Outcome → Options → Decision → Protocol draft → Execution handoff → Execution → Evidence → Resolution`

## Runtime modes

`PAYSWAP_EXECUTION_MODE=unconfigured` is the safe default. In this mode a product request does not attempt an external effect and remains explicitly waiting for execution infrastructure.

`PAYSWAP_EXECUTION_MODE=sandbox` is a development/dogfooding mode. It uses the repository's deterministic sandbox adapter through the real `ExecutionEngine` and transition kernel. This proves the command, authorization, effect, idempotency, and state-transition path without moving real funds.

A production deployment must supply a real `AdapterBinding` and its external service outside the product shell. Production credentials, routing authority, reservation authority, and safety decisions are never synthesized by the Flask application.

## Execution semantics

A product task may execute only after a protocol draft and execution handoff have both been persisted. The handoff's sealed execution plan is immutable. Sandbox resolution creates a new execution plan with a concrete sandbox adapter and held sandbox reservation declaration, then runs the plan through the existing execution domain.

The runtime records:

- execution plan and step state;
- concrete adapter identity;
- sandbox authorization and reservation markers;
- external effect result;
- native reference;
- settlement and finality as explicitly **not claimed**.

The product then advances the task to `COMPLETED` only for the observed sandbox execution result. This status does not imply settlement or finality.

## Failure semantics

An unconfigured runtime fails closed without attempting an effect. Execution errors leave the task in `WAITING` and do not manufacture a success state. Owner scoping and CSRF requirements remain unchanged.

## Authority boundary

The product does not own the execution transition kernel, real authorization, market routing, reservation capacity, external rail effects, retry/reconciliation policy, clearing, settlement, or finality. It coordinates user experience and stores projections of the outcomes returned by those authorities.
