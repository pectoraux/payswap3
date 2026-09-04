# Product execution handoff v0.2

## Purpose

This document defines the next product boundary after a selected workflow has been bound to a sealed sandbox `Intent`.

The product shell may prepare an execution handoff, but it does not become the execution authority. The frozen execution domain remains the sole owner of execution commands, effect submission, retry/reconciliation, and external observations.

## User model

The visible progression remains:

`Outcome → Options → Decision → Protocol draft → Waiting for governed execution`

After a protocol draft exists, the product exposes an **execution handoff ready** state. The handoff contains a protocol-visible execution plan in `DRAFT` plus its pending step declaration. It is a proposal for the governed execution path, not proof that execution has started.

## Handoff object

The product prepares:

- `payswap/execution-plan/v1` in `DRAFT` state;
- one internal `execution/step/v1` in `PENDING` state;
- the intent object id as the plan `source_ref`;
- an opaque reservation reference placeholder and adapter reference that must be resolved by governed execution infrastructure before authorization.

The step payload carries only canonical product/protocol references. Human-readable recipient/customer fields stay in the product projection.

## Authority boundary

The product must not:

- authorize the execution plan;
- pin an exercised execution authority class;
- invent fraud or compliance approvals;
- reserve funds;
- choose a real adapter or market route;
- submit an external effect;
- interpret `UNKNOWN` as failure or success;
- assert clearing, settlement, or finality.

The execution domain owns the command pipeline and requires its own authorization and safety gates before financial effect. External effect submission requires a typed adapter and covering authorization.

## Failure semantics

A failed preparation produces an explicit user-visible error and leaves the product task at its prior state. A prepared `DRAFT` execution plan is never displayed as running or completed.

This handoff is deliberately a thin adapter: the next integration phase must connect these persisted proposals to a configured execution service with real capability, reservation, authorization, and adapter bindings.
