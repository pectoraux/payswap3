# Simulation, Replay, Forecast and Shadow

## One machine, many worlds

PaySwap uses one executable protocol machine. The environment supplies protocol state, world observations, models, clocks, randomness and an effect policy.

```text
             SAME PAYSWAP MACHINE
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
  SIMULATION      SHADOW      PRODUCTION
  simulated       live          live
  world           observations  world
  + effects       no effects    + effects
```

## State separation

Every environment has separate namespaces for protocol, value, trust, economic and dependency state. Simulation may contain a full ledger and simulated settlements, but they are not production financial effects.

## Promotion

```text
simulation → evidence → production decision → fresh validation → production authorization → real execution
```

Simulation state is never copied into production financial state.

## Modes

- `SIMULATION` — hypothetical world.
- `REPLAY` — historical observation/state reconstruction.
- `FORECAST` — generated future observations.
- `COUNTERFACTUAL` — branch from a snapshot with changed assumptions.
- `SHADOW` — live observations, non-production effects.
- `PRODUCTION` — live observations and authorized real effects.

## Parity invariant

Given the same protocol version, policy, extension versions, initial state, inputs and world observations, protocol transitions must be identical across environments.

## Simulation as debugger

Checkpoint, replay, step, branch and fault-injection operate over the real protocol state machine. No second business-logic implementation exists.

## Epistemic separation

The system distinguishes `OBSERVED`, `ESTIMATED`, `PREDICTED`, `SIMULATED`, and `COUNTERFACTUAL` knowledge and carries provenance, freshness and uncertainty.

## Production feedback

Predictions are compared with observations through `ForecastError` and calibration. Learning updates models and future proposals; it does not rewrite financial truth.
