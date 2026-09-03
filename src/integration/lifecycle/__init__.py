"""IG-002 fulfillment lifecycle integration gate (WORK-027) — public boundary.

The gate proves that the merged implementations of the canonical
financial chain preserve the frozen lifecycle invariants TOGETHER, by
composing them through their public command APIs in one environment
and asserting the cross-domain invariants after every accepted stage:

```text
Intent → Execution → Clearing → Obligation → Netting → Settlement
       → Finality
```

* the intent stretch uses the real intent-domain durable objects
  (the compiler domain's own public input contract);
* compilation runs through the real fulfillment compiler kernel
  (WORK-013) over real capability/market/liquidity/reservation/safety
  records (WORK-009/010/011/012/017);
* execution drives the real execution engine (WORK-014) whose external
  effects pass through the typed adapter ports bound to the canonical
  world-adapter contract (WORK-007 interoperability) — the gate itself
  is rail-agnostic and never touches a provider;
* clearing, obligations and netting run through the real clearing
  engine (WORK-015) from the sealed execution evidence;
* settlement, reconciliation and the finality certificate run through
  the real settlement engine (WORK-016) over leg-bound OBSERVED rail
  evidence (WORK-018 epistemic vocabulary);
* a payment status is never promoted to settlement finality; finality
  derives from the settlement domain's validated FINALITY-class claims
  over settled legs only (constitution §4 and invariant 11).

The gate is an integration composition over merged domains — it
introduces no domain semantics, no protocol-visible name beyond those
the consumed domains already register, and no second authority:
``CoreValidationError`` from ``src.core`` remains the single error
authority, re-exported here for convenience like every sibling domain.
This subpackage executes only gate ``IG-002``; the IG-001 gate owned by
the parent package stays frozen and untouched.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CONSUMED_SURFACES,
    KNOWN_LIFECYCLE_GATES,
    LIFECYCLE_API_VERSION,
    LIFECYCLE_GATE_ID,
    LIFECYCLE_SCHEMA_VERSION,
    validate_lifecycle_gate_id,
)
from .harness import FulfillmentLifecycleGate
from .invariants import verify_lifecycle_invariants
from .replay import assert_replay_equivalence, rebuild_lifecycle_gate
from .world import LifecycleWorld, build_declared_world

__all__ = [
    "CONSUMED_SURFACES",
    "CoreValidationError",
    "FulfillmentLifecycleGate",
    "KNOWN_LIFECYCLE_GATES",
    "LIFECYCLE_API_VERSION",
    "LIFECYCLE_GATE_ID",
    "LIFECYCLE_SCHEMA_VERSION",
    "LifecycleWorld",
    "assert_replay_equivalence",
    "build_declared_world",
    "rebuild_lifecycle_gate",
    "validate_lifecycle_gate_id",
    "verify_lifecycle_invariants",
]
