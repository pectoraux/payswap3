"""IG-003 simulation parity integration gate (WORK-028) — public boundary.

The gate proves *identical protocol semantics across simulation and
production-compatible environments* (``spec/integration-gates.md`` row
IG-003) by composing ONLY already-merged implementations:

* the two compared environments are the SAME protocol machine — the
  merged IG-002 fulfillment lifecycle harness (WORK-027) over the real
  domain engines (compiler, execution, clearing, settlement) — bound
  to two environment harnesses that differ ONLY in their environment
  binding:
  - the **simulation world**: a sandbox-class environment whose rail
    adapter declares SIMULATION fidelity and whose every outcome is
    served by the merged WORK-019 deterministic world-adapter boundary
    (a :class:`~src.simulation.ScriptedWorld` of ``SIMULATED``
    observations, the frozen mode→epistemic binding);
  - the **production-compatible world**: a production-class environment
    whose rail adapter declares PRODUCTION fidelity, drives the same
    typed execution ports (WORK-014 over the WORK-007 canonical world
    adapter contract) and consumes ``OBSERVED`` world observations;
* the canonical requirement is SEMANTIC parity, not byte identity: the
  parity authority projects both executions canonically, applies the
  frozen field-bound normalization layer (environment identity, rail
  adapter identity, provider-issued references; a closed, per-field
  justified set of environment-bound digest exclusions), classifies
  every residual difference as a semantic divergence and fails closed
  on it;
* the epistemic provenance is preserved and reported, never normalized
  away: the simulation world's evidence is exactly ``SIMULATED`` and
  the production-compatible world's is exactly ``OBSERVED`` (the
  frozen WORK-019 vocabulary), while execution-domain external
  observations stay ``OBSERVED`` knowledge in both worlds (the frozen
  execution contract);
* the required scenarios (canonical success, rejection, idempotency,
  recovery, finality discipline) are driven through the public IG-002
  stage API in lockstep with identical declared inputs, and the
  13-dimension parity invariant battery runs on both worlds after
  every comparison.

The gate is an integration/comparison authority only — it introduces
no domain semantics, no protocol-visible name beyond those the
consumed implementations already register, and no second authority of
any kind: ``CoreValidationError`` from ``src.core`` remains the single
error authority, re-exported here for convenience like every sibling
package. This subpackage executes only gate ``IG-003``; the IG-001 and
IG-002 gates owned by the parent and the lifecycle sibling packages
stay frozen and untouched.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CONSUMED_SURFACES,
    ENV_BOUND_DIGEST_FIELDS,
    KNOWN_PARITY_GATES,
    NORMALIZATION_RULES,
    PARITY_API_VERSION,
    PARITY_DOMAIN_ID,
    PARITY_GATE_ID,
    PARITY_SCHEMA_VERSION,
    PRODUCTION_ADAPTER_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    SIMULATION_ADAPTER_ID,
    SIMULATION_ENVIRONMENT_ID,
    NormalizationRule,
    WorldRole,
    validate_parity_gate_id,
)
from .worlds import (
    DeclaredRailScript,
    EnvironmentPair,
    ParityRail,
    ParityWorld,
    build_environment_pair,
)
from .projection import (
    ENVIRONMENT_TOKEN,
    NATIVE_REFERENCE_TOKEN,
    NORMALIZATION_DIGEST,
    RAIL_ADAPTER_TOKEN,
    ClassifiedDifference,
    compare_projections,
    normalize_semantic_state,
    raw_state_digest,
    semantic_projection,
    semantic_projection_digest,
    semantic_state,
)
from .harness import (
    EpistemicProvenanceReport,
    ParityVerdict,
    ScenarioResult,
    SimulationParityGate,
    WorldExecutionReport,
    assert_semantic_parity,
)
from .invariants import verify_parity_invariants
from .scenarios import (
    run_parity_scenario,
    run_scenario_e_finality_discipline,
)
from .replay import assert_replay_equivalence, rebuild_parity_gate

__all__ = [
    "CONSUMED_SURFACES",
    "ClassifiedDifference",
    "CoreValidationError",
    "ENVIRONMENT_TOKEN",
    "ENV_BOUND_DIGEST_FIELDS",
    "EnvironmentPair",
    "EpistemicProvenanceReport",
    "NATIVE_REFERENCE_TOKEN",
    "NORMALIZATION_DIGEST",
    "NORMALIZATION_RULES",
    "NormalizationRule",
    "PARITY_API_VERSION",
    "PARITY_DOMAIN_ID",
    "PARITY_GATE_ID",
    "PARITY_SCHEMA_VERSION",
    "PRODUCTION_ADAPTER_ID",
    "PRODUCTION_COMPATIBLE_ENVIRONMENT_ID",
    "ParityRail",
    "ParityVerdict",
    "ParityWorld",
    "RAIL_ADAPTER_TOKEN",
    "SIMULATION_ADAPTER_ID",
    "SIMULATION_ENVIRONMENT_ID",
    "ScenarioResult",
    "SimulationParityGate",
    "WorldExecutionReport",
    "WorldRole",
    "assert_replay_equivalence",
    "assert_semantic_parity",
    "build_environment_pair",
    "compare_projections",
    "normalize_semantic_state",
    "raw_state_digest",
    "rebuild_parity_gate",
    "run_parity_scenario",
    "run_scenario_e_finality_discipline",
    "semantic_projection",
    "semantic_projection_digest",
    "semantic_state",
    "validate_parity_gate_id",
    "verify_parity_invariants",
]