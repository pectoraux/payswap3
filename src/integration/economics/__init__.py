"""IG-004 extension/agent economic integration gate (WORK-029) — public boundary.

The gate proves that the merged implementations compose TOGETHER on a
merchant demand scenario — agent + extension composition, authority
containment, simulation-first decision and economic contribution — by
driving ONLY public boundaries of already-merged surfaces:

* the WORK-020 extension runtime + capability marketplace: the REAL
  in-repo deterministic route-advisor extension is registered,
  sandbox-certified, reviewed, published, installed under a covering
  capability grant, invoked as a treatment, and its contribution is
  measured with counterfactual-baseline evidence and the exact
  integer revenue-share pricing;
* the WORK-021 models/agents/decision-mediation surface: REAL models
  are registered and approved, a REAL agent holds a bounded
  R2-PROPOSE mandate in a hypothetical-world-only context, submits
  route proposals, and the simulation-first mediation engine simulates
  every candidate in a SIMULATION-mode environment before the
  deterministic policy selects — the decision carries no execution
  authority;
* the WORK-028 IG-003 comparison authority: the merged public
  ``ClassifiedDifference`` diff walk classifies every residual
  cross-environment difference between the simulation and the
  production-compatible executions of the SAME declared composition as
  a semantic divergence that fails the gate closed;
* the real merchant checkout record boundary supplies the demand, and
  the merged money FX authority proves cross-currency conservation of
  the measured attribution (value is never created or destroyed).

The gate introduces no domain semantics and no second authority:
``CoreValidationError`` from ``src.core`` remains the single error
authority, re-exported here for convenience like every sibling domain.
This subpackage executes only gate ``IG-004``; every other gate id
fails closed here on purpose (one validator per gate — the house
discipline of every integration subpackage).

Identity: gate ``IG-004`` (``spec/integration-gates.md`` row
"extension/agent economic integration | WORK-020, 021, 028"), public
boundary version ``v0.1``, canonical economic-result schema version 1,
consumed surfaces ``src.core``, ``src.transition``, ``src.evidence``,
``src.value``, ``src.money``, ``src.merchant``, ``src.extensions``,
``src.agents``, ``src.simulation``, ``src.integration.parity``.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.integration.economics.contracts import (
    AGENTS_DOMAIN_ID,
    AGENT_PRINCIPAL,
    CONSUMED_SURFACES,
    CONTAINMENT_PROBES,
    CONTRIBUTION_ID,
    DECISION_ID,
    DEFAULT_ECONOMICS_ACTOR,
    DEMAND_ARTIFACT_ID,
    ECONOMICS_API_VERSION,
    ECONOMICS_ENV_BOUND_FIELDS,
    ECONOMICS_GATE_ID,
    ECONOMICS_NORMALIZATION_RULES,
    ECONOMICS_SCHEMA_VERSION,
    EXTENSIONS_DOMAIN_ID,
    EXTENSION_ID,
    INSTANCE_ID,
    KNOWN_ECONOMICS_GATES,
    MANDATE_ID,
    MEDIATION_ID,
    MERCHANT_CHECKOUT_ID,
    MERCHANT_DOMAIN_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    SIMULATION_ENVIRONMENT_ID,
    EconomicRole,
    validate_economics_gate_id,
)
from src.integration.economics.dogfooding import build_dogfood_transcript
from src.integration.economics.harness import (
    EconomicIntegrationGate,
    EconomicVerdict,
    assert_economic_parity,
)
from src.integration.economics.invariants import verify_economic_invariants
from src.integration.economics.projection import (
    economic_projection,
    economic_projection_digest,
    economic_state,
    normalize_economic_state,
)
from src.integration.economics.replay import assert_replay_equivalence, rebuild_economic_gate
from src.integration.economics.scenarios import (
    ContainmentProbeResult,
    run_containment_battery,
    run_contribution_integrity_scenario,
    run_economic_scenario,
)
from src.integration.economics.worlds import EconomicPair, EconomicWorld, build_economic_pair

__all__ = [
    "AGENTS_DOMAIN_ID",
    "AGENT_PRINCIPAL",
    "CONSUMED_SURFACES",
    "CONTAINMENT_PROBES",
    "CONTRIBUTION_ID",
    "ContainmentProbeResult",
    "CoreValidationError",
    "DECISION_ID",
    "DEFAULT_ECONOMICS_ACTOR",
    "DEMAND_ARTIFACT_ID",
    "ECONOMICS_API_VERSION",
    "ECONOMICS_ENV_BOUND_FIELDS",
    "ECONOMICS_GATE_ID",
    "ECONOMICS_NORMALIZATION_RULES",
    "ECONOMICS_SCHEMA_VERSION",
    "EXTENSIONS_DOMAIN_ID",
    "EXTENSION_ID",
    "EconomicIntegrationGate",
    "EconomicPair",
    "EconomicRole",
    "EconomicVerdict",
    "EconomicWorld",
    "INSTANCE_ID",
    "KNOWN_ECONOMICS_GATES",
    "MANDATE_ID",
    "MEDIATION_ID",
    "MERCHANT_CHECKOUT_ID",
    "MERCHANT_DOMAIN_ID",
    "PRODUCTION_COMPATIBLE_ENVIRONMENT_ID",
    "SIMULATION_ENVIRONMENT_ID",
    "assert_economic_parity",
    "assert_replay_equivalence",
    "build_dogfood_transcript",
    "build_economic_pair",
    "canonical_sha256",
    "economic_projection",
    "economic_projection_digest",
    "economic_state",
    "normalize_economic_state",
    "rebuild_economic_gate",
    "run_containment_battery",
    "run_contribution_integrity_scenario",
    "run_economic_scenario",
    "validate_economics_gate_id",
    "verify_economic_invariants",
]
