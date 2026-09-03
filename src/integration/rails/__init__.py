"""IG-005 external rail sandbox integration gate (WORK-030) — public boundary.

The gate exercises *canonical interoperability over at least two
rail-shaped adapters and the exception/investigation paths*
(``spec/integration-gates.md`` row IG-005) by composing ONLY
already-merged implementations:

* each rail world is the SAME protocol machine — the merged IG-002
  fulfillment lifecycle harness (WORK-027) over the real domain
  engines (compiler, execution, clearing, settlement) — bound to
  exactly ONE typed adapter binding;
* **rail A** is Stripe test mode (``REAL_PROVIDER_SANDBOX``): the
  merged WORK-027 ``StripeTestRail`` reused through import (never
  forked), its credential read from the ``STRIPE_SECRET_KEY``
  environment variable at call time and never stored, printed or
  committed;
* **rail B** is the public Stellar testnet (``REAL_PROVIDER_SANDBOX``):
  a NEW adapter — :class:`~src.integration.rails.stellar.StellarTestnetRail`
  — behind the SAME merged typed ports (WORK-014 over the WORK-007
  canonical world-adapter contract), credential-free (the testnet is
  an open public sandbox network), signing deterministic testnet
  transactions with a pure-Python RFC 8032 Ed25519 implementation
  pinned by the official test vectors and byte-golden envelopes
  verified against the live network;
* the **local deterministic pair** (the merged WORK-027
  ``LocalDeterministicRail``) drives the deterministic
  failure/investigation battery — transport ambiguity, reconciliation
  not-found, the unexpected provider status — classified
  ``LOCAL_DETERMINISTIC_SANDBOX`` and never counted as one of the two
  external rails (the classification is a frozen, validated,
  fail-closed vocabulary);
* the comparison target is CANONICAL semantics, never byte identity:
  the same canonical request drives both rails; the projection
  normalizes ONLY the frozen, per-field registered rail differences
  (provider-native references, native status words through the
  declared status maps, adapter/environment/domain identities, the
  declared per-rail asset pair, provider timestamps that never enter
  the canonical state, and the closed set of world-bound digest
  fields) with exact-value fail-closed validation; every other
  difference is a semantic divergence and fails the gate;
* amount values and scales, canonical outcome classes, failure
  classes, idempotency results, economic effects, settlement and
  finality states are NEVER normalized (pinned by the contract suite);
* the settlement/finality discipline is explicit: a provider payment
  status is never settlement finality — finality derives only from
  the merged WORK-016 settlement authority over settled legs, and the
  rails' finality claims are OBSERVED evidence only.

The gate is an integration/comparison authority only — it introduces
no domain semantics, no protocol-visible name beyond those the
consumed implementations already register, and no second authority of
any kind: ``CoreValidationError`` from ``src.core`` remains the single
error authority, re-exported here for convenience like every sibling
package. This subpackage executes only gate ``IG-005``; the IG-001,
IG-002 and IG-003 gates owned by the parent and the sibling packages
stay frozen and untouched.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CONSUMED_SURFACES,
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_RAILS_ACTOR,
    KNOWN_RAILS_GATES,
    LOCAL_RAIL_A_ADAPTER_ID,
    LOCAL_RAIL_A_DOMAIN_ID,
    LOCAL_RAIL_A_ENVIRONMENT_ID,
    LOCAL_RAIL_A_NAME,
    LOCAL_RAIL_B_ADAPTER_ID,
    LOCAL_RAIL_B_DOMAIN_ID,
    LOCAL_RAIL_B_ENVIRONMENT_ID,
    LOCAL_RAIL_B_NAME,
    LOCAL_RAIL_CURRENCY,
    RAILS_AMOUNT_MINOR,
    RAILS_API_VERSION,
    RAILS_ENV_BOUND_DIGEST_FIELDS,
    RAILS_GATE_ID,
    RAILS_NORMALIZATION_RULES,
    RAILS_DECLARED_CURRENCY,
    RAILS_PAYEE,
    RAILS_PAYER,
    RAILS_REJECTION_AMOUNT_MINOR,
    RAILS_SCHEMA_VERSION,
    RAIL_A_ADAPTER_ID,
    RAIL_A_CAPABILITY_ID,
    RAIL_A_CURRENCY,
    RAIL_A_DOMAIN_ID,
    RAIL_A_ENVIRONMENT_ID,
    RAIL_A_NAME,
    RAIL_B_ADAPTER_ID,
    RAIL_B_CAPABILITY_ID,
    RAIL_B_CURRENCY,
    RAIL_B_DOMAIN_ID,
    RAIL_B_ENVIRONMENT_ID,
    RAIL_B_NAME,
    RailClass,
    NormalizationRule,
    validate_rails_gate_id,
)
from .ed25519 import ed25519_public_key, ed25519_sign
from .stellar import (
    STELLAR_FEE_STROOPS,
    STELLAR_HORIZON_BASE,
    STELLAR_NETWORK_ID,
    STELLAR_STATUS_MAP,
    STELLAR_STROOPS_PER_XLM,
    STELLAR_TESTNET_PASSPHRASE,
    StellarTestnetRail,
    build_payment_envelope,
    build_payment_transaction_bytes,
    make_stellar_binding,
    make_stellar_status_map,
    make_stellar_world_adapter,
    stellar_transaction_hash,
    strkey_encode_account,
)
from .worlds import (
    RailWorld,
    build_local_rail_pair,
    build_rail_world_a,
    build_rail_world_b,
)
from .projection import (
    DECLARED_ASSET_TOKEN,
    DOMAIN_TOKEN,
    ENVIRONMENT_TOKEN,
    NATIVE_REFERENCE_TOKEN,
    NATIVE_STATUS_TOKEN,
    RAILS_NORMALIZATION_DIGEST,
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
    ExternalRailSandboxGate,
    RailComparisonVerdict,
    RailWorldExecutionReport,
    RailWorldPair,
    ScenarioOutcome,
    assert_semantic_equivalence,
)
from .invariants import verify_rails_invariants
from .scenarios import (
    run_failure_battery,
    run_rails_finality_discipline,
    run_rails_scenario_a,
    run_rails_scenario_b,
    run_rails_scenario_c,
    run_rails_scenario_d,
    shared_declared_input_digest,
)
from .replay import assert_rails_replay_equivalence, rebuild_rails_gate
from .dogfooding import (
    STRIPE_SECRET_ENV,
    build_local_dogfood_transcript,
    build_real_rails_transcript,
)
from src.integration.lifecycle.dogfooding import (  # merged WORK-027 rails
    LocalDeterministicRail,
    StripeTestRail,
)

__all__ = (
    "CONSUMED_SURFACES",
    "ClassifiedDifference",
    "DECLARED_ASSET_TOKEN",
    "DEFAULT_AUTHORIZED_ACTORS",
    "DEFAULT_RAILS_ACTOR",
    "DOMAIN_TOKEN",
    "ENVIRONMENT_TOKEN",
    "ExternalRailSandboxGate",
    "KNOWN_RAILS_GATES",
    "LOCAL_RAIL_A_ADAPTER_ID",
    "LOCAL_RAIL_A_DOMAIN_ID",
    "LOCAL_RAIL_A_ENVIRONMENT_ID",
    "LOCAL_RAIL_A_NAME",
    "LOCAL_RAIL_B_ADAPTER_ID",
    "LOCAL_RAIL_B_DOMAIN_ID",
    "LOCAL_RAIL_B_ENVIRONMENT_ID",
    "LOCAL_RAIL_B_NAME",
    "LOCAL_RAIL_CURRENCY",
    "LocalDeterministicRail",
    "NATIVE_REFERENCE_TOKEN",
    "NATIVE_STATUS_TOKEN",
    "NormalizationRule",
    "RAILS_AMOUNT_MINOR",
    "RAILS_API_VERSION",
    "RAILS_DECLARED_CURRENCY",
    "RAILS_ENV_BOUND_DIGEST_FIELDS",
    "RAILS_GATE_ID",
    "RAILS_NORMALIZATION_DIGEST",
    "RAILS_NORMALIZATION_RULES",
    "RAILS_PAYEE",
    "RAILS_PAYER",
    "RAILS_REJECTION_AMOUNT_MINOR",
    "RAILS_SCHEMA_VERSION",
    "RAIL_ADAPTER_TOKEN",
    "RAIL_A_ADAPTER_ID",
    "RAIL_A_CAPABILITY_ID",
    "RAIL_A_CURRENCY",
    "RAIL_A_DOMAIN_ID",
    "RAIL_A_ENVIRONMENT_ID",
    "RAIL_A_NAME",
    "RAIL_B_ADAPTER_ID",
    "RAIL_B_CAPABILITY_ID",
    "RAIL_B_CURRENCY",
    "RAIL_B_DOMAIN_ID",
    "RAIL_B_ENVIRONMENT_ID",
    "RAIL_B_NAME",
    "RailClass",
    "RailComparisonVerdict",
    "RailWorld",
    "RailWorldExecutionReport",
    "RailWorldPair",
    "STELLAR_FEE_STROOPS",
    "STELLAR_HORIZON_BASE",
    "STELLAR_NETWORK_ID",
    "STELLAR_STATUS_MAP",
    "STELLAR_STROOPS_PER_XLM",
    "STELLAR_TESTNET_PASSPHRASE",
    "STRIPE_SECRET_ENV",
    "ScenarioOutcome",
    "StellarTestnetRail",
    "StripeTestRail",
    "assert_rails_replay_equivalence",
    "assert_semantic_equivalence",
    "build_local_dogfood_transcript",
    "build_local_rail_pair",
    "build_payment_envelope",
    "build_payment_transaction_bytes",
    "build_rail_world_a",
    "build_rail_world_b",
    "build_real_rails_transcript",
    "compare_projections",
    "ed25519_public_key",
    "ed25519_sign",
    "make_stellar_binding",
    "make_stellar_status_map",
    "make_stellar_world_adapter",
    "normalize_semantic_state",
    "raw_state_digest",
    "rebuild_rails_gate",
    "run_failure_battery",
    "run_rails_finality_discipline",
    "run_rails_scenario_a",
    "run_rails_scenario_b",
    "run_rails_scenario_c",
    "run_rails_scenario_d",
    "semantic_projection",
    "semantic_projection_digest",
    "semantic_state",
    "shared_declared_input_digest",
    "stellar_transaction_hash",
    "strkey_encode_account",
    "validate_rails_gate_id",
    "verify_rails_invariants",
)
