"""PaySwap fulfillment compiler domain (WORK-013).

The public boundary is typed and versioned:

- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` (identity, state, provenance,
  version chain, integrity hash) owned by ``src.core`` and carries a
  compiler domain seal computed with the single canonical hash authority
  (``src.core.serialization.canonical_sha256``), so tampered or spliced
  objects fail closed on the trusted deserialization path;
- the ONLY registry-listed, protocol-visible object type owned here is
  ``payswap/fulfillment-plan/v1``; all other object kinds use internal
  non-registry ``compiler/...`` formats per the sibling convention, and no
  new registry name is invented (the registry is frozen);
- kernel event types live in the frozen registry's ``intent`` namespace
  (``intent/fulfillment-compiled`` etc.) because the registry has NO
  ``fulfillment`` namespace — fulfillment compiles an intent into a plan,
  so ``intent/<...>`` is the semantically correct frozen namespace;
  command types are internal free-form strings
  (``compiler/fulfillment.compile/recompile/accept/reject/invalidate``)
  implementing the frozen ``Fulfillment`` command family;
- economic optimization implements the constitution's constraint
  precedence explicitly: hard gates in the frozen order
  ``compliance > authority > settlement > safety > accounting`` reject
  candidates outright, and only then do the soft objectives (the intent
  domain's closed ten-member ``OptimizationObjective`` vocabulary) rank
  the feasible candidates lexicographically, with the canonical shape
  digest as the deterministic final tie-break — no objective can ever
  override a hard constraint, and no entropy exists anywhere;
- monetary arithmetic is exact: in-route FX conversions run through the
  money authority's exact ``convert`` under the frozen compiler rounding
  mode with explicit residuals; fees through the market authority's exact
  ``fee_for_fill``; cross-asset fee composition is exact rational
  arithmetic rounded once by the money rounding authority; payment splits
  through the money authority's exact ``allocate_equal``. No floating
  point is ever constructed;
- determinism: the same declared inputs (explicit ``as_of``, hop offers,
  intent, policy, slack) always compile to the byte-identical plan and
  plan digest — the deterministic semantic-equivalence proof;
- this domain is a PROPOSAL domain: it compiles intents into sealed
  fulfillment plans and advances their lifecycle. It NEVER executes
  external effects, NEVER posts to any ledger and NEVER grants authority
  (constitution invariants 3, 14, 18 — no second authority). The sibling
  domains (money, intent, capability, market, liquidity, reservation,
  safety) are consumed through their public contracts as declared input
  data only; unmerged sibling implementations are never imported;
- every failure path is explicit and fails closed on unknown policy,
  identity, evidence, version or state via the single error authority
  ``src.core.errors.CoreValidationError``.
"""

from __future__ import annotations

from .contracts import (
    AUTHORITY_TIER_RANK,
    BPS_DENOMINATOR,
    COMPILATION_INPUT_TYPE,
    COMPILATION_REQUEST_TYPE,
    COMPILER_ACCEPT_COMMAND,
    COMPILER_API_VERSION,
    COMPILER_AUTHORITY_CLASS,
    COMPILER_COMMANDS,
    COMPILER_COMPILE_COMMAND,
    COMPILER_COST_ROUNDING_MODE,
    COMPILER_EVENTS,
    COMPILER_EVENTS_BY_COMMAND,
    COMPILER_EVENT_NAMESPACE,
    COMPILER_FX_ROUNDING_MODE,
    COMPILER_INVALIDATE_COMMAND,
    COMPILER_PROTOCOL_VERSION,
    COMPILER_RECOMPILE_COMMAND,
    COMPILER_REJECT_COMMAND,
    COMPILER_SCHEMA_VERSION,
    FULFILLMENT_ACCEPTED_EVENT,
    FULFILLMENT_COMPILED_EVENT,
    FULFILLMENT_INVALIDATED_EVENT,
    FULFILLMENT_PLAN_OBJECT_TYPE,
    FULFILLMENT_PLAN_SPEC_TYPE,
    FULFILLMENT_RECOMPILED_EVENT,
    FULFILLMENT_REJECTED_EVENT,
    HARD_GATE_ACCOUNTING,
    HARD_GATE_AUTHORITY,
    HARD_GATE_COMPLIANCE,
    HARD_GATE_PRECEDENCE,
    HARD_GATE_SAFETY,
    HARD_GATE_SETTLEMENT,
    HARD_GATES,
    MAX_ROUTE_HOPS,
    MAX_SHAPE_CANDIDATES,
    PLAN_TERMINAL_STATES,
    PLAN_TRANSITIONS,
    RUNNER_UP_DIGEST_COUNT,
    ROUTE_HOP_OFFER_TYPE,
    PlanState,
)
from .compile import compile_fulfillment, compile_from_input
from .engine import COMPILER_PROVENANCE_SOURCE, FulfillmentCompiler
from .inputs import CompilationInput, CompilationRequest, RouteHopOffer
from .plan import (
    FulfillmentPlan,
    FulfillmentPlanSpec,
    HopPlanSpec,
    PaymentPlanSpec,
)

__all__ = [
    # typed, versioned public boundary
    "COMPILER_PROTOCOL_VERSION",
    "COMPILER_SCHEMA_VERSION",
    "COMPILER_API_VERSION",
    # object types (registry-listed + internal non-registry)
    "FULFILLMENT_PLAN_OBJECT_TYPE",
    "ROUTE_HOP_OFFER_TYPE",
    "COMPILATION_REQUEST_TYPE",
    "COMPILATION_INPUT_TYPE",
    "FULFILLMENT_PLAN_SPEC_TYPE",
    # frozen Fulfillment command family (internal command types)
    "COMPILER_COMMANDS",
    "COMPILER_COMPILE_COMMAND",
    "COMPILER_RECOMPILE_COMMAND",
    "COMPILER_ACCEPT_COMMAND",
    "COMPILER_REJECT_COMMAND",
    "COMPILER_INVALIDATE_COMMAND",
    "COMPILER_PROVENANCE_SOURCE",
    # kernel event types (frozen registry 'intent' namespace)
    "COMPILER_EVENT_NAMESPACE",
    "COMPILER_EVENTS",
    "COMPILER_EVENTS_BY_COMMAND",
    "FULFILLMENT_COMPILED_EVENT",
    "FULFILLMENT_RECOMPILED_EVENT",
    "FULFILLMENT_ACCEPTED_EVENT",
    "FULFILLMENT_REJECTED_EVENT",
    "FULFILLMENT_INVALIDATED_EVENT",
    "COMPILER_AUTHORITY_CLASS",
    # hard-constraint precedence (constitution order)
    "HARD_GATE_COMPLIANCE",
    "HARD_GATE_AUTHORITY",
    "HARD_GATE_SETTLEMENT",
    "HARD_GATE_SAFETY",
    "HARD_GATE_ACCOUNTING",
    "HARD_GATE_PRECEDENCE",
    "HARD_GATES",
    # frozen deterministic arithmetic constants
    "BPS_DENOMINATOR",
    "COMPILER_FX_ROUNDING_MODE",
    "COMPILER_COST_ROUNDING_MODE",
    "MAX_ROUTE_HOPS",
    "MAX_SHAPE_CANDIDATES",
    "RUNNER_UP_DIGEST_COUNT",
    "AUTHORITY_TIER_RANK",
    # plan lifecycle
    "PlanState",
    "PLAN_TERMINAL_STATES",
    "PLAN_TRANSITIONS",
    # public value objects
    "RouteHopOffer",
    "CompilationRequest",
    "CompilationInput",
    "HopPlanSpec",
    "PaymentPlanSpec",
    "FulfillmentPlanSpec",
    "FulfillmentPlan",
    # the compiler
    "compile_fulfillment",
    "compile_from_input",
    "FulfillmentCompiler",
]
