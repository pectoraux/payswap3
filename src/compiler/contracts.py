"""Typed and versioned public contracts for the compiler domain (WORK-013).

Frozen authorities consumed (never redefined here):

- ``spec/architecture/v0.1/constitution.md`` — the optimization clause:
  hard constraints (legal, authority, settlement, safety, accounting)
  dominate the soft objectives (cost, reliability, time, capital
  efficiency, ...); the ten objective dimensions are the intent domain's
  closed ``OptimizationObjective`` vocabulary;
- ``spec/architecture/v0.1/command-event-model.md`` — the frozen
  ``Fulfillment: Compile/Recompile/Accept/Reject/Invalidate`` command
  family, implemented as internal command types
  ``compiler/fulfillment.<verb>`` per the W026 sibling convention that
  command types are internal free-form strings;
- ``spec/registry/protocol-registry.json`` — the ONLY registry-listed
  object type owned here is ``payswap/fulfillment-plan/v1``. The registry
  has NO ``fulfillment`` event namespace, so kernel event types use the
  semantically correct frozen ``intent`` namespace: fulfillment compiles
  an intent into a plan, so ``intent/fulfillment-*`` events are the
  natural protocol-visible projection. The choice is documented here and
  in the package docstring; no registry name is invented or edited.

Hard-constraint precedence (the constitution's order): compliance/legal,
then authority, then settlement, then safety, then accounting. A candidate
failing a hard gate is rejected at the FIRST failing gate in this order —
no soft objective can ever override it.
"""

from __future__ import annotations

from enum import StrEnum

from src.money.rounding import RoundingMode

# -- typed, versioned public boundary ---------------------------------------

COMPILER_PROTOCOL_VERSION = "v0.1"
COMPILER_SCHEMA_VERSION = 1
COMPILER_API_VERSION = 1

# Registry-listed, protocol-visible object type of the durable fulfillment
# plan (the only registry-listed name this domain owns).
FULFILLMENT_PLAN_OBJECT_TYPE = "payswap/fulfillment-plan/v1"

# Internal (non-registry) type identifiers of the compiler's public value
# objects. They deliberately do not use registry-visible formats.
ROUTE_HOP_OFFER_TYPE = "compiler/route-hop-offer/v1"
COMPILATION_REQUEST_TYPE = "compiler/compilation-request/v1"
COMPILATION_INPUT_TYPE = "compiler/compilation-input/v1"
FULFILLMENT_PLAN_SPEC_TYPE = "compiler/fulfillment-plan-spec/v1"

# -- frozen Fulfillment command family (internal command types) -------------

#: Documented mapping to the frozen command family
#: ``Fulfillment: Compile/Recompile/Accept/Reject/Invalidate``.
COMPILER_COMPILE_COMMAND = "compiler/fulfillment.compile"
COMPILER_RECOMPILE_COMMAND = "compiler/fulfillment.recompile"
COMPILER_ACCEPT_COMMAND = "compiler/fulfillment.accept"
COMPILER_REJECT_COMMAND = "compiler/fulfillment.reject"
COMPILER_INVALIDATE_COMMAND = "compiler/fulfillment.invalidate"

COMPILER_COMMANDS = frozenset(
    {
        COMPILER_COMPILE_COMMAND,
        COMPILER_RECOMPILE_COMMAND,
        COMPILER_ACCEPT_COMMAND,
        COMPILER_REJECT_COMMAND,
        COMPILER_INVALIDATE_COMMAND,
    }
)

# -- kernel event types (frozen registry 'intent' namespace) -----------------
#
# Registry discipline: the frozen protocol registry lists event namespaces
# intent/market/reservation/execution/clearing/settlement/risk/extension/
# simulation/governance. There is no 'fulfillment' namespace, so the
# compiler emits its lifecycle events in the 'intent' namespace — the
# fulfillment compiler is the component that turns an intent into a plan.
# Every type below is validated against the frozen registry at import time
# by the test suite and by the transition kernel at registration time.

COMPILER_EVENT_NAMESPACE = "intent"
FULFILLMENT_COMPILED_EVENT = "intent/fulfillment-compiled"
FULFILLMENT_RECOMPILED_EVENT = "intent/fulfillment-recompiled"
FULFILLMENT_ACCEPTED_EVENT = "intent/fulfillment-accepted"
FULFILLMENT_REJECTED_EVENT = "intent/fulfillment-rejected"
FULFILLMENT_INVALIDATED_EVENT = "intent/fulfillment-invalidated"

COMPILER_EVENTS = frozenset(
    {
        FULFILLMENT_COMPILED_EVENT,
        FULFILLMENT_RECOMPILED_EVENT,
        FULFILLMENT_ACCEPTED_EVENT,
        FULFILLMENT_REJECTED_EVENT,
        FULFILLMENT_INVALIDATED_EVENT,
    }
)

#: Frozen command → kernel event mapping of the Fulfillment family.
COMPILER_EVENTS_BY_COMMAND = {
    COMPILER_COMPILE_COMMAND: FULFILLMENT_COMPILED_EVENT,
    COMPILER_RECOMPILE_COMMAND: FULFILLMENT_RECOMPILED_EVENT,
    COMPILER_ACCEPT_COMMAND: FULFILLMENT_ACCEPTED_EVENT,
    COMPILER_REJECT_COMMAND: FULFILLMENT_REJECTED_EVENT,
    COMPILER_INVALIDATE_COMMAND: FULFILLMENT_INVALIDATED_EVENT,
}

#: Registry authority class exercised by the compiler's kernel authorizer
#: (same class the IG-001 integration gate uses for protocol-object
#: lifecycle commands). The compiler never grants authority itself: it
#: proposes plans only.
COMPILER_AUTHORITY_CLASS = "A1"

# -- hard-constraint precedence (constitution order) -------------------------

HARD_GATE_COMPLIANCE = "compliance"
HARD_GATE_AUTHORITY = "authority"
HARD_GATE_SETTLEMENT = "settlement"
HARD_GATE_SAFETY = "safety"
HARD_GATE_ACCOUNTING = "accounting"

HARD_GATE_PRECEDENCE = (
    HARD_GATE_COMPLIANCE,
    HARD_GATE_AUTHORITY,
    HARD_GATE_SETTLEMENT,
    HARD_GATE_SAFETY,
    HARD_GATE_ACCOUNTING,
)
HARD_GATES = frozenset(HARD_GATE_PRECEDENCE)

# -- frozen deterministic arithmetic constants -------------------------------

#: Basis-point denominator of prices, reliability scores and risk weights.
BPS_DENOMINATOR = 10000

#: Rounding mode of every in-route FX conversion (deterministic, floor).
COMPILER_FX_ROUNDING_MODE = RoundingMode.FLOOR

#: Rounding mode used only when reporting cross-asset fees in the intent
#: asset for the COST objective (exact integer cross-asset composition
#: through the money rounding authority).
COMPILER_COST_ROUNDING_MODE = RoundingMode.HALF_EVEN

#: Structural bound on route length (simple paths over substitute assets).
MAX_ROUTE_HOPS = 4

#: Structural bound on the enumerated payment-shape candidates; exceeding
#: it fails closed with an explicit message (deterministic enumeration
#: must stay bounded).
MAX_SHAPE_CANDIDATES = 1024

#: Number of runner-up candidate digests preserved in the plan for
#: decision provenance (constitution invariant 13).
RUNNER_UP_DIGEST_COUNT = 2


class PlanState(StrEnum):
    """Closed lifecycle of the durable fulfillment plan.

    Models the frozen ``Fulfillment: Compile/Recompile/Accept/Reject/
    Invalidate`` command family. ``ACCEPTED`` hands the plan to the
    execution domain (WORK-014, not merged at this base): accepting a
    plan never executes it and never posts anything. Only invalidation
    may follow acceptance.
    """

    COMPILED = "COMPILED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INVALIDATED = "INVALIDATED"


#: Terminal plan states: no further lifecycle command applies.
PLAN_TERMINAL_STATES = frozenset({PlanState.REJECTED, PlanState.INVALIDATED})

#: Explicit command → source-state → target-state transition table.
PLAN_TRANSITIONS = {
    "accept": {PlanState.COMPILED: PlanState.ACCEPTED},
    "reject": {PlanState.COMPILED: PlanState.REJECTED},
    "invalidate": {
        PlanState.COMPILED: PlanState.INVALIDATED,
        PlanState.ACCEPTED: PlanState.INVALIDATED,
    },
    "recompile": {PlanState.COMPILED: PlanState.COMPILED},
}

#: Authority tiers that satisfy a routing hop, ordered weakest first
#: (consumed closed vocabulary of the capability domain, WORK-009).
AUTHORITY_TIER_RANK = ("R0", "R1", "R2", "R3", "R4", "R5")

__all__ = [
    "COMPILER_PROTOCOL_VERSION",
    "COMPILER_SCHEMA_VERSION",
    "COMPILER_API_VERSION",
    "FULFILLMENT_PLAN_OBJECT_TYPE",
    "ROUTE_HOP_OFFER_TYPE",
    "COMPILATION_REQUEST_TYPE",
    "COMPILATION_INPUT_TYPE",
    "FULFILLMENT_PLAN_SPEC_TYPE",
    "COMPILER_COMMANDS",
    "COMPILER_COMPILE_COMMAND",
    "COMPILER_RECOMPILE_COMMAND",
    "COMPILER_ACCEPT_COMMAND",
    "COMPILER_REJECT_COMMAND",
    "COMPILER_INVALIDATE_COMMAND",
    "COMPILER_EVENT_NAMESPACE",
    "COMPILER_EVENTS",
    "COMPILER_EVENTS_BY_COMMAND",
    "FULFILLMENT_COMPILED_EVENT",
    "FULFILLMENT_RECOMPILED_EVENT",
    "FULFILLMENT_ACCEPTED_EVENT",
    "FULFILLMENT_REJECTED_EVENT",
    "FULFILLMENT_INVALIDATED_EVENT",
    "COMPILER_AUTHORITY_CLASS",
    "HARD_GATE_COMPLIANCE",
    "HARD_GATE_AUTHORITY",
    "HARD_GATE_SETTLEMENT",
    "HARD_GATE_SAFETY",
    "HARD_GATE_ACCOUNTING",
    "HARD_GATE_PRECEDENCE",
    "HARD_GATES",
    "BPS_DENOMINATOR",
    "COMPILER_FX_ROUNDING_MODE",
    "COMPILER_COST_ROUNDING_MODE",
    "MAX_ROUTE_HOPS",
    "MAX_SHAPE_CANDIDATES",
    "RUNNER_UP_DIGEST_COUNT",
    "AUTHORITY_TIER_RANK",
    "PlanState",
    "PLAN_TERMINAL_STATES",
    "PLAN_TRANSITIONS",
]
