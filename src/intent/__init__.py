"""PaySwap intent domain (WORK-008): intent, funding binding, fulfillment
policy, economic slack, demand and demand classes.

The public boundary is typed and versioned:

- every durable object composes the canonical :class:`~src.core.envelope.ObjectEnvelope`
  (identity, state, provenance, version chain, integrity hash) owned by
  ``src.core``;
- protocol-visible names come exclusively from the frozen protocol registry
  (``payswap/intent/v1``); remaining domain object types use internal
  non-registry formats (``intent/policy``, ``intent/slack``,
  ``intent/demand``, ``intent/demand-class``);
- economic quantities are scaled-integer declarations
  (:class:`Amount` = integer value + scale + asset) with no floating-point
  values anywhere; monetary arithmetic is owned by the money domain
  (WORK-006) and is deliberately absent here;
- validation fails closed with :class:`~src.core.errors.CoreValidationError`,
  the single error authority, raised with descriptive messages;
- serialization is canonical JSON through ``src.core.serialization`` and is
  lossless and byte-stable; every composite object carries a domain seal
  (a SHA-256 digest computed with the canonical hash authority over the
  sealed envelope plus the payload) so tampered or spliced objects are
  rejected on the trusted deserialization path.
"""

from __future__ import annotations

from src.core import Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    DEMAND_CLASS_OBJECT_TYPE,
    DEMAND_OBJECT_TYPE,
    ECONOMIC_SLACK_OBJECT_TYPE,
    FULFILLMENT_POLICY_OBJECT_TYPE,
    INTENT_OBJECT_TYPE,
    INTENT_PROTOCOL_VERSION,
    INTENT_SCHEMA_VERSION,
)
from .amount import MAX_SCALE, Amount
from .funding import FundingBinding, FundingSourceRef
from .policy import FulfillmentPolicy, OptimizationObjective, PolicySpec, PolicyState
from .slack import EconomicSlack, SlackSpec, SlackState
from .intent import Intent, IntentSpec, IntentState
from .demand import Demand, DemandSpec, DemandState, derive_demand, withdraw_demand
from .demand_class import (
    DEADLINE_WINDOW_SECONDS,
    IMMEDIATE_WINDOW_SECONDS,
    DemandClass,
    DemandClassSpec,
    DemandShape,
    UrgencyClass,
    classify_demand,
    demand_class_id,
    urgency_for_window,
    window_seconds,
)

__all__ = [
    # versioned public boundary contracts
    "INTENT_PROTOCOL_VERSION",
    "INTENT_SCHEMA_VERSION",
    "INTENT_OBJECT_TYPE",
    "FULFILLMENT_POLICY_OBJECT_TYPE",
    "ECONOMIC_SLACK_OBJECT_TYPE",
    "DEMAND_OBJECT_TYPE",
    "DEMAND_CLASS_OBJECT_TYPE",
    "MAX_SCALE",
    "IMMEDIATE_WINDOW_SECONDS",
    "DEADLINE_WINDOW_SECONDS",
    # canonical value declarations
    "Amount",
    "FundingSourceRef",
    "FundingBinding",
    # fulfillment policy
    "PolicySpec",
    "FulfillmentPolicy",
    "OptimizationObjective",
    "PolicyState",
    # economic slack
    "SlackSpec",
    "EconomicSlack",
    "SlackState",
    # intent
    "IntentSpec",
    "Intent",
    "IntentState",
    # demand
    "DemandSpec",
    "Demand",
    "DemandState",
    "derive_demand",
    "withdraw_demand",
    # demand classes
    "DemandClassSpec",
    "DemandClass",
    "UrgencyClass",
    "DemandShape",
    "classify_demand",
    "demand_class_id",
    "urgency_for_window",
    "window_seconds",
    # re-exported owning authorities (single source: src.core)
    "CoreValidationError",
    "Provenance",
]
