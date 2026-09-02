"""Typed and versioned public contracts for the intent domain (WORK-008).

Frozen authorities consumed (never redefined here):
- ``spec/architecture/v0.1/canonical-object-model.md`` — object families and
  the common ``ObjectEnvelope``;
- ``spec/architecture/v0.1/constitution.md`` — intent-to-fulfillment purpose;
- ``spec/registry/protocol-registry.json`` — the only registry-listed object
  type owned by this domain is ``payswap/intent/v1``.

Registry discipline: every protocol-visible name must come from the frozen
registry. ``payswap/intent/v1`` is registry-listed. The remaining intent
domain object types are internal domain identifiers in non-registry formats
(``intent/...``) and are therefore not protocol-visible. No event names are
introduced here; the transition kernel (WORK-003) owns event envelopes.
"""

from __future__ import annotations

# Protocol identity of the governing frozen architecture.
INTENT_PROTOCOL_VERSION = "v0.1"

# Schema version of the intent domain payload contracts.
INTENT_SCHEMA_VERSION = 1

# Registry-listed, protocol-visible object type for the durable Intent object.
INTENT_OBJECT_TYPE = "payswap/intent/v1"

# Internal (non-registry) object types for the remaining intent domain
# durable objects. They deliberately do not use registry-visible formats.
FULFILLMENT_POLICY_OBJECT_TYPE = "intent/policy"
ECONOMIC_SLACK_OBJECT_TYPE = "intent/slack"
DEMAND_OBJECT_TYPE = "intent/demand"
DEMAND_CLASS_OBJECT_TYPE = "intent/demand-class"

__all__ = [
    "INTENT_PROTOCOL_VERSION",
    "INTENT_SCHEMA_VERSION",
    "INTENT_OBJECT_TYPE",
    "FULFILLMENT_POLICY_OBJECT_TYPE",
    "ECONOMIC_SLACK_OBJECT_TYPE",
    "DEMAND_OBJECT_TYPE",
    "DEMAND_CLASS_OBJECT_TYPE",
]
