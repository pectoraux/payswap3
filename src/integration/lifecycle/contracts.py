"""IG-002 gate contracts: identity, vocabulary and boundary constants.

The fulfillment lifecycle integration gate (``spec/integration-gates.md``
row IG-002) composes ONLY independently merged implementations — the
eleven declared required inputs (WORK-007 interoperability, WORK-009
capability, WORK-010 market, WORK-011 liquidity, WORK-012 reservation,
WORK-013 compiler, WORK-014 execution, WORK-015 clearing, WORK-016
settlement, WORK-017 safety, WORK-018 evidence) over the canonical core,
the money arithmetic and the intent domain whose durable objects are the
compiler's public input contract. This module declares the gate's typed,
versioned identity and freezes the vocabularies the composition harness
uses. It introduces no domain semantics of its own: every behavioral
authority stays with the consumed domains.

Identity discipline:

* ``IG-002`` is the gate identifier listed in
  ``spec/integration-gates.md``; unknown gate ids fail closed everywhere.
  The IG-001 gate id stays unknown HERE on purpose: this package
  executes only the fulfillment lifecycle gate, and the IG-001-owned
  validator in the parent package keeps failing closed on ``IG-002`` —
  one validator per gate, no shared mutation of the merged IG-001
  contract surface.
* The gate projects NO new protocol-visible name: every registry-listed
  object type and event namespace it touches belongs to the consumed
  domain engines, which use the frozen registry exactly as registered.
* Rail adapters are bound through the execution domain's typed ports
  (:class:`src.execution.adapters.AdapterBinding`); the gate invents no
  adapter vocabulary.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-002 row).
LIFECYCLE_GATE_ID = "IG-002"

#: Typed, versioned public boundary version of the gate package.
LIFECYCLE_API_VERSION = "v0.1"

#: Schema version of the gate's canonical snapshot representation.
LIFECYCLE_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_LIFECYCLE_GATES = frozenset({LIFECYCLE_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by the
#: contract suite). Anything else is a second authority or an unmerged
#: sibling and is forbidden. ``src.intent`` is the compiler domain's own
#: public input contract (its ``CompilationInput`` embeds real intent
#: objects), consumed here as declared input data only.
CONSUMED_SURFACES = (
    "src.core",
    "src.transition",
    "src.money",
    "src.intent",
    "src.capability",
    "src.market",
    "src.liquidity",
    "src.reservation",
    "src.safety",
    "src.evidence",
    "src.interoperability",
    "src.compiler",
    "src.execution",
    "src.clearing",
    "src.settlement",
)

#: Authority class granted to declared actors of the composed scenario
#: (registry class list A0-A7/R0-R5; A2 mirrors the execution dogfooding
#: and covers production-class effect authorization).
GATE_AUTHORITY_CLASS = "A2"

#: Provenance source stamp for every cross-domain translation the gate
#: drives (execution result details, settlement-facing observations).
GATE_PROVENANCE_SOURCE = "integration-gate-ig2"

#: The actor the composed domain engines act by default.
DEFAULT_GATE_ACTOR = "principal/ig002-ops"

#: Actors the gate authorizes by default (the paying customer plus the
#: integration operator).
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {"principal/ig002-ops", "principal/payer-ig2"}
)

#: Per-engine object-domain suffixes: each composed domain engine keeps
#: its own kernel-bound domain (the sibling convention — clearing,
#: settlement and execution objects never share a domain), derived
#: deterministically from the gate's base domain id.
COMPILER_DOMAIN_SUFFIX = "compiler"
EXECUTION_DOMAIN_SUFFIX = "execution"
CLEARING_DOMAIN_SUFFIX = "clearing"
SETTLEMENT_DOMAIN_SUFFIX = "settlement"

#: The canonical effect type of a payment submission step (the frozen
#: execution vocabulary; the sandbox and production rails submit it).
PAYMENT_SUBMIT_EFFECT_TYPE = "payment/submit"

#: Default maximum attempts per execution step (declared scenario data).
DEFAULT_STEP_MAX_ATTEMPTS = 2


def validate_lifecycle_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names the fulfillment lifecycle gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_LIFECYCLE_GATES:
        raise CoreValidationError(
            f"unknown lifecycle gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_LIFECYCLE_GATES)}"
        )
    return gate_id
