"""IG-001 gate contracts: identity, vocabulary and boundary constants.

The integration gate composes ONLY independently merged capabilities
(``spec/integration-gates.md``): the command/event transition kernel
(WORK-003), the ledger/posting/hold model (WORK-005) and fixed-point
money/FX (WORK-006), over the canonical core (WORK-002). This module
declares the gate's typed, versioned identity and freezes the vocabularies
used by the composition harness. It introduces no domain semantics of its
own: every behavioral authority stays with the consumed domains.

Identity discipline:

* ``IG-001`` is the gate identifier listed in ``spec/integration-gates.md``;
  unknown gate ids fail closed everywhere.
* ``payswap/intent/v1`` and ``payswap/settlement/v1`` are the ONLY object
  types the gate projects through the kernel, and both are listed in the
  frozen protocol registry (the gate invents no protocol-visible name).
* Event types use the frozen registry namespaces ``intent`` and
  ``settlement`` with names matching the frozen command families
  (``Intent: Create/Authorize`` and ``Settlement: Submit/Reconcile``).
* Command types are internal, non-registry identifiers of the form
  ``integration/<family>.<verb>`` (the kernel constrains only event types
  against the registry; this mirrors the sibling convention of internal
  domain-prefixed identifiers).
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-001 row).
INTEGRATION_GATE_ID = "IG-001"

#: Typed, versioned public boundary version of the gate package.
INTEGRATION_API_VERSION = "v0.1"

#: Schema version of the gate's canonical snapshot representation.
INTEGRATION_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_INTEGRATION_GATES = frozenset({INTEGRATION_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by the
#: contract suite). Anything else is a second authority or an unmerged
#: sibling and is forbidden.
CONSUMED_SURFACES = ("src.core", "src.transition", "src.value", "src.money")

# Registry-listed protocol object types used for the kernel projection.
INTENT_OBJECT_TYPE = "payswap/intent/v1"
SETTLEMENT_OBJECT_TYPE = "payswap/settlement/v1"

# Internal (non-registry) command types of the composed scenario. They
# mirror the frozen command families: Intent Create/Authorize and
# Settlement Submit/Reconcile.
INTENT_CREATE_COMMAND = "integration/intent.create"
INTENT_AUTHORIZE_COMMAND = "integration/intent.authorize"
SETTLEMENT_SUBMIT_COMMAND = "integration/settlement.submit"
SETTLEMENT_RECONCILE_COMMAND = "integration/settlement.reconcile"

#: The closed command vocabulary of the gate (registration boundary).
GATE_COMMAND_TYPES = frozenset(
    {
        INTENT_CREATE_COMMAND,
        INTENT_AUTHORIZE_COMMAND,
        SETTLEMENT_SUBMIT_COMMAND,
        SETTLEMENT_RECONCILE_COMMAND,
    }
)

# Event types (namespace-validated by the kernel against the frozen
# protocol registry).
INTENT_CREATED_EVENT = "intent/created"
INTENT_AUTHORIZED_EVENT = "intent/authorized"
SETTLEMENT_SUBMITTED_EVENT = "settlement/submitted"
SETTLEMENT_RECONCILED_EVENT = "settlement/reconciled"

#: Authority class granted to declared actors of the composed scenario
#: (registry class list A0-A7/R0-R5; A1 mirrors the kernel dogfooding).
GATE_AUTHORITY_CLASS = "A1"

#: Provenance source stamp for every ledger mutation the gate drives.
GATE_PROVENANCE_SOURCE = "integration-gate"

# Deterministic environment fixture identifiers of the composed scenario.
# They are internal value-domain identifiers (provisioned by the harness
# through the real ledger API); the value domain owns their semantics.
PAYER_ACCOUNT = "value/account/payer-ig1"
PAYEE_ACCOUNT = "value/account/payee-ig1"
SAVINGS_ACCOUNT = "value/account/payee-savings-ig1"
HOUSE_USD_ACCOUNT = "value/account/house-usd-ig1"
HOUSE_EUR_ACCOUNT = "value/account/house-eur-ig1"
VAULT_ACCOUNT = "value/account/vault-ig1"
FEE_INCOME_ACCOUNT = "value/account/fee-income-ig1"
USD_ASSET_ID = "value/asset/usd-ig1"
EUR_ASSET_ID = "value/asset/eur-ig1"
GATE_JOURNAL_ID = "value/journal/ig1"
SOURCE_ASSET_CODE = "USD"
TARGET_ASSET_CODE = "EUR"

#: Deterministic provisioning instant (declared data, never a clock read).
PROVISION_STAMP = "2026-09-02T00:00:00Z"

#: Actors the gate authorizes by default (the payer and treasury ops).
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {"principal/customer-7", "principal/treasury-ops"}
)


def house_account_id(asset_code: str) -> str:
    """Deterministic house (network) account id for one asset code."""
    return f"value/account/house-{asset_code.lower()}-ig1"


def validate_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names a known integration gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_INTEGRATION_GATES:
        raise CoreValidationError(
            f"unknown integration gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_INTEGRATION_GATES)}"
        )
    return gate_id
