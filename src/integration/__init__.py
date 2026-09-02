"""IG-001 kernel/value integration gate (WORK-026) — public boundary.

The gate proves that the command/event kernel (WORK-003, ``src.transition``),
the authoritative ledger/posting/hold model (WORK-005, ``src.value``) and
the fixed-point money/FX arithmetic (WORK-006, ``src.money``) preserve the
frozen value invariants TOGETHER, by driving them through one composed
environment and asserting the cross-layer invariants after every step:

* double-entry integrity (per posting, per journal, per asset sheet);
* derived-balance consistency with the posting history;
* hold/encumbrance reconciliation evidence;
* exact money conservation through every FX conversion (explicit residual)
  and every residual allocation;
* envelope/seal integrity over every produced object;
* kernel journal payload-hash integrity and digest reproducibility;
* end-to-end trace consistency between intent terms and ledger legs;
* deterministic journal-driven replay of the composed state.

The gate composes real merged implementations only (read-only consumed);
it introduces no domain semantics, no protocol-visible name beyond the
registry-listed ones it projects, and no second authority —
``CoreValidationError`` from ``src.core`` remains the single error
authority, re-exported here for convenience like every sibling domain.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CONSUMED_SURFACES,
    INTEGRATION_API_VERSION,
    INTEGRATION_GATE_ID,
    INTEGRATION_SCHEMA_VERSION,
    INTENT_AUTHORIZE_COMMAND,
    INTENT_CREATE_COMMAND,
    INTENT_CREATED_EVENT,
    INTENT_AUTHORIZED_EVENT,
    INTENT_OBJECT_TYPE,
    KNOWN_INTEGRATION_GATES,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_RECONCILE_COMMAND,
    SETTLEMENT_RECONCILED_EVENT,
    SETTLEMENT_SUBMIT_COMMAND,
    SETTLEMENT_SUBMITTED_EVENT,
    validate_gate_id,
)
from .harness import IntegrationGate
from .invariants import verify_invariants
from .replay import assert_replay_equivalence, replay_from_journal

__all__ = [
    "CONSUMED_SURFACES",
    "CoreValidationError",
    "INTEGRATION_API_VERSION",
    "INTEGRATION_GATE_ID",
    "INTEGRATION_SCHEMA_VERSION",
    "INTENT_AUTHORIZE_COMMAND",
    "INTENT_CREATE_COMMAND",
    "INTENT_CREATED_EVENT",
    "INTENT_AUTHORIZED_EVENT",
    "INTENT_OBJECT_TYPE",
    "KNOWN_INTEGRATION_GATES",
    "SETTLEMENT_OBJECT_TYPE",
    "SETTLEMENT_RECONCILE_COMMAND",
    "SETTLEMENT_RECONCILED_EVENT",
    "SETTLEMENT_SUBMIT_COMMAND",
    "SETTLEMENT_SUBMITTED_EVENT",
    "IntegrationGate",
    "assert_replay_equivalence",
    "replay_from_journal",
    "validate_gate_id",
    "verify_invariants",
]
