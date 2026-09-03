"""PaySwap protocol settlement domain (WORK-016).

The public boundary is typed and versioned:

- **settlement, finality and reconciliation.** This package owns the
  frozen v0.1 ``Settlement`` command family ``Create/Authorize/
  Submit/Cancel/Reconcile`` (discharge batches over sealed clearing
  obligations — the settlement stretch of the canonical chain
  ``Intent → Execution → Clearing → Obligation → Netting → Settlement
  → Finality``), the ``Finality`` command family ``Validate/Establish/
  Challenge/RevokeClaim`` (the registry-listed protocol finality object
  ``payswap/finality/v1``) and the ``Recourse`` command families
  ``Request/Approve/Reject/Compile/ExecuteRefund`` and ``Request/
  Approve/Reject/ExecuteReversal`` (the reversal/return boundaries);
- **consumed dependencies, never reimplemented.** The discharge source
  is the clearing domain's sealed :class:`src.clearing.Obligation`
  (WORK-015, ``DUE``-only, through its trusted decode path); the rail
  evidence is the execution domain's recorded
  :class:`src.execution.ExternalObservation` (WORK-014 — settlement
  never re-evaluates a rail outcome); the epistemic vocabulary is the
  evidence domain's :class:`src.evidence.EpistemicType` (WORK-018,
  ``OBSERVED``-only); the exact amount is the value domain's
  :class:`src.value.Amount` (WORK-005 — the sole accounting
  authority). Unmerged sibling domains are never reimplemented here;
- **no false finality.** A finality certificate is established only
  from ``OBSERVED`` external finality-class claims that are
  digest-bound to every settled leg of a ``COMPLETED`` settlement —
  a payment status can never stand in for settlement finality
  (constitution §4 and invariant 11);
- **no arbitrary ledger edits.** The posting journal is append-only
  and double-entry: discharges, suspense positions, suspense
  releases, reversals and refunds are balanced postings derived
  deterministically from committed events; corrections are new
  postings, never edits (constitution invariants 2 and 17);
- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` and carries a domain seal
  computed with the single canonical hash authority, so tampered or
  spliced objects fail closed on the trusted deserialization path.
  ``payswap/settlement/v1`` and ``payswap/finality/v1`` are
  registry-listed and used exactly as registered; the recourse case
  uses the internal non-registry ``settlement/recourse-case/v1`` type
  and no new protocol-visible name is invented;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority), and every command validates its source state, membership
  and gate preconditions before advancing through the real transition
  kernel.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    FINALITY_COMMANDS,
    FINALITY_OBJECT_TYPE,
    FINALITY_TERMINAL_STATES,
    REFUND_COMMANDS,
    RECOURSE_CASE_OBJECT_TYPE,
    REVERSAL_COMMANDS,
    SETTLEMENT_ALL_COMMANDS,
    SETTLEMENT_API_VERSION,
    SETTLEMENT_COMMANDS,
    SETTLEMENT_EVENT_NAMESPACE,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_PROTOCOL_VERSION,
    SETTLEMENT_SCHEMA_VERSION,
    SETTLEMENT_TRANSITIONS,
    COMMAND_EVENT_TYPES,
    OBJECT_TYPES,
    FinalityState,
    InstructionSourceKind,
    LegState,
    PostingKind,
    RecourseCaseState,
    RecourseKind,
    SettlementState,
    SETTLEMENT_TERMINAL_STATES,
    LEG_TERMINAL_STATES,
    validate_command,
)
from .records import (
    CancellationRecord,
    LegOutcome,
    ReconciliationRecord,
    Settlement,
    SettlementInstruction,
    SettlementSpec,
    SettlementWindow,
    compute_instructions_digest,
    make_settlement_record,
    parse_cancel_payload,
    parse_create_payload,
    parse_reconcile_payload,
)
from .finality import (
    ChallengeRecord,
    Finality,
    FinalityClaimBinding,
    FinalitySpec,
    RevocationRecord,
    advance_finality,
    make_finality_record,
    parse_challenge_payload,
    parse_revoke_payload,
    parse_validate_claim_payload,
)
from .postings import (
    ACCOUNT_KINDS,
    PostingEntry,
    account_name,
    discharge_pair,
    journal_digest,
    refund_pair,
    reversal_pair,
    suspense_pair,
    suspense_release_pair,
    verify_journal_balance,
)
from .recourse import (
    RecourseCase,
    RecourseCaseSpec,
    RecourseEvidence,
    RecourseExecution,
    RecourseRejection,
    RefundCompilation,
    advance_recourse,
    make_recourse_record,
    parse_decision_payload,
    parse_execute_refund_payload,
    parse_request_payload,
)
from .engine import (
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    SettlementEngine,
    SettlementTransition,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

__all__ = [
    # versioned public boundary contracts
    "SETTLEMENT_API_VERSION",
    "SETTLEMENT_PROTOCOL_VERSION",
    "SETTLEMENT_SCHEMA_VERSION",
    "SETTLEMENT_EVENT_NAMESPACE",
    "OBJECT_TYPES",
    "SETTLEMENT_OBJECT_TYPE",
    "FINALITY_OBJECT_TYPE",
    "RECOURSE_CASE_OBJECT_TYPE",
    "COMMAND_EVENT_TYPES",
    "validate_command",
    # frozen command families
    "SETTLEMENT_COMMANDS",
    "FINALITY_COMMANDS",
    "REFUND_COMMANDS",
    "REVERSAL_COMMANDS",
    "SETTLEMENT_ALL_COMMANDS",
    # closed lifecycles
    "SettlementState",
    "LegState",
    "FinalityState",
    "RecourseKind",
    "RecourseCaseState",
    "PostingKind",
    "InstructionSourceKind",
    "SETTLEMENT_TERMINAL_STATES",
    "LEG_TERMINAL_STATES",
    "FINALITY_TERMINAL_STATES",
    "SETTLEMENT_TRANSITIONS",
    # settlement records and lifecycle facts
    "Settlement",
    "SettlementSpec",
    "SettlementInstruction",
    "SettlementWindow",
    "LegOutcome",
    "ReconciliationRecord",
    "CancellationRecord",
    "make_settlement_record",
    "compute_instructions_digest",
    "parse_create_payload",
    "parse_cancel_payload",
    "parse_reconcile_payload",
    # finality certificates
    "Finality",
    "FinalitySpec",
    "FinalityClaimBinding",
    "ChallengeRecord",
    "RevocationRecord",
    "make_finality_record",
    "advance_finality",
    "parse_validate_claim_payload",
    "parse_challenge_payload",
    "parse_revoke_payload",
    # the append-only posting journal
    "PostingEntry",
    "ACCOUNT_KINDS",
    "account_name",
    "discharge_pair",
    "refund_pair",
    "suspense_pair",
    "suspense_release_pair",
    "reversal_pair",
    "verify_journal_balance",
    "journal_digest",
    # recourse cases
    "RecourseCase",
    "RecourseCaseSpec",
    "RecourseEvidence",
    "RefundCompilation",
    "RecourseExecution",
    "RecourseRejection",
    "make_recourse_record",
    "advance_recourse",
    "parse_request_payload",
    "parse_decision_payload",
    "parse_execute_refund_payload",
    # engine (kernel-bound)
    "SettlementEngine",
    "SettlementTransition",
    "DEFAULT_ENGINE_ACTOR",
    "DEFAULT_COMMAND_AUTHORITY_CLASS",
    # domain sealing (single hash authority)
    "build_domain_envelope",
    "advance_envelope",
    "seal_composite",
    "verify_composite",
    "composite_to_dict",
    "composite_to_json",
    "decode_composite",
    "decode_composite_json",
    # consumed owning authorities (single sources: src.core)
    "CoreValidationError",
    "Provenance",
]
