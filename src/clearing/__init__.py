"""PaySwap protocol clearing domain (WORK-015).

The public boundary is typed and versioned:

- **clearing, obligations and netting.** This package owns the frozen
  v0.1 ``Clearing`` command family ``Create/Validate/Finalize/Cancel``
  (clearing cycles — the recognition windows of the canonical chain
  ``Intent → Execution → Clearing → Obligation → Netting → Settlement →
  Finality``), the ``Obligation`` command family ``Create/Validate/
  Amend/Dispute/Restructure/MarkDue/Default/Resolve`` (the
  registry-listed protocol obligation object ``payswap/obligation/v1``,
  recognized from the execution domain's rail-reported effect results)
  and the ``Netting`` command family ``Create/Add/Remove/Calculate/
  Finalize/Cancel`` (bilateral and multilateral gross-to-net
  computation with explicit conservation and reduction proofs);
- **consumed dependencies, never reimplemented.** The exact amount is
  the value domain's (:class:`src.value.Amount`, WORK-005 — the sole
  accounting authority); common-unit valuation of netting statements
  uses the money domain's exact FX conversion
  (:class:`src.money.FxRate` with explicit rounding, WORK-006); the
  funding-gate vocabulary is the reservation domain's closed
  ``ReservationState`` (WORK-012, ``HELD``-only); the recognition
  source is the execution domain's sealed ``EffectResult`` (WORK-014,
  ``SUCCEEDED``-only, digest-bound); the epistemic vocabulary of
  evidence-bearing commands is the evidence domain's ``EpistemicType``
  (WORK-018, ``OBSERVED``-only). Unmerged sibling domains are never
  imported;
- **no external settlement effects.** Clearing recognizes, offsets and
  reclassifies obligations; it never moves funds, never posts, never
  settles and never claims settlement finality (constitution invariant
  11 — settlement, finality and reconciliation are WORK-016's
  authority). A ``RESOLVED`` obligation is a clearing-side closure
  recorded with explicit evidence;
- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` and carries a domain seal
  computed with the single canonical hash authority, so tampered or
  spliced objects fail closed on the trusted deserialization path.
  ``payswap/obligation/v1`` is registry-listed and used exactly as
  registered; the clearing cycle and netting cycle use internal
  non-registry ``clearing/...`` object types and no new
  protocol-visible name is invented;
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
    CLEARING_ALL_COMMANDS,
    CLEARING_API_VERSION,
    CLEARING_CYCLE_COMMANDS,
    CLEARING_CYCLE_OBJECT_TYPE,
    CLEARING_CYCLE_TERMINAL_STATES,
    CLEARING_EVENT_NAMESPACE,
    CLEARING_PROTOCOL_VERSION,
    CLEARING_SCHEMA_VERSION,
    CLEARING_TRANSITIONS,
    COMMAND_EVENT_TYPES,
    NETTING_COMMANDS,
    NETTING_CYCLE_OBJECT_TYPE,
    NETTING_TERMINAL_STATES,
    OBLIGATION_COMMANDS,
    OBLIGATION_OBJECT_TYPE,
    OBLIGATION_TERMINAL_STATES,
    OBLIGATION_VALIDATED_STATES,
    OBJECT_TYPES,
    ClearingCycleState,
    NettingCycleState,
    NettingMode,
    ObligationSourceKind,
    ObligationState,
    ResolutionKind,
    validate_command,
)
from .cycle import (
    AssetGross,
    ClearingCycle,
    ClearingCycleSpec,
    ClearingStatement,
    PairGross,
    RecognitionWindow,
    compute_clearing_statement,
    make_cycle_record,
)
from .engine import (
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    ClearingEngine,
    ClearingTransition,
)
from .netting import (
    AssetConversion,
    MemberBinding,
    NettingCycle,
    NettingCycleSpec,
    NettingGroup,
    NettingStatement,
    NettingValuation,
    PairNet,
    PositionNet,
    ValuationSpec,
    compute_netting_statement,
    derive_issued_obligation,
    make_netting_record,
)
from .obligations import (
    AmendmentRecord,
    DefaultRecord,
    DisputeRecord,
    DueRecord,
    DueWindow,
    FundingGate,
    Obligation,
    ObligationSpec,
    ResolutionRecord,
    RestructureRecord,
    make_obligation_record,
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
    "CLEARING_API_VERSION",
    "CLEARING_PROTOCOL_VERSION",
    "CLEARING_SCHEMA_VERSION",
    "CLEARING_EVENT_NAMESPACE",
    "OBJECT_TYPES",
    "OBLIGATION_OBJECT_TYPE",
    "CLEARING_CYCLE_OBJECT_TYPE",
    "NETTING_CYCLE_OBJECT_TYPE",
    "COMMAND_EVENT_TYPES",
    "validate_command",
    # frozen command families
    "CLEARING_CYCLE_COMMANDS",
    "OBLIGATION_COMMANDS",
    "NETTING_COMMANDS",
    "CLEARING_ALL_COMMANDS",
    # closed lifecycles
    "ClearingCycleState",
    "ObligationState",
    "ObligationSourceKind",
    "ResolutionKind",
    "NettingCycleState",
    "NettingMode",
    "CLEARING_CYCLE_TERMINAL_STATES",
    "OBLIGATION_TERMINAL_STATES",
    "OBLIGATION_VALIDATED_STATES",
    "NETTING_TERMINAL_STATES",
    "CLEARING_TRANSITIONS",
    # clearing cycles and statements
    "ClearingCycle",
    "ClearingCycleSpec",
    "ClearingStatement",
    "RecognitionWindow",
    "AssetGross",
    "PairGross",
    "compute_clearing_statement",
    "make_cycle_record",
    # obligations and lifecycle facts
    "Obligation",
    "ObligationSpec",
    "DueWindow",
    "AmendmentRecord",
    "DisputeRecord",
    "RestructureRecord",
    "DueRecord",
    "FundingGate",
    "DefaultRecord",
    "ResolutionRecord",
    "make_obligation_record",
    # netting cycles and statements
    "NettingCycle",
    "NettingCycleSpec",
    "NettingStatement",
    "NettingGroup",
    "PairNet",
    "PositionNet",
    "MemberBinding",
    "NettingValuation",
    "AssetConversion",
    "ValuationSpec",
    "compute_netting_statement",
    "derive_issued_obligation",
    "make_netting_record",
    # engine (kernel-bound)
    "ClearingEngine",
    "ClearingTransition",
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
