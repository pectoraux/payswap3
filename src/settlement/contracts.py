"""Frozen public-boundary contracts for the settlement domain (WORK-016).

This package owns the frozen v0.1 ``Settlement`` command family
``Create/Authorize/Submit/Cancel/Reconcile`` (the settlement stretch of
the canonical financial chain ``Intent → Execution → Clearing →
Obligation → Netting → Settlement → Finality`` — constitution §4), the
``Finality`` command family ``Validate/Establish/Challenge/RevokeClaim``
and the ``Recourse`` command families ``Request/Approve/Reject/Compile/
ExecuteRefund`` and ``Request/Approve/Reject/ExecuteReversal``
(reversal/return boundaries).

Registry discipline: ``payswap/settlement/v1`` and ``payswap/finality/v1``
(the protocol-visible settlement and finality objects) and the
``settlement`` event namespace are ALREADY listed in the frozen protocol
registry and are used here exactly as registered. Every other
settlement object kind below follows the sibling convention and uses
internal non-registry ``settlement/...`` formats. No new
protocol-visible name is invented here.

Boundary with the sibling Work Orders: this package settles and
discharges obligations recognized by the clearing domain (WORK-015 —
settlement consumes sealed clearing obligations and netting-issued
obligations through their trusted decode path), consumes the execution
domain's recorded external observations as rail evidence (WORK-014 owns
execution and external observation recording; settlement never
re-evaluates a rail outcome itself), and uses the evidence domain's
epistemic vocabulary (WORK-018 — only ``OBSERVED`` knowledge may back
any finality or recourse decision). It never edits the clearing domain's
obligation lifecycle (discharge there is driven by explicit clearing
resolve commands carrying settlement evidence) and never edits the value
domain's authoritative accounts (corrections here are new append-only
postings inside the settlement domain — the forbidden surface "no
arbitrary ledger edits").

The two forbidden surfaces of the Work Order are structural here:

* **no false finality** — a finality certificate can be established only
  from ``OBSERVED`` external finality-class claims (execution-domain
  ``ObservationKind.FINALITY`` with ``FinalityClaim.FINAL`` or
  ``SETTLED``) that are digest-bound to the exact settled legs of a
  ``COMPLETED`` settlement. A payment status (``ObservationKind.STATUS``)
  can never stand in for settlement finality (constitution §4 and
  invariant 11 — "PaySwap never overstates settlement finality");
* **no arbitrary ledger edits** — the settlement journal is append-only;
  every posting is a balanced double-entry pair derived deterministically
  from committed events; reversals are explicit compensation postings and
  refunds are new linked economic transactions. No command edits,
  rewrites or deletes a posting (constitution invariants 2, 17 and the
  ledger-posting-model source mapping).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_text

# -- typed, versioned public boundary --------------------------------------


#: Typed public API version of the settlement domain boundary.
SETTLEMENT_API_VERSION = "v0.1"

#: The frozen kernel protocol version every settlement record is bound to.
SETTLEMENT_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of the settlement composite record encoding.
SETTLEMENT_SCHEMA_VERSION = 1


#: The registry-listed protocol-visible settlement object type.
SETTLEMENT_OBJECT_TYPE = "payswap/settlement/v1"

#: The registry-listed protocol-visible finality object type.
FINALITY_OBJECT_TYPE = "payswap/finality/v1"

#: Internal (non-registry) recourse case object type following the
#: sibling convention for domain-local record kinds.
RECOURSE_CASE_OBJECT_TYPE = "settlement/recourse-case/v1"

#: Object types owned by this domain.
OBJECT_TYPES = (
    SETTLEMENT_OBJECT_TYPE,
    FINALITY_OBJECT_TYPE,
    RECOURSE_CASE_OBJECT_TYPE,
)

#: The registry-listed event namespace every settlement event uses.
SETTLEMENT_EVENT_NAMESPACE = "settlement"


# -- frozen command families ------------------------------------------------


SETTLEMENT_COMMANDS = frozenset(
    {
        "settlement/create",
        "settlement/authorize",
        "settlement/submit",
        "settlement/cancel",
        "settlement/reconcile",
    }
)

FINALITY_COMMANDS = frozenset(
    {
        "finality/validate",
        "finality/establish",
        "finality/challenge",
        "finality/revoke-claim",
    }
)

REFUND_COMMANDS = frozenset(
    {
        "recourse/refund.request",
        "recourse/refund.approve",
        "recourse/refund.reject",
        "recourse/refund.compile",
        "recourse/refund.execute",
    }
)

REVERSAL_COMMANDS = frozenset(
    {
        "recourse/reversal.request",
        "recourse/reversal.approve",
        "recourse/reversal.reject",
        "recourse/reversal.execute",
    }
)

#: The complete frozen command surface of the settlement domain.
SETTLEMENT_ALL_COMMANDS = (
    SETTLEMENT_COMMANDS | FINALITY_COMMANDS | REFUND_COMMANDS | REVERSAL_COMMANDS
)

#: Canonical event type per command (all in the registered
#: ``settlement`` namespace; rejected commands emit the kernel's audit
#: rejection events, never a domain event).
COMMAND_EVENT_TYPES: Mapping[str, str] = {
    "settlement/create": "settlement/settlement-created",
    "settlement/authorize": "settlement/settlement-authorized",
    "settlement/submit": "settlement/settlement-submitted",
    "settlement/cancel": "settlement/settlement-cancelled",
    "settlement/reconcile": "settlement/settlement-reconciled",
    "finality/validate": "settlement/finality-validated",
    "finality/establish": "settlement/finality-established",
    "finality/challenge": "settlement/finality-challenged",
    "finality/revoke-claim": "settlement/finality-revoked",
    "recourse/refund.request": "settlement/refund-requested",
    "recourse/refund.approve": "settlement/refund-approved",
    "recourse/refund.reject": "settlement/refund-rejected",
    "recourse/refund.compile": "settlement/refund-compiled",
    "recourse/refund.execute": "settlement/refund-executed",
    "recourse/reversal.request": "settlement/reversal-requested",
    "recourse/reversal.approve": "settlement/reversal-approved",
    "recourse/reversal.reject": "settlement/reversal-rejected",
    "recourse/reversal.execute": "settlement/reversal-executed",
}


# -- closed lifecycles -------------------------------------------------------


class SettlementState(StrEnum):
    """Closed lifecycle of a settlement batch.

    ``DRAFT → AUTHORIZED → SUBMITTED → COMPLETED | FAILED`` with
    ``CANCELLED`` available before submission. ``COMPLETED`` means every
    discharge instruction settled (observed rail success, matched by
    reconciliation). ``FAILED`` means every instruction reached a
    terminal leg outcome and at least one failed. Legs whose rail
    outcome is unknown never complete a settlement silently: they hold
    the settlement in ``SUBMITTED`` with an explicit suspense posting
    (the ledger-posting-model's suspense discipline — a state, never a
    silent loss or success classification).
    """

    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    SUBMITTED = "SUBMITTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "SettlementState":
        return parse_enum("settlement state", value, cls)  # type: ignore[return-value]


SETTLEMENT_TERMINAL_STATES = frozenset(
    {
        SettlementState.COMPLETED,
        SettlementState.FAILED,
        SettlementState.CANCELLED,
    }
)


class LegState(StrEnum):
    """Closed lifecycle of one discharge instruction (settlement leg).

    ``PENDING → SUBMITTED → SETTLED | FAILED | UNKNOWN``. ``UNKNOWN``
    is the explicit suspense state: the rail outcome is not yet
    authoritative knowledge, so the amount is posted to controlled
    suspense positions until a later observation resolves it
    (``UNKNOWN → SETTLED`` or ``UNKNOWN → FAILED``).
    """

    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: object) -> "LegState":
        return parse_enum("settlement leg state", value, cls)  # type: ignore[return-value]


#: Leg outcomes that end a leg's reconciliation.
LEG_TERMINAL_STATES = frozenset({LegState.SETTLED, LegState.FAILED})


class FinalityState(StrEnum):
    """Closed lifecycle of a finality certificate.

    ``PENDING → ESTABLISHED → CHALLENGED → REVOKED``, with direct
    ``PENDING → REVOKED`` and ``ESTABLISHED → REVOKED`` paths. Once
    challenged, a certificate can only be revoked — never silently
    re-established (fail closed; a replacement certificate is a new
    object, history stays append-only). ``REVOKED`` is terminal.
    """

    PENDING = "PENDING"
    ESTABLISHED = "ESTABLISHED"
    CHALLENGED = "CHALLENGED"
    REVOKED = "REVOKED"

    @classmethod
    def parse(cls, value: object) -> "FinalityState":
        return parse_enum("finality state", value, cls)  # type: ignore[return-value]


FINALITY_TERMINAL_STATES = frozenset({FinalityState.REVOKED})


class RecourseKind(StrEnum):
    """Closed vocabulary of recourse: a refund or a reversal."""

    REFUND = "REFUND"
    REVERSAL = "REVERSAL"

    @classmethod
    def parse(cls, value: object) -> "RecourseKind":
        return parse_enum("recourse kind", value, cls)  # type: ignore[return-value]


class RecourseCaseState(StrEnum):
    """Closed lifecycle of a recourse case.

    Refund: ``REQUESTED → APPROVED → COMPILED → EXECUTED`` (compile
    derives the linked refund settlement draft). Reversal:
    ``REQUESTED → APPROVED → EXECUTED`` (execution emits the explicit
    compensation postings). Both may be ``REJECTED`` from ``REQUESTED``.
    ``EXECUTED`` and ``REJECTED`` are terminal.
    """

    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    COMPILED = "COMPILED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"

    @classmethod
    def parse(cls, value: object) -> "RecourseCaseState":
        return parse_enum("recourse case state", value, cls)  # type: ignore[return-value]


RECOURSE_TERMINAL_STATES = frozenset({RecourseCaseState.EXECUTED, RecourseCaseState.REJECTED})


class PostingKind(StrEnum):
    """Closed vocabulary of settlement-domain posting events.

    Maps one-to-one onto the ledger-posting-model source mapping:
    ``DISCHARGE`` (``Settlement → discharge of obligations + asset
    movement``), ``SUSPENSE``/``SUSPENSE_RELEASE`` (controlled
    suspense/exception positions for uncertain external outcomes),
    ``REVERSAL`` (``Reversal → explicit reversal/compensation journal``)
    and ``REFUND`` (``Refund → new economic transaction linked to
    original``).
    """

    DISCHARGE = "DISCHARGE"
    SUSPENSE = "SUSPENSE"
    SUSPENSE_RELEASE = "SUSPENSE_RELEASE"
    REVERSAL = "REVERSAL"
    REFUND = "REFUND"

    @classmethod
    def parse(cls, value: object) -> "PostingKind":
        return parse_enum("posting kind", value, cls)  # type: ignore[return-value]


class InstructionSourceKind(StrEnum):
    """What a discharge instruction is pinned to.

    ``OBLIGATION`` — a sealed clearing obligation (the ordinary
    clearing-recognized or netting-issued obligation). ``REFUND_LEG`` —
    a refund leg compiled from a completed settlement's settled
    instruction (a new economic transaction linked to the original;
    it carries no live obligation binding).
    """

    OBLIGATION = "OBLIGATION"
    REFUND_LEG = "REFUND_LEG"

    @classmethod
    def parse(cls, value: object) -> "InstructionSourceKind":
        return parse_enum("instruction source kind", value, cls)  # type: ignore[return-value]


# -- transition table --------------------------------------------------------


#: Allowed SOURCE states per command of the frozen families, expressed
#: on the primary object the command advances (settlement batch for the
#: Settlement family, finality certificate for the Finality family,
#: recourse case for the Recourse families). Commands that create their
#: primary object have empty source sets. The engine's handlers validate
#: these tables before advancing any state.
SETTLEMENT_TRANSITIONS: Mapping[str, frozenset] = {
    # Settlement family (primary object: the settlement batch)
    "settlement/create": frozenset(),
    "settlement/authorize": frozenset({SettlementState.DRAFT}),
    "settlement/submit": frozenset({SettlementState.AUTHORIZED}),
    "settlement/cancel": frozenset({SettlementState.DRAFT, SettlementState.AUTHORIZED}),
    # Reconcile folds external rail evidence; it advances legs and may
    # complete or fail the batch, so it is valid while submitted.
    "settlement/reconcile": frozenset({SettlementState.SUBMITTED}),
    # Finality family (primary object: the finality certificate)
    # Validate creates the PENDING certificate or appends one more
    # validated claim binding to it.
    "finality/validate": frozenset({FinalityState.PENDING}),
    "finality/establish": frozenset({FinalityState.PENDING}),
    "finality/challenge": frozenset({FinalityState.ESTABLISHED}),
    "finality/revoke-claim": frozenset(
        {
            FinalityState.PENDING,
            FinalityState.ESTABLISHED,
            FinalityState.CHALLENGED,
        }
    ),
    # Recourse families (primary object: the recourse case)
    "recourse/refund.request": frozenset(),
    "recourse/refund.approve": frozenset({RecourseCaseState.REQUESTED}),
    "recourse/refund.reject": frozenset({RecourseCaseState.REQUESTED}),
    "recourse/refund.compile": frozenset({RecourseCaseState.APPROVED}),
    "recourse/refund.execute": frozenset({RecourseCaseState.COMPILED}),
    "recourse/reversal.request": frozenset(),
    "recourse/reversal.approve": frozenset({RecourseCaseState.REQUESTED}),
    "recourse/reversal.reject": frozenset({RecourseCaseState.REQUESTED}),
    "recourse/reversal.execute": frozenset({RecourseCaseState.APPROVED}),
}


def validate_command(command: str) -> str:
    """Require a command from the frozen settlement/finality/recourse families."""
    require_text("command", command)
    if command not in SETTLEMENT_ALL_COMMANDS:
        raise CoreValidationError(
            f"command {command!r} is not part of the frozen settlement, finality "
            "or recourse command families"
        )
    return command
