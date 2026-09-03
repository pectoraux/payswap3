"""Frozen public-boundary contracts for the clearing domain (WORK-015).

This package owns the frozen v0.1 ``Clearing`` command family
``Create/Validate/Finalize/Cancel``, the ``Obligation`` command family
``Create/Validate/Amend/Dispute/Restructure/MarkDue/Default/Resolve`` and
the ``Netting`` command family ``Create/Add/Remove/Calculate/Finalize/
Cancel`` — the clearing stretch of the canonical financial chain
``Intent → Execution → Clearing → Obligation → Netting → Settlement →
Finality`` (constitution §4).

Registry discipline: ``payswap/obligation/v1`` (the protocol-visible
obligation object) and the ``clearing`` event namespace are ALREADY
listed in the frozen protocol registry and are used here exactly as
registered. Every other clearing object kind below follows the sibling
convention and uses internal non-registry ``clearing/...`` formats. No
new protocol-visible name is invented here.

Boundary with the sibling Work Orders: this package RECOGNIZES
obligations from the execution domain's reported effect results
(WORK-014 owns execution and its external observations; clearing never
re-evaluates a rail outcome — it consumes the recorded evidence),
netting offsets/reclassifies obligations (ledger-posting model:
``Netting → obligation offset/reclassification``), and it NEVER settles,
discharges or claims finality (WORK-016 owns settlement, finality and
reconciliation; constitution invariant 11). An obligation resolved here
is a clearing-side closure recorded with explicit evidence — never a
settlement-finality claim.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_text

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
CLEARING_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
CLEARING_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of clearing-domain durable objects.
CLEARING_SCHEMA_VERSION = 1

#: Registry-listed protocol object type of the obligation identity.
OBLIGATION_OBJECT_TYPE = "payswap/obligation/v1"

#: Internal (non-registry) object types of clearing-domain durable objects.
CLEARING_CYCLE_OBJECT_TYPE = "clearing/cycle/v1"
NETTING_CYCLE_OBJECT_TYPE = "clearing/netting-cycle/v1"

#: Every object type this package may produce (obligation is registry-listed).
OBJECT_TYPES = (
    OBLIGATION_OBJECT_TYPE,
    CLEARING_CYCLE_OBJECT_TYPE,
    NETTING_CYCLE_OBJECT_TYPE,
)

#: Registry-listed protocol event namespace owned by this domain.
CLEARING_EVENT_NAMESPACE = "clearing"

# -- the frozen command families ---------------------------------------------

#: The frozen v0.1 ``Clearing`` command family (command-event-model.md):
#: ``Create/Validate/Finalize/Cancel`` on the clearing cycle.
CLEARING_CYCLE_COMMANDS = frozenset(
    {
        "clearing/cycle.create",
        "clearing/cycle.validate",
        "clearing/cycle.finalize",
        "clearing/cycle.cancel",
    }
)

#: The frozen v0.1 ``Obligation`` command family (command-event-model.md):
#: ``Create/Validate/Amend/Dispute/Restructure/MarkDue/Default/Resolve``.
OBLIGATION_COMMANDS = frozenset(
    {
        "clearing/obligation.create",
        "clearing/obligation.validate",
        "clearing/obligation.amend",
        "clearing/obligation.dispute",
        "clearing/obligation.restructure",
        "clearing/obligation.mark-due",
        "clearing/obligation.default",
        "clearing/obligation.resolve",
    }
)

#: The frozen v0.1 ``Netting`` command family (command-event-model.md):
#: ``Create/Add/Remove/Calculate/Finalize/Cancel`` on the netting cycle.
NETTING_COMMANDS = frozenset(
    {
        "clearing/netting.create",
        "clearing/netting.add",
        "clearing/netting.remove",
        "clearing/netting.calculate",
        "clearing/netting.finalize",
        "clearing/netting.cancel",
    }
)

#: Every command this domain registers with the transition kernel.
CLEARING_ALL_COMMANDS = CLEARING_CYCLE_COMMANDS | OBLIGATION_COMMANDS | NETTING_COMMANDS

#: Command → canonical event type (all events use the registered
#: ``clearing`` namespace; command types are internal free-form strings
#: per the sibling convention).
COMMAND_EVENT_TYPES: Mapping[str, str] = {
    "clearing/cycle.create": "clearing/cycle-created",
    "clearing/cycle.validate": "clearing/cycle-validated",
    "clearing/cycle.finalize": "clearing/cycle-finalized",
    "clearing/cycle.cancel": "clearing/cycle-cancelled",
    "clearing/obligation.create": "clearing/obligation-created",
    "clearing/obligation.validate": "clearing/obligation-validated",
    "clearing/obligation.amend": "clearing/obligation-amended",
    "clearing/obligation.dispute": "clearing/obligation-disputed",
    "clearing/obligation.restructure": "clearing/obligation-restructured",
    "clearing/obligation.mark-due": "clearing/obligation-due",
    "clearing/obligation.default": "clearing/obligation-defaulted",
    "clearing/obligation.resolve": "clearing/obligation-resolved",
    "clearing/netting.create": "clearing/netting-created",
    "clearing/netting.add": "clearing/netting-member-added",
    "clearing/netting.remove": "clearing/netting-member-removed",
    "clearing/netting.calculate": "clearing/netting-calculated",
    "clearing/netting.finalize": "clearing/netting-finalized",
    "clearing/netting.cancel": "clearing/netting-cancelled",
}


# -- closed lifecycles ------------------------------------------------------


class ClearingCycleState(StrEnum):
    """Closed lifecycle vocabulary of one clearing cycle.

    A clearing cycle is the recognition window inside which obligations
    are recognized from execution evidence. ``VALIDATED`` means every
    member obligation has passed validation; ``FINALIZED`` binds the
    clearing statement (per pair and per asset gross exposure) and makes
    the member obligations eligible for netting; ``CANCELLED`` closes
    the batch without a statement — member obligations survive (history
    is immutable), they simply never became cycle-cleared.
    """

    OPEN = "OPEN"
    VALIDATED = "VALIDATED"
    FINALIZED = "FINALIZED"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "ClearingCycleState":
        """Fail closed on unknown cycle states (implementation principle 6)."""
        return parse_enum("clearing cycle state", value, cls)  # type: ignore[return-value]


#: Terminal cycle states: history stays immutable after them.
CLEARING_CYCLE_TERMINAL_STATES = frozenset(
    {
        ClearingCycleState.FINALIZED,
        ClearingCycleState.CANCELLED,
    }
)


class ObligationState(StrEnum):
    """Closed lifecycle vocabulary of one obligation.

    ``RECOGNIZED`` — created and digest-bound to its execution evidence.
    ``VALIDATED`` — the derived facts re-verified (source binding,
    amount, window). ``AMENDED`` — terms restructured by ``Amend``.
    ``DISPUTED`` — a dispute backed by ``OBSERVED`` evidence is open.
    ``RESTRUCTURED`` — the dispute was resolved with new terms.
    ``DUE`` — marked due (optionally backed by ``HELD`` funding
    evidence). ``DEFAULTED``/``RESOLVED`` are terminal: the obligation
    either failed (recorded default evidence) or closed (netting
    offset, or recorded discharge evidence — a clearing-side closure,
    never a settlement-finality claim).
    """

    RECOGNIZED = "RECOGNIZED"
    VALIDATED = "VALIDATED"
    AMENDED = "AMENDED"
    DISPUTED = "DISPUTED"
    RESTRUCTURED = "RESTRUCTURED"
    DUE = "DUE"
    DEFAULTED = "DEFAULTED"
    RESOLVED = "RESOLVED"

    @classmethod
    def parse(cls, value: object) -> "ObligationState":
        return parse_enum("obligation state", value, cls)  # type: ignore[return-value]


#: Terminal obligation states: no command accepts them as a source state.
OBLIGATION_TERMINAL_STATES = frozenset(
    {
        ObligationState.DEFAULTED,
        ObligationState.RESOLVED,
    }
)

#: Obligation states that have passed validation (eligible for cycle
#: finalization membership and netting membership).
OBLIGATION_VALIDATED_STATES = frozenset(
    {
        ObligationState.VALIDATED,
        ObligationState.AMENDED,
        ObligationState.RESTRUCTURED,
        ObligationState.DUE,
    }
)


class NettingCycleState(StrEnum):
    """Closed lifecycle vocabulary of one netting cycle.

    ``OPEN`` — members are being added/removed. ``CALCULATED`` — the
    deterministic netting statement is bound (gross → net per pair or
    per participant, per asset). ``FINALIZED`` — the statement is
    binding: member obligations resolve through the netting and
    (bilateral mode) net obligations are issued. ``CANCELLED`` —
    abandoned before finalization; members untouched.
    """

    OPEN = "OPEN"
    CALCULATED = "CALCULATED"
    FINALIZED = "FINALIZED"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "NettingCycleState":
        return parse_enum("netting cycle state", value, cls)  # type: ignore[return-value]


#: Terminal netting states.
NETTING_TERMINAL_STATES = frozenset(
    {
        NettingCycleState.FINALIZED,
        NettingCycleState.CANCELLED,
    }
)


class NettingMode(StrEnum):
    """Closed vocabulary of netting modes.

    ``BILATERAL`` — reciprocal obligations between each unordered
    participant pair are offset; members resolve and one net obligation
    per pair/asset is issued in the dominant direction (ledger-posting
    model: ``Netting → obligation offset``).

    ``MULTILATERAL`` — obligations are reclassified into per participant
    net funding positions per asset (ledger-posting model:
    ``Netting → obligation reclassification``); members resolve and the
    sealed statement records the net positions (Σ positions = 0 per
    asset — conservation). No new obligations are issued: funding the
    net positions is settlement's concern (WORK-016).
    """

    BILATERAL = "BILATERAL"
    MULTILATERAL = "MULTILATERAL"

    @classmethod
    def parse(cls, value: object) -> "NettingMode":
        return parse_enum("netting mode", value, cls)  # type: ignore[return-value]


class ObligationSourceKind(StrEnum):
    """Closed vocabulary of how an obligation was recognized.

    ``EXECUTION_EVIDENCE`` — recognized from a rail-reported SUCCEEDED
    effect result of the execution domain (digest-bound).

    ``NETTING_ISSUANCE`` — issued by a finalized bilateral netting
    cycle as the net of offset reciprocal obligations (statement
    digest-bound).
    """

    EXECUTION_EVIDENCE = "EXECUTION_EVIDENCE"
    NETTING_ISSUANCE = "NETTING_ISSUANCE"

    @classmethod
    def parse(cls, value: object) -> "ObligationSourceKind":
        return parse_enum("obligation source kind", value, cls)  # type: ignore[return-value]


class ResolutionKind(StrEnum):
    """Closed vocabulary of obligation resolution.

    ``NETTING`` — the obligation was offset/reclassified by a finalized
    netting cycle (internal, statement digest-bound).

    ``DISCHARGE_EVIDENCE`` — externally declared discharge evidence was
    recorded (settlement's concern — WORK-016 owns settlement and
    finality; recording a discharge reference here NEVER establishes
    settlement finality, constitution invariant 11).
    """

    NETTING = "NETTING"
    DISCHARGE_EVIDENCE = "DISCHARGE_EVIDENCE"

    @classmethod
    def parse(cls, value: object) -> "ResolutionKind":
        return parse_enum("resolution kind", value, cls)  # type: ignore[return-value]


# -- transition table -------------------------------------------------------


#: Allowed SOURCE states per command of the frozen families, expressed
#: on the primary object the command advances (clearing cycle for the
#: Clearing family, obligation for the Obligation family, netting cycle
#: for the Netting family). Commands that create their primary object
#: have empty source sets. The engine's handlers validate these tables
#: before advancing any state.
CLEARING_TRANSITIONS: Mapping[str, frozenset] = {
    # Clearing family (primary object: the clearing cycle)
    "clearing/cycle.create": frozenset(),
    "clearing/cycle.validate": frozenset({ClearingCycleState.OPEN}),
    "clearing/cycle.finalize": frozenset({ClearingCycleState.VALIDATED}),
    "clearing/cycle.cancel": frozenset(
        {
            ClearingCycleState.OPEN,
            ClearingCycleState.VALIDATED,
        }
    ),
    # Obligation family (primary object: the obligation)
    "clearing/obligation.create": frozenset(),
    "clearing/obligation.validate": frozenset({ObligationState.RECOGNIZED}),
    # Amendments restructure terms; a disputed obligation must be
    # restructured (or defaulted after restructure/mark-due), never
    # silently amended.
    "clearing/obligation.amend": frozenset(
        {
            ObligationState.VALIDATED,
            ObligationState.AMENDED,
            ObligationState.RESTRUCTURED,
        }
    ),
    "clearing/obligation.dispute": frozenset(
        {
            ObligationState.VALIDATED,
            ObligationState.AMENDED,
            ObligationState.RESTRUCTURED,
            ObligationState.DUE,
        }
    ),
    "clearing/obligation.restructure": frozenset({ObligationState.DISPUTED}),
    "clearing/obligation.mark-due": frozenset(
        {
            ObligationState.VALIDATED,
            ObligationState.AMENDED,
            ObligationState.RESTRUCTURED,
        }
    ),
    "clearing/obligation.default": frozenset({ObligationState.DUE}),
    "clearing/obligation.resolve": frozenset({ObligationState.DUE}),
    # Netting family (primary object: the netting cycle)
    "clearing/netting.create": frozenset(),
    "clearing/netting.add": frozenset({NettingCycleState.OPEN}),
    "clearing/netting.remove": frozenset({NettingCycleState.OPEN}),
    "clearing/netting.calculate": frozenset({NettingCycleState.OPEN}),
    "clearing/netting.finalize": frozenset({NettingCycleState.CALCULATED}),
    "clearing/netting.cancel": frozenset(
        {
            NettingCycleState.OPEN,
            NettingCycleState.CALCULATED,
        }
    ),
}


def validate_command(command: str) -> str:
    """Require a command from the frozen clearing/obligation/netting families."""
    require_text("command", command)
    if command not in CLEARING_ALL_COMMANDS:
        raise CoreValidationError(
            f"command {command!r} is not part of the frozen clearing, obligation or "
            "netting command families"
        )
    return command
