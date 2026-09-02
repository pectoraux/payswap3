"""Frozen public-boundary contracts for the execution domain (WORK-014).

This package owns the frozen v0.1 ``Execution`` command family
``Create/Authorize/Start/Submit/Acknowledge/Complete/Fail/Timeout/Retry/
Cancel`` and the ``External`` command family
``RequestEffect/RecordObservation/RecordEffectResult/RecordStatus/
RecordFinality`` — the external effect adapters and execution surface of
the canonical chain ``Intent → Execution → Clearing → Obligation →
Netting → Settlement → Finality``.

Registry discipline: ``payswap/execution-plan/v1`` (the protocol-visible
plan object) and the ``execution`` event namespace are ALREADY listed in
the frozen protocol registry and are used here exactly as registered.
Every other execution object kind below follows the sibling convention
and uses internal non-registry ``execution/...`` formats. No new
protocol-visible name is invented here.

Boundary with the sibling Work Orders: this package records EXTERNAL
observations of clearing/settlement/finality (WORK-015/016 own those
domains); it never establishes, promises or overstates settlement
finality. A payment status is never allowed to stand in for settlement
finality (constitution §4 and invariant 11).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_text

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
EXECUTION_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
EXECUTION_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of execution-domain durable objects.
EXECUTION_SCHEMA_VERSION = 1

#: Version of the typed adapter port boundary (ports over providers).
ADAPTER_PORT_API_VERSION = "v0.1"

#: Registry-listed protocol object type of the execution plan identity.
EXECUTION_PLAN_OBJECT_TYPE = "payswap/execution-plan/v1"

#: Internal (non-registry) object types of execution-domain durable objects.
EXECUTION_STEP_OBJECT_TYPE = "execution/step/v1"
EXECUTION_ATTEMPT_OBJECT_TYPE = "execution/attempt/v1"
EFFECT_REQUEST_OBJECT_TYPE = "execution/effect-request/v1"
EFFECT_RESULT_OBJECT_TYPE = "execution/effect-result/v1"
EXECUTION_RECEIPT_OBJECT_TYPE = "execution/receipt/v1"
EXECUTION_OBSERVATION_OBJECT_TYPE = "execution/observation/v1"

#: Every object type this package may produce (plan is registry-listed).
OBJECT_TYPES = (
    EXECUTION_PLAN_OBJECT_TYPE,
    EXECUTION_STEP_OBJECT_TYPE,
    EXECUTION_ATTEMPT_OBJECT_TYPE,
    EFFECT_REQUEST_OBJECT_TYPE,
    EFFECT_RESULT_OBJECT_TYPE,
    EXECUTION_RECEIPT_OBJECT_TYPE,
    EXECUTION_OBSERVATION_OBJECT_TYPE,
)

#: Registry-listed protocol event namespace owned by this domain.
EXECUTION_EVENT_NAMESPACE = "execution"

#: The frozen ``Execution`` command family (command-event-model.md).
EXECUTION_COMMANDS = frozenset(
    {
        "execution/plan.create",
        "execution/plan.authorize",
        "execution/plan.start",
        "execution/step.submit",
        "execution/step.acknowledge",
        "execution/step.complete",
        "execution/step.fail",
        "execution/step.timeout",
        "execution/step.retry",
        "execution/plan.cancel",
    }
)

#: The frozen ``External`` command family (command-event-model.md).
EXTERNAL_COMMANDS = frozenset(
    {
        "external/request-effect",
        "external/record-observation",
        "external/record-effect-result",
        "external/record-status",
        "external/record-finality",
    }
)

#: Every command this domain registers with the transition kernel.
EXECUTION_ALL_COMMANDS = EXECUTION_COMMANDS | EXTERNAL_COMMANDS

#: Command → canonical event type (all events use the registered
#: ``execution`` namespace; command types are internal free-form strings
#: per the sibling convention).
COMMAND_EVENT_TYPES: Mapping[str, str] = {
    "execution/plan.create": "execution/plan-created",
    "execution/plan.authorize": "execution/plan-authorized",
    "execution/plan.start": "execution/plan-started",
    "execution/plan.cancel": "execution/plan-cancelled",
    "execution/step.submit": "execution/step-submitted",
    "execution/step.acknowledge": "execution/step-acknowledged",
    "execution/step.complete": "execution/step-completed",
    "execution/step.fail": "execution/step-failed",
    "execution/step.timeout": "execution/step-timed-out",
    "execution/step.retry": "execution/step-retried",
    "external/request-effect": "execution/effect-requested",
    "external/record-observation": "execution/observation-recorded",
    "external/record-effect-result": "execution/effect-result-recorded",
    "external/record-status": "execution/status-recorded",
    "external/record-finality": "execution/finality-recorded",
}


# -- closed lifecycles ------------------------------------------------------


class ExecutionPlanState(StrEnum):
    """Closed lifecycle vocabulary of one execution plan.

    ``COMPLETED`` means every step's external effect executed
    successfully — it is an EXECUTION fact, never a settlement-finality
    claim (WORK-016 owns settlement, finality and reconciliation).
    """

    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "ExecutionPlanState":
        """Fail closed on unknown plan states (implementation principle 6)."""
        return parse_enum("execution plan state", value, cls)  # type: ignore[return-value]


#: Terminal plan states: history stays immutable after them.
EXECUTION_PLAN_TERMINAL_STATES = frozenset(
    {
        ExecutionPlanState.COMPLETED,
        ExecutionPlanState.FAILED,
        ExecutionPlanState.CANCELLED,
    }
)


class ExecutionStepState(StrEnum):
    """Closed lifecycle vocabulary of one execution step.

    ``UNKNOWN`` is the explicit reconcilable-outcome state: the rail
    never reported a definitive outcome for the in-flight attempt
    (submission transport failure or declared timeout). A step in
    ``UNKNOWN`` must be reconciled — query/observe through the adapter
    port — before any retry (constitution invariants 9 and 12).
    """

    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "ExecutionStepState":
        return parse_enum("execution step state", value, cls)  # type: ignore[return-value]


#: Terminal step states: no command accepts them as a source state.
EXECUTION_STEP_TERMINAL_STATES = frozenset(
    {
        ExecutionStepState.SUCCEEDED,
        ExecutionStepState.FAILED,
        ExecutionStepState.CANCELLED,
    }
)

#: States in which an external effect of this step is in flight (cancel
#: and terminal resolution must treat them as unreconcilable risk).
IN_FLIGHT_STEP_STATES = frozenset(
    {
        ExecutionStepState.SUBMITTED,
        ExecutionStepState.ACKNOWLEDGED,
        ExecutionStepState.UNKNOWN,
    }
)


class ExecutionAttemptState(StrEnum):
    """Closed outcome vocabulary of one submission attempt."""

    IN_FLIGHT = "IN_FLIGHT"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: object) -> "ExecutionAttemptState":
        return parse_enum("execution attempt state", value, cls)  # type: ignore[return-value]


class EffectRequestState(StrEnum):
    """Closed lifecycle vocabulary of one external effect request."""

    REQUESTED = "REQUESTED"
    SUBMITTED = "SUBMITTED"
    RESOLVED = "RESOLVED"
    CANCELLED = "CANCELLED"

    @classmethod
    def parse(cls, value: object) -> "EffectRequestState":
        return parse_enum("effect request state", value, cls)  # type: ignore[return-value]


# -- closed external-outcome vocabularies -----------------------------------


class EffectOutcome(StrEnum):
    """Closed vocabulary of rail-reported effect outcomes.

    ``UNKNOWN`` is an explicit, reconcilable ambiguity — never a silent
    failure and never a permission to retry blindly.
    """

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class SubmissionStatus(StrEnum):
    """Closed vocabulary of adapter submission responses.

    ``ACCEPTED`` — the rail accepted the effect for processing (native
    reference issued or imminent); ``REJECTED`` — the rail definitively
    refused the submission (the effect did not happen); ``UNKNOWN`` —
    no definitive submission response (transport failure: the outcome
    of the submission itself is unknown and must be reconciled).
    """

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class QueryOutcome(StrEnum):
    """Closed vocabulary of adapter reconciliation-query outcomes.

    ``NOT_FOUND`` is the rail's authoritative statement that the
    submitted effect never arrived or was never processed — the only
    retry-safe reconciliation outcome. ``SUCCEEDED``/``FAILED`` are
    definitive outcomes. ``UNKNOWN`` keeps the reconciliation open.
    """

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


class ObservationKind(StrEnum):
    """Closed vocabulary of recorded external observations.

    Maps the frozen ``External`` command family onto observation kinds:
    ``RecordObservation`` records reconciliation-query evidence
    (``QUERY``), ``RecordStatus`` records canonical status observations
    (``STATUS``) and ``RecordFinality`` records external finality claims
    (``FINALITY`` — evidence for the settlement domain, never authority
    here).
    """

    QUERY = "QUERY"
    STATUS = "STATUS"
    FINALITY = "FINALITY"


class FinalityClaim(StrEnum):
    """Closed vocabulary of externally claimed finality states.

    The claim is what the RAIL claims; recording it never makes it true
    in this domain (constitution invariant 11 — PaySwap never overstates
    settlement finality; WORK-016 owns finality).
    """

    FINAL = "FINAL"
    SETTLED = "SETTLED"
    REVOKED = "REVOKED"


#: The closed finality-claim vocabulary (frozen set of :class:`FinalityClaim`).
FINALITY_CLAIMS = frozenset(FinalityClaim)


# -- transition table -------------------------------------------------------


def _frozen(values: frozenset) -> frozenset:
    return values


#: Allowed SOURCE states per command of the frozen families, expressed
#: on the primary object the command advances (plan for plan commands,
#: step for step commands, effect request for request/result commands).
#: Commands that create their primary object (plan.create,
#: request-effect, record-*) have empty source sets. The engine's
#: handlers validate these tables before advancing any state.
EXECUTION_TRANSITIONS: Mapping[str, frozenset] = {
    "execution/plan.create": frozenset(),
    "execution/plan.authorize": frozenset({ExecutionPlanState.DRAFT}),
    "execution/plan.start": frozenset({ExecutionPlanState.AUTHORIZED}),
    "execution/plan.cancel": frozenset(
        {
            ExecutionPlanState.DRAFT,
            ExecutionPlanState.AUTHORIZED,
            ExecutionPlanState.RUNNING,
        }
    ),
    "execution/step.submit": frozenset({ExecutionStepState.PENDING}),
    "execution/step.acknowledge": frozenset({ExecutionStepState.SUBMITTED}),
    "execution/step.complete": frozenset(
        {
            ExecutionStepState.SUBMITTED,
            ExecutionStepState.ACKNOWLEDGED,
            ExecutionStepState.UNKNOWN,
        }
    ),
    "execution/step.fail": frozenset(
        {
            ExecutionStepState.SUBMITTED,
            ExecutionStepState.ACKNOWLEDGED,
            ExecutionStepState.UNKNOWN,
        }
    ),
    # A timeout may be declared for any in-flight effect (including one
    # already in the explicit UNKNOWN branch): it is the system trigger
    # that bounds the acknowledgment window and re-declares the
    # reconcilable outcome when the window elapsed.
    "execution/step.timeout": frozenset(IN_FLIGHT_STEP_STATES),
    "execution/step.retry": frozenset(
        {
            ExecutionStepState.FAILED,
            ExecutionStepState.UNKNOWN,
        }
    ),
    "external/request-effect": frozenset({ExecutionStepState.PENDING}),
    "external/record-observation": frozenset(IN_FLIGHT_STEP_STATES),
    "external/record-effect-result": frozenset(
        {
            ExecutionStepState.SUBMITTED,
            ExecutionStepState.ACKNOWLEDGED,
            ExecutionStepState.UNKNOWN,
        }
    ),
    "external/record-status": frozenset(
        {
            ExecutionStepState.SUBMITTED,
            ExecutionStepState.ACKNOWLEDGED,
            ExecutionStepState.UNKNOWN,
        }
    ),
    "external/record-finality": frozenset(),
}


def validate_command(command: str) -> str:
    """Require a command from the frozen execution/external families."""
    require_text("command", command)
    if command not in EXECUTION_ALL_COMMANDS:
        raise CoreValidationError(
            f"command {command!r} is not part of the frozen execution/external "
            "command families"
        )
    return command
