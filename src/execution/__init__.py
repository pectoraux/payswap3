"""PaySwap execution domain (WORK-014) — external effect adapters and execution.

This package owns the frozen v0.1 ``Execution`` command family
``Create/Authorize/Start/Submit/Acknowledge/Complete/Fail/Timeout/Retry/
Cancel`` and the ``External`` command family
``RequestEffect/RecordObservation/RecordEffectResult/RecordStatus/
RecordFinality``: execution plans, steps, attempts, effect requests and
results, the typed adapter ports, idempotent effect submission and the
unknown-result recovery discipline (reconcile before any retry).

Registry discipline: ``payswap/execution-plan/v1`` (the protocol-visible
plan object) and the ``execution`` event namespace are registered in the
frozen protocol registry and used exactly as registered; every other
object kind here uses internal non-registry ``execution/...`` formats.
This package records EXTERNAL observations of clearing, settlement and
finality (owned by other Work Orders) — it never establishes, promises
or overstates settlement finality (constitution invariants 11 and 12).

The public boundary below is typed and versioned
(:data:`EXECUTION_API_VERSION`); it is pinned by the test suite and
changes only through an Architecture Change Request. The re-exported
:class:`~src.core.errors.CoreValidationError` is the single error
authority; :class:`~src.simulation.effects.EffectAuthorization` (owned
by the merged simulation domain) is importable here as a convenience
for callers of :meth:`ExecutionEngine.request_effect` while remaining
that domain's contract — one authority per concept.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.simulation.effects import EffectAuthorization  # convenience re-export

from .adapters import (
    ADAPTER_PORT_API_VERSION,
    AdapterBinding,
    AdapterQueryResult,
    AdapterSubmission,
    EffectReconciliationPort,
    EffectSubmissionPort,
)
from .contracts import (
    COMMAND_EVENT_TYPES,
    EFFECT_REQUEST_OBJECT_TYPE,
    EFFECT_RESULT_OBJECT_TYPE,
    EXECUTION_ALL_COMMANDS,
    EXECUTION_API_VERSION,
    EXECUTION_ATTEMPT_OBJECT_TYPE,
    EXECUTION_COMMANDS,
    EXECUTION_EVENT_NAMESPACE,
    EXECUTION_OBSERVATION_OBJECT_TYPE,
    EXECUTION_PLAN_OBJECT_TYPE,
    EXECUTION_PLAN_TERMINAL_STATES,
    EXECUTION_PROTOCOL_VERSION,
    EXECUTION_RECEIPT_OBJECT_TYPE,
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_STEP_OBJECT_TYPE,
    EXECUTION_STEP_TERMINAL_STATES,
    EXECUTION_TRANSITIONS,
    EXTERNAL_COMMANDS,
    FINALITY_CLAIMS,
    OBJECT_TYPES,
    EffectOutcome,
    EffectRequestState,
    ExecutionAttemptState,
    ExecutionPlanState,
    ExecutionStepState,
    FinalityClaim,
    ObservationKind,
    QueryOutcome,
    SubmissionStatus,
)
from .effects import (
    EffectRequest,
    EffectRequestSpec,
    EffectResult,
    EffectResultSpec,
    ExternalObservation,
    ExternalObservationSpec,
    Receipt,
    ReceiptSpec,
)
from .engine import ExecutionEngine, ExecutionTransition
from .idempotency import EffectSubmissionLedger
from .plan import (
    ExecutionAttempt,
    ExecutionAttemptSpec,
    ExecutionPlan,
    ExecutionPlanSpec,
    ExecutionStep,
    ExecutionStepSpec,
)

__all__ = [
    "ADAPTER_PORT_API_VERSION",
    "AdapterBinding",
    "AdapterQueryResult",
    "AdapterSubmission",
    "COMMAND_EVENT_TYPES",
    "EFFECT_REQUEST_OBJECT_TYPE",
    "EFFECT_RESULT_OBJECT_TYPE",
    "EffectOutcome",
    "EffectReconciliationPort",
    "EffectRequest",
    "EffectRequestSpec",
    "EffectRequestState",
    "EffectResult",
    "EffectResultSpec",
    "EffectSubmissionLedger",
    "EffectSubmissionPort",
    "EXECUTION_ALL_COMMANDS",
    "EXECUTION_API_VERSION",
    "EXECUTION_ATTEMPT_OBJECT_TYPE",
    "EXECUTION_COMMANDS",
    "EXECUTION_EVENT_NAMESPACE",
    "EXECUTION_OBSERVATION_OBJECT_TYPE",
    "EXECUTION_PLAN_OBJECT_TYPE",
    "EXECUTION_PLAN_TERMINAL_STATES",
    "EXECUTION_PROTOCOL_VERSION",
    "EXECUTION_RECEIPT_OBJECT_TYPE",
    "EXECUTION_SCHEMA_VERSION",
    "EXECUTION_STEP_OBJECT_TYPE",
    "EXECUTION_STEP_TERMINAL_STATES",
    "EXECUTION_TRANSITIONS",
    "ExecutionAttempt",
    "ExecutionAttemptSpec",
    "ExecutionAttemptState",
    "ExecutionEngine",
    "ExecutionPlan",
    "ExecutionPlanSpec",
    "ExecutionPlanState",
    "ExecutionStep",
    "ExecutionStepSpec",
    "ExecutionStepState",
    "ExecutionTransition",
    "EXTERNAL_COMMANDS",
    "ExternalObservation",
    "ExternalObservationSpec",
    "FINALITY_CLAIMS",
    "FinalityClaim",
    "ObservationKind",
    "QueryOutcome",
    "Receipt",
    "ReceiptSpec",
    "SubmissionStatus",
    "CoreValidationError",
    "OBJECT_TYPES",
]
