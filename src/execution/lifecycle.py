"""Execution lifecycle gates and command payloads (WORK-014).

The explicit state machine of the frozen ``Execution`` and ``External``
command families: source-state validation per command, the
authority-before-effect gates, the safety/reservation gate evidence
validators, the covering effect-authorization check, the
unknown-result reconciliation gate (never blind retry) and the command
payload parsers shared by the engine's kernel handlers.

Coupling to the merged dependency domains is minimal and documented:

* the fraud/compliance gate verdicts are the closed vocabularies owned
  by ``src.safety`` (FraudDecisionState, ComplianceVerdict) — consumed
  as binding inputs, never re-evaluated here (one authority per
  concept: safety decides, execution obeys);
* the reservation gate state is the closed vocabulary owned by
  ``src.reservation`` (ReservationState) — a submission requires a HELD
  reservation (the capacity the effect consumes is actually held);
* the covering effect authorization is the typed, windowed contract
  owned by ``src.simulation`` (EffectAuthorization) — consumed exactly
  as the merged mainline defines it (production effect intents require
  an explicit typed authorization; execution is the real-execution
  chain behind that boundary);
* the status-observation reconciliation classification reuses the
  frozen canonical payment status predicates owned by
  ``src.interoperability`` (requires_reconciliation /
  is_retry_safe_payment_status).

Every gate failure raises
:class:`~src.core.errors.CoreValidationError` — the single error
authority — with an explicit message: all required failure paths are
explicit.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.reservation import ReservationState
from src.safety.contracts import ComplianceVerdict, FraudDecisionState
from src.simulation.effects import EffectAuthorization
from src.transition.registry import validate_authority_class

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    EXECUTION_TRANSITIONS,
    EffectOutcome,
    ExecutionPlanState,
    ExecutionStepState,
    FinalityClaim,
    ObservationKind,
    QueryOutcome,
    SubmissionStatus,
)
from .effects import ExternalObservation
from .plan import ExecutionStep

_PLAN_CREATE_FIELDS = frozenset({"source_ref", "summary", "steps"})
_STEP_ENTRY_FIELDS = frozenset(
    {
        "step_id",
        "adapter_id",
        "effect_type",
        "payload",
        "reservation_ref",
        "max_attempts",
    }
)
_AUTHORIZE_FIELDS = frozenset(
    {
        "authority_class",
        "mandate_ref",
        "fraud_decision",
        "compliance_assessment",
    }
)
_FRAUD_GATE_FIELDS = frozenset({"decision_id", "verdict", "object_version"})
_COMPLIANCE_GATE_FIELDS = frozenset({"assessment_id", "verdict", "object_version"})
_HOLD_FIELDS = frozenset({"reservation_id", "state", "object_version"})
_REQUEST_EFFECT_FIELDS = frozenset({"idempotency_key", "authorization", "hold"})
_SUBMIT_FIELDS = frozenset({"idempotency_key"})
_AUTHORIZATION_FIELDS = frozenset(
    {
        "authorizer",
        "authority_class",
        "authorized_types",
        "valid_from",
        "valid_until",
    }
)
_ACKNOWLEDGE_FIELDS = frozenset({"native_reference"})
_RESULT_FIELDS = frozenset(
    {"request_id", "outcome", "native_reference", "error_code", "observed_at", "detail"}
)
_FAIL_FIELDS = frozenset({"reason"})
_TIMEOUT_FIELDS = frozenset({"deadline", "reason"})
_RETRY_FIELDS = frozenset({"reason"})
_CANCEL_FIELDS = frozenset({"reason"})
_OBSERVATION_FIELDS = frozenset({"query", "subject_ref"})
_QUERY_FIELDS = frozenset({"outcome", "native_reference"})
_STATUS_FIELDS = frozenset({"native_code", "canonical_status"})
_FINALITY_FIELDS = frozenset({"claim", "native_reference"})


# ---------------------------------------------------------------------------
# gate evidence validation
# ---------------------------------------------------------------------------


def validate_fraud_gate(value: Any) -> dict[str, Any]:
    """Require an evidence-backed fraud-decision gate that clears execution.

    The fraud verdict is the closed ``FraudDecisionState`` vocabulary
    owned by ``src.safety``; only ``ALLOW`` clears the gate. Every other
    verdict — including ``STEP_UP``, ``HELD`` and terminal ``BLOCKED`` —
    fails closed (compliance and fraud cannot be bypassed).
    """
    mapping = require_mapping("fraud gate", value)
    strict_fields("fraud gate", mapping, _FRAUD_GATE_FIELDS)
    decision_id = require_identifier("fraud gate decision_id", mapping["decision_id"])
    verdict = parse_enum("fraud gate verdict", mapping["verdict"], FraudDecisionState)
    if verdict is not FraudDecisionState.ALLOW:
        raise CoreValidationError(
            f"fraud gate verdict {verdict.value!r} does not clear execution; "
            "only ALLOW may authorize an execution plan"
        )
    object_version = require_int("fraud gate object_version", mapping["object_version"], minimum=1)
    return {"decision_id": decision_id, "verdict": verdict.value, "object_version": object_version}


def validate_compliance_gate(value: Any) -> dict[str, Any]:
    """Require an evidence-backed compliance gate that clears execution.

    The compliance verdict is the closed ``ComplianceVerdict`` vocabulary
    owned by ``src.safety``; only ``SATISFIED`` clears the gate (a
    ``BLOCKED`` verdict is binding for every execution decision).
    """
    mapping = require_mapping("compliance gate", value)
    strict_fields("compliance gate", mapping, _COMPLIANCE_GATE_FIELDS)
    assessment_id = require_identifier(
        "compliance gate assessment_id", mapping["assessment_id"]
    )
    verdict = parse_enum("compliance gate verdict", mapping["verdict"], ComplianceVerdict)
    if verdict is not ComplianceVerdict.SATISFIED:
        raise CoreValidationError(
            f"compliance gate verdict {verdict.value!r} does not clear execution; "
            "compliance cannot be bypassed through routing"
        )
    object_version = require_int(
        "compliance gate object_version", mapping["object_version"], minimum=1
    )
    return {
        "assessment_id": assessment_id,
        "verdict": verdict.value,
        "object_version": object_version,
    }


def validate_hold_gate(value: Any) -> dict[str, Any]:
    """Require reservation-gate evidence that the consumed capacity is HELD.

    The reservation state is the closed ``ReservationState`` vocabulary
    owned by ``src.reservation``; only a ``HELD`` reservation backs an
    external effect submission (the hold the execution must respect —
    constitution invariant 8, reservation safety).
    """
    mapping = require_mapping("hold gate", value)
    strict_fields("hold gate", mapping, _HOLD_FIELDS)
    reservation_id = require_identifier("hold gate reservation_id", mapping["reservation_id"])
    state = parse_enum("hold gate state", mapping["state"], ReservationState)
    if state is not ReservationState.HELD:
        raise CoreValidationError(
            f"reservation {reservation_id} is {state.value!r}; an external effect "
            "submission requires a HELD reservation"
        )
    object_version = require_int("hold gate object_version", mapping["object_version"], minimum=1)
    return {
        "reservation_id": reservation_id,
        "state": state.value,
        "object_version": object_version,
    }


def validate_covering_authorization(
    value: Any, *, effect_type: str, requested_at: str
) -> EffectAuthorization:
    """Require a typed, windowed, covering effect authorization.

    The authorization contract is owned by the merged simulation domain
    (``src.simulation.effects.EffectAuthorization``) and is consumed
    here without redefinition: the production real-execution chain sits
    behind exactly this boundary. The authorization must cover the
    request's effect type at the request's declared instant.
    """
    mapping = require_mapping("effect authorization", value)
    strict_fields("effect authorization", mapping, _AUTHORIZATION_FIELDS)
    authorized_types = mapping["authorized_types"]
    if not isinstance(authorized_types, (list, tuple, frozenset, set)):
        raise CoreValidationError(
            "effect authorization authorized_types must deserialize from a list"
        )
    authorization = EffectAuthorization(
        authorizer=mapping["authorizer"],
        authority_class=mapping["authority_class"],
        authorized_types=frozenset(authorized_types),
        valid_from=mapping["valid_from"],
        valid_until=mapping["valid_until"],
    )
    validate_authority_class(
        "effect authorization authority_class", authorization.authority_class
    )
    require_utc_timestamp("effect request requested_at", requested_at)
    if not authorization.covers(effect_type, requested_at):
        raise CoreValidationError(
            f"effect authorization does not cover effect type {effect_type!r} at "
            f"{requested_at} (type set or validity window)"
        )
    return authorization


# ---------------------------------------------------------------------------
# state-machine discipline
# ---------------------------------------------------------------------------


def require_source_state(command: str, state: ExecutionStepState | ExecutionPlanState) -> None:
    """Fail closed unless ``state`` is a valid source state for ``command``.

    The allowed source states are the frozen transition table in
    :data:`~src.execution.contracts.EXECUTION_TRANSITIONS`.
    """
    allowed = EXECUTION_TRANSITIONS.get(command)
    if allowed is None:
        raise CoreValidationError(f"command {command!r} is not part of the frozen families")
    if not isinstance(state, (ExecutionStepState, ExecutionPlanState)):
        raise CoreValidationError("source state must be an execution step or plan state")
    if state not in allowed:
        raise CoreValidationError(
            f"{command} requires one of the source states "
            f"{sorted(item.value for item in allowed)} but the object is {state.value}"
        )


def require_step_in_flight(step: ExecutionStep) -> None:
    """Fail closed unless the step's effect is in flight (submitted/unknown)."""
    if step.state not in {
        ExecutionStepState.SUBMITTED,
        ExecutionStepState.ACKNOWLEDGED,
        ExecutionStepState.UNKNOWN,
    }:
        raise CoreValidationError(
            f"step {step.object_id} is {step.state.value}; an in-flight effect "
            "is required for external observations"
        )


def observation_is_recent(observation: ExternalObservation, *, not_before: str) -> bool:
    """Whether reconciliation evidence postdates the unknown outcome.

    An observation that predates the moment the outcome became unknown
    proves nothing about that outcome and is ignored as stale evidence
    (never silently trusted).
    """
    from ._validation import parse_utc_timestamp

    observed = parse_utc_timestamp("observation observed_at", observation.spec.observed_at)
    floor = parse_utc_timestamp("reconciliation floor", not_before)
    return observed >= floor


def check_retry_gate(
    *,
    step: ExecutionStep,
    observations: tuple[ExternalObservation, ...],
    current_request: Any,
    attempt_count: int,
    recorded_result: Any = None,
) -> None:
    """The unknown-result no-blind-retry gate (constitution invariants 9/12).

    A retry is safe only when:

    * the step is ``FAILED`` (the rail definitively reported the effect
      did not succeed) — no reconciliation needed; or
    * the step is in flight but the CURRENT request carries a recorded
      definitive ``FAILED`` effect result (the rail's own statement that
      the effect did not happen — reconciliation evidence, consumed
      digest-bound); or
    * the step is ``UNKNOWN`` AND a recorded observation for the
      step's CURRENT request — observed after the outcome became
      unknown — establishes that the effect did NOT happen
      (reconciliation-query ``NOT_FOUND`` or a retry-safe canonical
      status). Otherwise the retry fails closed.

    A recorded definitive ``SUCCEEDED`` result never permits a retry:
    the effect happened — completing the step is the only legal move.

    The retry budget (``max_attempts``) bounds total submissions.
    """
    state = step.state
    if state is ExecutionStepState.FAILED:
        pass  # definitive failure: the rail reported the effect did not happen
    elif state in (ExecutionStepState.SUBMITTED, ExecutionStepState.ACKNOWLEDGED):
        if recorded_result is not None and recorded_result.spec.outcome is EffectOutcome.SUCCEEDED:
            raise CoreValidationError(
                f"step {step.object_id} has a recorded SUCCEEDED effect result for "
                "its current request; the effect happened — complete the step, "
                "never retry it"
            )
        if recorded_result is None or recorded_result.spec.outcome is not EffectOutcome.FAILED:
            raise CoreValidationError(
                f"step {step.object_id} is {state.value} without a definitive FAILED "
                "effect result; only FAILED or reconciled UNKNOWN steps may be "
                "retried"
            )
        # A definitive FAILED result for the current request is the rail's
        # own reconciliation evidence that the effect did not happen.
    elif state is ExecutionStepState.UNKNOWN:
        if current_request is None:
            raise CoreValidationError(
                f"step {step.object_id} is UNKNOWN but has no in-flight request to "
                "reconcile; refusing a blind retry"
            )
        reconciled = False
        unknown_since = _unknown_since_instant(step)
        for observation in observations:
            if observation.spec.subject_ref != current_request.spec.request_id:
                continue
            if observation.spec.subject_request_digest != current_request.spec.digest:
                continue
            if not observation_is_recent(observation, not_before=unknown_since):
                continue  # stale evidence predating the unknown outcome
            if observation.spec.kind is ObservationKind.QUERY:
                if observation.spec.query_outcome is QueryOutcome.NOT_FOUND:
                    reconciled = True
            elif observation.spec.kind is ObservationKind.STATUS:
                if _is_retry_safe_status(observation.spec.canonical_status.value):
                    reconciled = True
        if not reconciled:
            raise CoreValidationError(
                f"step {step.object_id} has an UNKNOWN outcome that has not been "
                "reconciled; a blind retry is forbidden (constitution invariants "
                "9 and 12 — reconcile through the adapter port before any retry)"
            )
    else:
        raise CoreValidationError(
            f"step {step.object_id} is {state.value}; only FAILED or reconciled "
            "UNKNOWN steps may be retried"
        )
    if attempt_count >= step.spec.max_attempts:
        raise CoreValidationError(
            f"step {step.object_id} exhausted its retry budget "
            f"({attempt_count}/{step.spec.max_attempts} attempts)"
        )


def _unknown_since_instant(step: ExecutionStep) -> str:
    """The instant from which reconciliation evidence counts.

    The step envelope's latest recorded transition — the moment the
    outcome became unknown (submission transport failure, declared
    timeout or an unknown status/result observation).
    """
    return step.envelope.provenance.recorded_at


def _is_retry_safe_status(status: str) -> bool:
    from src.interoperability.status import is_retry_safe_payment_status

    return is_retry_safe_payment_status(status)


def status_observation_effect(step: ExecutionStep, canonical_status: str) -> str | None:
    """Classify what a canonical status observation does to a step.

    Reuses the frozen interoperability classification:

    * a reconciliation-required status (``UNKNOWN``) moves a
      SUBMITTED/ACKNOWLEDGED step into the explicit unknown branch
      (mirrors the interoperability ambiguous-branch semantics);
    * a retry-safe status is reconciliation evidence (consumed by the
      retry gate) but never directly advances the step;
    * every other status — including success/terminal claims like
      SETTLED/FINAL — is evidence only: a payment status never stands
      in for settlement finality and never completes a step here.
    """
    from src.interoperability.status import (
        requires_reconciliation,
    )

    require_text("canonical status", canonical_status)
    if requires_reconciliation(canonical_status):
        return "unknown"
    return "evidence"


def classify_recorded_result(outcome: EffectOutcome) -> str:
    """Map a rail-reported result outcome onto its lifecycle meaning."""
    if outcome is EffectOutcome.SUCCEEDED:
        return "definitive-success"
    if outcome is EffectOutcome.FAILED:
        return "definitive-failure"
    return "unknown"


def plan_resolution(steps: tuple[ExecutionStep, ...]) -> ExecutionPlanState | None:
    """Resolve the plan's terminal state once every step is terminal.

    All steps SUCCEEDED → ``COMPLETED``; any step FAILED → ``FAILED``;
    otherwise (a cancelled mix) the plan was already cancelled by the
    plan-level command. Returns ``None`` while any step is not terminal
    or a cancelled mix leaves the plan non-terminal (the plan-level
    cancel command owns that transition).
    """
    if not steps:
        raise CoreValidationError("a plan must have at least one step to resolve")
    if any(step.state is ExecutionStepState.CANCELLED for step in steps):
        return None
    if not all(step.is_terminal() for step in steps):
        return None
    if all(step.state is ExecutionStepState.SUCCEEDED for step in steps):
        return ExecutionPlanState.COMPLETED
    return ExecutionPlanState.FAILED


# ---------------------------------------------------------------------------
# command payload parsing
# ---------------------------------------------------------------------------


def parse_plan_create_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("plan.create payload", payload)
    strict_fields("plan.create payload", mapping, _PLAN_CREATE_FIELDS)
    source_ref = require_text("plan.create source_ref", mapping["source_ref"])
    summary = mapping["summary"]
    if not isinstance(summary, str):
        raise CoreValidationError("plan.create summary must be a string")
    steps_raw = mapping["steps"]
    if not isinstance(steps_raw, (list, tuple)):
        raise CoreValidationError("plan.create steps must deserialize from a list")
    if not steps_raw:
        raise CoreValidationError("plan.create requires at least one step")
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(steps_raw):
        if not isinstance(entry, Mapping):
            raise CoreValidationError("plan.create steps entries must be objects")
        strict_fields("plan.create step", entry, _STEP_ENTRY_FIELDS)
        step_id = require_identifier(
            "plan.create step step_id", entry["step_id"]
        )
        if step_id in seen:
            raise CoreValidationError(
                f"plan.create declares duplicate step id {step_id!r}"
            )
        seen.add(step_id)
        require_identifier("plan.create step adapter_id", entry["adapter_id"])
        require_text("plan.create step effect_type", entry["effect_type"])
        from ._validation import require_effect_type

        require_effect_type("plan.create step effect_type", entry["effect_type"])
        require_identifier(
            "plan.create step reservation_ref", entry["reservation_ref"]
        )
        require_int("plan.create step max_attempts", entry["max_attempts"], minimum=1)
        steps.append(dict(entry))
    return {"source_ref": source_ref, "summary": summary, "steps": steps}


def parse_authorize_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("plan.authorize payload", payload)
    strict_fields("plan.authorize payload", mapping, _AUTHORIZE_FIELDS)
    authority_class = validate_authority_class(
        "plan.authorize authority_class", mapping["authority_class"]
    )
    mandate_ref = mapping["mandate_ref"]
    if mandate_ref is not None:
        require_identifier("plan.authorize mandate_ref", mandate_ref)
    fraud_decision = validate_fraud_gate(mapping["fraud_decision"])
    compliance_assessment = validate_compliance_gate(mapping["compliance_assessment"])
    return {
        "authority_class": authority_class,
        "mandate_ref": mandate_ref,
        "fraud_decision": fraud_decision,
        "compliance_assessment": compliance_assessment,
    }


def parse_submit_payload(payload: Any) -> dict[str, Any]:
    """The step.submit command names the effect key it submits."""
    mapping = require_mapping("step.submit payload", payload)
    strict_fields("step.submit payload", mapping, _SUBMIT_FIELDS)
    idempotency_key = require_text("step.submit idempotency_key", mapping["idempotency_key"])
    return {"idempotency_key": idempotency_key}


def parse_request_effect_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("request-effect payload", payload)
    strict_fields("request-effect payload", mapping, _REQUEST_EFFECT_FIELDS)
    idempotency_key = require_text(
        "request-effect idempotency_key", mapping["idempotency_key"]
    )
    authorization = require_mapping(
        "request-effect authorization", mapping["authorization"]
    )
    hold = validate_hold_gate(mapping["hold"])
    return {"idempotency_key": idempotency_key, "authorization": authorization, "hold": hold}


def parse_acknowledge_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("step.acknowledge payload", payload)
    strict_fields("step.acknowledge payload", mapping, _ACKNOWLEDGE_FIELDS)
    native_reference = require_text(
        "step.acknowledge native_reference", mapping["native_reference"]
    )
    return {"native_reference": native_reference}


def parse_record_result_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("record-effect-result payload", payload)
    strict_fields("record-effect-result payload", mapping, _RESULT_FIELDS)
    request_id = require_identifier(
        "record-effect-result request_id", mapping["request_id"]
    )
    outcome = parse_enum("record-effect-result outcome", mapping["outcome"], EffectOutcome)
    native_reference = mapping["native_reference"]
    if native_reference is not None:
        require_text("record-effect-result native_reference", native_reference)
    if outcome is not EffectOutcome.UNKNOWN and not native_reference:
        raise CoreValidationError(
            "a definitive effect result must carry the rail's native reference"
        )
    error_code = mapping["error_code"]
    if error_code is not None:
        require_text("record-effect-result error_code", error_code)
    observed_at = require_utc_timestamp(
        "record-effect-result observed_at", mapping["observed_at"]
    )
    detail = mapping["detail"]
    return {
        "request_id": request_id,
        "outcome": outcome,
        "native_reference": native_reference,
        "error_code": error_code,
        "observed_at": observed_at,
        "detail": detail,
    }


def parse_reason_payload(command: str, payload: Any) -> dict[str, Any]:
    mapping = require_mapping(f"{command} payload", payload)
    strict_fields(f"{command} payload", mapping, _FAIL_FIELDS)
    reason = require_text(f"{command} reason", mapping["reason"])
    return {"reason": reason}


def parse_timeout_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("step.timeout payload", payload)
    strict_fields("step.timeout payload", mapping, _TIMEOUT_FIELDS)
    deadline = require_utc_timestamp("step.timeout deadline", mapping["deadline"])
    reason = require_text("step.timeout reason", mapping["reason"])
    return {"deadline": deadline, "reason": reason}


def parse_observation_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("record-observation payload", payload)
    strict_fields("record-observation payload", mapping, _OBSERVATION_FIELDS)
    query = require_mapping("record-observation query", mapping["query"])
    strict_fields("record-observation query", query, _QUERY_FIELDS)
    outcome = parse_enum("record-observation query outcome", query["outcome"], QueryOutcome)
    native_reference = query["native_reference"]
    if native_reference is not None:
        require_text("record-observation query native_reference", native_reference)
    if outcome in (QueryOutcome.SUCCEEDED, QueryOutcome.FAILED) and not native_reference:
        raise CoreValidationError(
            "a definitive reconciliation outcome must carry the rail's native reference"
        )
    subject_ref = require_identifier(
        "record-observation subject_ref", mapping["subject_ref"]
    )
    return {
        "query": {"outcome": outcome.value, "native_reference": native_reference},
        "subject_ref": subject_ref,
    }


def parse_status_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("record-status payload", payload)
    strict_fields("record-status payload", mapping, _STATUS_FIELDS)
    native_code = require_text("record-status native_code", mapping["native_code"])
    from src.interoperability.status import coerce_payment_status

    canonical_status = coerce_payment_status(mapping["canonical_status"])
    return {"native_code": native_code, "canonical_status": canonical_status.value}


def parse_finality_payload(payload: Any) -> dict[str, Any]:
    mapping = require_mapping("record-finality payload", payload)
    strict_fields("record-finality payload", mapping, _FINALITY_FIELDS)
    claim = parse_enum("record-finality claim", mapping["claim"], FinalityClaim)
    native_reference = require_text(
        "record-finality native_reference", mapping["native_reference"]
    )
    return {"claim": claim.value, "native_reference": native_reference}


def validate_timeout_declaration(*, requested_at: str, deadline: str) -> None:
    """A timeout may only be declared at or after the declared deadline."""
    from ._validation import parse_utc_timestamp

    declared = parse_utc_timestamp("timeout requested_at", requested_at)
    limit = parse_utc_timestamp("timeout deadline", deadline)
    if declared < limit:
        raise CoreValidationError(
            f"timeout declared at {requested_at} is before the deadline {deadline}; "
            "a timeout may only be declared once the window has elapsed"
        )


def validate_submission_status(value: Any) -> SubmissionStatus:
    return parse_enum("submission status", value, SubmissionStatus)


def validate_result_outcome(value: Any) -> EffectOutcome:
    return parse_enum("result outcome", value, EffectOutcome)


__all__ = [
    "check_retry_gate",
    "classify_recorded_result",
    "observation_is_recent",
    "parse_acknowledge_payload",
    "parse_authorize_payload",
    "parse_finality_payload",
    "parse_observation_payload",
    "parse_plan_create_payload",
    "parse_reason_payload",
    "parse_record_result_payload",
    "parse_request_effect_payload",
    "parse_status_payload",
    "parse_submit_payload",
    "parse_timeout_payload",
    "plan_resolution",
    "require_source_state",
    "require_step_in_flight",
    "status_observation_effect",
    "validate_compliance_gate",
    "validate_covering_authorization",
    "validate_fraud_gate",
    "validate_hold_gate",
    "validate_result_outcome",
    "validate_submission_status",
    "validate_timeout_declaration",
]
