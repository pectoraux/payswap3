"""The kernel-bound execution engine (WORK-014).

One :class:`ExecutionEngine` binds the frozen ``Execution``/``External``
command families to the real transition kernel
(:class:`src.transition.engine.TransitionEngine`) exactly as the frozen
command-event model prescribes: every accepted command passes the kernel
pipeline ``input → authorization → preconditions → policy → invariant
check → transition → immutable event`` and lands in the kernel's store,
journal and idempotency records; rejected commands change nothing.

Discipline implemented here (all failure paths explicit, every failure a
:class:`~src.core.errors.CoreValidationError` or a typed kernel rejection):

* **authority before financial effect** (constitution invariant 3): an
  effect request requires an AUTHORIZED plan (pinned registry authority
  class + evidence-backed safety gates), a HELD reservation and a typed,
  windowed, covering :class:`EffectAuthorization` — the contract owned by
  the merged simulation domain, consumed unchanged;
* **idempotent external effects** (invariant 9): every request declares
  its idempotency key in the :class:`EffectSubmissionLedger` before any
  port call, duplicate submissions converge without a second port call,
  and a key may never be silently re-bound to different content;
* **never overstate finality** (invariant 11): external finality claims
  are recorded as OBSERVED evidence only — no command here clears,
  settles or finalizes anything;
* **reconcilable outcomes** (invariant 12): an UNKNOWN outcome never
  allows a blind retry — :meth:`reconcile_step` drives the adapter's
  reconciliation port and the retry gate consumes only recorded,
  post-UNKNOWN, subject-bound observations.

Kernel binding contract: handlers validate and *compute* — they never
mutate the engine index directly. The resulting composite records are
carried in the transition payload, committed by the kernel, journaled,
and only then applied to the index through the same trusted
deserialization path used everywhere else (transformation completeness:
the journal alone can rebuild the index and the ledger — see
:meth:`ExecutionEngine.rebuild_from_journal`).

Determinism: no wall-clock reads, no entropy, no generated identifiers;
every instant is the command's declared ``requested_at`` and every
object id is derived from declared data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.transition.command import Command, ExpectedVersion
from src.transition.engine import (
    AuthorizationDecision,
    EngineState,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)
from src.transition.payload import normalize_payload, payload_to_json_value
from src.transition.registry import validate_authority_class
from src.transition.store import MemoryStateStore

from ._validation import (
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .adapters import AdapterBinding
from src.evidence.contracts import EpistemicType
from .contracts import (
    COMMAND_EVENT_TYPES,
    EFFECT_REQUEST_OBJECT_TYPE,
    EFFECT_RESULT_OBJECT_TYPE,
    EXECUTION_ATTEMPT_OBJECT_TYPE,
    EXECUTION_OBSERVATION_OBJECT_TYPE,
    EXECUTION_PLAN_OBJECT_TYPE,
    EXECUTION_RECEIPT_OBJECT_TYPE,
    EXECUTION_STEP_OBJECT_TYPE,
    EffectOutcome,
    EffectRequestState,
    ExecutionAttemptState,
    ExecutionPlanState,
    ExecutionStepState,
    ObservationKind,
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
    make_observation_record,
    make_receipt_record,
    make_request_record,
    make_result_record,
)
from .idempotency import EffectSubmissionLedger
from .lifecycle import (
    check_retry_gate,
    parse_acknowledge_payload,
    parse_authorize_payload,
    parse_finality_payload,
    parse_observation_payload,
    parse_plan_create_payload,
    parse_reason_payload,
    parse_record_result_payload,
    parse_request_effect_payload,
    parse_status_payload,
    parse_submit_payload,
    parse_timeout_payload,
    plan_resolution,
    require_source_state,
    require_step_in_flight,
    status_observation_effect,
    validate_covering_authorization,
    validate_timeout_declaration,
)
from .plan import (
    ExecutionAttempt,
    ExecutionAttemptSpec,
    ExecutionPlan,
    ExecutionPlanSpec,
    ExecutionStep,
    ExecutionStepSpec,
    attempt_object_id,
    make_attempt_record,
    make_plan_record,
    make_step_record,
    observation_object_id,
    receipt_object_id,
    request_object_id,
    result_object_id,
    step_object_id,
)
from .seal import advance_envelope, seal_composite

#: Default service actor driving engine-issued commands.
DEFAULT_ENGINE_ACTOR = "principal/execution-service"

#: Default registry authority class exercised by the command-level
#: authorization hook. This is the OPERATOR authority to drive the
#: execution machine; the financial-effect authority is the plan's pinned
#: class plus its safety gates, enforced per command in the handlers.
DEFAULT_COMMAND_AUTHORITY_CLASS = "A3"

#: Deterministic command nonce (the kernel requires one; it is declared
#: data, never generated).
_COMMAND_NONCE = "execution-command-1"

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "environment_id",
        "domain_id",
        "index",
        "ledger",
        "engine",
        "store",
    }
)

#: Trusted decode path per durable object kind (fail closed on unknown).
_RECORD_DECODERS = {
    EXECUTION_PLAN_OBJECT_TYPE: ExecutionPlan.from_dict,
    EXECUTION_STEP_OBJECT_TYPE: ExecutionStep.from_dict,
    EXECUTION_ATTEMPT_OBJECT_TYPE: ExecutionAttempt.from_dict,
    EFFECT_REQUEST_OBJECT_TYPE: EffectRequest.from_dict,
    EFFECT_RESULT_OBJECT_TYPE: EffectResult.from_dict,
    EXECUTION_RECEIPT_OBJECT_TYPE: Receipt.from_dict,
    EXECUTION_OBSERVATION_OBJECT_TYPE: ExternalObservation.from_dict,
}

_IN_FLIGHT_STATES = frozenset(
    {
        ExecutionStepState.SUBMITTED,
        ExecutionStepState.ACKNOWLEDGED,
        ExecutionStepState.UNKNOWN,
    }
)


def _payload_dict(command: Command) -> dict[str, Any]:
    """Decode the command payload into the canonical JSON object form."""
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("execution command payloads must be objects")
    return decoded


@dataclass(frozen=True, slots=True)
class ExecutionTransition:
    """Explicit decision record for one processed execution command.

    ``outcome`` mirrors the kernel outcome (``accepted`` / ``rejected`` /
    ``duplicate``); rejections carry a closed-vocabulary ``reason``;
    duplicates echo the original decision without emitting a new event.
    """

    command_id: str
    command_type: str
    outcome: Outcome
    reason: RejectionReason | None
    detail: str | None
    result: TransitionResult

    def __post_init__(self) -> None:
        require_text("transition.command_id", self.command_id)
        require_text("transition.command_type", self.command_type)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("transition outcome must use the kernel vocabulary")
        if self.detail is not None:
            require_text("transition.detail", self.detail)
        if not isinstance(self.result, TransitionResult):
            raise CoreValidationError("transition result must be a TransitionResult")
        if self.result.outcome is not self.outcome:
            raise CoreValidationError("transition outcome must mirror the kernel result")
        if self.reason != self.result.reason:
            raise CoreValidationError("transition reason must mirror the kernel result")


class ExecutionEngine:
    """Kernel-bound engine for the execution domain (WORK-014).

    The engine owns the domain index (sealed composite records rebuilt
    through the trusted decode path), the effect-submission idempotency
    ledger, and one real transition kernel per environment. Adapter
    bindings supply the typed ports; concrete rails are external
    (implementation principle 4 — ports over providers).
    """

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        bindings: Mapping[str, AdapterBinding],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
        authorized_actors: Iterable[str] = (),
    ) -> None:
        require_text("engine environment_id", environment_id)
        require_text("engine domain_id", domain_id)
        require_text("engine actor", actor)
        validate_authority_class("engine command_authority_class", command_authority_class)
        if not isinstance(bindings, Mapping):
            raise CoreValidationError("engine bindings must be a mapping")
        if not bindings:
            raise CoreValidationError(
                "an execution engine requires at least one bound adapter; "
                "effects cannot be submitted without a typed port"
            )
        for adapter_id, binding in bindings.items():
            require_identifier("engine binding adapter_id", adapter_id)
            if not isinstance(binding, AdapterBinding):
                raise CoreValidationError(
                    f"engine binding for {adapter_id!r} must be an AdapterBinding"
                )
            if binding.adapter_id != adapter_id:
                raise CoreValidationError(
                    f"engine binding key {adapter_id!r} does not match the bound "
                    f"adapter id {binding.adapter_id!r}"
                )
        extra_actors = set(authorized_actors)
        for extra in extra_actors:
            require_text("engine authorized actor", extra)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._bindings = dict(bindings)
        self._actor = actor
        self._command_authority_class = command_authority_class
        self._authorized_actors = frozenset({actor} | extra_actors)
        self._store = MemoryStateStore()
        self._kernel = self._build_kernel()
        self._records: dict[str, Any] = {}
        self._ledger = EffectSubmissionLedger()
        self._transitions: list[ExecutionTransition] = []

    # ------------------------------------------------------------------
    # construction and kernel binding
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    def _build_kernel(self) -> TransitionEngine:
        kernel = TransitionEngine(
            self._environment_id,
            authorization=self._authorize,
            store=self._store,
        )
        registrations = (
            ("execution/plan.create", self._handle_plan_create),
            ("execution/plan.authorize", self._handle_plan_authorize),
            ("execution/plan.start", self._handle_plan_start),
            ("execution/plan.cancel", self._handle_plan_cancel),
            ("external/request-effect", self._handle_request_effect),
            ("execution/step.submit", self._handle_step_submit),
            ("execution/step.acknowledge", self._handle_step_acknowledge),
            ("external/record-effect-result", self._handle_record_effect_result),
            ("execution/step.complete", self._handle_step_complete),
            ("execution/step.fail", self._handle_step_fail),
            ("execution/step.timeout", self._handle_step_timeout),
            ("execution/step.retry", self._handle_step_retry),
            ("external/record-observation", self._handle_record_observation),
            ("external/record-status", self._handle_record_status),
            ("external/record-finality", self._handle_record_finality),
        )
        for command_type, handler in registrations:
            event_type = COMMAND_EVENT_TYPES[command_type]
            kernel.register(command_type, event_type, handler)
        return kernel

    def _authorize(self, command: Command, view: Any) -> AuthorizationDecision:
        """Command-level authorization: the operator gate.

        The financial-effect authority (plan authorization with pinned
        authority class and safety gates, covering typed effect
        authorization) is enforced per command inside the handlers.
        """
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True,
                authority=self._command_authority_class,
                reason=None,
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                f"actor {command.actor!r} is not authorized to drive execution "
                f"in environment {self._environment_id!r}"
            ),
        )

    def _provenance(self, command: Command):
        from src.core.envelope import Provenance

        return Provenance(
            issuer=command.actor,
            source="execution/domain",
            recorded_at=command.requested_at,
        )

    # ------------------------------------------------------------------
    # command construction and submission
    # ------------------------------------------------------------------

    def build_raw_command(
        self,
        *,
        command_id: str,
        command_type: str,
        requested_at: str,
        target_refs: Iterable[str],
        payload: Any,
        environment_id: str | None = None,
        domain_id: str | None = None,
        actor: str | None = None,
        expected_versions: Mapping[str, int] | Iterable[ExpectedVersion] | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> Command:
        """Build a kernel command envelope against this engine's binding.

        ``expected_versions`` accepts either a mapping
        ``{object_ref: version}`` or an iterable of
        :class:`~src.transition.command.ExpectedVersion`. The command's
        idempotency key is derived deterministically from the command id.
        """
        require_text("command_id", command_id)
        require_text("command_type", command_type)
        require_utc_timestamp("requested_at", requested_at)
        targets = tuple(target_refs)
        if not targets:
            raise CoreValidationError("target_refs must declare at least one target object")
        for target in targets:
            require_text("target_ref", target)
        if expected_versions is None:
            expected: tuple[ExpectedVersion, ...] = ()
        elif isinstance(expected_versions, Mapping):
            expected = tuple(
                ExpectedVersion(object_ref=ref, object_version=version)
                for ref, version in expected_versions.items()
            )
        else:
            expected = tuple(expected_versions)
            for item in expected:
                if not isinstance(item, ExpectedVersion):
                    raise CoreValidationError(
                        "expected_versions entries must be ExpectedVersion records"
                    )
        return Command.build(
            command_id=command_id,
            command_type=command_type,
            actor=actor if actor is not None else self._actor,
            target_refs=targets,
            payload=payload,
            environment_id=environment_id if environment_id is not None else self._environment_id,
            domain_id=domain_id if domain_id is not None else self._domain_id,
            expected_versions=expected,
            idempotency_key=f"execution:{command_id}",
            nonce=_COMMAND_NONCE,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def submit(self, command: Command) -> ExecutionTransition:
        """Process one command through the real kernel pipeline."""
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        result = self._kernel.process(command)
        if result.outcome is Outcome.ACCEPTED:
            self._apply_accepted(command.command_type, result)
        transition = ExecutionTransition(
            command_id=command.command_id,
            command_type=command.command_type,
            outcome=result.outcome,
            reason=result.reason,
            detail=result.detail,
            result=result,
        )
        self._transitions.append(transition)
        return transition

    # ------------------------------------------------------------------
    # public command surface (the frozen families)
    # ------------------------------------------------------------------

    def create_plan(
        self,
        *,
        command_id: str,
        requested_at: str,
        plan_id: str,
        steps: Iterable[Mapping[str, Any]],
        source_ref: str,
        summary: str = "",
    ) -> ExecutionTransition:
        """``Execution: Create`` — a plan and its steps in DRAFT/PENDING."""
        require_identifier("create_plan plan_id", plan_id)
        step_entries = list(steps)
        step_ids = []
        for position, entry in enumerate(step_entries, start=1):
            expected_id = step_object_id(plan_id, position)
            if entry.get("step_id") != expected_id:
                raise CoreValidationError(
                    f"step at position {position} must use the derived id {expected_id!r}"
                )
            step_ids.append(expected_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/plan.create",
            requested_at=requested_at,
            target_refs=(plan_id, *step_ids),
            payload={"source_ref": source_ref, "summary": summary, "steps": step_entries},
            expected_versions={object_ref: 0 for object_ref in (plan_id, *step_ids)},
        )
        return self.submit(command)

    def authorize_plan(
        self,
        *,
        command_id: str,
        requested_at: str,
        plan_id: str,
        authority_class: str,
        fraud_decision: Mapping[str, Any] | None,
        compliance_assessment: Mapping[str, Any] | None,
        mandate_ref: str | None = None,
    ) -> ExecutionTransition:
        """``Execution: Authorize`` — pin the authority class and gates."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/plan.authorize",
            requested_at=requested_at,
            target_refs=(plan_id,),
            payload={
                "authority_class": authority_class,
                "mandate_ref": mandate_ref,
                "fraud_decision": fraud_decision,
                "compliance_assessment": compliance_assessment,
            },
        )
        return self.submit(command)

    def start_plan(
        self, *, command_id: str, requested_at: str, plan_id: str
    ) -> ExecutionTransition:
        """``Execution: Start`` — move an authorized plan into RUNNING."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/plan.start",
            requested_at=requested_at,
            target_refs=(plan_id,),
            payload={},
        )
        return self.submit(command)

    def cancel_plan(
        self, *, command_id: str, requested_at: str, plan_id: str, reason: str
    ) -> ExecutionTransition:
        """``Execution: Cancel`` — cancel a plan and its open steps."""
        step_ids = self._numbered_ids(f"{plan_id}/step/")
        request_ids: list[str] = []
        for step_id in step_ids:
            request_ids.extend(self._numbered_ids(f"{step_id}/request/"))
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/plan.cancel",
            requested_at=requested_at,
            target_refs=(plan_id, *step_ids, *request_ids),
            payload={"reason": reason},
        )
        return self.submit(command)

    def request_effect(
        self,
        *,
        command_id: str,
        requested_at: str,
        step_id: str,
        idempotency_key: str,
        authorization: Any,
        hold: Mapping[str, Any],
    ) -> ExecutionTransition:
        """``External: RequestEffect`` — declare one idempotent effect request."""
        duplicate = self._declaration_duplicate(
            step_id=step_id,
            key=idempotency_key,
            requested_at=requested_at,
            authorization=authorization,
        )
        if duplicate is not None:
            return duplicate
        request_id = request_object_id(
            step_id, len(self._numbered_ids(f"{step_id}/request/")) + 1
        )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="external/request-effect",
            requested_at=requested_at,
            target_refs=(step_id, request_id),
            payload={
                "idempotency_key": idempotency_key,
                "authorization": authorization.to_dict(),
                "hold": hold,
            },
            expected_versions={request_id: 0},
        )
        return self.submit(command)

    def submit_step(
        self, *, command_id: str, requested_at: str, step_id: str
    ) -> ExecutionTransition:
        """``Execution: Submit`` — hand the current request to the rail."""
        step = self.step(step_id)
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(
                f"step {step_id!r} has no declared effect request to submit"
            )
        key = request.spec.idempotency_key
        if step.state in _IN_FLIGHT_STATES and self._ledger.is_submitted(key):
            # Duplicate convergence: the port is NEVER called a second time
            # for one idempotency key (constitution invariant 9).
            return self._duplicate_submission(command_id, requested_at, step, request)
        attempt_id = attempt_object_id(step_id, request.spec.attempt_number)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.submit",
            requested_at=requested_at,
            target_refs=(step_id, request.object_id, attempt_id),
            payload={"idempotency_key": key},
            expected_versions={
                step_id: step.envelope.object_version,
                request.object_id: request.envelope.object_version,
                attempt_id: 0,
            },
        )
        return self.submit(command)

    def acknowledge_step(
        self, *, command_id: str, requested_at: str, step_id: str, native_reference: str
    ) -> ExecutionTransition:
        """``Execution: Acknowledge`` — record the rail's acknowledgment."""
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(f"step {step_id!r} has no in-flight effect request")
        receipt_id = receipt_object_id(request.object_id)
        attempt_id = attempt_object_id(step_id, request.spec.attempt_number)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.acknowledge",
            requested_at=requested_at,
            target_refs=(step_id, attempt_id, receipt_id),
            payload={"native_reference": native_reference},
            expected_versions={receipt_id: 0},
        )
        return self.submit(command)

    def record_effect_result(
        self,
        *,
        command_id: str,
        requested_at: str,
        step_id: str,
        outcome: str,
        native_reference: str | None = None,
        error_code: str | None = None,
        observed_at: str,
        detail: Any = None,
    ) -> ExecutionTransition:
        """``External: RecordEffectResult`` — record the rail's outcome."""
        # Explicit failure path up front: a terminal step can never take
        # a new effect result (the handler re-validates; this guard keeps
        # the failure explicit before any kernel precondition races it).
        require_source_state("external/record-effect-result", self.step(step_id).state)
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(f"step {step_id!r} has no in-flight effect request")
        result_id = result_object_id(request.object_id)
        attempt_id = attempt_object_id(step_id, request.spec.attempt_number)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="external/record-effect-result",
            requested_at=requested_at,
            target_refs=(step_id, request.object_id, result_id, attempt_id),
            payload={
                "request_id": request.object_id,
                "outcome": outcome,
                "native_reference": native_reference,
                "error_code": error_code,
                "observed_at": observed_at,
                "detail": detail,
            },
            expected_versions={result_id: 0},
        )
        return self.submit(command)

    def complete_step(
        self, *, command_id: str, requested_at: str, step_id: str
    ) -> ExecutionTransition:
        """``Execution: Complete`` — complete a step on its recorded success."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.complete",
            requested_at=requested_at,
            target_refs=(step_id, self.step(step_id).spec.plan_id),
            payload={},
        )
        return self.submit(command)

    def fail_step(
        self, *, command_id: str, requested_at: str, step_id: str, reason: str
    ) -> ExecutionTransition:
        """``Execution: Fail`` — fail a step on its recorded failure."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.fail",
            requested_at=requested_at,
            target_refs=(step_id, self.step(step_id).spec.plan_id),
            payload={"reason": reason},
        )
        return self.submit(command)

    def timeout_step(
        self, *, command_id: str, requested_at: str, step_id: str, deadline: str, reason: str
    ) -> ExecutionTransition:
        """``Execution: Timeout`` — move an unresponsive step into UNKNOWN."""
        step = self.step(step_id)
        attempt = self._latest_attempt(step_id)
        target_refs = [step_id, step.spec.plan_id]
        if attempt is not None:
            target_refs.append(attempt.object_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.timeout",
            requested_at=requested_at,
            target_refs=target_refs,
            payload={"deadline": deadline, "reason": reason},
        )
        return self.submit(command)

    def retry_step(
        self, *, command_id: str, requested_at: str, step_id: str, reason: str
    ) -> ExecutionTransition:
        """``Execution: Retry`` — re-arm a FAILED or reconciled UNKNOWN step."""
        step = self.step(step_id)
        request = self._latest_request(step_id)
        target_refs = [step_id, step.spec.plan_id]
        if request is not None:
            # A retry cancels the step's current in-flight request when it
            # is still SUBMITTED; the command must declare every object
            # its handler may produce.
            target_refs.append(request.object_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="execution/step.retry",
            requested_at=requested_at,
            target_refs=target_refs,
            payload={"reason": reason},
        )
        return self.submit(command)

    def reconcile_step(
        self, *, command_id: str, requested_at: str, step_id: str
    ) -> ExecutionTransition:
        """``External: RecordObservation`` — query the rail through the port.

        The engine drives the adapter's reconciliation port (the only
        source of query outcomes on this path) and journals the rail's
        answer as an OBSERVED observation bound to the step's current
        request.
        """
        step = self.step(step_id)
        require_step_in_flight(step)
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(f"step {step_id!r} has no in-flight effect request")
        binding = self._binding_for(request.spec.adapter_id)
        query = binding.query(request)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="external/record-observation",
            requested_at=requested_at,
            target_refs=(
                step_id,
                request.object_id,
                observation_object_id(command_id),
            ),
            payload={
                "query": {
                    "outcome": query.outcome.value,
                    "native_reference": query.native_reference,
                },
                "subject_ref": request.object_id,
            },
        )
        return self.submit(command)

    def record_status(
        self, *, command_id: str, requested_at: str, step_id: str, native_code: str
    ) -> ExecutionTransition:
        """``External: RecordStatus`` — record a canonical status observation."""
        step = self.step(step_id)
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(f"step {step_id!r} has no in-flight effect request")
        binding = self._binding_for(step.spec.adapter_id)
        canonical_status = binding.map_status(native_code)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="external/record-status",
            requested_at=requested_at,
            target_refs=(
                step_id,
                request.object_id,
                observation_object_id(command_id),
            ),
            payload={"native_code": native_code, "canonical_status": canonical_status},
        )
        return self.submit(command)

    def record_finality(
        self, *, command_id: str, requested_at: str, step_id: str, claim: str, native_reference: str
    ) -> ExecutionTransition:
        """``External: RecordFinality`` — record an external finality CLAIM.

        The claim is evidence about what the rail claims; recording it
        never makes it true here (constitution invariant 11 — settlement
        finality belongs to the settlement domain).
        """
        step = self.step(step_id)
        request = self._latest_request(step_id)
        if request is None:
            raise CoreValidationError(
                f"step {step_id!r} has no effect request to attach the claim to"
            )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="external/record-finality",
            requested_at=requested_at,
            target_refs=(
                step_id,
                request.object_id,
                observation_object_id(command_id),
            ),
            payload={"claim": claim, "native_reference": native_reference},
        )
        return self.submit(command)

    # ------------------------------------------------------------------
    # read-only surface
    # ------------------------------------------------------------------

    def plan(self, plan_id: str) -> ExecutionPlan:
        record = self._record(plan_id)
        if not isinstance(record, ExecutionPlan):
            raise CoreValidationError(f"object {plan_id!r} is not an execution plan")
        return record

    def step(self, step_id: str) -> ExecutionStep:
        record = self._record(step_id)
        if not isinstance(record, ExecutionStep):
            raise CoreValidationError(f"object {step_id!r} is not an execution step")
        return record

    def steps(self, plan_id: str) -> tuple[ExecutionStep, ...]:
        """The plan's steps in declared position order."""
        step_ids = self._numbered_ids(f"{plan_id}/step/")
        if not step_ids:
            self._record(plan_id)  # fail closed on unknown plans
        return tuple(self.step(step_id) for step_id in step_ids)

    def attempt(self, attempt_id: str) -> ExecutionAttempt:
        record = self._record(attempt_id)
        if not isinstance(record, ExecutionAttempt):
            raise CoreValidationError(f"object {attempt_id!r} is not an execution attempt")
        return record

    def effect_request(self, request_id: str) -> EffectRequest:
        record = self._record(request_id)
        if not isinstance(record, EffectRequest):
            raise CoreValidationError(f"object {request_id!r} is not an effect request")
        return record

    def effect_result(self, result_id: str) -> EffectResult:
        record = self._record(result_id)
        if not isinstance(record, EffectResult):
            raise CoreValidationError(f"object {result_id!r} is not an effect result")
        return record

    def receipt(self, receipt_id: str) -> Receipt:
        record = self._record(receipt_id)
        if not isinstance(record, Receipt):
            raise CoreValidationError(f"object {receipt_id!r} is not a receipt")
        return record

    def observations(self) -> tuple[ExternalObservation, ...]:
        return tuple(
            record
            for record in self._records.values()
            if isinstance(record, ExternalObservation)
        )

    def objects(self) -> tuple[Any, ...]:
        """Every durable record in the index, in journal order."""
        return tuple(self._records.values())

    def journal(self):
        return self._kernel.journal

    def transitions(self) -> tuple[ExecutionTransition, ...]:
        return tuple(self._transitions)

    def submission_ledger(self) -> EffectSubmissionLedger:
        return self._ledger

    # ------------------------------------------------------------------
    # snapshot / restore / journal rebuild
    # ------------------------------------------------------------------

    def snapshot_state(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed engine state."""
        return {
            "schema_version": 1,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "index": {
                object_id: record.to_dict() for object_id, record in self._records.items()
            },
            "ledger": self._ledger.to_dict(),
            "engine": self._kernel.snapshot_state().to_dict(),
            "store": [envelope.to_dict() for envelope in self._store.snapshot()],
        }

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        """Rebuild the engine from a canonical snapshot (fail closed)."""
        require_mapping("engine snapshot", snapshot)
        strict_fields("engine snapshot", snapshot, _SNAPSHOT_FIELDS)
        if snapshot["schema_version"] != 1:
            raise CoreValidationError("engine snapshot schema version must be 1")
        if snapshot["environment_id"] != self._environment_id:
            raise CoreValidationError(
                f"snapshot environment {snapshot['environment_id']!r} does not match "
                f"engine environment {self._environment_id!r}"
            )
        if snapshot["domain_id"] != self._domain_id:
            raise CoreValidationError(
                f"snapshot domain {snapshot['domain_id']!r} does not match "
                f"engine domain {self._domain_id!r}"
            )
        index_raw = require_mapping("engine snapshot index", snapshot["index"])
        records: dict[str, Any] = {}
        for object_id, composite in index_raw.items():
            require_identifier("engine snapshot object_id", object_id)
            record = self._decode_record(composite)
            if record.object_id != object_id:
                raise CoreValidationError(
                    f"snapshot key {object_id!r} does not match object id "
                    f"{record.object_id!r}"
                )
            records[object_id] = record
        ledger = EffectSubmissionLedger.from_dict(snapshot["ledger"])
        store_raw = snapshot["store"]
        if not isinstance(store_raw, list):
            raise CoreValidationError("engine snapshot store must deserialize from a list")
        from src.core.envelope import ObjectEnvelope

        envelopes = tuple(ObjectEnvelope.from_dict(entry) for entry in store_raw)
        store = MemoryStateStore(envelopes)
        store_by_id = {envelope.object_id: envelope for envelope in envelopes}
        for object_id, record in records.items():
            stored = store_by_id.get(object_id)
            if stored is None or stored != record.envelope:
                raise CoreValidationError(
                    f"snapshot index and store disagree on object {object_id!r}"
                )
        engine_state = EngineState.from_dict(snapshot["engine"])
        self._records = records
        self._ledger = ledger
        self._store = store
        self._kernel = self._build_kernel()
        self._kernel.restore_state(engine_state)
        # The transitions log is an engine-local decision log; it is not
        # part of durable state (the kernel journal is authoritative).

    @classmethod
    def rebuild_from_journal(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        bindings: Mapping[str, AdapterBinding],
        journal: Iterable[Any],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
    ) -> "ExecutionEngine":
        """Rebuild the domain index and ledger from the kernel journal alone.

        Transformation completeness: the committed event payloads carry
        every resulting record and ledger mutation, so folding the journal
        rebuilds the composed domain state deterministically. The kernel's
        command-id dedup restarts after a journal-only rebuild (command
        envelopes are not part of the journal); effect-submission
        idempotency is preserved by the rebuilt ledger.
        """
        engine = cls(
            environment_id=environment_id,
            domain_id=domain_id,
            bindings=bindings,
            actor=actor,
            command_authority_class=command_authority_class,
        )
        entries = tuple(journal)
        for entry in entries:
            engine._apply_event_payload(entry.event.event_type, _journal_payload(entry))
        if entries:
            state = EngineState(
                logical_time=entries[-1].event.logical_time,
                records=(),
                journal=entries,
            )
            engine._store = MemoryStateStore(
                record.envelope for record in engine._records.values()
            )
            engine._kernel = engine._build_kernel()
            engine._kernel.restore_state(state)
        return engine

    # ------------------------------------------------------------------
    # index maintenance (the only mutation path)
    # ------------------------------------------------------------------

    def _record(self, object_id: str) -> Any:
        record = self._records.get(object_id)
        if record is None:
            raise CoreValidationError(f"unknown execution object {object_id!r}")
        return record

    def _decode_record(self, composite: Any) -> Any:
        require_mapping("execution record", composite)
        object_type = composite.get("envelope", {}).get("object_type")
        decoder = _RECORD_DECODERS.get(object_type)
        if decoder is None:
            raise CoreValidationError(
                f"record claims unknown object type {object_type!r}"
            )
        return decoder(composite)

    def _numbered_ids(self, prefix: str) -> list[str]:
        """Object ids under ``prefix`` with numeric suffixes, in number order."""
        numbered: list[tuple[int, str]] = []
        for object_id in self._records:
            if object_id.startswith(prefix):
                suffix = object_id[len(prefix) :]
                if suffix.isdigit():
                    numbered.append((int(suffix), object_id))
        return [object_id for _, object_id in sorted(numbered)]

    def _latest_request(self, step_id: str) -> EffectRequest | None:
        request_ids = self._numbered_ids(f"{step_id}/request/")
        if not request_ids:
            return None
        return self.effect_request(request_ids[-1])

    def _latest_attempt(self, step_id: str) -> ExecutionAttempt | None:
        attempt_ids = self._numbered_ids(f"{step_id}/attempt/")
        if not attempt_ids:
            return None
        return self.attempt(attempt_ids[-1])

    def _binding_for(self, adapter_id: str) -> AdapterBinding:
        binding = self._bindings.get(adapter_id)
        if binding is None:
            raise CoreValidationError(
                f"adapter {adapter_id!r} has no bound execution port"
            )
        return binding

    def _apply_accepted(self, command_type: str, result: TransitionResult) -> None:
        event_type = COMMAND_EVENT_TYPES.get(command_type)
        if event_type is None:
            raise CoreValidationError(f"command {command_type!r} is not registered")
        payload = payload_to_json_value(result.payload) if result.payload is not None else {}
        self._apply_event_payload(event_type, payload)

    def _apply_event_payload(self, event_type: str, payload: Any) -> None:
        """Apply one committed event payload to the index and ledger.

        This is the single mutation path, shared by live commits and
        journal rebuilds; every record re-enters through the trusted
        decode path (seal verification included).
        """
        if not isinstance(payload, Mapping):
            raise CoreValidationError("committed execution payloads must be objects")
        if event_type == "execution/plan-created":
            self._store_record(self._decode_record(payload["plan"]))
            for composite in payload["steps"]:
                self._store_record(self._decode_record(composite))
        elif event_type in ("execution/plan-authorized", "execution/plan-started"):
            self._store_record(self._decode_record(payload["plan"]))
        elif event_type == "execution/plan-cancelled":
            self._store_record(self._decode_record(payload["plan"]))
            for composite in payload["steps"]:
                self._store_record(self._decode_record(composite))
            for composite in payload["requests"]:
                self._store_record(self._decode_record(composite))
        elif event_type == "execution/effect-requested":
            request = self._decode_record(payload["request"])
            self._store_record(request)
            self._ledger.declare(
                key=payload["idempotency_key"],
                request_id=request.object_id,
                request_digest=request.spec.digest,
            )
        elif event_type == "execution/step-submitted":
            self._store_record(self._decode_record(payload["step"]))
            self._store_record(self._decode_record(payload["request"]))
            self._store_record(self._decode_record(payload["attempt"]))
            self._ledger.record_submission(
                key=payload["idempotency_key"], submission=payload["submission"]
            )
        elif event_type == "execution/step-acknowledged":
            self._store_record(self._decode_record(payload["step"]))
            self._store_record(self._decode_record(payload["attempt"]))
            self._store_record(self._decode_record(payload["receipt"]))
        elif event_type == "execution/effect-result-recorded":
            self._store_record(self._decode_record(payload["result"]))
            self._store_record(self._decode_record(payload["attempt"]))
            if payload.get("request") is not None:
                self._store_record(self._decode_record(payload["request"]))
        elif event_type in ("execution/step-completed", "execution/step-failed"):
            self._store_record(self._decode_record(payload["step"]))
            if payload.get("plan") is not None:
                self._store_record(self._decode_record(payload["plan"]))
        elif event_type == "execution/step-timed-out":
            self._store_record(self._decode_record(payload["step"]))
            self._store_record(self._decode_record(payload["attempt"]))
        elif event_type == "execution/step-retried":
            self._store_record(self._decode_record(payload["step"]))
            if payload.get("request") is not None:
                self._store_record(self._decode_record(payload["request"]))
        elif event_type in (
            "execution/observation-recorded",
            "execution/status-recorded",
            "execution/finality-recorded",
        ):
            self._store_record(self._decode_record(payload["observation"]))
            if payload.get("step") is not None:
                self._store_record(self._decode_record(payload["step"]))
        else:
            raise CoreValidationError(f"unknown execution event type {event_type!r}")

    def _store_record(self, record: Any) -> None:
        self._records[record.object_id] = record

    def _advance(self, record: Any, command: Command, *, state: str, spec: Any = None) -> Any:
        envelope = advance_envelope(
            record.envelope,
            state=state,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_spec = spec if spec is not None else record.spec
        integrity = seal_composite(envelope, new_spec)
        return type(record)(envelope=envelope, spec=new_spec, integrity_hash=integrity)

    # ------------------------------------------------------------------
    # domain-level idempotency (before any kernel call)
    # ------------------------------------------------------------------

    def _declaration_duplicate(
        self, *, step_id: str, key: str, requested_at: str, authorization: Any
    ) -> ExecutionTransition | None:
        """Converge duplicate effect declarations without a second command."""
        if not self._ledger.request_declared(key):
            return None
        bound_request_id = self._ledger.request_id_for(key)
        bound_digest = self._ledger.request_digest_for(key)
        latest = self._latest_request(step_id)
        if latest is None or latest.object_id != bound_request_id:
            raise CoreValidationError(
                f"idempotency key {key!r} is bound to request {bound_request_id!r}; "
                "a new declaration would re-bind the key — retries must use a "
                "new idempotency key"
            )
        candidate = EffectRequestSpec(
            request_id=latest.spec.request_id,
            plan_id=latest.spec.plan_id,
            step_id=latest.spec.step_id,
            attempt_number=latest.spec.attempt_number,
            effect_type=latest.spec.effect_type,
            adapter_id=latest.spec.adapter_id,
            idempotency_key=key,
            payload=payload_to_json_value(latest.spec.payload),
            requested_at=requested_at,
            authorization_digest=authorization.digest,
        )
        if candidate.digest != bound_digest:
            raise CoreValidationError(
                f"idempotency key {key!r} was already used for different request "
                "content; an effect key may never be silently re-bound "
                "(idempotency conflict)"
            )
        submission = self._ledger.submission_for(key)
        result = TransitionResult(
            command_id=f"duplicate/{key}",
            idempotency_key=f"execution:duplicate:{key}",
            outcome=Outcome.DUPLICATE,
            reason=None,
            detail=f"duplicate declaration of effect request {bound_request_id!r}",
            event=None,
            payload=normalize_payload(
                "duplicate declaration payload",
                {
                    "idempotency_key": key,
                    "request_id": bound_request_id,
                    "request_digest": bound_digest,
                    "submission": submission,
                },
            ),
            resulting_envelopes=(),
        )
        transition = ExecutionTransition(
            command_id=f"duplicate/{key}",
            command_type="external/request-effect",
            outcome=result.outcome,
            reason=None,
            detail=result.detail,
            result=result,
        )
        self._transitions.append(transition)
        return transition

    def _duplicate_submission(
        self, command_id: str, requested_at: str, step: ExecutionStep, request: EffectRequest
    ) -> ExecutionTransition:
        """Echo the recorded submission — the port is never called twice."""
        key = request.spec.idempotency_key
        submission = self._ledger.submission_for(key)
        result = TransitionResult(
            command_id=command_id,
            idempotency_key=f"execution:{command_id}",
            outcome=Outcome.DUPLICATE,
            reason=None,
            detail=(
                f"duplicate submission of effect request {request.object_id!r} "
                f"under key {key!r}"
            ),
            event=None,
            payload=normalize_payload(
                "duplicate submission payload",
                {
                    "idempotency_key": key,
                    "request_id": request.object_id,
                    "request_digest": request.spec.digest,
                    "submission": submission,
                },
            ),
            resulting_envelopes=(),
        )
        transition = ExecutionTransition(
            command_id=command_id,
            command_type="execution/step.submit",
            outcome=result.outcome,
            reason=None,
            detail=result.detail,
            result=result,
        )
        self._transitions.append(transition)
        return transition

    # ------------------------------------------------------------------
    # kernel handlers (validate-then-compute; never mutate the index)
    # ------------------------------------------------------------------

    def _handle_plan_create(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_plan_create_payload(_payload_dict(command))
        plan_id = command.target_refs[0]
        require_identifier("plan.create plan_id", plan_id)
        for entry in payload["steps"]:
            adapter_id = entry["adapter_id"]
            if adapter_id not in self._bindings:
                raise CoreValidationError(
                    f"plan declares adapter {adapter_id!r} which has no bound "
                    "execution port; effects cannot target an unknown adapter"
                )
        step_records: list[ExecutionStep] = []
        declared = set(command.target_refs)
        for position, entry in enumerate(payload["steps"], start=1):
            expected_id = step_object_id(plan_id, position)
            if entry["step_id"] != expected_id:
                raise CoreValidationError(
                    f"step at position {position} must use the derived id {expected_id!r}"
                )
            if expected_id not in declared:
                raise CoreValidationError(
                    f"command did not declare step target {expected_id!r}"
                )
            if expected_id in self._records:
                raise CoreValidationError(
                    f"execution object {expected_id!r} already exists; plans are "
                    "append-only"
                )
        if plan_id in self._records:
            raise CoreValidationError(
                f"execution plan {plan_id!r} already exists; plans are append-only"
            )
        provenance = self._provenance(command)
        plan = make_plan_record(
            plan_id=plan_id,
            source_ref=payload["source_ref"],
            summary=payload["summary"],
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=provenance,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        for position, entry in enumerate(payload["steps"], start=1):
            spec = ExecutionStepSpec(
                step_id=step_object_id(plan_id, position),
                plan_id=plan_id,
                position=position,
                adapter_id=entry["adapter_id"],
                effect_type=entry["effect_type"],
                payload=entry["payload"],
                reservation_ref=entry["reservation_ref"],
                max_attempts=entry["max_attempts"],
            )
            step_records.append(
                make_step_record(
                    step_spec=spec,
                    environment_id=command.environment_id,
                    domain_id=command.domain_id,
                    provenance=provenance,
                    causation_id=command.command_id,
                    correlation_id=command.correlation_id,
                )
            )
        envelopes = (plan.envelope, *(record.envelope for record in step_records))
        journal_payload = {
            "plan": plan.to_dict(),
            "steps": [record.to_dict() for record in step_records],
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_plan_authorize(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_authorize_payload(_payload_dict(command))
        plan = self.plan(command.target_refs[0])
        require_source_state("execution/plan.authorize", plan.state)
        new_spec = ExecutionPlanSpec(
            plan_id=plan.spec.plan_id,
            source_ref=plan.spec.source_ref,
            summary=plan.spec.summary,
            authority_class=payload["authority_class"],
            mandate_ref=payload["mandate_ref"],
            fraud_decision=payload["fraud_decision"],
            compliance_assessment=payload["compliance_assessment"],
        )
        authorized = self._advance(
            plan,
            command,
            state=ExecutionPlanState.AUTHORIZED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (authorized.envelope,), {"plan": authorized.to_dict()}
        )

    def _handle_plan_start(self, command: Command, view: Any) -> TransitionApplication:
        plan = self.plan(command.target_refs[0])
        require_source_state("execution/plan.start", plan.state)
        started = self._advance(plan, command, state=ExecutionPlanState.RUNNING.value)
        return TransitionApplication((started.envelope,), {"plan": started.to_dict()})

    def _handle_plan_cancel(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_reason_payload("execution/plan.cancel", _payload_dict(command))
        plan_id = command.target_refs[0]
        plan = self.plan(plan_id)
        require_source_state("execution/plan.cancel", plan.state)
        steps = self.steps(plan_id)
        for step in steps:
            if step.state in _IN_FLIGHT_STATES:
                raise CoreValidationError(
                    f"step {step.object_id} is {step.state.value}; a plan with an "
                    "in-flight external effect cannot be cancelled — reconcile or "
                    "resolve the effect first"
                )
        cancelled_steps = [
            self._advance(step, command, state=ExecutionStepState.CANCELLED.value)
            for step in steps
            if not step.is_terminal()
        ]
        cancelled_requests = []
        for step in steps:
            if step.is_terminal():
                continue
            for request_id in self._numbered_ids(f"{step.object_id}/request/"):
                request = self.effect_request(request_id)
                if request.state is EffectRequestState.REQUESTED:
                    cancelled_requests.append(
                        self._advance(
                            request,
                            command,
                            state=EffectRequestState.CANCELLED.value,
                        )
                    )
        cancelled_plan = self._advance(
            plan, command, state=ExecutionPlanState.CANCELLED.value
        )
        envelopes = (
            cancelled_plan.envelope,
            *(record.envelope for record in cancelled_steps),
            *(record.envelope for record in cancelled_requests),
        )
        journal_payload = {
            "plan": cancelled_plan.to_dict(),
            "steps": [record.to_dict() for record in cancelled_steps],
            "requests": [record.to_dict() for record in cancelled_requests],
            "reason": payload["reason"],
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_request_effect(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_request_effect_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        require_source_state("external/request-effect", step.state)
        plan = self.plan(step.spec.plan_id)
        if plan.state is not ExecutionPlanState.RUNNING:
            raise CoreValidationError(
                f"plan {plan.spec.plan_id} is {plan.state.value}; an external "
                "effect may only be requested for a RUNNING plan"
            )
        hold = payload["hold"]
        if hold["reservation_id"] != step.spec.reservation_ref:
            raise CoreValidationError(
                f"the hold gate references reservation {hold['reservation_id']!r} "
                f"but the step consumes reservation {step.spec.reservation_ref!r}"
            )
        authorization = validate_covering_authorization(
            payload["authorization"],
            effect_type=step.spec.effect_type,
            requested_at=command.requested_at,
        )
        key = payload["idempotency_key"]
        if self._ledger.request_declared(key):
            raise CoreValidationError(
                f"idempotency key {key!r} is already declared; duplicate "
                "declarations converge at the engine boundary and a key may "
                "never be re-bound"
            )
        attempt_number = len(self._numbered_ids(f"{step.object_id}/request/")) + 1
        request_id = request_object_id(step.object_id, attempt_number)
        if request_id in self._records:
            raise CoreValidationError(
                f"effect request {request_id!r} already exists; requests are "
                "append-only"
            )
        spec = EffectRequestSpec(
            request_id=request_id,
            plan_id=step.spec.plan_id,
            step_id=step.object_id,
            attempt_number=attempt_number,
            effect_type=step.spec.effect_type,
            adapter_id=step.spec.adapter_id,
            idempotency_key=key,
            payload=payload_to_json_value(step.spec.payload),
            requested_at=command.requested_at,
            authorization_digest=authorization.digest,
        )
        request = make_request_record(
            spec=spec,
            state=EffectRequestState.REQUESTED,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        journal_payload = {
            "request": request.to_dict(),
            "idempotency_key": key,
            "request_digest": spec.digest,
        }
        return TransitionApplication((request.envelope,), journal_payload)

    def _handle_step_submit(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_submit_payload(_payload_dict(command))
        key = payload["idempotency_key"]
        step = self.step(command.target_refs[0])
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no declared effect request to submit"
            )
        if request.spec.idempotency_key != key:
            raise CoreValidationError(
                f"step.submit declares key {key!r} but the request {request.object_id!r} "
                f"was declared under {request.spec.idempotency_key!r}"
            )
        if request.state is not EffectRequestState.REQUESTED:
            raise CoreValidationError(
                f"effect request {request.object_id} is {request.state.value}; "
                "only a REQUESTED request may be submitted"
            )
        require_source_state("execution/step.submit", step.state)
        if self._ledger.is_submitted(key):
            raise CoreValidationError(
                f"idempotency key {key!r} was already submitted; a second port "
                "call for one key is forbidden (constitution invariant 9) — "
                "duplicate submissions converge at the engine boundary"
            )
        binding = self._binding_for(request.spec.adapter_id)
        # The single port call: the external side effect happens exactly
        # once per idempotency key, inside the kernel transition.
        submission = binding.submit(request)
        attempt_number = request.spec.attempt_number
        attempt_spec = ExecutionAttemptSpec(
            attempt_id=attempt_object_id(step.object_id, attempt_number),
            plan_id=step.spec.plan_id,
            step_id=step.object_id,
            attempt_number=attempt_number,
            request_id=request.object_id,
            idempotency_key=key,
            status=submission.status,
            native_reference=submission.native_reference,
            reason=submission.reason,
            submitted_at=command.requested_at,
        )
        if submission.status is SubmissionStatus.ACCEPTED:
            request_state = EffectRequestState.SUBMITTED
            step_state = ExecutionStepState.SUBMITTED
            attempt_state = ExecutionAttemptState.IN_FLIGHT
        elif submission.status is SubmissionStatus.REJECTED:
            request_state = EffectRequestState.RESOLVED
            step_state = ExecutionStepState.FAILED
            attempt_state = ExecutionAttemptState.FAILED
        else:
            request_state = EffectRequestState.SUBMITTED
            step_state = ExecutionStepState.UNKNOWN
            attempt_state = ExecutionAttemptState.UNKNOWN
        new_request = self._advance(request, command, state=request_state.value)
        new_step = self._advance(step, command, state=step_state.value)
        attempt = make_attempt_record(
            attempt_spec=attempt_spec,
            state=attempt_state,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        submission_record = {
            "status": submission.status.value,
            "native_reference": submission.native_reference,
            "reason": submission.reason,
            "submitted_at": command.requested_at,
            "command_id": command.command_id,
        }
        envelopes = (new_step.envelope, new_request.envelope, attempt.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "request": new_request.to_dict(),
            "attempt": attempt.to_dict(),
            "idempotency_key": key,
            "submission": submission_record,
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_step_acknowledge(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_acknowledge_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        require_source_state("execution/step.acknowledge", step.state)
        request = self._latest_request(step.object_id)
        if request is None or request.state is not EffectRequestState.SUBMITTED:
            raise CoreValidationError(
                f"step {step.object_id} has no in-flight submitted effect request "
                "to acknowledge"
            )
        attempt = self._latest_attempt(step.object_id)
        if attempt is None or attempt.state is not ExecutionAttemptState.IN_FLIGHT:
            raise CoreValidationError(
                f"step {step.object_id} has no in-flight attempt to acknowledge"
            )
        key = request.spec.idempotency_key
        recorded = self._ledger.submission_for(key)
        if (
            recorded is not None
            and recorded.get("status") == "ACCEPTED"
            and recorded.get("native_reference") != payload["native_reference"]
        ):
            raise CoreValidationError(
                f"acknowledged native reference {payload['native_reference']!r} does "
                f"not match the reference recorded for key {key!r}"
            )
        receipt_id = receipt_object_id(request.object_id)
        if receipt_id in self._records:
            raise CoreValidationError(
                f"receipt {receipt_id!r} already exists; receipts are append-only"
            )
        receipt_spec = ReceiptSpec(
            receipt_id=receipt_id,
            request_id=request.object_id,
            step_id=step.object_id,
            adapter_id=request.spec.adapter_id,
            native_reference=payload["native_reference"],
            acknowledged_at=command.requested_at,
            request_digest=request.spec.digest,
        )
        receipt = make_receipt_record(
            spec=receipt_spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_step = self._advance(step, command, state=ExecutionStepState.ACKNOWLEDGED.value)
        new_attempt = self._advance(
            attempt, command, state=ExecutionAttemptState.ACKNOWLEDGED.value
        )
        envelopes = (new_step.envelope, new_attempt.envelope, receipt.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "attempt": new_attempt.to_dict(),
            "receipt": receipt.to_dict(),
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_record_effect_result(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_record_result_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        require_source_state("external/record-effect-result", step.state)
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no effect request to resolve"
            )
        if payload["request_id"] != request.object_id:
            raise CoreValidationError(
                f"a recorded effect result must bind to the step's current request "
                f"{request.object_id!r}, not {payload['request_id']!r}"
            )
        result_id = result_object_id(request.object_id)
        if result_id in self._records:
            raise CoreValidationError(
                f"effect result {result_id!r} already exists; results are "
                "append-only"
            )
        attempt = self._latest_attempt(step.object_id)
        if attempt is None:
            raise CoreValidationError(
                f"step {step.object_id} has no attempt to resolve"
            )
        outcome = payload["outcome"]
        if outcome is EffectOutcome.SUCCEEDED:
            attempt_state = ExecutionAttemptState.SUCCEEDED
            request_state = EffectRequestState.RESOLVED
        elif outcome is EffectOutcome.FAILED:
            attempt_state = ExecutionAttemptState.FAILED
            request_state = EffectRequestState.RESOLVED
        else:
            attempt_state = ExecutionAttemptState.UNKNOWN
            request_state = None
        result_spec = EffectResultSpec(
            result_id=result_id,
            request_id=request.object_id,
            step_id=step.object_id,
            effect_type=step.spec.effect_type,
            outcome=outcome,
            native_reference=payload["native_reference"],
            error_code=payload["error_code"],
            observed_at=payload["observed_at"],
            request_digest=request.spec.digest,
            detail=payload["detail"],
        )
        result = make_result_record(
            spec=result_spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_attempt = self._advance(attempt, command, state=attempt_state.value)
        new_request = (
            self._advance(request, command, state=request_state.value)
            if request_state is not None
            else None
        )
        envelopes = (result.envelope, new_attempt.envelope)
        journal_payload = {
            "result": result.to_dict(),
            "attempt": new_attempt.to_dict(),
            "request": new_request.to_dict() if new_request is not None else None,
        }
        if new_request is not None:
            envelopes = (result.envelope, new_attempt.envelope, new_request.envelope)
        return TransitionApplication(envelopes, journal_payload)

    def _handle_step_complete(self, command: Command, view: Any) -> TransitionApplication:
        step = self.step(command.target_refs[0])
        require_source_state("execution/step.complete", step.state)
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no effect request to complete on"
            )
        result = self._records.get(result_object_id(request.object_id))
        if not isinstance(result, EffectResult) or result.spec.outcome is not EffectOutcome.SUCCEEDED:
            raise CoreValidationError(
                f"step {step.object_id} may only complete on a recorded SUCCEEDED "
                "effect result for its current request"
            )
        if result.spec.request_digest != request.spec.digest:
            raise CoreValidationError(
                f"the recorded result for step {step.object_id} is not bound to "
                "the current request content"
            )
        new_step = self._advance(step, command, state=ExecutionStepState.SUCCEEDED.value)
        resolved_plan = self._resolve_plan(command, step.spec.plan_id, new_step=new_step)
        envelopes = (new_step.envelope,)
        if resolved_plan is not None:
            envelopes = (new_step.envelope, resolved_plan.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "plan": resolved_plan.to_dict() if resolved_plan is not None else None,
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_step_fail(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_reason_payload("execution/step.fail", _payload_dict(command))
        step = self.step(command.target_refs[0])
        require_source_state("execution/step.fail", step.state)
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no effect request to fail on"
            )
        result = self._records.get(result_object_id(request.object_id))
        if not isinstance(result, EffectResult) or result.spec.outcome is not EffectOutcome.FAILED:
            raise CoreValidationError(
                f"step {step.object_id} may only fail on a recorded FAILED effect "
                "result for its current request"
            )
        new_step = self._advance(step, command, state=ExecutionStepState.FAILED.value)
        resolved_plan = self._resolve_plan(command, step.spec.plan_id, new_step=new_step)
        envelopes = (new_step.envelope,)
        if resolved_plan is not None:
            envelopes = (new_step.envelope, resolved_plan.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "plan": resolved_plan.to_dict() if resolved_plan is not None else None,
            "reason": payload["reason"],
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_step_timeout(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_timeout_payload(_payload_dict(command))
        validate_timeout_declaration(
            requested_at=command.requested_at, deadline=payload["deadline"]
        )
        step = self.step(command.target_refs[0])
        require_source_state("execution/step.timeout", step.state)
        attempt = self._latest_attempt(step.object_id)
        if attempt is None or attempt.state not in (
            ExecutionAttemptState.IN_FLIGHT,
            ExecutionAttemptState.ACKNOWLEDGED,
            ExecutionAttemptState.UNKNOWN,
        ):
            raise CoreValidationError(
                f"step {step.object_id} has no in-flight attempt to time out"
            )
        new_step = self._advance(step, command, state=ExecutionStepState.UNKNOWN.value)
        new_attempt = self._advance(
            attempt, command, state=ExecutionAttemptState.UNKNOWN.value
        )
        envelopes = (new_step.envelope, new_attempt.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "attempt": new_attempt.to_dict(),
            "deadline": payload["deadline"],
            "reason": payload["reason"],
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_step_retry(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_reason_payload("execution/step.retry", _payload_dict(command))
        step = self.step(command.target_refs[0])
        request = self._latest_request(step.object_id)
        recorded_result = None
        if request is not None:
            candidate = self._records.get(result_object_id(request.object_id))
            if isinstance(candidate, EffectResult) and candidate.spec.request_id == request.object_id:
                recorded_result = candidate
        check_retry_gate(
            step=step,
            observations=self.observations(),
            current_request=request,
            attempt_count=len(self._numbered_ids(f"{step.object_id}/attempt/")),
            recorded_result=recorded_result,
        )
        new_step = self._advance(step, command, state=ExecutionStepState.PENDING.value)
        cancelled_request = None
        if request is not None and request.state is EffectRequestState.SUBMITTED:
            cancelled_request = self._advance(
                request, command, state=EffectRequestState.CANCELLED.value
            )
        envelopes = (new_step.envelope,)
        if cancelled_request is not None:
            envelopes = (new_step.envelope, cancelled_request.envelope)
        journal_payload = {
            "step": new_step.to_dict(),
            "request": cancelled_request.to_dict() if cancelled_request is not None else None,
            "reason": payload["reason"],
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_record_observation(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_observation_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        require_step_in_flight(step)
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no in-flight effect request to reconcile"
            )
        if payload["subject_ref"] != request.object_id:
            raise CoreValidationError(
                f"the reconciliation query must target the step's current request "
                f"{request.object_id!r}, not {payload['subject_ref']!r}"
            )
        observation_id = observation_object_id(command.command_id)
        if observation_id in self._records:
            raise CoreValidationError(
                f"observation {observation_id!r} already exists; observations are "
                "append-only"
            )
        spec = ExternalObservationSpec(
            observation_id=observation_id,
            kind=ObservationKind.QUERY,
            subject_ref=request.object_id,
            adapter_id=request.spec.adapter_id,
            epistemic=EpistemicType.OBSERVED,
            observed_at=command.requested_at,
            content=payload["query"],
            subject_request_digest=request.spec.digest,
        )
        observation = make_observation_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (observation.envelope,), {"observation": observation.to_dict()}
        )

    def _handle_record_status(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_status_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        require_source_state("external/record-status", step.state)
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no in-flight effect request to observe"
            )
        binding = self._binding_for(step.spec.adapter_id)
        mapped_status = binding.map_status(payload["native_code"])
        if mapped_status != payload["canonical_status"]:
            raise CoreValidationError(
                f"the declared canonical status {payload['canonical_status']!r} does "
                f"not match the adapter's declared status map ({mapped_status!r})"
            )
        observation_id = observation_object_id(command.command_id)
        if observation_id in self._records:
            raise CoreValidationError(
                f"observation {observation_id!r} already exists; observations are "
                "append-only"
            )
        spec = ExternalObservationSpec(
            observation_id=observation_id,
            kind=ObservationKind.STATUS,
            subject_ref=request.object_id,
            adapter_id=step.spec.adapter_id,
            epistemic=EpistemicType.OBSERVED,
            observed_at=command.requested_at,
            content={
                "native_code": payload["native_code"],
                "canonical_status": payload["canonical_status"],
            },
            subject_request_digest=request.spec.digest,
        )
        observation = make_observation_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        effect = status_observation_effect(step, payload["canonical_status"])
        new_step = None
        if effect == "unknown":
            new_step = self._advance(step, command, state=ExecutionStepState.UNKNOWN.value)
        envelopes = (observation.envelope,)
        if new_step is not None:
            envelopes = (observation.envelope, new_step.envelope)
        journal_payload = {
            "observation": observation.to_dict(),
            "step": new_step.to_dict() if new_step is not None else None,
        }
        return TransitionApplication(envelopes, journal_payload)

    def _handle_record_finality(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_finality_payload(_payload_dict(command))
        step = self.step(command.target_refs[0])
        request = self._latest_request(step.object_id)
        if request is None:
            raise CoreValidationError(
                f"step {step.object_id} has no effect request to attach the "
                "finality claim to"
            )
        observation_id = observation_object_id(command.command_id)
        if observation_id in self._records:
            raise CoreValidationError(
                f"observation {observation_id!r} already exists; observations are "
                "append-only"
            )
        spec = ExternalObservationSpec(
            observation_id=observation_id,
            kind=ObservationKind.FINALITY,
            subject_ref=request.object_id,
            adapter_id=step.spec.adapter_id,
            epistemic=EpistemicType.OBSERVED,
            observed_at=command.requested_at,
            content={
                "claim": payload["claim"],
                "native_reference": payload["native_reference"],
            },
            subject_request_digest=request.spec.digest,
        )
        observation = make_observation_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        # Finality claims are evidence only: no plan, step, request or
        # attempt envelope mutates here (constitution invariant 11).
        return TransitionApplication(
            (observation.envelope,), {"observation": observation.to_dict()}
        )

    def _resolve_plan(
        self, command: Command, plan_id: str, *, new_step: ExecutionStep | None = None
    ) -> ExecutionPlan | None:
        """Advance the plan when the last open step resolves.

        ``new_step`` is the step THIS command resolves: the handler
        computes it before the index is updated, so resolution must see
        the post-command step state (otherwise the last step's own
        completion would never resolve the plan).
        """
        plan = self.plan(plan_id)
        if plan.state is not ExecutionPlanState.RUNNING:
            return None
        steps = self.steps(plan_id)
        if new_step is not None:
            steps = tuple(
                new_step if step.object_id == new_step.object_id else step
                for step in steps
            )
        resolution = plan_resolution(steps)
        if resolution is None:
            return None
        return self._advance(plan, command, state=resolution.value)


def _journal_payload(entry: Any) -> Any:
    payload = payload_to_json_value(entry.payload) if entry.payload is not None else {}
    if not isinstance(payload, dict):
        raise CoreValidationError("execution journal payloads must be objects")
    return payload


__all__ = [
    "DEFAULT_COMMAND_AUTHORITY_CLASS",
    "DEFAULT_ENGINE_ACTOR",
    "ExecutionEngine",
    "ExecutionTransition",
]
