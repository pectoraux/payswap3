"""Execution plan, step and attempt records (WORK-014).

Durable composite records of the execution domain: the protocol-visible
execution plan (registry type ``payswap/execution-plan/v1``), its steps
and the per-submission attempts. Every record is
``ObjectEnvelope + payload`` sealed with the single canonical hash
authority; tampered or spliced records fail closed on the trusted
deserialization path.

Identity derivation is deterministic: step ids live under the plan id
(``<plan_id>/step/<position>``), attempts under the step id
(``<step_id>/attempt/<n>``) and effect requests under the step id
(``<step_id>/request/<n>``) — derived from declared data, never
generated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.transition.payload import normalize_payload, payload_to_json_value
from src.transition.registry import validate_authority_class

from ._validation import (
    require_identifier,
    require_int,
    require_effect_type,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    EXECUTION_ATTEMPT_OBJECT_TYPE,
    EXECUTION_PLAN_OBJECT_TYPE,
    EXECUTION_STEP_OBJECT_TYPE,
    ExecutionAttemptState,
    ExecutionPlanState,
    ExecutionStepState,
    SubmissionStatus,
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

_PLAN_SPEC_FIELDS = frozenset(
    {
        "plan_id",
        "source_ref",
        "summary",
        "authority_class",
        "mandate_ref",
        "fraud_decision",
        "compliance_assessment",
    }
)
_STEP_SPEC_FIELDS = frozenset(
    {
        "step_id",
        "plan_id",
        "position",
        "adapter_id",
        "effect_type",
        "payload",
        "reservation_ref",
        "max_attempts",
    }
)
_ATTEMPT_SPEC_FIELDS = frozenset(
    {
        "attempt_id",
        "plan_id",
        "step_id",
        "attempt_number",
        "request_id",
        "idempotency_key",
        "status",
        "native_reference",
        "reason",
        "submitted_at",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionPlanSpec:
    """Canonical payload of one execution plan.

    ``authority_class``/``fraud_decision``/``compliance_assessment`` are
    ``None`` until the ``Authorize`` command pins the exercised registry
    authority class and the evidence-backed safety gates (constitution
    invariant 3 — authority before financial effect; invariant 13 —
    material decisions preserve provenance).
    """

    plan_id: str
    source_ref: str
    summary: str = ""
    authority_class: str | None = None
    mandate_ref: str | None = None
    fraud_decision: Any = None
    compliance_assessment: Any = None

    def __post_init__(self) -> None:
        require_identifier("plan spec plan_id", self.plan_id)
        require_text("plan spec source_ref", self.source_ref)
        if not isinstance(self.summary, str):
            raise CoreValidationError("plan spec summary must be a string")
        if self.authority_class is not None:
            validate_authority_class("plan spec authority_class", self.authority_class)
        if self.mandate_ref is not None:
            require_identifier("plan spec mandate_ref", self.mandate_ref)
        for name in ("fraud_decision", "compliance_assessment"):
            value = getattr(self, name)
            if value is not None:
                require_mapping(f"plan spec {name}", value)
                # Validate through the canonical kernel pipeline (floats and
                # unsafe values fail closed), then store the fresh JSON-form
                # tree: gate evidence is read as data (indexed by callers),
                # so it must support mapping access while staying canonical.
                object.__setattr__(
                    self,
                    name,
                    payload_to_json_value(normalize_payload(f"plan spec {name}", value)),
                )

    @staticmethod
    def _gate_copy(value: Any) -> Any:
        """Fresh canonical JSON-form copy of one gate projection."""
        if value is None:
            return None
        return payload_to_json_value(normalize_payload("plan spec gate", value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "source_ref": self.source_ref,
            "summary": self.summary,
            "authority_class": self.authority_class,
            "mandate_ref": self.mandate_ref,
            "fraud_decision": self._gate_copy(self.fraud_decision),
            "compliance_assessment": self._gate_copy(self.compliance_assessment),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionPlanSpec":
        strict_fields("plan spec", value, _PLAN_SPEC_FIELDS)
        return cls(
            plan_id=value["plan_id"],
            source_ref=value["source_ref"],
            summary=value["summary"],
            authority_class=value["authority_class"],
            mandate_ref=value["mandate_ref"],
            fraud_decision=value["fraud_decision"],
            compliance_assessment=value["compliance_assessment"],
        )


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Durable execution plan record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ExecutionPlanSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EXECUTION_PLAN_OBJECT_TYPE
    STATE_TYPE = ExecutionPlanState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("plan envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ExecutionPlanSpec):
            raise CoreValidationError("plan spec must be an ExecutionPlanSpec")
        if self.envelope.object_type != EXECUTION_PLAN_OBJECT_TYPE:
            raise CoreValidationError(
                f"plan object_type must be {EXECUTION_PLAN_OBJECT_TYPE!r}, "
                f"got {self.envelope.object_type!r}"
            )
        if self.envelope.object_id != self.spec.plan_id:
            raise CoreValidationError("plan object_id must equal spec plan_id")
        try:
            ExecutionPlanState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown execution plan state: {self.envelope.state!r}"
            ) from exc
        state = ExecutionPlanState(self.envelope.state)
        # Only states that carry exercised financial-effect authority must
        # pin the registry authority class: AUTHORIZED/RUNNING/COMPLETED/
        # FAILED all passed Authorize; CANCELLED may legitimately arise
        # from a never-authorized DRAFT plan (cancel from draft).
        if state not in (
            ExecutionPlanState.DRAFT,
            ExecutionPlanState.CANCELLED,
        ) and self.spec.authority_class is None:
            raise CoreValidationError(
                "a plan beyond DRAFT must carry its pinned authority class"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ExecutionPlanState:
        return ExecutionPlanState(self.envelope.state)

    def is_terminal(self) -> bool:
        return self.state in {
            ExecutionPlanState.COMPLETED,
            ExecutionPlanState.FAILED,
            ExecutionPlanState.CANCELLED,
        }

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionPlan":
        envelope, payload = decode_composite(
            value, object_type=EXECUTION_PLAN_OBJECT_TYPE, state_type=ExecutionPlanState
        )
        spec = ExecutionPlanSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "ExecutionPlan":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EXECUTION_PLAN_OBJECT_TYPE, state_type=ExecutionPlanState
        )
        spec = ExecutionPlanSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


@dataclass(frozen=True, slots=True)
class ExecutionStepSpec:
    """Canonical payload of one execution step.

    ``reservation_ref`` names the protocol reservation whose held
    capacity this step's effect consumes (WORK-012 owns reservations);
    ``max_attempts`` bounds submission attempts per step (the retry
    budget).
    """

    step_id: str
    plan_id: str
    position: int
    adapter_id: str
    effect_type: str
    payload: Any
    reservation_ref: str
    max_attempts: int

    def __post_init__(self) -> None:
        require_identifier("step spec step_id", self.step_id)
        require_identifier("step spec plan_id", self.plan_id)
        if not self.step_id.startswith(f"{self.plan_id}/step/"):
            raise CoreValidationError(
                "step id must live under the plan id: <plan_id>/step/<position>"
            )
        require_int("step spec position", self.position, minimum=1)
        require_identifier("step spec adapter_id", self.adapter_id)
        require_effect_type("step spec effect_type", self.effect_type)
        require_identifier("step spec reservation_ref", self.reservation_ref)
        require_int("step spec max_attempts", self.max_attempts, minimum=1)
        object.__setattr__(self, "payload", normalize_payload("step spec payload", self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "plan_id": self.plan_id,
            "position": self.position,
            "adapter_id": self.adapter_id,
            "effect_type": self.effect_type,
            "payload": payload_to_json_value(self.payload),
            "reservation_ref": self.reservation_ref,
            "max_attempts": self.max_attempts,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionStepSpec":
        strict_fields("step spec", value, _STEP_SPEC_FIELDS)
        return cls(
            step_id=value["step_id"],
            plan_id=value["plan_id"],
            position=value["position"],
            adapter_id=value["adapter_id"],
            effect_type=value["effect_type"],
            payload=value["payload"],
            reservation_ref=value["reservation_ref"],
            max_attempts=value["max_attempts"],
        )


@dataclass(frozen=True, slots=True)
class ExecutionStep:
    """Durable execution step record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ExecutionStepSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EXECUTION_STEP_OBJECT_TYPE
    STATE_TYPE = ExecutionStepState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("step envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ExecutionStepSpec):
            raise CoreValidationError("step spec must be an ExecutionStepSpec")
        if self.envelope.object_type != EXECUTION_STEP_OBJECT_TYPE:
            if str(self.envelope.object_type).startswith("payswap/"):
                raise CoreValidationError(
                    "execution step object_type must not claim a registry-governed "
                    f"protocol-visible type; steps use the internal type "
                    f"{EXECUTION_STEP_OBJECT_TYPE}"
                )
            raise CoreValidationError(
                f"step object_type must be {EXECUTION_STEP_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.step_id:
            raise CoreValidationError("step object_id must equal spec step_id")
        try:
            ExecutionStepState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown execution step state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ExecutionStepState:
        return ExecutionStepState(self.envelope.state)

    def is_terminal(self) -> bool:
        return self.state in {
            ExecutionStepState.SUCCEEDED,
            ExecutionStepState.FAILED,
            ExecutionStepState.CANCELLED,
        }

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionStep":
        envelope, payload = decode_composite(
            value, object_type=EXECUTION_STEP_OBJECT_TYPE, state_type=ExecutionStepState
        )
        spec = ExecutionStepSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "ExecutionStep":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EXECUTION_STEP_OBJECT_TYPE, state_type=ExecutionStepState
        )
        spec = ExecutionStepSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


@dataclass(frozen=True, slots=True)
class ExecutionAttemptSpec:
    """Canonical payload of one submission attempt.

    One attempt is created by ``Submit``; its outcome vocabulary is the
    closed :class:`~src.execution.contracts.ExecutionAttemptState` set.
    ``UNKNOWN`` is the explicit reconcilable outcome (never a silent
    failure, never permission to retry blindly).
    """

    attempt_id: str
    plan_id: str
    step_id: str
    attempt_number: int
    request_id: str
    idempotency_key: str
    status: SubmissionStatus
    native_reference: str | None
    reason: str | None
    submitted_at: str

    def __post_init__(self) -> None:
        require_identifier("attempt spec attempt_id", self.attempt_id)
        require_identifier("attempt spec plan_id", self.plan_id)
        require_identifier("attempt spec step_id", self.step_id)
        if not self.attempt_id.startswith(f"{self.step_id}/attempt/"):
            raise CoreValidationError(
                "attempt id must live under the step id: <step_id>/attempt/<n>"
            )
        require_int("attempt spec attempt_number", self.attempt_number, minimum=1)
        require_identifier("attempt spec request_id", self.request_id)
        require_text("attempt spec idempotency_key", self.idempotency_key)
        if not isinstance(self.status, SubmissionStatus):
            raise CoreValidationError("attempt spec status must be a SubmissionStatus")
        if self.native_reference is not None:
            require_text("attempt spec native_reference", self.native_reference)
        if self.reason is not None:
            require_text("attempt spec reason", self.reason)
        require_utc_timestamp("attempt spec submitted_at", self.submitted_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
            "attempt_number": self.attempt_number,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "status": self.status.value,
            "native_reference": self.native_reference,
            "reason": self.reason,
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionAttemptSpec":
        strict_fields("attempt spec", value, _ATTEMPT_SPEC_FIELDS)
        return cls(
            attempt_id=value["attempt_id"],
            plan_id=value["plan_id"],
            step_id=value["step_id"],
            attempt_number=value["attempt_number"],
            request_id=value["request_id"],
            idempotency_key=value["idempotency_key"],
            status=SubmissionStatus(value["status"]),
            native_reference=value["native_reference"],
            reason=value["reason"],
            submitted_at=value["submitted_at"],
        )


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """Durable submission-attempt record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ExecutionAttemptSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EXECUTION_ATTEMPT_OBJECT_TYPE
    STATE_TYPE = ExecutionAttemptState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("attempt envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ExecutionAttemptSpec):
            raise CoreValidationError("attempt spec must be an ExecutionAttemptSpec")
        if self.envelope.object_type != EXECUTION_ATTEMPT_OBJECT_TYPE:
            raise CoreValidationError(
                f"attempt object_type must be {EXECUTION_ATTEMPT_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.attempt_id:
            raise CoreValidationError("attempt object_id must equal spec attempt_id")
        try:
            ExecutionAttemptState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown execution attempt state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ExecutionAttemptState:
        return ExecutionAttemptState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionAttempt":
        envelope, payload = decode_composite(
            value, object_type=EXECUTION_ATTEMPT_OBJECT_TYPE, state_type=ExecutionAttemptState
        )
        spec = ExecutionAttemptSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "ExecutionAttempt":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EXECUTION_ATTEMPT_OBJECT_TYPE, state_type=ExecutionAttemptState
        )
        spec = ExecutionAttemptSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def step_object_id(plan_id: str, position: int) -> str:
    """Derive the deterministic step object id: ``<plan_id>/step/<position>``."""
    require_identifier("plan_id", plan_id)
    require_int("position", position, minimum=1)
    return f"{plan_id}/step/{position}"


def attempt_object_id(step_id: str, attempt_number: int) -> str:
    """Derive the deterministic attempt object id: ``<step_id>/attempt/<n>``."""
    require_identifier("step_id", step_id)
    require_int("attempt_number", attempt_number, minimum=1)
    return f"{step_id}/attempt/{attempt_number}"


def request_object_id(step_id: str, attempt_number: int) -> str:
    """Derive the deterministic effect-request object id: ``<step_id>/request/<n>``."""
    require_identifier("step_id", step_id)
    require_int("attempt_number", attempt_number, minimum=1)
    return f"{step_id}/request/{attempt_number}"


def result_object_id(request_id: str) -> str:
    """Derive the deterministic effect-result object id: ``<request_id>/result``."""
    require_identifier("request_id", request_id)
    return f"{request_id}/result"


def receipt_object_id(request_id: str) -> str:
    """Derive the deterministic receipt object id: ``<request_id>/receipt``."""
    require_identifier("request_id", request_id)
    return f"{request_id}/receipt"


def observation_object_id(command_id: str) -> str:
    """Derive the deterministic observation object id from the command id."""
    require_identifier("command_id", command_id)
    return f"execution/observation/{command_id}"


def make_plan_record(
    *,
    plan_id: str,
    source_ref: str,
    summary: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ExecutionPlan:
    spec = ExecutionPlanSpec(plan_id=plan_id, source_ref=source_ref, summary=summary)
    envelope = build_domain_envelope(
        object_id=plan_id,
        object_type=EXECUTION_PLAN_OBJECT_TYPE,
        state=ExecutionPlanState.DRAFT.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return ExecutionPlan(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def make_step_record(
    *,
    step_spec: ExecutionStepSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ExecutionStep:
    envelope = build_domain_envelope(
        object_id=step_spec.step_id,
        object_type=EXECUTION_STEP_OBJECT_TYPE,
        state=ExecutionStepState.PENDING.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return ExecutionStep(
        envelope=envelope, spec=step_spec, integrity_hash=seal_composite(envelope, step_spec)
    )


def make_attempt_record(
    *,
    attempt_spec: ExecutionAttemptSpec,
    state: ExecutionAttemptState,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ExecutionAttempt:
    envelope = build_domain_envelope(
        object_id=attempt_spec.attempt_id,
        object_type=EXECUTION_ATTEMPT_OBJECT_TYPE,
        state=state.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return ExecutionAttempt(
        envelope=envelope, spec=attempt_spec, integrity_hash=seal_composite(envelope, attempt_spec)
    )
