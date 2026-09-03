"""The model registry: the frozen Model command family (WORK-021).

``ModelRegistry`` owns the typed model records and applies the frozen
lifecycle
``REGISTERED → VALIDATED → APPROVED → DEPLOYED → SUSPENDED → RETIRED``
(``Register/Validate/Approve/Deploy/Suspend/Resume/Retire``) as immutable
record versions. It never touches the kernel directly: the kernel binding
(:mod:`src.agents.engine`) routes ``model/*`` commands here.

Three surfaces matter to the mediation discipline:

* :meth:`ModelRegistry.evaluate_command` — the semantic gate used by the
  kernel's policy stage: it validates the transition and payload BEFORE
  any mutation and returns an explicit rejection reason (or ``None``),
  so every invalid lifecycle command is a recorded kernel rejection.
* :meth:`ModelRegistry.apply_command` — the transition handler: it
  re-validates, mutates the typed record, and returns the kernel
  application (sealed envelopes + canonical payload).
* :meth:`ModelRegistry.require_deployed` — the consumption gate: only
  ``DEPLOYED`` models may back agent proposals. Unregistered, unapproved,
  suspended and retired models fail closed.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import Command, TransitionApplication, payload_to_json_value

from .contracts import (
    MODEL_COMMANDS,
    MODEL_ID_PREFIX,
    MODEL_TRANSITIONS,
    ModelLifecycleState,
    ModelRiskClass,
    require_agents_identifier,
)
from ._validation import (
    parse_enum,
    require_digest,
    require_identifier,
    require_str_tuple,
    require_text,
    strict_fields,
)
from .models import ModelRecord, ModelSpec

_REGISTER_FIELDS = frozenset(
    {
        "model_id",
        "developer",
        "task",
        "risk_class",
        "declared_limitations",
        "code_hash",
    }
)
_VALIDATE_FIELDS = frozenset({"model_id", "validation_notes"})
_APPROVE_FIELDS = frozenset({"model_id", "approver"})
_DEPLOY_FIELDS = frozenset({"model_id"})
_SUSPEND_FIELDS = frozenset({"model_id", "reason"})
_RESUME_FIELDS = frozenset({"model_id"})
_RETIRE_FIELDS = frozenset({"model_id", "reason"})

_COMMAND_FIELDS = {
    "model/register": _REGISTER_FIELDS,
    "model/validate": _VALIDATE_FIELDS,
    "model/approve": _APPROVE_FIELDS,
    "model/deploy": _DEPLOY_FIELDS,
    "model/suspend": _SUSPEND_FIELDS,
    "model/resume": _RESUME_FIELDS,
    "model/retire": _RETIRE_FIELDS,
}


def parse_model_payload(command: Command) -> dict[str, Any]:
    """Parse and structurally validate one model command payload.

    Payload fields are strict (unknown or missing fields fail closed),
    the model id must use the family prefix, the risk class must be a
    closed-vocabulary member, declared limitations must be non-empty
    strings, the code hash must be a canonical digest, and the
    transition instant is the command's explicit ``requested_at``.
    Every structural failure is raised here so the kernel's policy
    stage turns it into a recorded rejection.
    """
    if command.command_type not in _COMMAND_FIELDS:
        raise CoreValidationError(
            f"model registry received non-model command {command.command_type!r}"
        )
    data = payload_to_json_value(command.payload)
    if not isinstance(data, Mapping):
        raise CoreValidationError("model command payload must be an object")
    strict_fields(
        f"model command {command.command_type}", data, _COMMAND_FIELDS[command.command_type]
    )
    require_agents_identifier("model command model_id", data["model_id"], MODEL_ID_PREFIX)
    if command.command_type == "model/register":
        require_identifier("model command developer", data["developer"])
        require_text("model command task", data["task"])
        parse_enum("model risk_class", data["risk_class"], ModelRiskClass)
        limitations = require_str_tuple(
            "model command declared_limitations",
            data["declared_limitations"],
            non_empty=True,
        )
        if not all(isinstance(item, str) and item.strip() for item in limitations):
            raise CoreValidationError(
                "model command declared_limitations must be non-empty strings"
            )
        require_digest("model command code_hash", data["code_hash"])
    elif command.command_type in ("model/validate", "model/approve"):
        require_text(
            f"model command {command.command_type} annotation", data[
                "validation_notes" if command.command_type == "model/validate" else "approver"
            ]
        )
    elif command.command_type in ("model/suspend", "model/retire"):
        require_text(
            f"model command {command.command_type} reason", data["reason"]
        )
    return dict(data)


class ModelRegistry:
    """Typed model record store applying the frozen Model lifecycle."""

    def __init__(self, *, environment_id: str, domain_id: str) -> None:
        require_identifier("registry environment_id", environment_id)
        require_identifier("registry domain_id", domain_id)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._models: dict[str, ModelRecord] = {}

    # -- read-only surface --------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    def get(self, model_id: str) -> ModelRecord | None:
        require_agents_identifier("model_id", model_id, MODEL_ID_PREFIX)
        return self._models.get(model_id)

    def require_model(self, model_id: str) -> ModelRecord:
        """Fail closed on unknown models."""
        record = self.get(model_id)
        if record is None:
            raise CoreValidationError(
                f"unknown model {model_id!r}: the registry fails closed on unknown "
                "model identity"
            )
        return record

    def require_deployed(self, model_id: str) -> ModelRecord:
        """The consumption gate: only DEPLOYED models may back proposals."""
        record = self.require_model(model_id)
        if record.state is not ModelLifecycleState.DEPLOYED:
            raise CoreValidationError(
                f"model {model_id!r} is {record.state.value}, not DEPLOYED: "
                "unregistered/unapproved/suspended/retired models fail closed at "
                "consumption"
            )
        return record

    def models(self) -> tuple[ModelRecord, ...]:
        """Deterministic ordered view of every registered model."""
        return tuple(self._models[model_id] for model_id in sorted(self._models))

    def state_digest(self) -> str:
        """Canonical digest of the registry state."""
        return canonical_sha256([record.to_dict() for record in self.models()])

    # -- semantic gate (kernel policy stage) ----------------------------------

    def evaluate_command(self, command: Command) -> str | None:
        """Validate the transition; return an explicit rejection reason."""
        if command.command_type not in MODEL_COMMANDS:
            raise CoreValidationError(
                f"model registry received non-model command {command.command_type!r}"
            )
        try:
            data = parse_model_payload(command)
        except CoreValidationError as exc:
            return f"model command payload fails closed: {exc}"
        if command.command_type == "model/register":
            if data["model_id"] in self._models:
                return (
                    f"model command model/register fails closed: model "
                    f"{data['model_id']!r} is already registered"
                )
            return None
        record = self.get(data["model_id"])
        if record is None:
            return (
                f"model command {command.command_type} fails closed: unknown model "
                f"{data['model_id']!r}"
            )
        if command.command_type == "model/approve":
            if data["approver"] == record.spec.developer:
                return (
                    "model approval requires separation of duties: the approver "
                    f"must differ from the developer {record.spec.developer!r}"
                )
        transitions = MODEL_TRANSITIONS[command.command_type]
        if record.state not in transitions:
            return (
                f"model command {command.command_type} fails closed: model "
                f"{data['model_id']!r} is {record.state.value}"
            )
        return None

    # -- transition handler (kernel transition stage) --------------------------

    def apply_command(self, command: Command) -> TransitionApplication:
        """Apply one validated model lifecycle command."""
        data = parse_model_payload(command)
        at = command.requested_at
        if command.command_type == "model/register":
            if data["model_id"] in self._models:
                raise CoreValidationError(
                    f"model {data['model_id']!r} is already registered"
                )
            spec = ModelSpec(
                model_id=data["model_id"],
                developer=data["developer"],
                task=data["task"],
                risk_class=parse_enum(
                    "model risk_class", data["risk_class"], ModelRiskClass
                ),
                declared_limitations=tuple(data["declared_limitations"]),
                code_hash=data["code_hash"],
            )
            record = ModelRecord.register(
                environment_id=self._environment_id,
                domain_id=self._domain_id,
                spec=spec,
                provenance=Provenance(
                    issuer=command.actor,
                    source=f"agents/{command.command_type}",
                    recorded_at=at,
                    evidence_refs=(spec.code_hash,),
                ),
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
            )
            self._models[record.model_id] = record
            return TransitionApplication(
                resulting_envelopes=(record.envelope,),
                payload=spec.to_dict(),
            )
        record = self.require_model(data["model_id"])
        if command.command_type == "model/approve":
            if data["approver"] == record.spec.developer:
                raise CoreValidationError(
                    "model approval requires separation of duties: the approver "
                    f"must differ from the developer {record.spec.developer!r}"
                )
        transitions = MODEL_TRANSITIONS[command.command_type]
        if record.state not in transitions:
            raise CoreValidationError(
                f"model command {command.command_type} fails closed: model "
                f"{data['model_id']!r} is {record.state.value}"
            )
        spec = self._annotate(record.spec, command.command_type, data, at)
        advanced = record.advance(
            state=transitions[record.state],
            spec=spec,
            provenance=Provenance(
                issuer=command.actor,
                source=f"agents/{command.command_type}",
                recorded_at=at,
                evidence_refs=record.envelope.provenance.evidence_refs,
            ),
            causation_id=command.command_id,
        )
        self._models[advanced.model_id] = advanced
        return TransitionApplication(
            resulting_envelopes=(advanced.envelope,),
            payload=spec.to_dict(),
        )

    # -- helpers ---------------------------------------------------------------

    def _annotate(
        self, spec: ModelSpec, command_type: str, data: Mapping[str, Any], at: str
    ) -> ModelSpec:
        if command_type == "model/validate":
            return replace(
                spec, validation_notes=data["validation_notes"], validated_at=at
            )
        if command_type == "model/approve":
            return replace(spec, approver=data["approver"], approved_at=at)
        if command_type == "model/deploy":
            return replace(spec, deployed_at=at)
        if command_type == "model/suspend":
            return replace(spec, suspension_reason=data["reason"], suspended_at=at)
        if command_type == "model/resume":
            return replace(spec, suspension_reason=None, suspended_at=None)
        if command_type == "model/retire":
            return replace(spec, retirement_reason=data["reason"], retired_at=at)
        raise CoreValidationError(
            f"model registry cannot annotate command {command_type!r}"
        )
