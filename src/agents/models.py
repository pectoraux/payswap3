"""Model records and model outputs (WORK-021).

The frozen v0.1 canonical object model places ``Model`` and
``ModelOutput`` in the "Extensibility and simulation" family. This module
owns their typed representations:

* :class:`ModelRecord` — the durable model registry record: a sealed
  ``ObjectEnvelope`` (identity, lifecycle state, provenance, version
  chain) plus the immutable :class:`ModelSpec` payload, sealed with the
  single canonical hash authority. The envelope state carries the frozen
  lifecycle (``REGISTERED → VALIDATED → APPROVED → DEPLOYED → SUSPENDED
  → RETIRED``) and every lifecycle annotation (validation notes, approver,
  deployment, suspension, retirement) accumulates in the spec as
  append-only immutable record versions.
* :class:`ModelOutput` — a typed model artifact: the frozen epistemic
  vocabulary re-used from ``src.evidence`` (``SIMULATED``/``PREDICTED``
  only — a model output can never masquerade as an observation), an exact
  basis-point confidence, declared limitations, explicit provenance with
  non-empty evidence references (constitution invariant 13), an explicit
  half-open freshness window and a domain seal. A model output is a
  proposal input, never an authority: nothing here can cause a financial
  effect.

Determinism discipline: no clock reads, no entropy sources, no generated
identifiers — every instant is explicit declared data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition.payload import normalize_payload, payload_to_json_value

from .contracts import (
    CONFIDENCE_BPS_MAX,
    CONFIDENCE_BPS_MIN,
    MODEL_OBJECT_TYPE,
    MODEL_OUTPUT_EPISTEMIC_TYPES,
    MODEL_OUTPUT_ID_PREFIX,
    MODEL_OUTPUT_OBJECT_TYPE,
    MODEL_ID_PREFIX,
    ModelLifecycleState,
    ModelRiskClass,
    require_agents_identifier,
)
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_int,
    require_str_tuple,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_MODEL_SPEC_FIELDS = frozenset(
    {
        "model_id",
        "developer",
        "task",
        "risk_class",
        "declared_limitations",
        "code_hash",
        "validation_notes",
        "validated_at",
        "approver",
        "approved_at",
        "deployed_at",
        "suspension_reason",
        "suspended_at",
        "retirement_reason",
        "retired_at",
    }
)

_OUTPUT_FIELDS = frozenset(
    {
        "output_id",
        "model_id",
        "epistemic_type",
        "confidence_bps",
        "value",
        "declared_limitations",
        "produced_at",
        "valid_from",
        "valid_until",
        "provenance",
        "integrity_hash",
    }
)


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """Immutable model registry payload (registration + lifecycle marks)."""

    model_id: str
    developer: str
    task: str
    risk_class: ModelRiskClass
    declared_limitations: tuple[str, ...]
    code_hash: str
    validation_notes: str | None = None
    validated_at: str | None = None
    approver: str | None = None
    approved_at: str | None = None
    deployed_at: str | None = None
    suspension_reason: str | None = None
    suspended_at: str | None = None
    retirement_reason: str | None = None
    retired_at: str | None = None

    def __post_init__(self) -> None:
        require_agents_identifier("model.model_id", self.model_id, MODEL_ID_PREFIX)
        require_identifier("model.developer", self.developer)
        require_text("model.task", self.task)
        if not isinstance(self.risk_class, ModelRiskClass):
            raise CoreValidationError(
                "model.risk_class must use the closed ModelRiskClass vocabulary"
            )
        object.__setattr__(
            self,
            "declared_limitations",
            require_str_tuple(
                "model.declared_limitations", self.declared_limitations, non_empty=True
            ),
        )
        require_digest("model.code_hash", self.code_hash)
        for name, value in (
            ("validation_notes", self.validation_notes),
            ("approver", self.approver),
            ("suspension_reason", self.suspension_reason),
            ("retirement_reason", self.retirement_reason),
        ):
            if value is not None:
                require_text(f"model.{name}", value)
        for name, value in (
            ("validated_at", self.validated_at),
            ("approved_at", self.approved_at),
            ("deployed_at", self.deployed_at),
            ("suspended_at", self.suspended_at),
            ("retired_at", self.retired_at),
        ):
            if value is not None:
                require_utc_timestamp(f"model.{name}", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "developer": self.developer,
            "task": self.task,
            "risk_class": self.risk_class.value,
            "declared_limitations": list(self.declared_limitations),
            "code_hash": self.code_hash,
            "validation_notes": self.validation_notes,
            "validated_at": self.validated_at,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "deployed_at": self.deployed_at,
            "suspension_reason": self.suspension_reason,
            "suspended_at": self.suspended_at,
            "retirement_reason": self.retirement_reason,
            "retired_at": self.retired_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelSpec":
        strict_fields("model", value, _MODEL_SPEC_FIELDS)
        return cls(
            model_id=value["model_id"],
            developer=value["developer"],
            task=value["task"],
            risk_class=parse_enum("model.risk_class", value["risk_class"], ModelRiskClass),
            declared_limitations=tuple(value["declared_limitations"]),
            code_hash=value["code_hash"],
            validation_notes=value["validation_notes"],
            validated_at=value["validated_at"],
            approver=value["approver"],
            approved_at=value["approved_at"],
            deployed_at=value["deployed_at"],
            suspension_reason=value["suspension_reason"],
            suspended_at=value["suspended_at"],
            retirement_reason=value["retirement_reason"],
            retired_at=value["retired_at"],
        )


@dataclass(frozen=True, slots=True)
class ModelRecord:
    """Durable model registry record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ModelSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = MODEL_OBJECT_TYPE
    STATE_TYPE = ModelLifecycleState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("model record envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ModelSpec):
            raise CoreValidationError("model record spec must be a ModelSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != MODEL_OBJECT_TYPE:
            raise CoreValidationError(
                f"model record object_type must be {MODEL_OBJECT_TYPE!r}"
            )
        try:
            ModelLifecycleState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown model record state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.model_id:
            raise CoreValidationError(
                "model record identity mismatch: envelope and spec must name the "
                "same model"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.model_id)

    @property
    def model_id(self) -> str:
        return self.spec.model_id

    @property
    def state(self) -> ModelLifecycleState:
        return ModelLifecycleState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelRecord":
        envelope, payload = decode_composite(
            value,
            expected_object_type=MODEL_OBJECT_TYPE,
            state_type=ModelLifecycleState,
        )
        spec = ModelSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "ModelRecord":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=MODEL_OBJECT_TYPE,
            state_type=ModelLifecycleState,
        )
        spec = ModelSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    @classmethod
    def register(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        spec: ModelSpec,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "ModelRecord":
        """Create the version-1 REGISTERED record."""
        envelope = build_domain_envelope(
            object_id=spec.model_id,
            object_type=MODEL_OBJECT_TYPE,
            state=ModelLifecycleState.REGISTERED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec))

    def advance(
        self,
        *,
        state: ModelLifecycleState,
        spec: ModelSpec,
        provenance: Provenance,
        causation_id: str | None = None,
    ) -> "ModelRecord":
        """Produce the next sealed record version with a new lifecycle state."""
        envelope = advance_envelope(
            self.envelope,
            state=state.value,
            provenance=provenance,
            causation_id=causation_id,
        )
        return ModelRecord(
            envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
        )


@dataclass(frozen=True, slots=True)
class ModelOutput:
    """One sealed model output artifact (proposal input, never authority).

    The epistemic type is restricted to the frozen ``SIMULATED``/
    ``PREDICTED`` vocabulary owned by ``src.evidence``; confidence is an
    exact basis-point value; the declared limitations are carried on the
    artifact itself; the provenance must cite evidence; freshness is an
    explicit half-open window checked against the consuming instant. The
    domain seal rejects tampering on the trusted deserialization path.
    """

    output_id: str
    model_id: str
    epistemic_type: Any
    confidence_bps: int
    value: Any
    declared_limitations: tuple[str, ...]
    produced_at: str
    valid_from: str
    valid_until: str
    provenance: Provenance
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        from src.evidence.contracts import EpistemicType  # local: avoid cycle at import

        require_agents_identifier(
            "model output output_id", self.output_id, MODEL_OUTPUT_ID_PREFIX
        )
        require_agents_identifier("model output model_id", self.model_id, MODEL_ID_PREFIX)
        if not isinstance(self.epistemic_type, EpistemicType):
            raise CoreValidationError(
                "model output epistemic_type must be the frozen EpistemicType"
            )
        if self.epistemic_type not in MODEL_OUTPUT_EPISTEMIC_TYPES:
            raise CoreValidationError(
                "model output epistemic_type must be SIMULATED or PREDICTED; a "
                "model output can never masquerade as an observation"
            )
        require_int(
            "model output confidence_bps",
            self.confidence_bps,
            minimum=CONFIDENCE_BPS_MIN,
            maximum=CONFIDENCE_BPS_MAX,
        )
        object.__setattr__(
            self, "value", normalize_payload("model output value", self.value)
        )
        object.__setattr__(
            self,
            "declared_limitations",
            require_str_tuple(
                "model output declared_limitations",
                self.declared_limitations,
                non_empty=True,
            ),
        )
        require_utc_timestamp("model output produced_at", self.produced_at)
        require_utc_timestamp("model output valid_from", self.valid_from)
        require_utc_timestamp("model output valid_until", self.valid_until)
        require_utc_timestamp_order(
            "model output valid_from", self.valid_from, "model output valid_until", self.valid_until
        )
        if not isinstance(self.provenance, Provenance):
            raise CoreValidationError("model output provenance must be a Provenance")
        if not self.provenance.evidence_refs:
            raise CoreValidationError(
                "model output provenance must cite evidence; material decisions "
                "preserve provenance"
            )
        expected = canonical_sha256(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                f"integrity hash mismatch for model output {self.output_id}"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "output_id": self.output_id,
            "model_id": self.model_id,
            "epistemic_type": self.epistemic_type.value,
            "confidence_bps": self.confidence_bps,
            "value": payload_to_json_value(self.value),
            "declared_limitations": list(self.declared_limitations),
            "produced_at": self.produced_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "provenance": self.provenance.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelOutput":
        from src.evidence.contracts import EpistemicType

        strict_fields("model output", value, _OUTPUT_FIELDS)
        epistemic_type = value["epistemic_type"]
        if not isinstance(epistemic_type, EpistemicType):
            try:
                epistemic_type = EpistemicType(value["epistemic_type"])
            except ValueError as exc:
                raise CoreValidationError(
                    "model output epistemic_type must be the frozen EpistemicType"
                ) from exc
        return cls(
            output_id=value["output_id"],
            model_id=value["model_id"],
            epistemic_type=epistemic_type,
            confidence_bps=value["confidence_bps"],
            value=value["value"],
            declared_limitations=tuple(value["declared_limitations"]),
            produced_at=value["produced_at"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            provenance=Provenance.from_dict(value["provenance"]),
            integrity_hash=value["integrity_hash"],
        )

    @property
    def digest(self) -> str:
        """Canonical digest of the sealed content."""
        return canonical_sha256(self._content())

    def is_fresh_at(self, as_of: str) -> bool:
        """Half-open freshness window ``[valid_from, valid_until)``."""
        require_utc_timestamp("model output freshness instant", as_of)
        return utc_timestamp_within(as_of, self.valid_from, self.valid_until)

    def verify(self) -> None:
        """Recompute and verify the domain seal (trusted path)."""
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"integrity_hash is required for trusted deserialization of {self.output_id}"
            )
        expected = canonical_sha256(self._content())
        if self.integrity_hash != expected:
            raise CoreValidationError(
                f"integrity hash mismatch for model output {self.output_id}"
            )
