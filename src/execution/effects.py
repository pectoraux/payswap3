"""External effect requests, results, receipts and observations (WORK-014).

The external-facing records of the execution domain:

* :class:`EffectRequest` — one typed, authorized, idempotent-keyed
  request for an external effect, bound to a step and an attempt and
  pinned to the covering effect authorization digest (the typed
  authorization contract owned by the merged simulation domain,
  ``src.simulation.effects.EffectAuthorization`` — consumed, never
  redefined: one authority per concept);
* :class:`EffectResult` — the rail's reported outcome for a request,
  sealed to the exact request content it resolves (``request_digest``
  integrity binding — a result may never be spliced onto a different
  request);
* :class:`Receipt` — the rail's durable acknowledgment artifact for an
  acknowledged submission (execution-domain receipt; settlement receipts
  belong to WORK-016);
* :class:`ExternalObservation` — recorded external evidence (query,
  status, finality claim). Observations record what the OUTSIDE WORLD
  reported through an adapter; they never clear, settle or finalize
  anything here (constitution invariant 11: PaySwap never overstates
  settlement finality).

The epistemic discipline is the frozen vocabulary owned by
``src.evidence``: external observations are ``OBSERVED`` knowledge and
anything else fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.evidence.contracts import EpistemicType
from src.interoperability.status import CanonicalPaymentStatus, coerce_payment_status
from src.transition.payload import normalize_payload, payload_to_json_value

from ._validation import (
    parse_enum,
    require_digest,
    require_effect_type,
    require_identifier,
    require_int,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    EFFECT_REQUEST_OBJECT_TYPE,
    EFFECT_RESULT_OBJECT_TYPE,
    EXECUTION_OBSERVATION_OBJECT_TYPE,
    EXECUTION_RECEIPT_OBJECT_TYPE,
    EffectOutcome,
    EffectRequestState,
    FinalityClaim,
    ObservationKind,
    QueryOutcome,
)
from .seal import (
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_REQUEST_SPEC_FIELDS = frozenset(
    {
        "request_id",
        "plan_id",
        "step_id",
        "attempt_number",
        "effect_type",
        "adapter_id",
        "idempotency_key",
        "payload",
        "requested_at",
        "authorization_digest",
    }
)
_RESULT_SPEC_FIELDS = frozenset(
    {
        "result_id",
        "request_id",
        "step_id",
        "effect_type",
        "outcome",
        "native_reference",
        "error_code",
        "observed_at",
        "request_digest",
        "detail",
    }
)
_RECEIPT_SPEC_FIELDS = frozenset(
    {
        "receipt_id",
        "request_id",
        "step_id",
        "adapter_id",
        "native_reference",
        "acknowledged_at",
        "request_digest",
    }
)
_OBSERVATION_SPEC_FIELDS = frozenset(
    {
        "observation_id",
        "kind",
        "subject_ref",
        "adapter_id",
        "epistemic",
        "observed_at",
        "content",
        "subject_request_digest",
    }
)
_QUERY_CONTENT_FIELDS = frozenset({"outcome", "native_reference"})
_STATUS_CONTENT_FIELDS = frozenset({"native_code", "canonical_status"})
_FINALITY_CONTENT_FIELDS = frozenset({"claim", "native_reference"})


class _EffectResultState(StrEnum):
    """Closed single-member state vocabulary of a recorded effect result."""

    RECORDED = "RECORDED"


class _ReceiptState(StrEnum):
    """Closed single-member state vocabulary of an issued receipt."""

    ISSUED = "ISSUED"


class _ObservationState(StrEnum):
    """Closed single-member state vocabulary of a recorded observation."""

    RECORDED = "RECORDED"


@dataclass(frozen=True, slots=True)
class EffectRequestSpec:
    """Canonical payload of one external effect request.

    The ``idempotency_key`` is the rail-side idempotency contract: the
    adapter MUST deduplicate submissions on it and the domain-side
    ledger detects duplicates before any second port call (constitution
    invariant 9 — idempotent external effects).
    """

    request_id: str
    plan_id: str
    step_id: str
    attempt_number: int
    effect_type: str
    adapter_id: str
    idempotency_key: str
    payload: Any
    requested_at: str
    authorization_digest: str

    def __post_init__(self) -> None:
        require_identifier("request spec request_id", self.request_id)
        require_identifier("request spec plan_id", self.plan_id)
        require_identifier("request spec step_id", self.step_id)
        if not self.request_id.startswith(f"{self.step_id}/request/"):
            raise CoreValidationError(
                "request id must live under the step id: <step_id>/request/<n>"
            )
        require_int("request spec attempt_number", self.attempt_number, minimum=1)
        require_effect_type("request spec effect_type", self.effect_type)
        require_identifier("request spec adapter_id", self.adapter_id)
        require_text("request spec idempotency_key", self.idempotency_key)
        require_utc_timestamp("request spec requested_at", self.requested_at)
        require_digest("request spec authorization_digest", self.authorization_digest)
        object.__setattr__(self, "payload", normalize_payload("request spec payload", self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
            "attempt_number": self.attempt_number,
            "effect_type": self.effect_type,
            "adapter_id": self.adapter_id,
            "idempotency_key": self.idempotency_key,
            "payload": payload_to_json_value(self.payload),
            "requested_at": self.requested_at,
            "authorization_digest": self.authorization_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectRequestSpec":
        strict_fields("request spec", value, _REQUEST_SPEC_FIELDS)
        return cls(
            request_id=value["request_id"],
            plan_id=value["plan_id"],
            step_id=value["step_id"],
            attempt_number=value["attempt_number"],
            effect_type=value["effect_type"],
            adapter_id=value["adapter_id"],
            idempotency_key=value["idempotency_key"],
            payload=value["payload"],
            requested_at=value["requested_at"],
            authorization_digest=value["authorization_digest"],
        )

    @property
    def digest(self) -> str:
        """Canonical digest over the full request content."""
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class EffectRequest:
    """Durable external effect request record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: EffectRequestSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EFFECT_REQUEST_OBJECT_TYPE
    STATE_TYPE = EffectRequestState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("request envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, EffectRequestSpec):
            raise CoreValidationError("request spec must be an EffectRequestSpec")
        if self.envelope.object_type != EFFECT_REQUEST_OBJECT_TYPE:
            raise CoreValidationError(
                f"request object_type must be {EFFECT_REQUEST_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.request_id:
            raise CoreValidationError("request object_id must equal spec request_id")
        try:
            EffectRequestState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown effect request state: {self.envelope.state!r}"
            ) from exc
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> EffectRequestState:
        return EffectRequestState(self.envelope.state)

    @property
    def digest(self) -> str:
        return self.spec.digest

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectRequest":
        envelope, payload = decode_composite(
            value, object_type=EFFECT_REQUEST_OBJECT_TYPE, state_type=EffectRequestState
        )
        spec = EffectRequestSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "EffectRequest":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EFFECT_REQUEST_OBJECT_TYPE, state_type=EffectRequestState
        )
        spec = EffectRequestSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


@dataclass(frozen=True, slots=True)
class EffectResultSpec:
    """Canonical payload of one rail-reported effect result.

    ``request_digest`` binds the result to the EXACT request content it
    resolves — a result may never be spliced onto another request or a
    mutated request (fail closed on mismatch).
    """

    result_id: str
    request_id: str
    step_id: str
    effect_type: str
    outcome: EffectOutcome
    native_reference: str | None
    error_code: str | None
    observed_at: str
    request_digest: str
    detail: Any

    def __post_init__(self) -> None:
        require_identifier("result spec result_id", self.result_id)
        require_identifier("result spec request_id", self.request_id)
        require_identifier("result spec step_id", self.step_id)
        if not self.result_id.startswith(f"{self.request_id}/result"):
            raise CoreValidationError(
                "result id must live under the request id: <request_id>/result"
            )
        require_effect_type("result spec effect_type", self.effect_type)
        if not isinstance(self.outcome, EffectOutcome):
            raise CoreValidationError("result spec outcome must be an EffectOutcome")
        if self.native_reference is not None:
            require_text("result spec native_reference", self.native_reference)
        if self.native_reference is None and self.outcome is not EffectOutcome.UNKNOWN:
            raise CoreValidationError(
                "a definitive effect result must carry the rail's native reference"
            )
        if self.error_code is not None:
            require_text("result spec error_code", self.error_code)
        require_utc_timestamp("result spec observed_at", self.observed_at)
        require_digest("result spec request_digest", self.request_digest)
        object.__setattr__(self, "detail", normalize_payload("result spec detail", self.detail))

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "request_id": self.request_id,
            "step_id": self.step_id,
            "effect_type": self.effect_type,
            "outcome": self.outcome.value,
            "native_reference": self.native_reference,
            "error_code": self.error_code,
            "observed_at": self.observed_at,
            "request_digest": self.request_digest,
            "detail": payload_to_json_value(self.detail),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectResultSpec":
        strict_fields("result spec", value, _RESULT_SPEC_FIELDS)
        return cls(
            result_id=value["result_id"],
            request_id=value["request_id"],
            step_id=value["step_id"],
            effect_type=value["effect_type"],
            outcome=parse_enum("result spec outcome", value["outcome"], EffectOutcome),
            native_reference=value["native_reference"],
            error_code=value["error_code"],
            observed_at=value["observed_at"],
            request_digest=value["request_digest"],
            detail=value["detail"],
        )


@dataclass(frozen=True, slots=True)
class EffectResult:
    """Durable rail-reported effect result record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: EffectResultSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EFFECT_RESULT_OBJECT_TYPE
    STATE_TYPE = _EffectResultState

    RECORDED_STATE = _EffectResultState.RECORDED

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("result envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, EffectResultSpec):
            raise CoreValidationError("result spec must be an EffectResultSpec")
        if self.envelope.object_type != EFFECT_RESULT_OBJECT_TYPE:
            raise CoreValidationError(
                f"result object_type must be {EFFECT_RESULT_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.result_id:
            raise CoreValidationError("result object_id must equal spec result_id")
        if self.envelope.state != _EffectResultState.RECORDED.value:
            raise CoreValidationError(
                f"unknown effect result state: {self.envelope.state!r}"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> _EffectResultState:
        return _EffectResultState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectResult":
        envelope, payload = decode_composite(
            value, object_type=EFFECT_RESULT_OBJECT_TYPE, state_type=_EffectResultState
        )
        spec = EffectResultSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "EffectResult":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EFFECT_RESULT_OBJECT_TYPE, state_type=_EffectResultState
        )
        spec = EffectResultSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


@dataclass(frozen=True, slots=True)
class ReceiptSpec:
    """Canonical payload of one execution receipt.

    An execution receipt is the rail's acknowledgment artifact for an
    acknowledged submission. Settlement receipts are a different concept
    owned by WORK-016 (settlement/finality domain).
    """

    receipt_id: str
    request_id: str
    step_id: str
    adapter_id: str
    native_reference: str
    acknowledged_at: str
    request_digest: str

    def __post_init__(self) -> None:
        require_identifier("receipt spec receipt_id", self.receipt_id)
        require_identifier("receipt spec request_id", self.request_id)
        require_identifier("receipt spec step_id", self.step_id)
        if not self.receipt_id.startswith(f"{self.request_id}/receipt"):
            raise CoreValidationError(
                "receipt id must live under the request id: <request_id>/receipt"
            )
        require_identifier("receipt spec adapter_id", self.adapter_id)
        require_text("receipt spec native_reference", self.native_reference)
        require_utc_timestamp("receipt spec acknowledged_at", self.acknowledged_at)
        require_digest("receipt spec request_digest", self.request_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "step_id": self.step_id,
            "adapter_id": self.adapter_id,
            "native_reference": self.native_reference,
            "acknowledged_at": self.acknowledged_at,
            "request_digest": self.request_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReceiptSpec":
        strict_fields("receipt spec", value, _RECEIPT_SPEC_FIELDS)
        return cls(
            receipt_id=value["receipt_id"],
            request_id=value["request_id"],
            step_id=value["step_id"],
            adapter_id=value["adapter_id"],
            native_reference=value["native_reference"],
            acknowledged_at=value["acknowledged_at"],
            request_digest=value["request_digest"],
        )


@dataclass(frozen=True, slots=True)
class Receipt:
    """Durable execution receipt record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ReceiptSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EXECUTION_RECEIPT_OBJECT_TYPE
    STATE_TYPE = _ReceiptState

    ISSUED_STATE = _ReceiptState.ISSUED

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("receipt envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ReceiptSpec):
            raise CoreValidationError("receipt spec must be a ReceiptSpec")
        if self.envelope.object_type != EXECUTION_RECEIPT_OBJECT_TYPE:
            raise CoreValidationError(
                f"receipt object_type must be {EXECUTION_RECEIPT_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.receipt_id:
            raise CoreValidationError("receipt object_id must equal spec receipt_id")
        if self.envelope.state != _ReceiptState.ISSUED.value:
            raise CoreValidationError(
                f"unknown receipt state: {self.envelope.state!r}"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> _ReceiptState:
        return _ReceiptState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Receipt":
        envelope, payload = decode_composite(
            value, object_type=EXECUTION_RECEIPT_OBJECT_TYPE, state_type=_ReceiptState
        )
        spec = ReceiptSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Receipt":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EXECUTION_RECEIPT_OBJECT_TYPE, state_type=_ReceiptState
        )
        spec = ReceiptSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


@dataclass(frozen=True, slots=True)
class ExternalObservationSpec:
    """Canonical payload of one recorded external observation.

    ``content`` is typed by ``kind``:

    * ``QUERY`` — ``{"outcome": QueryOutcome, "native_reference"}``:
      reconciliation-query evidence (the recovery-discipline driver);
    * ``STATUS`` — ``{"native_code": str, "canonical_status": str}``: a
      canonical payment status observation mapped through the adapter's
      declared status map (vocabulary owned by the interoperability
      domain);
    * ``FINALITY`` — ``{"claim": FinalityClaim, "native_reference"}``:
      an externally claimed finality state — evidence for the settlement
      domain, never authority here.

    ``epistemic`` is always the frozen ``OBSERVED`` vocabulary value
    owned by ``src.evidence``: an external observation is observed
    knowledge, and anything else fails closed.
    """

    observation_id: str
    kind: ObservationKind
    subject_ref: str
    adapter_id: str
    epistemic: EpistemicType
    observed_at: str
    content: Any
    subject_request_digest: str

    def __post_init__(self) -> None:
        require_identifier("observation spec observation_id", self.observation_id)
        if not isinstance(self.kind, ObservationKind):
            raise CoreValidationError("observation spec kind must be an ObservationKind")
        require_identifier("observation spec subject_ref", self.subject_ref)
        require_identifier("observation spec adapter_id", self.adapter_id)
        if not isinstance(self.epistemic, EpistemicType):
            raise CoreValidationError(
                "observation spec epistemic must be an EpistemicType"
            )
        if self.epistemic is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                "external observations are OBSERVED knowledge; epistemic type "
                f"{self.epistemic.value} fails closed"
            )
        require_utc_timestamp("observation spec observed_at", self.observed_at)
        require_digest("observation spec subject_request_digest", self.subject_request_digest)
        content = require_mapping("observation spec content", self.content)
        if self.kind is ObservationKind.QUERY:
            strict_fields("observation content", content, _QUERY_CONTENT_FIELDS)
            outcome = parse_enum(
                "observation content outcome", content["outcome"], QueryOutcome
            )
            object.__setattr__(
                self,
                "content",
                {
                    "outcome": outcome.value,
                    "native_reference": content["native_reference"],
                },
            )
        elif self.kind is ObservationKind.STATUS:
            strict_fields("observation content", content, _STATUS_CONTENT_FIELDS)
            status = coerce_payment_status(content["canonical_status"])
            require_text("observation content native_code", content["native_code"])
            object.__setattr__(
                self,
                "content",
                {
                    "native_code": content["native_code"],
                    "canonical_status": status.value,
                },
            )
        else:
            strict_fields("observation content", content, _FINALITY_CONTENT_FIELDS)
            claim = parse_enum("observation content claim", content["claim"], FinalityClaim)
            require_text("observation content native_reference", content["native_reference"])
            object.__setattr__(
                self,
                "content",
                {
                    "claim": claim.value,
                    "native_reference": content["native_reference"],
                },
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "kind": self.kind.value,
            "subject_ref": self.subject_ref,
            "adapter_id": self.adapter_id,
            "epistemic": self.epistemic.value,
            "observed_at": self.observed_at,
            "content": self.content,
            "subject_request_digest": self.subject_request_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExternalObservationSpec":
        strict_fields("observation spec", value, _OBSERVATION_SPEC_FIELDS)
        kind = parse_enum("observation spec kind", value["kind"], ObservationKind)
        epistemic = parse_enum(
            "observation spec epistemic", value["epistemic"], EpistemicType
        )
        return cls(
            observation_id=value["observation_id"],
            kind=kind,
            subject_ref=value["subject_ref"],
            adapter_id=value["adapter_id"],
            epistemic=epistemic,
            observed_at=value["observed_at"],
            content=value["content"],
            subject_request_digest=value["subject_request_digest"],
        )

    @property
    def query_outcome(self) -> QueryOutcome:
        if self.kind is not ObservationKind.QUERY:
            raise CoreValidationError("query outcome applies to QUERY observations only")
        return QueryOutcome(self.content["outcome"])

    @property
    def canonical_status(self) -> CanonicalPaymentStatus:
        if self.kind is not ObservationKind.STATUS:
            raise CoreValidationError("canonical status applies to STATUS observations only")
        return CanonicalPaymentStatus(self.content["canonical_status"])

    @property
    def finality_claim(self) -> FinalityClaim:
        if self.kind is not ObservationKind.FINALITY:
            raise CoreValidationError("finality claim applies to FINALITY observations only")
        return FinalityClaim(self.content["claim"])


@dataclass(frozen=True, slots=True)
class ExternalObservation:
    """Durable external observation record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ExternalObservationSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EXECUTION_OBSERVATION_OBJECT_TYPE
    STATE_TYPE = _ObservationState

    RECORDED_STATE = _ObservationState.RECORDED

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("observation envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ExternalObservationSpec):
            raise CoreValidationError(
                "observation spec must be an ExternalObservationSpec"
            )
        if self.envelope.object_type != EXECUTION_OBSERVATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"observation object_type must be {EXECUTION_OBSERVATION_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.observation_id:
            raise CoreValidationError(
                "observation object_id must equal spec observation_id"
            )
        if self.envelope.state != _ObservationState.RECORDED.value:
            raise CoreValidationError(
                f"unknown observation state: {self.envelope.state!r}"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> _ObservationState:
        return _ObservationState(self.envelope.state)

    @property
    def query_outcome(self) -> QueryOutcome:
        return self.spec.query_outcome

    @property
    def canonical_status(self) -> CanonicalPaymentStatus:
        return self.spec.canonical_status

    @property
    def finality_claim(self) -> FinalityClaim:
        return self.spec.finality_claim

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExternalObservation":
        envelope, payload = decode_composite(
            value, object_type=EXECUTION_OBSERVATION_OBJECT_TYPE, state_type=_ObservationState
        )
        spec = ExternalObservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "ExternalObservation":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=EXECUTION_OBSERVATION_OBJECT_TYPE, state_type=_ObservationState
        )
        spec = ExternalObservationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def make_request_record(
    *,
    spec: EffectRequestSpec,
    state: EffectRequestState,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> EffectRequest:
    envelope = build_domain_envelope(
        object_id=spec.request_id,
        object_type=EFFECT_REQUEST_OBJECT_TYPE,
        state=state.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return EffectRequest(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def make_result_record(
    *,
    spec: EffectResultSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> EffectResult:
    envelope = build_domain_envelope(
        object_id=spec.result_id,
        object_type=EFFECT_RESULT_OBJECT_TYPE,
        state=_EffectResultState.RECORDED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return EffectResult(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def make_receipt_record(
    *,
    spec: ReceiptSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Receipt:
    envelope = build_domain_envelope(
        object_id=spec.receipt_id,
        object_type=EXECUTION_RECEIPT_OBJECT_TYPE,
        state=_ReceiptState.ISSUED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return Receipt(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def make_observation_record(
    *,
    spec: ExternalObservationSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ExternalObservation:
    envelope = build_domain_envelope(
        object_id=spec.observation_id,
        object_type=EXECUTION_OBSERVATION_OBJECT_TYPE,
        state=_ObservationState.RECORDED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return ExternalObservation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


__all__ = [
    "EffectRequest",
    "EffectRequestSpec",
    "EffectResult",
    "EffectResultSpec",
    "ExternalObservation",
    "ExternalObservationSpec",
    "Receipt",
    "ReceiptSpec",
    "make_request_record",
    "make_result_record",
    "make_receipt_record",
    "make_observation_record",
]
