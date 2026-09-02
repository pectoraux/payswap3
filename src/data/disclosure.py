"""Disclosure: privacy assessment, data minimization and typed reveals.

The disclosure lifecycle implements the frozen privacy mechanism
(``security-risk.md`` "Privacy is both policy and mechanism: data
minimization, selective disclosure ... where legal requirements permit"):

* a :class:`DisclosureRequest` asks for a typed subset of a subject's
  fields for one closed-vocabulary purpose;
* :func:`evaluate_disclosure_request` evaluates the request against the
  DECLARED policy at an explicit ``as_of`` instant and records a sealed
  :class:`PrivacyAssessment` (canonical object model "Safety and
  knowledge" family) with a closed verdict and the exact permitted /
  denied field split — unclassified fields fail closed, ungranted
  purposes are denied, inactive policies fail closed;
* :func:`disclose` performs the data-minimization reveal: only
  policy-permitted fields may ever be carried in a ``DISCLOSED``
  disclosure record (the leakage gate is enforced structurally — a
  record containing a non-permitted value cannot even be constructed);
* :func:`reject_disclosure` records an explicit rejection path.

Provenance is preserved on every material step (constitution invariant
13): disclosure transitions require provenance evidence references.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import validate_canonical_value
from src.trust import TrustRegistry

from .contracts import (
    DISCLOSURE_OBJECT_TYPE,
    PRIVACY_ASSESSMENT_OBJECT_TYPE,
    PRINCIPAL_PREFIX,
    AssessmentVerdict,
    DisclosurePurpose,
    DisclosureState,
    PolicyState,
)
from .policy import DataPolicy, require_active_policy
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_pair_items,
    require_pairs,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
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


class AssessmentState(StrEnum):
    """Closed lifecycle of a privacy assessment (single recorded state)."""

    RECORDED = "RECORDED"


def require_active_principal(principal_id: str, registry: TrustRegistry) -> Any:
    """Fail closed unless the principal is a registered ACTIVE trust principal.

    Consumes the trust domain (WORK-004) as the owning authority for
    principals: the data domain never decides who may request
    disclosures or act in recourse — it references the trust registry
    and fails closed on unknown, suspended or retired principals.
    """
    require_identifier("principal", principal_id, prefix=PRINCIPAL_PREFIX)
    if not isinstance(registry, TrustRegistry):
        raise CoreValidationError("principal validation requires a TrustRegistry")
    principal = registry.principal(principal_id)
    if principal.state != "ACTIVE":
        raise CoreValidationError(
            f"principal {principal_id} is not ACTIVE (state {principal.state})"
        )
    return principal


@dataclass(frozen=True, slots=True)
class DisclosureRequest:
    """Typed request for a subset of a subject's fields for one purpose."""

    requester: str
    subject_ref: str
    purpose: Any
    requested_fields: tuple[str, ...]
    requested_at: str
    justification_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("request.requester", self.requester, prefix=PRINCIPAL_PREFIX)
        require_identifier("request.subject_ref", self.subject_ref)
        object.__setattr__(
            self, "purpose", parse_enum("request.purpose", DisclosurePurpose, self.purpose)
        )
        if not isinstance(self.requested_fields, tuple) or not self.requested_fields:
            raise CoreValidationError("request.requested_fields must be a non-empty tuple")
        fields = list(self.requested_fields)
        for field_name in fields:
            require_text("request.requested_field", field_name)
        if len(set(fields)) != len(fields):
            raise CoreValidationError("request.requested_fields must be unique")
        require_utc_timestamp("request.requested_at", self.requested_at)
        if not isinstance(self.justification_refs, tuple):
            raise CoreValidationError("request.justification_refs must be a tuple")
        for ref in self.justification_refs:
            require_identifier("request.justification_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requester": self.requester,
            "subject_ref": self.subject_ref,
            "purpose": self.purpose.value,
            "requested_fields": list(self.requested_fields),
            "requested_at": self.requested_at,
            "justification_refs": list(self.justification_refs),
        }

    @classmethod
    def from_dict(cls, value: object) -> "DisclosureRequest":
        strict_fields(
            "disclosure request",
            value,
            {
                "requester",
                "subject_ref",
                "purpose",
                "requested_fields",
                "requested_at",
                "justification_refs",
            },
        )
        return cls(
            requester=value["requester"],
            subject_ref=value["subject_ref"],
            purpose=value["purpose"],
            requested_fields=tuple(value["requested_fields"]),
            requested_at=value["requested_at"],
            justification_refs=tuple(value["justification_refs"]),
        )


@dataclass(frozen=True, slots=True)
class AssessmentSpec:
    """Immutable privacy-assessment payload: the recorded evaluation."""

    assessment_id: str
    request: DisclosureRequest
    policy_id: str
    policy_version: int
    as_of: str
    verdict: Any
    permitted_fields: tuple[str, ...]
    denied_fields: tuple[str, ...]
    evaluated_by: str

    def __post_init__(self) -> None:
        require_identifier("assessment.assessment_id", self.assessment_id)
        if not isinstance(self.request, DisclosureRequest):
            raise CoreValidationError("assessment.request must be a DisclosureRequest")
        require_identifier("assessment.policy_id", self.policy_id)
        if not isinstance(self.policy_version, int) or isinstance(self.policy_version, bool):
            raise CoreValidationError("assessment.policy_version must be an integer")
        require_utc_timestamp("assessment.as_of", self.as_of)
        object.__setattr__(
            self, "verdict", parse_enum("assessment.verdict", AssessmentVerdict, self.verdict)
        )
        for name in ("permitted_fields", "denied_fields"):
            fields = getattr(self, name)
            if not isinstance(fields, tuple):
                raise CoreValidationError(f"assessment.{name} must be a tuple")
            for field_name in fields:
                require_text(f"assessment.{name} entry", field_name)
        require_identifier("assessment.evaluated_by", self.evaluated_by, prefix=PRINCIPAL_PREFIX)
        combined = tuple(sorted(self.permitted_fields + self.denied_fields))
        if combined != tuple(sorted(self.request.requested_fields)):
            raise CoreValidationError(
                "assessment field split must partition the requested fields exactly"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "request": self.request.to_dict(),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "as_of": self.as_of,
            "verdict": self.verdict.value,
            "permitted_fields": list(self.permitted_fields),
            "denied_fields": list(self.denied_fields),
            "evaluated_by": self.evaluated_by,
        }

    @classmethod
    def from_dict(cls, value: object) -> "AssessmentSpec":
        strict_fields(
            "assessment",
            value,
            {
                "assessment_id",
                "request",
                "policy_id",
                "policy_version",
                "as_of",
                "verdict",
                "permitted_fields",
                "denied_fields",
                "evaluated_by",
            },
        )
        return cls(
            assessment_id=value["assessment_id"],
            request=DisclosureRequest.from_dict(value["request"]),
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            as_of=value["as_of"],
            verdict=value["verdict"],
            permitted_fields=tuple(value["permitted_fields"]),
            denied_fields=tuple(value["denied_fields"]),
            evaluated_by=value["evaluated_by"],
        )


@dataclass(frozen=True, slots=True)
class PrivacyAssessment:
    """Immutable durable privacy-assessment record (envelope + spec + seal)."""

    envelope: ObjectEnvelope
    spec: AssessmentSpec
    integrity_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.spec, AssessmentSpec):
            raise CoreValidationError("privacy assessment payload must be an AssessmentSpec")
        decode_composite(
            composite_to_dict(self.envelope, self.spec, self.integrity_hash),
            expected_object_type=PRIVACY_ASSESSMENT_OBJECT_TYPE,
            state_type=AssessmentState,
        )
        if self.envelope.object_id != self.spec.assessment_id:
            raise CoreValidationError(
                "privacy assessment object id must equal the assessment identifier"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def assessment_id(self) -> str:
        return self.spec.assessment_id

    @property
    def verdict(self) -> AssessmentVerdict:
        return self.spec.verdict

    @property
    def permitted_fields(self) -> tuple[str, ...]:
        return self.spec.permitted_fields

    @property
    def denied_fields(self) -> tuple[str, ...]:
        return self.spec.denied_fields

    @property
    def policy_id(self) -> str:
        return self.spec.policy_id

    @property
    def policy_version(self) -> int:
        return self.spec.policy_version

    @property
    def as_of(self) -> str:
        return self.spec.as_of

    @property
    def requester(self) -> str:
        return self.spec.request.requester

    @property
    def request(self) -> DisclosureRequest:
        return self.spec.request

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "PrivacyAssessment":
        envelope, payload = decode_composite(
            value,
            expected_object_type=PRIVACY_ASSESSMENT_OBJECT_TYPE,
            state_type=AssessmentState,
        )
        return cls(
            envelope=envelope,
            spec=AssessmentSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )


def evaluate_disclosure_request(
    *,
    assessment_id: str,
    request: DisclosureRequest,
    policy: DataPolicy,
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> PrivacyAssessment:
    """Evaluate a request against the declared policy at an explicit instant.

    Fail-closed paths: the policy must be ACTIVE at ``as_of``; the
    evaluation instant must not precede the request; every requested
    field must be classified by the declared policy (unclassified data
    can never be disclosed). A purpose without a grant yields verdict
    ``DENIED`` for every requested field.
    """
    if not isinstance(request, DisclosureRequest):
        raise CoreValidationError("evaluate requires a DisclosureRequest")
    require_active_policy(policy, as_of)
    if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
        "request.requested_at", request.requested_at
    ):
        raise CoreValidationError(
            f"disclosure request cannot be evaluated at {as_of} before it was "
            f"requested at {request.requested_at}"
        )
    allowed = policy.spec.classes_for(request.purpose)
    permitted: list[str] = []
    denied: list[str] = []
    for field_name in request.requested_fields:
        data_class = policy.spec.data_class_for(field_name)  # fail closed on unknown field
        if data_class in allowed:
            permitted.append(field_name)
        else:
            denied.append(field_name)
    if permitted and denied:
        verdict = AssessmentVerdict.PARTIALLY_PERMITTED
    elif permitted:
        verdict = AssessmentVerdict.PERMITTED
    else:
        verdict = AssessmentVerdict.DENIED
    spec = AssessmentSpec(
        assessment_id=assessment_id,
        request=request,
        policy_id=policy.policy_id,
        policy_version=policy.envelope.object_version,
        as_of=as_of,
        verdict=verdict,
        permitted_fields=tuple(permitted),
        denied_fields=tuple(denied),
        evaluated_by=provenance.issuer,
    )
    envelope = build_domain_envelope(
        object_id=assessment_id,
        object_type=PRIVACY_ASSESSMENT_OBJECT_TYPE,
        state=AssessmentState.RECORDED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return PrivacyAssessment(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


_DISCLOSURE_PAYLOAD_FIELDS = frozenset(
    {
        "disclosure_id",
        "requester",
        "subject_ref",
        "purpose",
        "requested_fields",
        "requested_at",
        "justification_refs",
        "as_of",
        "policy_id",
        "policy_version",
        "assessment_id",
        "disclosed_values",
        "denied_fields",
        "selective_proof_id",
        "rejection_verdict",
        "rejection_note",
        "rejected_at",
    }
)


@dataclass(frozen=True, slots=True)
class DisclosurePayload:
    """Immutable disclosure payload across the REQUESTED/DISCLOSED/REJECTED lifecycle."""

    disclosure_id: str
    requester: str
    subject_ref: str
    purpose: Any
    requested_fields: tuple[str, ...]
    requested_at: str
    justification_refs: tuple[str, ...]
    as_of: str | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    assessment_id: str | None = None
    disclosed_values: tuple[tuple[str, Any], ...] = ()
    denied_fields: tuple[str, ...] = ()
    selective_proof_id: str | None = None
    rejection_verdict: str | None = None
    rejection_note: str | None = None
    rejected_at: str | None = None

    def __post_init__(self) -> None:
        require_identifier("disclosure.disclosure_id", self.disclosure_id)
        require_identifier("disclosure.requester", self.requester, prefix=PRINCIPAL_PREFIX)
        require_identifier("disclosure.subject_ref", self.subject_ref)
        object.__setattr__(
            self, "purpose", parse_enum("disclosure.purpose", DisclosurePurpose, self.purpose)
        )
        if not isinstance(self.requested_fields, tuple) or not self.requested_fields:
            raise CoreValidationError("disclosure.requested_fields must be a non-empty tuple")
        if len(set(self.requested_fields)) != len(self.requested_fields):
            raise CoreValidationError("disclosure.requested_fields must be unique")
        require_utc_timestamp("disclosure.requested_at", self.requested_at)
        if not isinstance(self.justification_refs, tuple):
            raise CoreValidationError("disclosure.justification_refs must be a tuple")
        for ref in self.justification_refs:
            require_identifier("disclosure.justification_ref", ref)
        for name, value in (
            ("as_of", self.as_of),
            ("rejected_at", self.rejected_at),
        ):
            if value is not None:
                require_utc_timestamp(f"disclosure.{name}", value)
        if self.policy_id is not None:
            require_identifier("disclosure.policy_id", self.policy_id)
        if self.policy_version is not None and (
            not isinstance(self.policy_version, int) or isinstance(self.policy_version, bool)
        ):
            raise CoreValidationError("disclosure.policy_version must be an integer")
        if self.assessment_id is not None:
            require_identifier("disclosure.assessment_id", self.assessment_id)
        if self.selective_proof_id is not None:
            require_identifier("disclosure.selective_proof_id", self.selective_proof_id)
        for name, value in (
            ("denied_fields", self.denied_fields),
        ):
            if not isinstance(value, tuple):
                raise CoreValidationError(f"disclosure.{name} must be a tuple")
        if not isinstance(self.disclosed_values, tuple):
            raise CoreValidationError("disclosure.disclosed_values must be a tuple")
        for pair in self.disclosed_values:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise CoreValidationError("disclosure.disclosed_values entries must be pairs")
            key, value = pair
            require_text("disclosure.disclosed_value field", key)
            validate_canonical_value(f"disclosure.disclosed_values.{key}", value)
        if self.rejection_verdict is not None:
            parse_enum("disclosure.rejection_verdict", AssessmentVerdict, self.rejection_verdict)
        if self.rejection_note is not None:
            require_text("disclosure.rejection_note", self.rejection_note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "disclosure_id": self.disclosure_id,
            "requester": self.requester,
            "subject_ref": self.subject_ref,
            "purpose": self.purpose.value,
            "requested_fields": list(self.requested_fields),
            "requested_at": self.requested_at,
            "justification_refs": list(self.justification_refs),
            "as_of": self.as_of,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "assessment_id": self.assessment_id,
            "disclosed_values": [[key, value] for key, value in self.disclosed_values],
            "denied_fields": list(self.denied_fields),
            "selective_proof_id": self.selective_proof_id,
            "rejection_verdict": (
                self.rejection_verdict.value
                if isinstance(self.rejection_verdict, AssessmentVerdict)
                else self.rejection_verdict
            ),
            "rejection_note": self.rejection_note,
            "rejected_at": self.rejected_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> "DisclosurePayload":
        strict_fields("disclosure", value, _DISCLOSURE_PAYLOAD_FIELDS)
        return cls(
            disclosure_id=value["disclosure_id"],
            requester=value["requester"],
            subject_ref=value["subject_ref"],
            purpose=value["purpose"],
            requested_fields=tuple(value["requested_fields"]),
            requested_at=value["requested_at"],
            justification_refs=tuple(value["justification_refs"]),
            as_of=value["as_of"],
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            assessment_id=value["assessment_id"],
            disclosed_values=tuple(
                (pair[0], pair[1])
                for pair in require_pair_items(
                    "disclosure.disclosed_values", value["disclosed_values"]
                )
            ),
            denied_fields=tuple(value["denied_fields"]),
            selective_proof_id=value["selective_proof_id"],
            rejection_verdict=value["rejection_verdict"],
            rejection_note=value["rejection_note"],
            rejected_at=value["rejected_at"],
        )


def _validate_payload_state(envelope: ObjectEnvelope, payload: DisclosurePayload) -> None:
    state = DisclosureState(envelope.state)
    if state is DisclosureState.REQUESTED:
        for name in (
            "as_of",
            "policy_id",
            "policy_version",
            "assessment_id",
            "selective_proof_id",
            "rejection_verdict",
            "rejection_note",
            "rejected_at",
        ):
            if getattr(payload, name) is not None:
                raise CoreValidationError(
                    f"disclosure.requested must not carry {name}"
                )
        if payload.disclosed_values or payload.denied_fields:
            raise CoreValidationError(
                "a REQUESTED disclosure carries no disclosed or denied fields"
            )
    elif state is DisclosureState.DISCLOSED:
        for name in ("as_of", "policy_id", "policy_version", "assessment_id"):
            if getattr(payload, name) is None:
                raise CoreValidationError(f"disclosure.disclosed requires {name}")
        if not payload.disclosed_values:
            raise CoreValidationError("a DISCLOSED disclosure must reveal at least one field")
        if payload.rejection_verdict is not None or payload.rejected_at is not None:
            raise CoreValidationError("a DISCLOSED disclosure carries no rejection fields")
        if not envelope.provenance.evidence_refs:
            raise CoreValidationError(
                "a DISCLOSED disclosure must preserve provenance evidence references"
            )
    else:
        for name in ("as_of", "policy_id", "policy_version", "assessment_id"):
            if getattr(payload, name) is None:
                raise CoreValidationError(f"disclosure.rejected requires {name}")
        if payload.rejection_verdict is None or payload.rejected_at is None:
            raise CoreValidationError(
                "a REJECTED disclosure must record the verdict and the rejection instant"
            )
        if payload.disclosed_values:
            raise CoreValidationError("a REJECTED disclosure reveals no values")


@dataclass(frozen=True, slots=True)
class DisclosureRecord:
    """Immutable durable disclosure record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: DisclosurePayload
    integrity_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.payload, DisclosurePayload):
            raise CoreValidationError("disclosure payload must be a DisclosurePayload")
        decode_composite(
            composite_to_dict(self.envelope, self.payload, self.integrity_hash),
            expected_object_type=DISCLOSURE_OBJECT_TYPE,
            state_type=DisclosureState,
        )
        if self.envelope.object_id != self.payload.disclosure_id:
            raise CoreValidationError(
                "disclosure object id must equal the disclosure identifier"
            )
        _validate_payload_state(self.envelope, self.payload)
        verify_composite(
            self.envelope, self.payload, self.integrity_hash, self.envelope.object_id
        )

    @property
    def disclosure_id(self) -> str:
        return self.payload.disclosure_id

    @property
    def state(self) -> DisclosureState:
        return DisclosureState(self.envelope.state)

    @property
    def requester(self) -> str:
        return self.payload.requester

    @property
    def requested_fields(self) -> tuple[str, ...]:
        return self.payload.requested_fields

    @property
    def purpose(self) -> DisclosurePurpose:
        return self.payload.purpose

    @property
    def disclosed_values(self) -> tuple[tuple[str, Any], ...]:
        return self.payload.disclosed_values

    @property
    def denied_fields(self) -> tuple[str, ...]:
        return self.payload.denied_fields

    @property
    def policy_id(self) -> str | None:
        return self.payload.policy_id

    @property
    def policy_version(self) -> int | None:
        return self.payload.policy_version

    @property
    def assessment_id(self) -> str | None:
        return self.payload.assessment_id

    @property
    def rejection_verdict(self) -> AssessmentVerdict | None:
        if self.payload.rejection_verdict is None:
            return None
        return AssessmentVerdict(self.payload.rejection_verdict)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "DisclosureRecord":
        envelope, payload = decode_composite(
            value, expected_object_type=DISCLOSURE_OBJECT_TYPE, state_type=DisclosureState
        )
        return cls(
            envelope=envelope,
            payload=DisclosurePayload.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "DisclosureRecord":
        decoded = decode_composite_json(
            value, expected_object_type=DISCLOSURE_OBJECT_TYPE, state_type=DisclosureState
        )
        return cls.from_dict(
            {"envelope": decoded[0].to_dict(), "payload": decoded[1], "integrity_hash": decoded[2]}
        )

    def _request_view(self) -> DisclosureRequest:
        return DisclosureRequest(
            requester=self.payload.requester,
            subject_ref=self.payload.subject_ref,
            purpose=self.payload.purpose,
            requested_fields=self.payload.requested_fields,
            requested_at=self.payload.requested_at,
            justification_refs=self.payload.justification_refs,
        )


def request_disclosure(
    *,
    disclosure_id: str,
    request: DisclosureRequest,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> DisclosureRecord:
    """Record a typed disclosure request as sealed version 1 REQUESTED."""
    if not isinstance(request, DisclosureRequest):
        raise CoreValidationError("request_disclosure requires a DisclosureRequest")
    payload = DisclosurePayload(
        disclosure_id=disclosure_id,
        requester=request.requester,
        subject_ref=request.subject_ref,
        purpose=request.purpose,
        requested_fields=request.requested_fields,
        requested_at=request.requested_at,
        justification_refs=request.justification_refs,
    )
    envelope = build_domain_envelope(
        object_id=disclosure_id,
        object_type=DISCLOSURE_OBJECT_TYPE,
        state=DisclosureState.REQUESTED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return DisclosureRecord(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )


def _require_same_request(record: DisclosureRecord, assessment: PrivacyAssessment) -> None:
    if record._request_view() != assessment.request:
        raise CoreValidationError(
            "the privacy assessment must evaluate exactly this disclosure request"
        )


def disclose(
    record: DisclosureRecord,
    *,
    assessment: PrivacyAssessment,
    disclosed_values: Mapping[str, Any],
    as_of: str,
    provenance: Provenance,
    selective_proof_id: str | None = None,
) -> DisclosureRecord:
    """Perform the data-minimization reveal (REQUESTED -> DISCLOSED).

    Fail-closed paths: the record must be REQUESTED; the assessment must
    evaluate exactly this request; the disclosure instant must not
    precede the assessment; every disclosed key must be policy-permitted
    per the assessment (the leakage gate — a forbidden field value can
    never enter a durable disclosure record); values must be canonical
    protocol values; provenance must carry evidence references.
    """
    if record.state is not DisclosureState.REQUESTED:
        raise CoreValidationError(
            f"disclosure {record.disclosure_id} cannot be disclosed from state "
            f"{record.state.value}"
        )
    if not isinstance(assessment, PrivacyAssessment):
        raise CoreValidationError("disclose requires a PrivacyAssessment")
    _require_same_request(record, assessment)
    require_utc_timestamp("as_of", as_of)
    if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
        "assessment.as_of", assessment.as_of
    ):
        raise CoreValidationError(
            f"disclosure cannot happen at {as_of} before its assessment at {assessment.as_of}"
        )
    if not provenance.evidence_refs:
        raise CoreValidationError(
            "disclosing a record is a material decision and must preserve provenance "
            "evidence references"
        )
    if not isinstance(disclosed_values, Mapping):
        raise CoreValidationError("disclosed_values must be a mapping")
    permitted = set(assessment.permitted_fields)
    for key in disclosed_values:
        if key not in permitted:
            raise CoreValidationError(
                f"field {key!r} is not permitted by the privacy assessment; forbidden "
                "fields can never be disclosed"
            )
    if not disclosed_values:
        raise CoreValidationError(
            "a DISCLOSED record must reveal at least one permitted field"
        )
    payload = DisclosurePayload(
        disclosure_id=record.payload.disclosure_id,
        requester=record.payload.requester,
        subject_ref=record.payload.subject_ref,
        purpose=record.payload.purpose,
        requested_fields=record.payload.requested_fields,
        requested_at=record.payload.requested_at,
        justification_refs=record.payload.justification_refs,
        as_of=as_of,
        policy_id=assessment.policy_id,
        policy_version=assessment.policy_version,
        assessment_id=assessment.assessment_id,
        disclosed_values=require_pairs(
            "disclosure.disclosed_values", disclosed_values, key_name="field"
        ),
        denied_fields=assessment.denied_fields,
        selective_proof_id=selective_proof_id,
    )
    envelope = advance_envelope(
        record.envelope, state=DisclosureState.DISCLOSED.value, provenance=provenance
    )
    return DisclosureRecord(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )


def reject_disclosure(
    record: DisclosureRecord,
    *,
    assessment: PrivacyAssessment,
    as_of: str,
    provenance: Provenance,
    note: str | None = None,
) -> DisclosureRecord:
    """Record an explicit rejection (REQUESTED -> REJECTED)."""
    if record.state is not DisclosureState.REQUESTED:
        raise CoreValidationError(
            f"disclosure {record.disclosure_id} cannot be rejected from state "
            f"{record.state.value}"
        )
    if not isinstance(assessment, PrivacyAssessment):
        raise CoreValidationError("reject requires a PrivacyAssessment")
    _require_same_request(record, assessment)
    require_utc_timestamp("as_of", as_of)
    if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
        "assessment.as_of", assessment.as_of
    ):
        raise CoreValidationError(
            f"rejection cannot happen at {as_of} before the assessment at {assessment.as_of}"
        )
    payload = DisclosurePayload(
        disclosure_id=record.payload.disclosure_id,
        requester=record.payload.requester,
        subject_ref=record.payload.subject_ref,
        purpose=record.payload.purpose,
        requested_fields=record.payload.requested_fields,
        requested_at=record.payload.requested_at,
        justification_refs=record.payload.justification_refs,
        as_of=as_of,
        policy_id=assessment.policy_id,
        policy_version=assessment.policy_version,
        assessment_id=assessment.assessment_id,
        rejection_verdict=assessment.verdict.value,
        rejection_note=note,
        rejected_at=as_of,
    )
    envelope = advance_envelope(
        record.envelope, state=DisclosureState.REJECTED.value, provenance=provenance
    )
    return DisclosureRecord(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )
