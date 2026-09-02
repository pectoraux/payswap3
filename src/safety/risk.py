"""Risk assessments: typed, reproducible, evidence-backed risk evaluation.

A :class:`RiskAssessment` is a DERIVED immutable snapshot (ownership
lifecycle class DERIVED: risk scores never outrank their sources of
truth). It is produced by :func:`evaluate_risk`, a pure deterministic
function of the typed inputs, the pinned policy version and the explicit
``as_of`` instant: the same inputs + the same policy version + the same
``as_of`` always produce a byte-identical assessment.

Every input score carries its own explicit evidence references (opaque
identifiers owned by the evidence domain) and the creating provenance
must itself be evidence-backed — no oracle risk decisions out of thin
air.

The aggregate score is computed with exact integer arithmetic: the
weighted sum ``sum(score_i * weight_i)`` is compared against band
thresholds by exact cross-multiplication (``weighted >= threshold *
10000``), so banding is never distorted by rounding; the recorded
aggregate is the weighted sum divided by the weight total under the
caller's explicit rounding mode (the money domain's deterministic
rounding authority). The domain is a control plane: it emits typed
verdicts only and never touches ledgers, holds or postings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money.amount import Amount
from src.money.rounding import RoundingMode, round_ratio

from .contracts import (
    RISK_ASSESSMENT_OBJECT_TYPE,
    RISK_SCALE_MAX,
    RISK_SCALE_MIN,
    RISK_WEIGHT_TOTAL_BPS,
    RiskBand,
    RiskDimension,
)
from ._validation import (
    parse_enum,
    require_digest,
    require_identifier,
    require_int,
    require_provenance_evidence,
    require_utc_timestamp,
    strict_fields,
)
from .policy import SafetyPolicy, require_active_policy
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_RISK_SPEC_FIELDS = frozenset(
    {
        "subject_id",
        "scores",
        "aggregate_score",
        "band",
        "policy_id",
        "policy_version",
        "as_of",
        "inputs_digest",
        "exposure",
    }
)

_INPUT_FIELDS = frozenset({"dimension", "score", "evidence_refs"})


class RiskAssessmentState(StrEnum):
    """Closed lifecycle of a risk assessment (DERIVED, single terminal state)."""

    RECORDED = "RECORDED"


def _convert_dimension(item: Any) -> RiskDimension:
    if isinstance(item, RiskDimension):
        return item
    if isinstance(item, str):
        try:
            return RiskDimension(item)
        except ValueError as exc:
            raise CoreValidationError(f"unknown risk dimension {item!r}") from exc
    raise CoreValidationError(
        "risk inputs must use the closed RiskDimension vocabulary"
    )


@dataclass(frozen=True, slots=True)
class RiskInput:
    """One typed risk score with explicit scale bounds and evidence references."""

    dimension: RiskDimension
    score: int
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, RiskDimension):
            raise CoreValidationError(
                "risk input dimension must use the closed RiskDimension vocabulary"
            )
        require_int(
            "risk input score", self.score,
            minimum=RISK_SCALE_MIN, maximum=RISK_SCALE_MAX,
        )
        self._require_evidence_refs()

    def _require_evidence_refs(self) -> None:
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("risk input evidence_refs must be a tuple")
        if not self.evidence_refs:
            raise CoreValidationError(
                "risk input evidence_refs must not be empty; every score is "
                "evidence-backed"
            )
        for ref in self.evidence_refs:
            require_identifier("risk input evidence_ref", ref)

    @classmethod
    def build(
        cls,
        *,
        dimension: Any,
        score: int,
        evidence_refs: Iterable[str],
    ) -> "RiskInput":
        if not isinstance(evidence_refs, (list, tuple)):
            raise CoreValidationError("risk input evidence_refs must be a sequence")
        return cls(
            dimension=_convert_dimension(dimension),
            score=score,
            evidence_refs=tuple(evidence_refs),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "score": self.score,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RiskInput":
        strict_fields("risk input", value, _INPUT_FIELDS)
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError(
                "risk input evidence_refs must deserialize from an array"
            )
        return cls(
            dimension=_convert_dimension(value["dimension"]),
            score=value["score"],
            evidence_refs=tuple(refs),
        )


@dataclass(frozen=True, slots=True)
class RiskAssessmentSpec:
    """Immutable risk assessment payload."""

    subject_id: str
    scores: tuple[RiskInput, ...]
    aggregate_score: int
    band: RiskBand
    policy_id: str
    policy_version: int
    as_of: str
    inputs_digest: str
    exposure: Amount | None = None

    def __post_init__(self) -> None:
        require_identifier("risk assessment subject_id", self.subject_id)
        if not isinstance(self.scores, tuple) or not self.scores:
            raise CoreValidationError(
                "risk assessment scores must be a non-empty tuple of RiskInput"
            )
        for item in self.scores:
            if not isinstance(item, RiskInput):
                raise CoreValidationError(
                    "risk assessment scores must be RiskInput records"
                )
        dimensions = [item.dimension for item in self.scores]
        if len(set(dimensions)) != len(dimensions):
            raise CoreValidationError(
                "risk assessment scores must map each dimension at most once"
            )
        if dimensions != sorted(dimensions, key=lambda d: d.value):
            raise CoreValidationError(
                "risk assessment scores must be canonically ordered by dimension"
            )
        require_int(
            "risk assessment aggregate_score", self.aggregate_score,
            minimum=RISK_SCALE_MIN, maximum=RISK_SCALE_MAX,
        )
        if not isinstance(self.band, RiskBand):
            raise CoreValidationError(
                "risk assessment band must use the closed RiskBand vocabulary"
            )
        require_identifier("risk assessment policy_id", self.policy_id)
        require_int("risk assessment policy_version", self.policy_version, minimum=1)
        require_utc_timestamp("risk assessment as_of", self.as_of)
        require_digest("risk assessment inputs_digest", self.inputs_digest)
        if self.exposure is not None:
            if not isinstance(self.exposure, Amount):
                raise CoreValidationError(
                    "risk assessment exposure must be a money Amount"
                )
            if self.exposure.value < 0:
                raise CoreValidationError(
                    "risk assessment exposure must be a non-negative amount"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "scores": [score.to_dict() for score in self.scores],
            "aggregate_score": self.aggregate_score,
            "band": self.band.value,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "as_of": self.as_of,
            "inputs_digest": self.inputs_digest,
            "exposure": None if self.exposure is None else self.exposure.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RiskAssessmentSpec":
        strict_fields("risk assessment", value, _RISK_SPEC_FIELDS)
        scores = value["scores"]
        if not isinstance(scores, list):
            raise CoreValidationError(
                "risk assessment scores must deserialize from an array"
            )
        exposure = value["exposure"]
        return cls(
            subject_id=value["subject_id"],
            scores=tuple(RiskInput.from_dict(item) for item in scores),
            aggregate_score=value["aggregate_score"],
            band=parse_enum("risk assessment band", RiskBand, value["band"]),
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            as_of=value["as_of"],
            inputs_digest=value["inputs_digest"],
            exposure=None if exposure is None else Amount.from_dict(exposure),
        )


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Durable risk assessment record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: RiskAssessmentSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = RISK_ASSESSMENT_OBJECT_TYPE
    STATE_TYPE = RiskAssessmentState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("risk assessment envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, RiskAssessmentSpec):
            raise CoreValidationError("risk assessment spec must be a RiskAssessmentSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != RISK_ASSESSMENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"risk assessment object_type must be {RISK_ASSESSMENT_OBJECT_TYPE!r}"
            )
        try:
            RiskAssessmentState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown risk assessment state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> RiskAssessmentState:
        return RiskAssessmentState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RiskAssessment":
        envelope, payload = decode_composite(
            value,
            expected_object_type=RISK_ASSESSMENT_OBJECT_TYPE,
            state_type=RiskAssessmentState,
        )
        spec = RiskAssessmentSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "RiskAssessment":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=RISK_ASSESSMENT_OBJECT_TYPE,
            state_type=RiskAssessmentState,
        )
        spec = RiskAssessmentSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def evaluate_risk(
    *,
    assessment_id: str,
    subject_id: str,
    inputs: Iterable[RiskInput],
    policy: SafetyPolicy,
    as_of: str,
    rounding: RoundingMode,
    environment_id: str,
    domain_id: str,
    provenance,
    exposure: Amount | None = None,
    correlation_id: str | None = None,
) -> RiskAssessment:
    """Evaluate a risk assessment deterministically (system-trigger style).

    The evaluation is a pure function of ``(inputs, policy, as_of)``:
    inputs are canonicalized (sorted by dimension) so the assessment is
    order-independent, the policy must be ACTIVE (fail closed on retired
    policy), every input dimension must be covered by the policy weights,
    and the aggregate band is decided by exact integer cross-multiplication
    of the weighted sum against the band thresholds.
    """
    require_active_policy("risk evaluation", policy)
    require_provenance_evidence("risk evaluation", provenance)
    require_utc_timestamp("risk evaluation as_of", as_of)
    if not isinstance(rounding, RoundingMode):
        raise CoreValidationError(
            "risk evaluation requires an explicit rounding mode from the "
            "closed RoundingMode vocabulary"
        )
    if not isinstance(inputs, (list, tuple)):
        raise CoreValidationError("risk inputs must be provided as a sequence")
    if not inputs:
        raise CoreValidationError("risk evaluation requires at least one input score")
    for item in inputs:
        if not isinstance(item, RiskInput):
            raise CoreValidationError("risk inputs must be RiskInput records")
    scores = tuple(sorted(inputs, key=lambda item: item.dimension.value))
    dimensions = [item.dimension for item in scores]
    if len(set(dimensions)) != len(dimensions):
        raise CoreValidationError(
            "risk evaluation rejects duplicate dimensions in its inputs"
        )
    spec = policy.spec
    weighted_sum = 0
    for item in scores:
        weighted_sum += item.score * spec.risk_weight(item.dimension)
    # Exact cross-multiplication: band thresholds apply to the weighted sum
    # scaled by the weight total, never to the rounded aggregate.
    medium, high, critical = spec.band_thresholds
    if weighted_sum >= critical * RISK_WEIGHT_TOTAL_BPS:
        band = RiskBand.CRITICAL
    elif weighted_sum >= high * RISK_WEIGHT_TOTAL_BPS:
        band = RiskBand.HIGH
    elif weighted_sum >= medium * RISK_WEIGHT_TOTAL_BPS:
        band = RiskBand.MEDIUM
    else:
        band = RiskBand.LOW
    aggregate_score = round_ratio(weighted_sum, RISK_WEIGHT_TOTAL_BPS, rounding)
    inputs_digest = canonical_sha256(
        {
            "inputs": [item.to_dict() for item in scores],
            "policy_id": policy.object_id,
            "policy_version": policy.policy_version,
            "as_of": as_of,
        }
    )
    payload = RiskAssessmentSpec(
        subject_id=subject_id,
        scores=scores,
        aggregate_score=aggregate_score,
        band=band,
        policy_id=policy.object_id,
        policy_version=policy.policy_version,
        as_of=as_of,
        inputs_digest=inputs_digest,
        exposure=exposure,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("risk assessment assessment_id", assessment_id),
        object_type=RISK_ASSESSMENT_OBJECT_TYPE,
        state=RiskAssessmentState.RECORDED.value,
        environment_id=require_identifier("risk assessment environment_id", environment_id),
        domain_id=require_identifier("risk assessment domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return RiskAssessment(
        envelope=envelope, spec=payload,
        integrity_hash=seal_composite(envelope, payload),
    )
