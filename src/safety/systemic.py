"""The systemic exposure interface: a typed predicate over aggregated risk.

``SystemicRiskAssessment`` belongs to the Federation family of the
canonical object model and is therefore NOT owned by this domain: this
module exposes only the interface — a typed, deterministic summary and
breach predicate over aggregated risk inputs — that a federation domain
can consume when it constructs its own assessment objects. The summary
is a plain immutable value: it carries no envelope, no seal and no
durable identity, and it never becomes a protocol-visible object.

Aggregation is exact: band counts and the maximum aggregate score are
integer facts, and the total exposure sums typed money amounts of one
currency (mixed currencies fail closed — aggregating across currencies
would silently need FX policy owned by the money domain).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money.amount import Amount

from .contracts import (
    SystemicBreachReason,
    RiskBand,
)
from ._validation import (
    parse_utc_timestamp,
    require_int,
    require_text,
    require_utc_timestamp,
)
from .policy import SafetyPolicy, require_active_policy
from .risk import RiskAssessment


@dataclass(frozen=True, slots=True)
class SystemicExposureSummary:
    """Typed systemic exposure summary and breach predicate (interface only).

    ``breached`` is the predicate; ``breach_reasons`` is the closed,
    deterministically ordered set of reasons (subject-count first, then
    aggregate exposure).
    """

    subject_count: int
    low_count: int
    medium_count: int
    high_count: int
    critical_count: int
    max_aggregate_score: int
    total_exposure: Amount | None
    breached: bool
    breach_reasons: tuple[SystemicBreachReason, ...]
    as_of: str
    policy_id: str
    policy_version: int

    def __post_init__(self) -> None:
        require_int("systemic subject_count", self.subject_count, minimum=0)
        for name in ("low_count", "medium_count", "high_count", "critical_count"):
            require_int(f"systemic {name}", getattr(self, name), minimum=0)
        require_int("systemic max_aggregate_score", self.max_aggregate_score, minimum=0)
        if self.total_exposure is not None and not isinstance(self.total_exposure, Amount):
            raise CoreValidationError("systemic total_exposure must be a money Amount")
        if not isinstance(self.breached, bool):
            raise CoreValidationError("systemic breached must be a boolean")
        if not isinstance(self.breach_reasons, tuple):
            raise CoreValidationError("systemic breach_reasons must be a tuple")
        for reason in self.breach_reasons:
            if not isinstance(reason, SystemicBreachReason):
                raise CoreValidationError(
                    "systemic breach_reasons must use the closed "
                    "SystemicBreachReason vocabulary"
                )
        if self.breached != bool(self.breach_reasons):
            raise CoreValidationError(
                "a breached systemic summary must carry breach reasons, and an "
                "unbreached one must carry none"
            )
        require_text("systemic policy_id", self.policy_id)
        require_utc_timestamp("systemic as_of", self.as_of)
        require_int("systemic policy_version", self.policy_version, minimum=1)
        if self.subject_count != (
            self.low_count + self.medium_count + self.high_count + self.critical_count
        ):
            raise CoreValidationError(
                "systemic band counts must add up to the subject count"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_count": self.subject_count,
            "low_count": self.low_count,
            "medium_count": self.medium_count,
            "high_count": self.high_count,
            "critical_count": self.critical_count,
            "max_aggregate_score": self.max_aggregate_score,
            "total_exposure": (
                None if self.total_exposure is None else self.total_exposure.to_dict()
            ),
            "breached": self.breached,
            "breach_reasons": [reason.value for reason in self.breach_reasons],
            "as_of": self.as_of,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }

    def digest(self) -> str:
        """Canonical digest of the summary (deterministic interface value)."""
        return canonical_sha256(self.to_dict())


def assess_systemic_exposure(
    assessments: Iterable[RiskAssessment],
    *,
    policy: SafetyPolicy,
    as_of: str,
) -> SystemicExposureSummary:
    """Aggregate risk assessments into the systemic exposure summary.

    Deterministic and order-independent: subjects are unique and
    canonically sorted; the aggregation instant must not precede any
    input assessment. The breach predicate trips when the count of
    HIGH/CRITICAL subjects reaches the policy threshold or the exact
    aggregate exposure reaches the policy cap.
    """
    require_active_policy("systemic exposure assessment", policy)
    require_utc_timestamp("systemic exposure as_of", as_of)
    if not isinstance(assessments, (list, tuple)):
        raise CoreValidationError("systemic assessments must be provided as a sequence")
    for assessment in assessments:
        if not isinstance(assessment, RiskAssessment):
            raise CoreValidationError(
                "systemic assessments must be RiskAssessment records"
            )
        if parse_utc_timestamp(
            "systemic exposure as_of", as_of
        ) < parse_utc_timestamp(
            "risk assessment as_of", assessment.spec.as_of
        ):
            raise CoreValidationError(
                "systemic exposure aggregation cannot precede its input "
                f"assessment {assessment.object_id}"
            )
    subjects = [assessment.spec.subject_id for assessment in assessments]
    if len(set(subjects)) != len(subjects):
        raise CoreValidationError(
            "systemic exposure aggregation rejects duplicate subjects"
        )
    ordered = tuple(sorted(assessments, key=lambda a: a.spec.subject_id))
    counts = {band: 0 for band in RiskBand}
    max_score = 0
    total_exposure: Amount | None = None
    for assessment in ordered:
        counts[assessment.spec.band] += 1
        max_score = max(max_score, assessment.spec.aggregate_score)
        exposure = assessment.spec.exposure
        if exposure is not None:
            total_exposure = (
                exposure if total_exposure is None else total_exposure.add(exposure)
            )
    high_risk_count = counts[RiskBand.HIGH] + counts[RiskBand.CRITICAL]
    reasons: list[SystemicBreachReason] = []
    if high_risk_count >= policy.spec.systemic_breach_subject_count:
        reasons.append(SystemicBreachReason.HIGH_RISK_SUBJECT_COUNT)
    cap = policy.spec.systemic_exposure_cap
    if cap is not None and total_exposure is not None and total_exposure >= cap:
        reasons.append(SystemicBreachReason.AGGREGATE_EXPOSURE)
    return SystemicExposureSummary(
        subject_count=len(ordered),
        low_count=counts[RiskBand.LOW],
        medium_count=counts[RiskBand.MEDIUM],
        high_count=counts[RiskBand.HIGH],
        critical_count=counts[RiskBand.CRITICAL],
        max_aggregate_score=max_score,
        total_exposure=total_exposure,
        breached=bool(reasons),
        breach_reasons=tuple(reasons),
        as_of=as_of,
        policy_id=policy.object_id,
        policy_version=policy.policy_version,
    )
