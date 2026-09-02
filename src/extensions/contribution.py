"""Contribution measurement: verified incremental value over a
counterfactual baseline (extensions.md "Economics").

Rewards are based on **verified incremental contribution**, measured as a
counterfactual baseline/treatment comparison: the baseline is the outcome
the protocol would have achieved without the extension (epistemic type
``COUNTERFACTUAL``); the treatment is the measured outcome with the
extension applied. Contribution is the non-negative increment of the
treatment over the baseline on one closed-vocabulary outcome metric.

Three distinct typed economic quantities are kept strictly separate and
can never be conflated:

1. **resource credits** — metered sandbox consumption (:class:`ResourceCredits`);
2. **real economic earnings** — measured rewards (:class:`EconomicEarnings`);
3. **financial collateral** — pledged value for higher authority tiers
   (:class:`FinancialCollateral`).

Activity volume alone is not a valid contribution measure: it is not a
member of the metric vocabulary, volume cannot manufacture earnings, and
per-invocation price accounting is recorded as caller billing, never as
contribution.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.evidence.contracts import EpistemicType

from ._validation import (
    exact_fields,
    require_int,
    require_internal_id,
    require_text,
    validate_timestamp,
)
from .contracts import (
    EXTENSION_CONTRIBUTION_OBJECT_TYPE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    ContributionMetric,
    EconomicEarnings,
    ResourceCredits,
)
from .manifest import PricingSpec, PricingModel

#: Basis points denominator for exact integer revenue-share arithmetic.
BPS_DENOMINATOR = 10_000

_MEASUREMENT_FIELDS = (
    "extension_id",
    "metric",
    "value",
    "as_of",
    "epistemic_type",
    "evidence_refs",
)


def _parse_epistemic_type(value: object) -> EpistemicType:
    """Fail closed unless the value is in the frozen epistemic vocabulary."""
    if isinstance(value, EpistemicType):
        return value
    try:
        return EpistemicType(value)
    except ValueError as exc:
        raise CoreValidationError(
            "measurement epistemic type must use the closed vocabulary "
            "(OBSERVED, ESTIMATED, PREDICTED, SIMULATED, COUNTERFACTUAL)"
        ) from exc


@dataclass(frozen=True, slots=True)
class OutcomeMeasurement:
    """One measured outcome on a closed-vocabulary contribution metric.

    A measurement carries its epistemic type explicitly (the frozen
    ``simulation.md`` vocabulary, owned by ``src.evidence``): the baseline
    of a contribution comparison must be ``COUNTERFACTUAL``; the
    treatment may be any other epistemic type. Evidence references point
    at the records that back the value; a measurement without evidence
    references is representable (an *unbacked* measurement) but can never
    verify, so it can never earn.
    """

    extension_id: str
    metric: ContributionMetric
    value: int
    as_of: str
    epistemic_type: EpistemicType
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_internal_id("measurement.extension_id", self.extension_id)
        if not isinstance(self.metric, ContributionMetric):
            object.__setattr__(
                self, "metric", ContributionMetric.parse(self.metric)
            )
        require_int("measurement.value", self.value, minimum=0)
        validate_timestamp("measurement.as_of", self.as_of)
        if not isinstance(self.epistemic_type, EpistemicType):
            object.__setattr__(
                self, "epistemic_type", _parse_epistemic_type(self.epistemic_type)
            )
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("measurement.evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            require_text("measurement.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "metric": self.metric.value,
            "value": self.value,
            "as_of": self.as_of,
            "epistemic_type": self.epistemic_type.value,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OutcomeMeasurement":
        if not isinstance(value, Mapping):
            raise CoreValidationError("measurement must be an object")
        exact_fields("measurement", value, set(_MEASUREMENT_FIELDS))
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError(
                "measurement.evidence_refs must deserialize from a list"
            )
        return cls(
            extension_id=value["extension_id"],
            metric=value["metric"],
            value=value["value"],
            as_of=value["as_of"],
            epistemic_type=value["epistemic_type"],
            evidence_refs=tuple(refs),
        )


@dataclass(frozen=True, slots=True)
class ExtensionContribution:
    """One sealed contribution measurement record (kernel-bound).

    The record carries the full comparison (baseline, treatment, pricing)
    so it is independently re-derivable: deserialization recomputes the
    incremental value, the verification verdict, the earnings and the
    billed price accounting from the carried inputs and fails closed on
    any mismatch (tampered records are rejected).
    """

    contribution_id: str
    extension_id: str
    metric: ContributionMetric
    baseline: OutcomeMeasurement
    treatment: OutcomeMeasurement
    pricing: PricingSpec
    incremental: int
    verified: bool
    earnings: EconomicEarnings
    billed_minor: int
    applied_invocations: int
    resource_credits: ResourceCredits
    as_of: str
    envelope: ObjectEnvelope | None = None

    def __post_init__(self) -> None:
        require_internal_id("contribution.contribution_id", self.contribution_id)
        require_internal_id("contribution.extension_id", self.extension_id)
        if not isinstance(self.metric, ContributionMetric):
            object.__setattr__(
                self, "metric", ContributionMetric.parse(self.metric)
            )
        if not isinstance(self.baseline, OutcomeMeasurement):
            object.__setattr__(
                self, "baseline", OutcomeMeasurement.from_dict(self.baseline)
            )
        if not isinstance(self.treatment, OutcomeMeasurement):
            object.__setattr__(
                self, "treatment", OutcomeMeasurement.from_dict(self.treatment)
            )
        if not isinstance(self.pricing, PricingSpec):
            object.__setattr__(self, "pricing", PricingSpec.from_dict(self.pricing))
        require_int("contribution.incremental", self.incremental, minimum=0)
        if not isinstance(self.verified, bool):
            raise CoreValidationError("contribution.verified must be a boolean")
        if not isinstance(self.earnings, EconomicEarnings):
            if isinstance(self.earnings, Mapping):
                object.__setattr__(
                    self, "earnings", EconomicEarnings.from_dict(self.earnings)
                )
            else:
                raise CoreValidationError("contribution.earnings must be EconomicEarnings")
        require_int("contribution.billed_minor", self.billed_minor, minimum=0)
        require_int("contribution.applied_invocations", self.applied_invocations, minimum=0)
        if not isinstance(self.resource_credits, ResourceCredits):
            if isinstance(self.resource_credits, int):
                object.__setattr__(
                    self,
                    "resource_credits",
                    ResourceCredits(credits=self.resource_credits),
                )
            else:
                raise CoreValidationError(
                    "contribution.resource_credits must be ResourceCredits"
                )
        validate_timestamp("contribution.as_of", self.as_of)
        if self.envelope is not None and not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("contribution envelope must be an ObjectEnvelope")

    # -- envelope binding ---------------------------------------------------

    @property
    def state(self) -> str:
        if self.envelope is None:
            raise CoreValidationError(
                "contribution state requires the bound kernel envelope"
            )
        return self.envelope.state

    def bind_envelope(self, envelope: ObjectEnvelope) -> "ExtensionContribution":
        if not isinstance(envelope, ObjectEnvelope):
            raise CoreValidationError("contribution envelope must be an ObjectEnvelope")
        if envelope.integrity_hash is None:
            raise CoreValidationError(
                "contribution envelope must be sealed with with_integrity_hash()"
            )
        if envelope.object_id != self.contribution_id:
            raise CoreValidationError(
                "contribution envelope object_id must equal contribution_id"
            )
        if envelope.object_type != EXTENSION_CONTRIBUTION_OBJECT_TYPE:
            raise CoreValidationError(
                "contribution envelope object_type must be exactly "
                f"{EXTENSION_CONTRIBUTION_OBJECT_TYPE}"
            )
        if envelope.protocol_version != EXTENSIONS_PROTOCOL_VERSION:
            raise CoreValidationError(
                "contribution envelope protocol_version must be "
                f"{EXTENSIONS_PROTOCOL_VERSION}"
            )
        if envelope.schema_version != EXTENSIONS_SCHEMA_VERSION:
            raise CoreValidationError(
                "contribution envelope schema_version must be the domain schema version"
            )
        if envelope.state != "MEASURED":
            raise CoreValidationError(
                "contribution envelope state must be MEASURED"
            )
        return replace(self, envelope=envelope)

    # -- canonical serialization -------------------------------------------

    def to_record_dict(self) -> dict[str, Any]:
        return {
            "contribution_id": self.contribution_id,
            "extension_id": self.extension_id,
            "metric": self.metric.value,
            "baseline": self.baseline.to_dict(),
            "treatment": self.treatment.to_dict(),
            "pricing": self.pricing.to_dict(),
            "incremental": self.incremental,
            "verified": self.verified,
            "earnings": self.earnings.to_dict(),
            "billed_minor": self.billed_minor,
            "applied_invocations": self.applied_invocations,
            "resource_credits": self.resource_credits.credits,
            "as_of": self.as_of,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict() if self.envelope is not None else None,
            "record": self.to_record_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionContribution":
        if not isinstance(value, Mapping):
            raise CoreValidationError("contribution must be an object")
        exact_fields("contribution", value, {"envelope", "record"})
        record = value["record"]
        if not isinstance(record, Mapping):
            raise CoreValidationError("contribution record must be an object")
        exact_fields(
            "contribution record",
            record,
            {
                "contribution_id",
                "extension_id",
                "metric",
                "baseline",
                "treatment",
                "pricing",
                "incremental",
                "verified",
                "earnings",
                "billed_minor",
                "applied_invocations",
                "resource_credits",
                "as_of",
            },
        )
        contribution = cls(
            contribution_id=record["contribution_id"],
            extension_id=record["extension_id"],
            metric=record["metric"],
            baseline=OutcomeMeasurement.from_dict(record["baseline"]),
            treatment=OutcomeMeasurement.from_dict(record["treatment"]),
            pricing=PricingSpec.from_dict(record["pricing"]),
            incremental=record["incremental"],
            verified=record["verified"],
            earnings=record["earnings"],
            billed_minor=record["billed_minor"],
            applied_invocations=record["applied_invocations"],
            resource_credits=record["resource_credits"],
            as_of=record["as_of"],
        )
        # Trusted deserialization re-derives every computed field from the
        # carried comparison and fails closed on any mismatch: tampered
        # contribution records (inflated incremental, forged verification,
        # manufactured earnings or billing) are rejected.
        derived_incremental, derived_verified, derived_earnings, derived_billed = (
            rederive_contribution_fields(contribution)
        )
        if (
            derived_incremental != contribution.incremental
            or derived_verified != contribution.verified
            or derived_earnings != contribution.earnings
            or derived_billed != contribution.billed_minor
        ):
            raise CoreValidationError(
                f"contribution record {contribution.contribution_id} is not "
                "self-consistent: derived fields do not match the carried "
                "baseline/treatment comparison (tampered record)"
            )
        if value["envelope"] is None:
            return contribution
        return contribution.bind_envelope(ObjectEnvelope.from_dict(value["envelope"]))


def _require_comparison(
    baseline: OutcomeMeasurement, treatment: OutcomeMeasurement
) -> None:
    """Fail closed unless the comparison is a well-formed counterfactual test."""
    if baseline.epistemic_type is not EpistemicType.COUNTERFACTUAL:
        raise CoreValidationError(
            "contribution baselines must be COUNTERFACTUAL measurements of the "
            "outcome without the extension; declared "
            f"{baseline.epistemic_type.value}"
        )
    if treatment.epistemic_type is EpistemicType.COUNTERFACTUAL:
        raise CoreValidationError(
            "contribution treatments must not be COUNTERFACTUAL: the treatment is "
            "the measured outcome with the extension applied"
        )
    if baseline.metric is not treatment.metric:
        raise CoreValidationError(
            f"contribution metric mismatch: baseline {baseline.metric.value} vs "
            f"treatment {treatment.metric.value}"
        )
    if baseline.extension_id != treatment.extension_id:
        raise CoreValidationError(
            "contribution baseline and treatment must measure the same extension; "
            f"baseline {baseline.extension_id} vs treatment {treatment.extension_id}"
        )


def _derive(
    *,
    baseline: OutcomeMeasurement,
    treatment: OutcomeMeasurement,
    pricing: PricingSpec,
    applied_invocations: int,
) -> tuple[int, bool, EconomicEarnings, int]:
    """Deterministically derive (incremental, verified, earnings, billed).

    The single derivation used by both :func:`measure_contribution` and
    :meth:`ExtensionContribution.from_dict` tamper checking. Earnings are
    always gated on verified incremental contribution; price accounting
    (caller billing) is recorded independently and is never a reward.
    """
    incremental = treatment.value - baseline.value
    if incremental < 0:
        incremental = 0
    verified = incremental > 0 and len(treatment.evidence_refs) > 0

    if pricing.model is PricingModel.REVENUE_SHARE:
        billed_minor = (pricing.share_bps * incremental) // BPS_DENOMINATOR
        earnings_minor = billed_minor if verified else 0
    elif pricing.model is PricingModel.FIXED:
        billed_minor = pricing.amount_minor
        earnings_minor = pricing.amount_minor if verified else 0
    else:  # PER_INVOCATION — price accounting per applied invocation
        billed_minor = pricing.amount_minor * applied_invocations
        earnings_minor = billed_minor if verified else 0

    return (
        incremental,
        verified,
        EconomicEarnings(amount_minor=earnings_minor, asset=pricing.asset),
        billed_minor,
    )


def measure_contribution(
    *,
    contribution_id: str,
    baseline: OutcomeMeasurement,
    treatment: OutcomeMeasurement,
    pricing: PricingSpec,
    applied_invocations: int,
    resource_credits: int | ResourceCredits,
    as_of: str,
) -> ExtensionContribution:
    """Measure one verified incremental contribution (pure, deterministic).

    The comparison must be a counterfactual baseline/treatment pair on one
    closed-vocabulary outcome metric. Activity volume is never a
    contribution: ``applied_invocations`` and ``resource_credits`` are
    metered bookkeeping (volume and consumption), and only the verified
    increment can produce earnings.
    """
    require_internal_id("contribution.contribution_id", contribution_id)
    if not isinstance(baseline, OutcomeMeasurement):
        raise CoreValidationError("measure_contribution requires a baseline measurement")
    if not isinstance(treatment, OutcomeMeasurement):
        raise CoreValidationError("measure_contribution requires a treatment measurement")
    if not isinstance(pricing, PricingSpec):
        raise CoreValidationError("measure_contribution requires a PricingSpec")
    require_int("contribution.applied_invocations", applied_invocations, minimum=0)
    if not isinstance(resource_credits, ResourceCredits):
        if isinstance(resource_credits, int):
            resource_credits = ResourceCredits(credits=resource_credits)
        else:
            raise CoreValidationError(
                "contribution.resource_credits must be an integer or ResourceCredits"
            )
    validate_timestamp("contribution.as_of", as_of)

    _require_comparison(baseline, treatment)
    incremental, verified, earnings, billed_minor = _derive(
        baseline=baseline,
        treatment=treatment,
        pricing=pricing,
        applied_invocations=applied_invocations,
    )
    return ExtensionContribution(
        contribution_id=contribution_id,
        extension_id=treatment.extension_id,
        metric=treatment.metric,
        baseline=baseline,
        treatment=treatment,
        pricing=pricing,
        incremental=incremental,
        verified=verified,
        earnings=earnings,
        billed_minor=billed_minor,
        applied_invocations=applied_invocations,
        resource_credits=resource_credits,
        as_of=as_of,
    )


def rederive_contribution_fields(
    contribution: ExtensionContribution,
) -> tuple[int, bool, EconomicEarnings, int]:
    """Recompute the derived fields of one contribution record.

    Used by trusted deserialization to reject tampered records: any
    mismatch between the carried derived fields and the recomputation
    fails closed.
    """
    _require_comparison(contribution.baseline, contribution.treatment)
    return _derive(
        baseline=contribution.baseline,
        treatment=contribution.treatment,
        pricing=contribution.pricing,
        applied_invocations=contribution.applied_invocations,
    )
