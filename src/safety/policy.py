"""The versioned safety policy: explicit policy versioning for decisions.

Safety policy evaluation must be reproducible (constitution hard
invariant: same inputs + same policy version + same as_of produce a
byte-identical decision). Every safety decision therefore pins the exact
policy object version it was evaluated under, and the policy object
itself is a VERSIONED durable object (ACTIVE -> RETIRED with in-place
amendments producing new sealed versions), mirroring the sibling
convention for fulfillment policies.

The policy owns the tunable decision parameters only: risk dimension
weights, risk band thresholds, fraud severity weights, fraud decision
thresholds, the default circuit-breaker hold window and the systemic
exposure thresholds. The constraint precedence vocabulary is NOT
policy-parameterizable: it is frozen in ``contracts.py`` and versioned by
the domain protocol/schema versions.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.money.amount import Amount

from .contracts import (
    RISK_SCALE_MAX,
    RISK_WEIGHT_TOTAL_BPS,
    RISK_SCALE_MIN,
    SAFETY_POLICY_OBJECT_TYPE,
    FraudSeverity,
    RiskBand,
    RiskDimension,
    SafetyPolicyState,
)
from ._validation import (
    require_identifier,
    require_int,
    strict_fields,
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

_POLICY_SPEC_FIELDS = frozenset(
    {
        "risk_weights",
        "band_thresholds",
        "fraud_severity_weights",
        "decision_thresholds",
        "default_hold_window_seconds",
        "systemic_breach_subject_count",
        "systemic_exposure_cap",
    }
)

_POLICY_COMMANDS: dict[str, dict[SafetyPolicyState, SafetyPolicyState]] = {
    "retire": {SafetyPolicyState.ACTIVE: SafetyPolicyState.RETIRED},
    "amend": {SafetyPolicyState.ACTIVE: SafetyPolicyState.ACTIVE},
}


def _convert_dimension(item: Any) -> RiskDimension:
    if isinstance(item, RiskDimension):
        return item
    if isinstance(item, str):
        try:
            return RiskDimension(item)
        except ValueError as exc:
            raise CoreValidationError(f"unknown risk dimension {item!r}") from exc
    raise CoreValidationError(
        "risk weights must use (RiskDimension, weight) pairs"
    )


def _convert_severity(item: Any) -> FraudSeverity:
    if isinstance(item, FraudSeverity):
        return item
    if isinstance(item, str):
        try:
            return FraudSeverity(item)
        except ValueError as exc:
            raise CoreValidationError(f"unknown fraud severity {item!r}") from exc
    raise CoreValidationError(
        "fraud severity weights must use (FraudSeverity, weight) pairs"
    )


def _validate_weight_pairs(
    name: str, pairs: tuple[tuple[Any, int], ...]
) -> tuple[tuple[Any, int], ...]:
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            raise CoreValidationError(f"{name} entries must be (kind, weight) pairs")
        require_int(
            f"{name} weight", item[1],
            minimum=RISK_SCALE_MIN, maximum=RISK_SCALE_MAX,
        )
    return pairs


@dataclass(frozen=True, slots=True)
class SafetyPolicySpec:
    """Immutable safety policy payload.

    - ``risk_weights``: basis-point weights per risk dimension; unique
      dimensions, canonical order (sorted by dimension), summing to
      exactly ``RISK_WEIGHT_TOTAL_BPS`` so aggregate scores are exact
      fixed-point values on the 0..10000 scale.
    - ``band_thresholds``: ``(medium, high, critical)`` band cut-offs;
      strictly increasing within (0, 10000].
    - ``fraud_severity_weights``: basis-point contribution per fraud
      signal severity; every severity must be mapped explicitly.
    - ``decision_thresholds``: ``(step_up, hold, block)`` fraud decision
      cut-offs; strictly increasing within (0, 10000].
    - ``default_hold_window_seconds``: the circuit-breaker hold window
      applied by policy-derived HOLD decisions.
    - ``systemic_breach_subject_count``: count of HIGH/CRITICAL risk
      subjects that trips the systemic exposure predicate.
    - ``systemic_exposure_cap``: optional exact aggregate exposure cap
      (typed money amount, non-negative) for the same predicate.
    """

    risk_weights: tuple[tuple[RiskDimension, int], ...]
    band_thresholds: tuple[int, int, int]
    fraud_severity_weights: tuple[tuple[FraudSeverity, int], ...]
    decision_thresholds: tuple[int, int, int]
    default_hold_window_seconds: int
    systemic_breach_subject_count: int
    systemic_exposure_cap: Amount | None

    def __post_init__(self) -> None:
        if not isinstance(self.risk_weights, tuple) or not self.risk_weights:
            raise CoreValidationError(
                "policy.risk_weights must be a non-empty tuple of (dimension, weight) pairs"
            )
        _validate_weight_pairs("policy.risk_weights", self.risk_weights)
        dimensions = [pair[0] for pair in self.risk_weights]
        for dimension in dimensions:
            if not isinstance(dimension, RiskDimension):
                raise CoreValidationError(
                    "policy.risk_weights must use the closed RiskDimension vocabulary"
                )
        if len(set(dimensions)) != len(dimensions):
            raise CoreValidationError(
                "policy.risk_weights must map each dimension at most once"
            )
        if [pair[0] for pair in self.risk_weights] != sorted(dimensions):
            raise CoreValidationError(
                "policy.risk_weights must be canonically ordered by dimension"
            )
        total = sum(pair[1] for pair in self.risk_weights)
        if total != RISK_WEIGHT_TOTAL_BPS:
            raise CoreValidationError(
                f"policy.risk_weights must sum exactly to {RISK_WEIGHT_TOTAL_BPS}; "
                f"got {total}"
            )
        thresholds = self._require_triple("policy.band_thresholds", self.band_thresholds)
        self._require_triple("policy.decision_thresholds", self.decision_thresholds)
        require_int("policy.default_hold_window_seconds",
                    self.default_hold_window_seconds, minimum=1)
        require_int("policy.systemic_breach_subject_count",
                    self.systemic_breach_subject_count, minimum=1)
        if self.systemic_exposure_cap is not None:
            if not isinstance(self.systemic_exposure_cap, Amount):
                raise CoreValidationError(
                    "policy.systemic_exposure_cap must be a money Amount"
                )
            if self.systemic_exposure_cap.value < 0:
                raise CoreValidationError(
                    "policy.systemic_exposure_cap must be a non-negative amount"
                )
        if not isinstance(self.fraud_severity_weights, tuple):
            raise CoreValidationError(
                "policy.fraud_severity_weights must be a tuple of (severity, weight) pairs"
            )
        _validate_weight_pairs("policy.fraud_severity_weights", self.fraud_severity_weights)
        severities = [pair[0] for pair in self.fraud_severity_weights]
        for severity in severities:
            if not isinstance(severity, FraudSeverity):
                raise CoreValidationError(
                    "policy.fraud_severity_weights must use the closed "
                    "FraudSeverity vocabulary"
                )
        if set(severities) != set(FraudSeverity):
            missing = sorted(member.value for member in FraudSeverity if member not in severities)
            raise CoreValidationError(
                f"policy.fraud_severity_weights must map every severity; missing={missing}"
            )
        if [pair[0] for pair in self.fraud_severity_weights] != sorted(
            member for member in FraudSeverity
        ):
            raise CoreValidationError(
                "policy.fraud_severity_weights must be canonically ordered by severity"
            )

    @staticmethod
    def _require_triple(name: str, value: Any) -> tuple[int, int, int]:
        if not isinstance(value, tuple) or len(value) != 3:
            raise CoreValidationError(f"{name} must be a triple of integers")
        for item in value:
            require_int(f"{name} entry", item, minimum=1, maximum=RISK_SCALE_MAX)
        if not (value[0] < value[1] < value[2]):
            raise CoreValidationError(f"{name} must strictly increase")
        return value

    @classmethod
    def build(
        cls,
        *,
        risk_weights: Iterable[Any],
        band_thresholds: Any,
        fraud_severity_weights: Iterable[Any],
        decision_thresholds: Any,
        default_hold_window_seconds: int,
        systemic_breach_subject_count: int,
        systemic_exposure_cap: Amount | None = None,
    ) -> "SafetyPolicySpec":
        """Build a policy spec, canonicalizing pair order (fail closed)."""
        if not isinstance(risk_weights, (list, tuple)):
            raise CoreValidationError("risk weights must be provided as a sequence")
        if not isinstance(fraud_severity_weights, (list, tuple)):
            raise CoreValidationError("fraud severity weights must be provided as a sequence")
        # Canonicalize: convert kinds, sort by kind, re-validate in __post_init__.
        converted_risk: list[tuple[RiskDimension, int]] = []
        for item in risk_weights:
            if not isinstance(item, tuple) or len(item) != 2:
                raise CoreValidationError(
                    "risk_weights entries must be (dimension, weight) pairs"
                )
            converted_risk.append((_convert_dimension(item[0]), item[1]))
        converted_risk.sort(key=lambda pair: pair[0].value)
        converted_severity: list[tuple[FraudSeverity, int]] = []
        for item in fraud_severity_weights:
            if not isinstance(item, tuple) or len(item) != 2:
                raise CoreValidationError(
                    "fraud_severity_weights entries must be (severity, weight) pairs"
                )
            converted_severity.append((_convert_severity(item[0]), item[1]))
        converted_severity.sort(key=lambda pair: pair[0].value)
        if not isinstance(band_thresholds, (tuple, list)) or len(band_thresholds) != 3:
            raise CoreValidationError("band_thresholds must be a triple")
        if not isinstance(decision_thresholds, (tuple, list)) or len(decision_thresholds) != 3:
            raise CoreValidationError("decision_thresholds must be a triple")
        return cls(
            risk_weights=tuple(converted_risk),
            band_thresholds=tuple(band_thresholds),
            fraud_severity_weights=tuple(converted_severity),
            decision_thresholds=tuple(decision_thresholds),
            default_hold_window_seconds=default_hold_window_seconds,
            systemic_breach_subject_count=systemic_breach_subject_count,
            systemic_exposure_cap=systemic_exposure_cap,
        )

    def with_changes(self, changes: Mapping[str, Any]) -> "SafetyPolicySpec":
        if not isinstance(changes, Mapping):
            raise CoreValidationError("safety policy changes must be a mapping")
        unknown = sorted(set(changes) - _POLICY_SPEC_FIELDS)
        if unknown:
            raise CoreValidationError(
                f"unknown safety policy fields for amendment: {unknown}"
            )
        return replace(self, **changes)

    # -- deterministic lookups -------------------------------------------

    def risk_weight(self, dimension: RiskDimension) -> int:
        """Weight for one dimension; fails closed on uncovered dimensions."""
        for candidate, weight in self.risk_weights:
            if candidate == dimension:
                return weight
        raise CoreValidationError(
            f"safety policy does not cover risk dimension {dimension.value}"
        )

    def severity_weight(self, severity: FraudSeverity) -> int:
        for candidate, weight in self.fraud_severity_weights:
            if candidate == severity:
                return weight
        raise CoreValidationError(
            f"safety policy does not cover fraud severity {severity.value}"
        )

    def band_for_score(self, score: int) -> RiskBand:
        """Map a 0..10000 score onto the closed band vocabulary.

        Bands are half-open: LOW [0, medium), MEDIUM [medium, high),
        HIGH [high, critical), CRITICAL [critical, 10000].
        """
        require_int("band score", score, minimum=RISK_SCALE_MIN, maximum=RISK_SCALE_MAX)
        medium, high, critical = self.band_thresholds
        if score >= critical:
            return RiskBand.CRITICAL
        if score >= high:
            return RiskBand.HIGH
        if score >= medium:
            return RiskBand.MEDIUM
        return RiskBand.LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_weights": [
                [dimension.value, weight] for dimension, weight in self.risk_weights
            ],
            "band_thresholds": list(self.band_thresholds),
            "fraud_severity_weights": [
                [severity.value, weight] for severity, weight in self.fraud_severity_weights
            ],
            "decision_thresholds": list(self.decision_thresholds),
            "default_hold_window_seconds": self.default_hold_window_seconds,
            "systemic_breach_subject_count": self.systemic_breach_subject_count,
            "systemic_exposure_cap": (
                None if self.systemic_exposure_cap is None
                else self.systemic_exposure_cap.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SafetyPolicySpec":
        strict_fields("safety policy", value, _POLICY_SPEC_FIELDS)
        risk_weights = value["risk_weights"]
        if not isinstance(risk_weights, list):
            raise CoreValidationError(
                "policy.risk_weights must deserialize from an array"
            )
        severities = value["fraud_severity_weights"]
        if not isinstance(severities, list):
            raise CoreValidationError(
                "policy.fraud_severity_weights must deserialize from an array"
            )
        cap = value["systemic_exposure_cap"]
        return cls(
            risk_weights=tuple(
                (_convert_dimension(pair[0]), pair[1]) for pair in risk_weights
            ),
            band_thresholds=tuple(value["band_thresholds"]),
            fraud_severity_weights=tuple(
                (_convert_severity(pair[0]), pair[1]) for pair in severities
            ),
            decision_thresholds=tuple(value["decision_thresholds"]),
            default_hold_window_seconds=value["default_hold_window_seconds"],
            systemic_breach_subject_count=value["systemic_breach_subject_count"],
            systemic_exposure_cap=None if cap is None else Amount.from_dict(cap),
        )


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Durable, versioned safety policy (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: SafetyPolicySpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = SAFETY_POLICY_OBJECT_TYPE
    STATE_TYPE = SafetyPolicyState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("safety policy envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, SafetyPolicySpec):
            raise CoreValidationError("safety policy spec must be a SafetyPolicySpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != SAFETY_POLICY_OBJECT_TYPE:
            raise CoreValidationError(
                f"safety policy object_type must be {SAFETY_POLICY_OBJECT_TYPE!r}"
            )
        try:
            SafetyPolicyState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown safety policy state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: SafetyPolicySpec,
        provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "SafetyPolicy":
        if not isinstance(spec, SafetyPolicySpec):
            raise CoreValidationError("safety policy spec must be a SafetyPolicySpec")
        envelope = build_domain_envelope(
            object_id=require_identifier("policy.object_id", object_id),
            object_type=SAFETY_POLICY_OBJECT_TYPE,
            state=SafetyPolicyState.ACTIVE.value,
            environment_id=require_identifier("policy.environment_id", environment_id),
            domain_id=require_identifier("policy.domain_id", domain_id),
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> SafetyPolicyState:
        return SafetyPolicyState(self.envelope.state)

    @property
    def policy_version(self) -> int:
        """The exact policy object version decisions must pin."""
        return self.envelope.object_version

    def retire(self, *, provenance, causation_id: str | None = None) -> "SafetyPolicy":
        return self._command("retire", provenance=provenance, causation_id=causation_id)

    def amend(
        self,
        *,
        provenance,
        causation_id: str | None = None,
        **spec_changes: Any,
    ) -> "SafetyPolicy":
        return self._command(
            "amend", provenance=provenance, causation_id=causation_id,
            spec_changes=spec_changes,
        )

    def _command(
        self,
        name: str,
        *,
        provenance,
        causation_id: str | None = None,
        spec_changes: Mapping[str, Any] | None = None,
    ) -> "SafetyPolicy":
        current = SafetyPolicyState(self.envelope.state)
        transitions = _POLICY_COMMANDS[name]
        if current not in transitions:
            raise CoreValidationError(
                f"safety policy command {name!r} is not allowed from state {current.value}"
            )
        spec = self.spec.with_changes(spec_changes or {})
        envelope = advance_envelope(
            self.envelope,
            state=transitions[current].value,
            provenance=provenance,
            causation_id=causation_id,
        )
        return type(self)(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SafetyPolicy":
        envelope, payload = decode_composite(
            value,
            expected_object_type=SAFETY_POLICY_OBJECT_TYPE,
            state_type=SafetyPolicyState,
        )
        spec = SafetyPolicySpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "SafetyPolicy":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=SAFETY_POLICY_OBJECT_TYPE,
            state_type=SafetyPolicyState,
        )
        spec = SafetyPolicySpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def require_active_policy(name: str, policy: SafetyPolicy) -> SafetyPolicy:
    """Fail closed on retired (or non-) policies: no evaluation on stale policy."""
    if not isinstance(policy, SafetyPolicy):
        raise CoreValidationError(f"{name} requires a SafetyPolicy")
    if policy.state is not SafetyPolicyState.ACTIVE:
        raise CoreValidationError(
            f"{name} requires an ACTIVE safety policy; state is {policy.state.value}"
        )
    return policy
