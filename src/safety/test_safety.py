"""WORK-017 contract and discrimination suite for the safety domain.

Authored RED FIRST (before any implementation existed): every test below
pins the public contract of ``src.safety`` — the versioned typed boundary,
the frozen Safety/Compliance command-family lifecycles, evidence-backed
decisions, deterministic reproducible policy evaluation, constraint
precedence resolution, seal/tamper rejection, the systemic exposure
interface and the domain import/entropy boundary.

Failure is explicit: every violation raises the single core error
authority ``CoreValidationError``.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical
from src.money import Amount, RoundingMode, get_currency

from src.safety import (
    COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
    COMPLIANCE_TERMINAL_STATES,
    CONSTRAINT_PRECEDENCE_ORDER,
    FRAUD_ASSESSMENT_OBJECT_TYPE,
    FRAUD_DECISION_OBJECT_TYPE,
    FRAUD_DECISION_TERMINAL_STATES,
    FRAUD_SIGNAL_OBJECT_TYPE,
    RISK_ASSESSMENT_OBJECT_TYPE,
    RISK_SCALE_MAX,
    RISK_SCALE_MIN,
    RISK_WEIGHT_TOTAL_BPS,
    SAFETY_API_VERSION,
    SAFETY_POLICY_OBJECT_TYPE,
    SAFETY_PROTOCOL_VERSION,
    SAFETY_SCHEMA_VERSION,
    ComplianceAssessment,
    ComplianceAssessmentState,
    ComplianceConstraint,
    ComplianceResult,
    ComplianceVerdict,
    ConstraintOutcome,
    ConstraintPrecedence,
    FraudAssessment,
    FraudDecision,
    FraudDecisionState,
    FraudKind,
    FraudReleaseReason,
    FraudSeverity,
    FraudSignal,
    InvalidationRecord,
    OverrideRecord,
    ResolutionRecord,
    RiskAssessment,
    RiskBand,
    RiskDimension,
    RiskInput,
    SafetyPolicy,
    SafetyPolicySpec,
    SafetyPolicyState,
    SystemicBreachReason,
    SystemicExposureSummary,
    assess_fraud,
    assess_systemic_exposure,
    block_fraud_decision,
    create_fraud_decision,
    decide_fraud,
    evaluate_risk,
    hold_active,
    hold_fraud_decision,
    invalidate_compliance_result,
    record_compliance_result,
    release_fraud_decision,
    request_compliance_assessment,
    submit_fraud_signal,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-03T00:00:00Z"
AS_OF = "2026-09-03T00:10:00Z"
LATER = "2026-09-03T00:30:00Z"
USD = get_currency("USD")
EUR = get_currency("EUR")


def prov(source: str, evidence: tuple[str, ...] = ("evidence/unit-test",)) -> Provenance:
    return Provenance(
        issuer="principal/safety-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=evidence,
    )


def build_policy(**overrides) -> SafetyPolicy:
    values = dict(
        risk_weights=[
            (RiskDimension.COUNTERPARTY, 3000),
            (RiskDimension.FRAUD, 4000),
            (RiskDimension.SETTLEMENT, 2000),
            (RiskDimension.OPERATIONAL, 1000),
        ],
        band_thresholds=(4000, 7000, 9000),
        fraud_severity_weights=[
            (FraudSeverity.INFO, 0),
            (FraudSeverity.LOW, 1000),
            (FraudSeverity.MEDIUM, 3000),
            (FraudSeverity.HIGH, 6000),
            (FraudSeverity.CRITICAL, 9000),
        ],
        decision_thresholds=(3000, 6000, 8500),
        default_hold_window_seconds=3600,
        systemic_breach_subject_count=2,
        systemic_exposure_cap=None,
    )
    values.update(overrides)
    spec = SafetyPolicySpec.build(**values)
    return SafetyPolicy.build(
        object_id="safety/policy/unit",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=prov("safety/policy"),
    )


def build_assessment(policy: SafetyPolicy, **overrides) -> RiskAssessment:
    values = dict(
        assessment_id="safety/risk/unit-1",
        subject_id="intent/pay-unit-1",
        inputs=[
            RiskInput(RiskDimension.COUNTERPARTY, 2000, ("evidence/cp-score",)),
            RiskInput(RiskDimension.FRAUD, 3000, ("evidence/fraud-score",)),
        ],
        policy=policy,
        as_of=AS_OF,
        rounding=RoundingMode.HALF_UP,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("safety/risk-evaluation"),
    )
    values.update(overrides)
    return evaluate_risk(**values)


def build_signal(signal_id: str, subject: str, severity: FraudSeverity,
                 observed_at: str = "2026-09-03T00:05:00Z",
                 kind: FraudKind = FraudKind.AUTHORIZED_PUSH_SCAM) -> FraudSignal:
    return submit_fraud_signal(
        signal_id=signal_id,
        subject_id=subject,
        kind=kind,
        severity=severity,
        observed_at=observed_at,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("safety/fraud-signal"),
    )


def build_fraud_assessment(policy: SafetyPolicy, **overrides) -> FraudAssessment:
    values = dict(
        assessment_id="safety/fraud-assessment/unit-1",
        subject_id="intent/pay-unit-1",
        signals=[
            build_signal("safety/fraud-signal/unit-1", "intent/pay-unit-1", FraudSeverity.LOW),
        ],
        policy=policy,
        as_of=AS_OF,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("safety/fraud-assessment"),
    )
    values.update(overrides)
    return assess_fraud(**values)


def build_constraint(constraint_id: str, requirement: str, precedence: ConstraintPrecedence,
                     outcome: ConstraintOutcome, version: int = 1,
                     effective_from: str = "2026-09-01T00:00:00Z",
                     effective_until: str = "2026-12-31T00:00:00Z") -> ComplianceConstraint:
    return ComplianceConstraint(
        constraint_id=constraint_id,
        requirement=requirement,
        precedence=precedence,
        outcome=outcome,
        version=version,
        effective_from=effective_from,
        effective_until=effective_until,
        evidence_refs=(f"evidence/constraint/{constraint_id}",),
    )


def build_compliance_request(**overrides) -> ComplianceAssessment:
    values = dict(
        assessment_id="safety/compliance/unit-1",
        subject_id="intent/pay-unit-1",
        jurisdiction="jurisdiction/EU",
        constraints=[
            build_constraint("safety/constraint/sanctions", "sanctions_screening",
                             ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
            build_constraint("safety/constraint/limit", "transaction_limit",
                             ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
        ],
        as_of=AS_OF,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("safety/compliance-request"),
    )
    values.update(overrides)
    return request_compliance_assessment(**values)


# ---------------------------------------------------------------------------
# contract, vocabulary and boundary
# ---------------------------------------------------------------------------


class ContractBoundaryTests(unittest.TestCase):
    def test_api_and_schema_versions_are_declared(self) -> None:
        self.assertEqual(SAFETY_API_VERSION, "v0.1")
        self.assertEqual(SAFETY_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(SAFETY_SCHEMA_VERSION, 1)

    def test_object_types_use_internal_non_registry_formats(self) -> None:
        for object_type in (
            RISK_ASSESSMENT_OBJECT_TYPE,
            FRAUD_SIGNAL_OBJECT_TYPE,
            FRAUD_ASSESSMENT_OBJECT_TYPE,
            FRAUD_DECISION_OBJECT_TYPE,
            COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
            SAFETY_POLICY_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("safety/"), object_type)
            self.assertTrue(object_type.endswith("/v1"), object_type)
            self.assertFalse(object_type.startswith("payswap/"), object_type)

    def test_object_types_are_carried_by_their_envelopes(self) -> None:
        self.assertEqual(build_policy().envelope.object_type, SAFETY_POLICY_OBJECT_TYPE)
        self.assertEqual(build_assessment(build_policy()).envelope.object_type,
                         RISK_ASSESSMENT_OBJECT_TYPE)
        self.assertEqual(build_signal("s", "intent/x", FraudSeverity.LOW)
                         .envelope.object_type, FRAUD_SIGNAL_OBJECT_TYPE)
        self.assertEqual(build_fraud_assessment(build_policy()).envelope.object_type,
                         FRAUD_ASSESSMENT_OBJECT_TYPE)
        decision = create_fraud_decision(
            decision_id="safety/fraud-decision/unit-1",
            subject_id="intent/pay-unit-1",
            assessment_ref="safety/fraud-assessment/unit-1",
            state=FraudDecisionState.ALLOW,
            as_of=AS_OF,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("safety/fraud-decision"),
        )
        self.assertEqual(decision.envelope.object_type, FRAUD_DECISION_OBJECT_TYPE)
        self.assertEqual(build_compliance_request().envelope.object_type,
                         COMPLIANCE_ASSESSMENT_OBJECT_TYPE)

    def test_risk_scale_bounds_are_explicit(self) -> None:
        self.assertEqual(RISK_SCALE_MIN, 0)
        self.assertEqual(RISK_SCALE_MAX, 10000)
        self.assertEqual(RISK_WEIGHT_TOTAL_BPS, 10000)

    def test_constraint_precedence_is_an_ordered_vocabulary(self) -> None:
        self.assertEqual(CONSTRAINT_PRECEDENCE_ORDER,
                         ("LEGAL", "REGULATORY", "CONTRACTUAL", "POLICY"))
        self.assertEqual([member.value for member in ConstraintPrecedence],
                         ["LEGAL", "REGULATORY", "CONTRACTUAL", "POLICY"])

    def test_fraud_decision_vocabulary_is_closed(self) -> None:
        self.assertEqual(
            {member.value for member in FraudDecisionState},
            {"ALLOW", "STEP_UP", "DELAY", "RECONFIRM", "ESCALATE",
             "HELD", "RELEASED", "BLOCKED"},
        )
        with self.assertRaises(ValueError):
            FraudDecisionState("DEFER")

    def test_fraud_decision_terminal_states_are_explicit(self) -> None:
        self.assertEqual(FRAUD_DECISION_TERMINAL_STATES,
                         frozenset({FraudDecisionState.RELEASED, FraudDecisionState.BLOCKED}))

    def test_compliance_lifecycle_vocabulary_is_closed(self) -> None:
        self.assertEqual(
            {member.value for member in ComplianceAssessmentState},
            {"REQUESTED", "RECORDED", "INVALIDATED"},
        )
        with self.assertRaises(ValueError):
            ComplianceAssessmentState("OPEN")
        self.assertEqual(COMPLIANCE_TERMINAL_STATES,
                         frozenset({ComplianceAssessmentState.INVALIDATED}))

    def test_fraud_kinds_severities_and_outcomes_are_closed(self) -> None:
        self.assertEqual(
            {member.value for member in FraudKind},
            {"ACCOUNT_TAKEOVER", "AUTHORIZED_PUSH_SCAM", "MERCHANT_FRAUD",
             "PROVIDER_FRAUD", "COLLUSION", "CREDENTIAL_COMPROMISE"},
        )
        self.assertEqual(
            {member.value for member in FraudSeverity},
            {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
        )
        self.assertEqual(
            {member.value for member in ConstraintOutcome},
            {"SATISFIED", "VIOLATED"},
        )
        self.assertEqual(
            {member.value for member in ComplianceVerdict},
            {"SATISFIED", "BLOCKED"},
        )
        self.assertEqual(
            {member.value for member in FraudReleaseReason},
            {"OPERATOR", "WINDOW_ELAPSED"},
        )
        self.assertEqual(
            {member.value for member in RiskDimension},
            {"COUNTERPARTY", "LIQUIDITY", "CREDIT", "SETTLEMENT", "OPERATIONAL",
             "CONCENTRATION", "SYSTEMIC", "MODEL", "EXTENSION", "FRAUD"},
        )
        self.assertEqual(
            {member.value for member in RiskBand},
            {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
        )
        self.assertEqual(
            {member.value for member in SafetyPolicyState},
            {"ACTIVE", "RETIRED"},
        )
        self.assertEqual(
            {member.value for member in SystemicBreachReason},
            {"HIGH_RISK_SUBJECT_COUNT", "AGGREGATE_EXPOSURE"},
        )

    def test_public_all_is_exact_and_complete(self) -> None:
        import src.safety

        expected = {
            "SAFETY_API_VERSION", "SAFETY_PROTOCOL_VERSION", "SAFETY_SCHEMA_VERSION",
            "RISK_ASSESSMENT_OBJECT_TYPE", "FRAUD_SIGNAL_OBJECT_TYPE",
            "FRAUD_ASSESSMENT_OBJECT_TYPE", "FRAUD_DECISION_OBJECT_TYPE",
            "COMPLIANCE_ASSESSMENT_OBJECT_TYPE", "SAFETY_POLICY_OBJECT_TYPE",
            "RISK_SCALE_MIN", "RISK_SCALE_MAX", "RISK_WEIGHT_TOTAL_BPS",
            "CONSTRAINT_PRECEDENCE_ORDER", "FRAUD_DECISION_TERMINAL_STATES",
            "COMPLIANCE_TERMINAL_STATES",
            "RiskDimension", "RiskBand", "RiskInput", "RiskAssessment", "evaluate_risk",
            "FraudKind", "FraudSeverity", "FraudSignal", "submit_fraud_signal",
            "FraudAssessment", "assess_fraud",
            "FraudDecisionState", "FraudReleaseReason", "FraudDecision",
            "create_fraud_decision", "decide_fraud", "hold_fraud_decision",
            "release_fraud_decision", "block_fraud_decision", "hold_active",
            "ConstraintPrecedence", "ConstraintOutcome", "ComplianceVerdict",
            "ComplianceAssessmentState", "ComplianceConstraint", "ComplianceResult",
            "ResolutionRecord", "OverrideRecord", "InvalidationRecord",
            "ComplianceAssessment", "request_compliance_assessment",
            "record_compliance_result", "invalidate_compliance_result",
            "SafetyPolicyState", "SafetyPolicySpec", "SafetyPolicy",
            "SystemicBreachReason", "SystemicExposureSummary",
            "assess_systemic_exposure",
            "CoreValidationError", "Provenance",
        }
        self.assertEqual(set(src.safety.__all__), expected)
        for name in expected:
            self.assertTrue(hasattr(src.safety, name), name)

    def test_domain_never_imports_unmerged_or_forbidden_siblings(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name in ("test_safety.py", "dogfooding.py"):
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "src.transition", "src.trust", "src.value", "src.intent",
                "src.capability", "src.market", "src.interoperability",
                "src.liquidity", "src.reservation", "src.evidence",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_dogfooding_harness_imports_only_declared_dependency_domains(self) -> None:
        harness = (Path(__file__).parent / "dogfooding.py").read_text(encoding="utf-8")
        for forbidden in (
            "src.transition", "src.trust", "src.value", "src.capability",
            "src.market", "src.interoperability", "src.liquidity",
            "src.reservation", "src.evidence",
        ):
            self.assertNotIn(forbidden, harness, f"dogfooding.py references {forbidden}")

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_safety.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time", "datetime.now", "utcnow", "random", "uuid",
                "time.monotonic", "uuid4",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")


# ---------------------------------------------------------------------------
# versioned safety policy
# ---------------------------------------------------------------------------


class SafetyPolicyTests(unittest.TestCase):
    def test_build_active_policy_and_round_trip(self) -> None:
        policy = build_policy()
        self.assertIs(policy.state, SafetyPolicyState.ACTIVE)
        self.assertEqual(policy.policy_version, 1)
        restored = SafetyPolicy.from_json(policy.to_json())
        self.assertEqual(restored, policy)

    def test_risk_weights_must_sum_exactly_to_the_scale_total(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(risk_weights=[
                (RiskDimension.COUNTERPARTY, 3000),
                (RiskDimension.FRAUD, 4000),
                (RiskDimension.SETTLEMENT, 2000),
                (RiskDimension.OPERATIONAL, 999),
            ])

    def test_risk_weights_reject_duplicate_dimensions(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(risk_weights=[
                (RiskDimension.COUNTERPARTY, 5000),
                (RiskDimension.COUNTERPARTY, 5000),
            ])

    def test_risk_weights_reject_out_of_range_values(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(risk_weights=[(RiskDimension.COUNTERPARTY, -1)])
        with self.assertRaises(CoreValidationError):
            build_policy(risk_weights=[(RiskDimension.COUNTERPARTY, 10001)])

    def test_band_thresholds_must_strictly_increase(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(band_thresholds=(4000, 4000, 9000))
        with self.assertRaises(CoreValidationError):
            build_policy(band_thresholds=(4000, 9000, 7000))
        with self.assertRaises(CoreValidationError):
            build_policy(band_thresholds=(0, 7000, 9000))

    def test_decision_thresholds_must_strictly_increase(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(decision_thresholds=(3000, 6000, 6000))

    def test_fraud_severity_weights_must_cover_every_severity(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(fraud_severity_weights=[
                (FraudSeverity.LOW, 1000),
                (FraudSeverity.MEDIUM, 3000),
                (FraudSeverity.HIGH, 6000),
                (FraudSeverity.CRITICAL, 9000),
            ])

    def test_hold_window_and_systemic_counts_must_be_positive(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_policy(default_hold_window_seconds=0)
        with self.assertRaises(CoreValidationError):
            build_policy(systemic_breach_subject_count=0)

    def test_amend_replaces_spec_and_increments_policy_version(self) -> None:
        policy = build_policy()
        amended = policy.amend(
            provenance=prov("safety/policy-amend"),
            band_thresholds=(5000, 7000, 9000),
        )
        self.assertEqual(amended.policy_version, 2)
        self.assertIs(amended.state, SafetyPolicyState.ACTIVE)
        self.assertEqual(amended.spec.band_thresholds, (5000, 7000, 9000))
        self.assertEqual(amended.envelope.previous_version, 1)

    def test_retire_is_terminal(self) -> None:
        policy = build_policy().retire(provenance=prov("safety/policy-retire"))
        self.assertIs(policy.state, SafetyPolicyState.RETIRED)
        with self.assertRaises(CoreValidationError):
            policy.retire(provenance=prov("safety/policy-retire"))
        with self.assertRaises(CoreValidationError):
            policy.amend(provenance=prov("safety/policy-amend"),
                         band_thresholds=(5000, 7000, 9000))

    def test_evaluation_fails_closed_on_retired_policy(self) -> None:
        retired = build_policy().retire(provenance=prov("safety/policy-retire"))
        with self.assertRaises(CoreValidationError):
            build_assessment(retired)

    def test_policy_tamper_rejection(self) -> None:
        policy = build_policy()
        decoded = loads_canonical(policy.to_json())
        decoded["payload"]["band_thresholds"] = [1, 2, 3]
        with self.assertRaises(CoreValidationError):
            SafetyPolicy.from_json(canonical_json(decoded))


# ---------------------------------------------------------------------------
# risk assessments
# ---------------------------------------------------------------------------


class RiskAssessmentTests(unittest.TestCase):
    def test_weighted_aggregate_is_exact(self) -> None:
        assessment = build_assessment(build_policy())
        # 2000*3000 + 3000*4000 = 18,000,000 -> 1800 bps on the 10000 scale.
        self.assertEqual(assessment.spec.aggregate_score, 1800)
        self.assertIs(assessment.spec.band, RiskBand.LOW)
        self.assertIs(assessment.state.value, "RECORDED")

    def test_scores_are_bounded_by_the_explicit_scale(self) -> None:
        with self.assertRaises(CoreValidationError):
            RiskInput(RiskDimension.FRAUD, RISK_SCALE_MIN - 1, ("evidence/x",))
        with self.assertRaises(CoreValidationError):
            RiskInput(RiskDimension.FRAUD, RISK_SCALE_MAX + 1, ("evidence/x",))
        edge = RiskInput(RiskDimension.FRAUD, RISK_SCALE_MAX, ("evidence/x",))
        self.assertEqual(edge.score, RISK_SCALE_MAX)

    def test_inputs_require_evidence_references(self) -> None:
        with self.assertRaises(CoreValidationError):
            RiskInput(RiskDimension.FRAUD, 1000, ())

    def test_inputs_reject_duplicate_dimensions(self) -> None:
        policy = build_policy()
        with self.assertRaises(CoreValidationError):
            build_assessment(policy, inputs=[
                RiskInput(RiskDimension.FRAUD, 1000, ("evidence/a",)),
                RiskInput(RiskDimension.FRAUD, 2000, ("evidence/b",)),
            ])

    def test_inputs_reject_empty_input_sets(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_assessment(build_policy(), inputs=[])

    def test_inputs_fail_closed_on_dimensions_the_policy_does_not_cover(self) -> None:
        policy = build_policy()
        with self.assertRaises(CoreValidationError):
            build_assessment(policy, inputs=[
                RiskInput(RiskDimension.SYSTEMIC, 1000, ("evidence/systemic",)),
            ])

    def test_decision_requires_provenance_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            evaluate_risk(
                assessment_id="safety/risk/unit-2",
                subject_id="intent/pay-unit-1",
                inputs=[RiskInput(RiskDimension.FRAUD, 1000, ("evidence/a",))],
                policy=build_policy(),
                as_of=AS_OF,
                rounding=RoundingMode.HALF_UP,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance("principal/x", "safety/risk-evaluation", STAMP),
            )

    def test_banding_uses_exact_rational_comparison(self) -> None:
        policy = build_policy(
            risk_weights=[
                (RiskDimension.COUNTERPARTY, 5000),
                (RiskDimension.FRAUD, 5000),
            ],
        )
        # weighted sum = (6999 + 7001) * 5000 = 70,000,000 -> exactly the HIGH
        # threshold; the band is decided by exact cross-multiplication.
        assessment = build_assessment(policy, inputs=[
            RiskInput(RiskDimension.COUNTERPARTY, 6999, ("evidence/a",)),
            RiskInput(RiskDimension.FRAUD, 7001, ("evidence/b",)),
        ])
        self.assertEqual(assessment.spec.aggregate_score, 7000)
        self.assertIs(assessment.spec.band, RiskBand.HIGH)

    def test_banding_beats_rounded_aggregate_on_ties(self) -> None:
        policy = build_policy(
            risk_weights=[
                (RiskDimension.COUNTERPARTY, 5000),
                (RiskDimension.FRAUD, 5000),
            ],
        )
        # weighted = (6999 + 7000) * 5000 = 69,995,000 -> aggregate rounds up to
        # 7000 but the exact value is below the HIGH threshold: band MEDIUM.
        assessment = build_assessment(policy, inputs=[
            RiskInput(RiskDimension.COUNTERPARTY, 6999, ("evidence/a",)),
            RiskInput(RiskDimension.FRAUD, 7000, ("evidence/b",)),
        ])
        self.assertEqual(assessment.spec.aggregate_score, 7000)
        self.assertIs(assessment.spec.band, RiskBand.MEDIUM)

    def test_rounding_mode_is_explicit_and_discriminated(self) -> None:
        policy = build_policy(
            risk_weights=[
                (RiskDimension.COUNTERPARTY, 5000),
                (RiskDimension.FRAUD, 5000),
            ],
        )
        inputs = [
            RiskInput(RiskDimension.COUNTERPARTY, 1, ("evidence/a",)),
            RiskInput(RiskDimension.FRAUD, 2, ("evidence/b",)),
        ]
        up = build_assessment(policy, inputs=inputs, rounding=RoundingMode.HALF_UP)
        down = build_assessment(policy, inputs=inputs, rounding=RoundingMode.FLOOR)
        self.assertEqual(up.spec.aggregate_score, 2)
        self.assertEqual(down.spec.aggregate_score, 1)

    def test_evaluation_is_reproducible_byte_for_byte(self) -> None:
        policy = build_policy()
        first = build_assessment(policy)
        second = build_assessment(policy)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.integrity_hash, second.integrity_hash)

    def test_evaluation_is_input_order_independent(self) -> None:
        policy = build_policy()
        a = build_assessment(policy, inputs=[
            RiskInput(RiskDimension.COUNTERPARTY, 2000, ("evidence/cp-score",)),
            RiskInput(RiskDimension.FRAUD, 3000, ("evidence/fraud-score",)),
        ])
        b = build_assessment(policy, inputs=[
            RiskInput(RiskDimension.FRAUD, 3000, ("evidence/fraud-score",)),
            RiskInput(RiskDimension.COUNTERPARTY, 2000, ("evidence/cp-score",)),
        ])
        self.assertEqual(a.to_json(), b.to_json())

    def test_different_as_of_or_policy_version_changes_the_decision(self) -> None:
        policy = build_policy()
        base = build_assessment(policy)
        later = build_assessment(policy, as_of=LATER)
        self.assertNotEqual(base.integrity_hash, later.integrity_hash)
        amended = policy.amend(provenance=prov("safety/policy-amend"),
                               band_thresholds=(5000, 7000, 9000))
        revalued = build_assessment(amended)
        self.assertNotEqual(base.integrity_hash, revalued.integrity_hash)
        self.assertEqual(revalued.spec.policy_version, 2)

    def test_inputs_digest_is_recorded_and_stable(self) -> None:
        policy = build_policy()
        assessment = build_assessment(policy)
        expected = canonical_sha256({
            "inputs": [
                {"dimension": "COUNTERPARTY", "score": 2000,
                 "evidence_refs": ["evidence/cp-score"]},
                {"dimension": "FRAUD", "score": 3000,
                 "evidence_refs": ["evidence/fraud-score"]},
            ],
            "policy_id": "safety/policy/unit",
            "policy_version": 1,
            "as_of": AS_OF,
        })
        self.assertEqual(assessment.spec.inputs_digest, expected)

    def test_exposure_amount_is_optional_and_non_negative(self) -> None:
        policy = build_policy()
        with self.assertRaises(CoreValidationError):
            build_assessment(policy, exposure=Amount(USD, -1, 2))
        exposed = build_assessment(
            policy, exposure=Amount(USD, 500000, 2),
            assessment_id="safety/risk/unit-exposed",
        )
        self.assertEqual(exposed.spec.exposure, Amount(USD, 500000, 2))

    def test_round_trip_and_tamper_rejection(self) -> None:
        assessment = build_assessment(build_policy())
        restored = RiskAssessment.from_json(assessment.to_json())
        self.assertEqual(restored, assessment)
        decoded = loads_canonical(assessment.to_json())
        decoded["payload"]["aggregate_score"] = 9999
        with self.assertRaises(CoreValidationError):
            RiskAssessment.from_json(canonical_json(decoded))

    def test_envelope_tamper_rejection(self) -> None:
        assessment = build_assessment(build_policy())
        decoded = loads_canonical(assessment.to_json())
        decoded["envelope"]["state"] = "FORGED"
        with self.assertRaises(CoreValidationError):
            RiskAssessment.from_json(canonical_json(decoded))

    def test_scores_carry_their_evidence_references(self) -> None:
        assessment = build_assessment(build_policy())
        self.assertEqual(
            assessment.spec.scores[0].evidence_refs, ("evidence/cp-score",)
        )


# ---------------------------------------------------------------------------
# fraud signals
# ---------------------------------------------------------------------------


class FraudSignalTests(unittest.TestCase):
    def test_submit_records_the_signal_with_evidence(self) -> None:
        signal = build_signal("safety/fraud-signal/unit-1", "intent/pay-unit-1",
                              FraudSeverity.HIGH)
        self.assertIs(signal.state.value, "SUBMITTED")
        self.assertIs(signal.spec.kind, FraudKind.AUTHORIZED_PUSH_SCAM)
        self.assertEqual(signal.envelope.provenance.evidence_refs,
                         ("evidence/unit-test",))

    def test_submit_without_evidence_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            submit_fraud_signal(
                signal_id="safety/fraud-signal/unit-2",
                subject_id="intent/pay-unit-1",
                kind=FraudKind.COLLUSION,
                severity=FraudSeverity.LOW,
                observed_at="2026-09-03T00:05:00Z",
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance("principal/x", "safety/fraud-signal", STAMP),
            )

    def test_severity_and_kind_vocabularies_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_signal("s", "intent/x", "EXTREME")  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            build_signal("s", "intent/x", FraudSeverity.LOW,
                         kind="INSIDER_TRADING")  # type: ignore[arg-type]

    def test_observed_at_must_be_canonical_utc(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_signal("s", "intent/x", FraudSeverity.LOW,
                         observed_at="2026-09-03T00:05:00+01:00")

    def test_round_trip_and_tamper_rejection(self) -> None:
        signal = build_signal("safety/fraud-signal/unit-3", "intent/pay-unit-1",
                              FraudSeverity.MEDIUM)
        restored = FraudSignal.from_json(signal.to_json())
        self.assertEqual(restored, signal)
        decoded = loads_canonical(signal.to_json())
        decoded["payload"]["severity"] = "CRITICAL"
        with self.assertRaises(CoreValidationError):
            FraudSignal.from_json(canonical_json(decoded))


# ---------------------------------------------------------------------------
# fraud assessments
# ---------------------------------------------------------------------------


class FraudAssessmentTests(unittest.TestCase):
    def test_assessment_aggregates_signal_severities_exactly(self) -> None:
        assessment = build_fraud_assessment(build_policy(), signals=[
            build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.LOW),
            build_signal("safety/fraud-signal/b", "intent/pay-unit-1", FraudSeverity.MEDIUM),
        ])
        # LOW (1000) + MEDIUM (3000) = 4000 bps; the band boundary is
        # inclusive-lower (MEDIUM [medium, high)), matching the risk-side
        # exact-rational convention pinned by
        # test_banding_uses_exact_rational_comparison.
        self.assertEqual(assessment.spec.fraud_score, 4000)
        self.assertIs(assessment.spec.band, RiskBand.MEDIUM)
        self.assertIs(assessment.state.value, "RECORDED")

    def test_assessment_caps_the_score_at_the_scale_bound(self) -> None:
        assessment = build_fraud_assessment(build_policy(), signals=[
            build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.CRITICAL),
            build_signal("safety/fraud-signal/b", "intent/pay-unit-1", FraudSeverity.HIGH),
        ])
        self.assertEqual(assessment.spec.fraud_score, RISK_SCALE_MAX)
        self.assertIs(assessment.spec.band, RiskBand.CRITICAL)

    def test_assessment_requires_at_least_one_signal(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_fraud_assessment(build_policy(), signals=[])

    def test_assessment_rejects_foreign_subjects(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_fraud_assessment(build_policy(), signals=[
                build_signal("safety/fraud-signal/a", "intent/other-payment",
                             FraudSeverity.LOW),
            ])

    def test_assessment_rejects_future_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_fraud_assessment(build_policy(), signals=[
                build_signal("safety/fraud-signal/a", "intent/pay-unit-1",
                             FraudSeverity.LOW, observed_at=LATER),
            ])

    def test_assessment_rejects_duplicate_signals(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_fraud_assessment(build_policy(), signals=[
                build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.LOW),
                build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.HIGH),
            ])

    def test_assessment_fails_closed_on_retired_policy_and_missing_evidence(self) -> None:
        retired = build_policy().retire(provenance=prov("safety/policy-retire"))
        with self.assertRaises(CoreValidationError):
            build_fraud_assessment(retired)
        with self.assertRaises(CoreValidationError):
            assess_fraud(
                assessment_id="safety/fraud-assessment/unit-2",
                subject_id="intent/pay-unit-1",
                signals=[build_signal("s", "intent/pay-unit-1", FraudSeverity.LOW)],
                policy=build_policy(),
                as_of=AS_OF,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance("principal/x", "safety/fraud-assessment", STAMP),
            )

    def test_assessment_is_signal_order_independent(self) -> None:
        policy = build_policy()
        a = build_fraud_assessment(policy, signals=[
            build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.LOW),
            build_signal("safety/fraud-signal/b", "intent/pay-unit-1", FraudSeverity.MEDIUM),
        ])
        b = build_fraud_assessment(policy, signals=[
            build_signal("safety/fraud-signal/b", "intent/pay-unit-1", FraudSeverity.MEDIUM),
            build_signal("safety/fraud-signal/a", "intent/pay-unit-1", FraudSeverity.LOW),
        ])
        self.assertEqual(a.to_json(), b.to_json())

    def test_signals_digest_is_recorded(self) -> None:
        assessment = build_fraud_assessment(build_policy())
        expected = canonical_sha256({
            "signals": [{
                "signal_id": "safety/fraud-signal/unit-1",
                "kind": "AUTHORIZED_PUSH_SCAM",
                "severity": "LOW",
                "observed_at": "2026-09-03T00:05:00Z",
            }],
            "policy_id": "safety/policy/unit",
            "policy_version": 1,
            "as_of": AS_OF,
        })
        self.assertEqual(assessment.spec.signals_digest, expected)

    def test_round_trip_and_tamper_rejection(self) -> None:
        assessment = build_fraud_assessment(build_policy())
        restored = FraudAssessment.from_json(assessment.to_json())
        self.assertEqual(restored, assessment)
        decoded = loads_canonical(assessment.to_json())
        decoded["payload"]["fraud_score"] = 0
        with self.assertRaises(CoreValidationError):
            FraudAssessment.from_json(canonical_json(decoded))


# ---------------------------------------------------------------------------
# fraud decisions: the circuit-breaker lifecycle
# ---------------------------------------------------------------------------


class FraudDecisionLifecycleTests(unittest.TestCase):
    def _decision(self, state: FraudDecisionState = FraudDecisionState.ALLOW,
                  **overrides) -> FraudDecision:
        values = dict(
            decision_id="safety/fraud-decision/unit-1",
            subject_id="intent/pay-unit-1",
            assessment_ref="safety/fraud-assessment/unit-1",
            state=state,
            as_of=AS_OF,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("safety/fraud-decision"),
        )
        values.update(overrides)
        return create_fraud_decision(**values)

    def test_create_records_each_creation_verdict(self) -> None:
        for state in (FraudDecisionState.ALLOW, FraudDecisionState.STEP_UP,
                      FraudDecisionState.DELAY, FraudDecisionState.RECONFIRM,
                      FraudDecisionState.ESCALATE):
            self.assertIs(self._decision(state).state, state)
        blocked = self._decision(FraudDecisionState.BLOCKED)
        self.assertIs(blocked.state, FraudDecisionState.BLOCKED)
        self.assertIn(blocked.state, FRAUD_DECISION_TERMINAL_STATES)

    def test_release_is_not_a_creation_verdict(self) -> None:
        with self.assertRaises(CoreValidationError):
            self._decision(FraudDecisionState.RELEASED)

    def test_creation_requires_provenance_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            create_fraud_decision(
                decision_id="safety/fraud-decision/unit-2",
                subject_id="intent/pay-unit-1",
                assessment_ref="safety/fraud-assessment/unit-1",
                state=FraudDecisionState.ALLOW,
                as_of=AS_OF,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance("principal/x", "safety/fraud-decision", STAMP),
            )

    def test_held_creation_requires_an_active_window_containing_as_of(self) -> None:
        held = self._decision(
            FraudDecisionState.HELD,
            hold_from="2026-09-03T00:00:00Z",
            hold_until="2026-09-03T01:00:00Z",
        )
        self.assertIs(held.state, FraudDecisionState.HELD)
        with self.assertRaises(CoreValidationError):
            self._decision(FraudDecisionState.HELD)  # no window at all
        with self.assertRaises(CoreValidationError):
            self._decision(FraudDecisionState.HELD,
                           hold_from="2026-09-03T01:00:00Z",
                           hold_until="2026-09-03T02:00:00Z")  # as_of before window
        with self.assertRaises(CoreValidationError):
            self._decision(FraudDecisionState.HELD,
                           hold_from="2026-09-02T23:00:00Z",
                           hold_until="2026-09-03T00:10:00Z")  # half-open: as_of == until
        with self.assertRaises(CoreValidationError):
            self._decision(FraudDecisionState.HELD,
                           hold_from="2026-09-03T02:00:00Z",
                           hold_until="2026-09-03T01:00:00Z")  # inverted window

    def test_hold_command_transitions_non_held_states(self) -> None:
        for state in (FraudDecisionState.ALLOW, FraudDecisionState.STEP_UP,
                      FraudDecisionState.DELAY, FraudDecisionState.RECONFIRM,
                      FraudDecisionState.ESCALATE):
            held = hold_fraud_decision(
                self._decision(state, decision_id=f"safety/fraud-decision/{state.value}"),
                as_of="2026-09-03T00:12:00Z",
                hold_from="2026-09-03T00:12:00Z",
                hold_until="2026-09-03T01:12:00Z",
                provenance=prov("safety/fraud-hold"),
            )
            self.assertIs(held.state, FraudDecisionState.HELD)
            self.assertEqual(held.envelope.object_version, 2)
            self.assertEqual(held.envelope.previous_version, 1)

    def test_hold_command_requires_an_active_window(self) -> None:
        decision = self._decision()
        with self.assertRaises(CoreValidationError):
            hold_fraud_decision(
                decision,
                as_of="2026-09-03T00:12:00Z",
                hold_from="2026-09-03T02:00:00Z",
                hold_until="2026-09-03T03:00:00Z",
                provenance=prov("safety/fraud-hold"),
            )
        with self.assertRaises(CoreValidationError):
            hold_fraud_decision(
                decision,
                as_of="2026-09-02T00:00:00Z",  # time cannot run backwards
                hold_from="2026-09-03T00:12:00Z",
                hold_until="2026-09-03T01:12:00Z",
                provenance=prov("safety/fraud-hold"),
            )

    def test_hold_command_fails_from_held_or_terminal_states(self) -> None:
        held = self._decision(FraudDecisionState.HELD,
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        with self.assertRaises(CoreValidationError):
            hold_fraud_decision(
                held,
                as_of="2026-09-03T00:12:00Z",
                hold_from="2026-09-03T00:12:00Z",
                hold_until="2026-09-03T01:12:00Z",
                provenance=prov("safety/fraud-hold"),
            )
        blocked = self._decision(FraudDecisionState.BLOCKED)
        with self.assertRaises(CoreValidationError):
            hold_fraud_decision(
                blocked,
                as_of="2026-09-03T00:12:00Z",
                hold_from="2026-09-03T00:12:00Z",
                hold_until="2026-09-03T01:12:00Z",
                provenance=prov("safety/fraud-hold"),
            )

    def test_hold_active_predicate_uses_half_open_windows(self) -> None:
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/hold-window",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        self.assertTrue(hold_active(held, "2026-09-03T00:00:00Z"))
        self.assertTrue(hold_active(held, "2026-09-03T00:59:59Z"))
        self.assertFalse(hold_active(held, "2026-09-03T01:00:00Z"))
        self.assertFalse(hold_active(held, "2026-09-02T23:59:59Z"))
        self.assertFalse(hold_active(self._decision(), "2026-09-03T00:10:00Z"))

    def test_operator_release_requires_an_active_hold_window(self) -> None:
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/release-1",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        released = release_fraud_decision(
            held,
            as_of="2026-09-03T00:30:00Z",
            reason=FraudReleaseReason.OPERATOR,
            provenance=prov("safety/fraud-release"),
        )
        self.assertIs(released.state, FraudDecisionState.RELEASED)
        self.assertIs(released.spec.release_reason, FraudReleaseReason.OPERATOR)
        # the released window is retained as provenance of what was held
        self.assertEqual(released.spec.hold_from, "2026-09-03T00:00:00Z")
        with self.assertRaises(CoreValidationError):
            release_fraud_decision(
                held,
                as_of="2026-09-03T02:00:00Z",  # beyond the window: not an operator release
                reason=FraudReleaseReason.OPERATOR,
                provenance=prov("safety/fraud-release"),
            )

    def test_window_elapsed_release_requires_the_window_to_have_elapsed(self) -> None:
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/release-2",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        released = release_fraud_decision(
            held,
            as_of="2026-09-03T01:00:00Z",
            reason=FraudReleaseReason.WINDOW_ELAPSED,
            provenance=prov("safety/fraud-release"),
        )
        self.assertIs(released.spec.release_reason, FraudReleaseReason.WINDOW_ELAPSED)
        with self.assertRaises(CoreValidationError):
            release_fraud_decision(
                held,
                as_of="2026-09-03T00:30:00Z",  # still active: window has not elapsed
                reason=FraudReleaseReason.WINDOW_ELAPSED,
                provenance=prov("safety/fraud-release"),
            )

    def test_release_only_applies_to_holds(self) -> None:
        with self.assertRaises(CoreValidationError):
            release_fraud_decision(
                self._decision(),
                as_of="2026-09-03T00:30:00Z",
                reason=FraudReleaseReason.OPERATOR,
                provenance=prov("safety/fraud-release"),
            )
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/release-3",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        released = release_fraud_decision(
            held, as_of="2026-09-03T00:30:00Z",
            reason=FraudReleaseReason.OPERATOR,
            provenance=prov("safety/fraud-release"),
        )
        with self.assertRaises(CoreValidationError):  # terminal
            release_fraud_decision(
                released, as_of="2026-09-03T00:31:00Z",
                reason=FraudReleaseReason.OPERATOR,
                provenance=prov("safety/fraud-release"),
            )

    def test_release_rejects_unknown_reasons(self) -> None:
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/release-4",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        with self.assertRaises(CoreValidationError):
            release_fraud_decision(
                held, as_of="2026-09-03T00:30:00Z",
                reason="SUPERSEDED",  # type: ignore[arg-type]
                provenance=prov("safety/fraud-release"),
            )

    def test_block_command_from_issued_and_held_states(self) -> None:
        blocked = block_fraud_decision(
            self._decision(decision_id="safety/fraud-decision/block-1"),
            as_of="2026-09-03T00:20:00Z",
            provenance=prov("safety/fraud-block"),
        )
        self.assertIs(blocked.state, FraudDecisionState.BLOCKED)
        self.assertIsNone(blocked.spec.release_reason)
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/block-2",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        blocked_held = block_fraud_decision(
            held, as_of="2026-09-03T00:20:00Z",
            provenance=prov("safety/fraud-block"),
        )
        self.assertIs(blocked_held.state, FraudDecisionState.BLOCKED)
        self.assertEqual(blocked_held.spec.hold_from, "2026-09-03T00:00:00Z")

    def test_block_command_fails_from_terminal_states(self) -> None:
        blocked = self._decision(FraudDecisionState.BLOCKED)
        with self.assertRaises(CoreValidationError):
            block_fraud_decision(blocked, as_of=LATER,
                                 provenance=prov("safety/fraud-block"))
        held = self._decision(FraudDecisionState.HELD,
                              decision_id="safety/fraud-decision/block-3",
                              hold_from="2026-09-03T00:00:00Z",
                              hold_until="2026-09-03T01:00:00Z")
        released = release_fraud_decision(
            held, as_of="2026-09-03T00:30:00Z",
            reason=FraudReleaseReason.OPERATOR,
            provenance=prov("safety/fraud-release"),
        )
        with self.assertRaises(CoreValidationError):
            block_fraud_decision(released, as_of=LATER,
                                 provenance=prov("safety/fraud-block"))

    def test_commands_cannot_move_time_backwards(self) -> None:
        decision = self._decision()
        with self.assertRaises(CoreValidationError):
            block_fraud_decision(decision, as_of="2026-09-03T00:09:59Z",
                                 provenance=prov("safety/fraud-block"))

    def test_version_chain_and_provenance_are_preserved(self) -> None:
        held = hold_fraud_decision(
            self._decision(decision_id="safety/fraud-decision/chain"),
            as_of="2026-09-03T00:12:00Z",
            hold_from="2026-09-03T00:12:00Z",
            hold_until="2026-09-03T01:12:00Z",
            provenance=Provenance("principal/fraud-ops", "safety/fraud-hold", STAMP,
                                  ("evidence/hold-review",)),
        )
        released = release_fraud_decision(
            held, as_of="2026-09-03T00:40:00Z",
            reason=FraudReleaseReason.OPERATOR,
            provenance=Provenance("principal/fraud-ops", "safety/fraud-release", STAMP,
                                  ("evidence/release-review",)),
        )
        self.assertEqual(released.envelope.object_version, 3)
        self.assertEqual(released.envelope.previous_version, 2)
        self.assertEqual(held.envelope.previous_version, 1)
        self.assertEqual(released.envelope.provenance.evidence_refs,
                         ("evidence/release-review",))
        self.assertEqual(held.envelope.provenance.issuer, "principal/fraud-ops")
        self.assertEqual(released.spec.as_of, "2026-09-03T00:40:00Z")

    def test_policy_derived_decisions_follow_thresholds(self) -> None:
        policy = build_policy()

        def decide_for_score(signals: list[FraudSignal]) -> FraudDecision:
            assessment = assess_fraud(
                assessment_id="safety/fraud-assessment/derived",
                subject_id="intent/pay-unit-1",
                signals=signals,
                policy=policy,
                as_of=AS_OF,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov("safety/fraud-assessment"),
            )
            return decide_fraud(
                decision_id="safety/fraud-decision/derived",
                assessment=assessment,
                policy=policy,
                as_of=AS_OF,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov("safety/fraud-decision"),
            )

        allowed = decide_for_score([
            build_signal("safety/fraud-signal/low-1", "intent/pay-unit-1", FraudSeverity.LOW),
        ])
        self.assertIs(allowed.state, FraudDecisionState.ALLOW)  # 1000 < 3000
        stepped = decide_for_score([
            build_signal("safety/fraud-signal/med-1", "intent/pay-unit-1", FraudSeverity.MEDIUM),
        ])
        self.assertIs(stepped.state, FraudDecisionState.STEP_UP)  # 3000 == step-up
        held = decide_for_score([
            build_signal("safety/fraud-signal/high-1", "intent/pay-unit-1", FraudSeverity.HIGH),
        ])
        self.assertIs(held.state, FraudDecisionState.HELD)  # 6000 == hold
        self.assertEqual(held.spec.hold_from, AS_OF)
        self.assertEqual(held.spec.hold_until, "2026-09-03T01:10:00Z")
        blocked = decide_for_score([
            build_signal("safety/fraud-signal/crit-1", "intent/pay-unit-1", FraudSeverity.CRITICAL),
        ])
        self.assertIs(blocked.state, FraudDecisionState.BLOCKED)  # 9000 >= block

    def test_policy_derived_decision_pins_subject_and_assessment(self) -> None:
        policy = build_policy()
        assessment = build_fraud_assessment(policy)
        decision = decide_fraud(
            decision_id="safety/fraud-decision/derived-2",
            assessment=assessment,
            policy=policy,
            as_of=AS_OF,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("safety/fraud-decision"),
        )
        self.assertEqual(decision.spec.subject_id, assessment.spec.subject_id)
        self.assertEqual(decision.spec.assessment_ref, assessment.object_id)

    def test_policy_derived_decision_rejects_time_travel(self) -> None:
        policy = build_policy()
        assessment = build_fraud_assessment(policy)
        with self.assertRaises(CoreValidationError):
            decide_fraud(
                decision_id="safety/fraud-decision/derived-3",
                assessment=assessment,
                policy=policy,
                as_of="2026-09-03T00:09:59Z",
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov("safety/fraud-decision"),
            )

    def test_round_trip_and_tamper_rejection(self) -> None:
        held = hold_fraud_decision(
            self._decision(decision_id="safety/fraud-decision/round-trip"),
            as_of="2026-09-03T00:12:00Z",
            hold_from="2026-09-03T00:12:00Z",
            hold_until="2026-09-03T01:12:00Z",
            provenance=prov("safety/fraud-hold"),
        )
        restored = FraudDecision.from_json(held.to_json())
        self.assertEqual(restored, held)
        decoded = loads_canonical(held.to_json())
        decoded["payload"]["hold_until"] = "2026-09-04T01:12:00Z"
        with self.assertRaises(CoreValidationError):
            FraudDecision.from_json(canonical_json(decoded))

    def test_held_payload_is_state_consistent_on_decode(self) -> None:
        decision = self._decision(decision_id="safety/fraud-decision/consistent")
        from src.core.envelope import ObjectEnvelope

        # A HELD envelope paired with a windowless payload fails closed.
        forged_envelope = ObjectEnvelope(
            object_id=decision.envelope.object_id,
            object_type=FRAUD_DECISION_OBJECT_TYPE,
            object_version=1,
            environment_id=ENV,
            domain_id=DOMAIN,
            schema_version=SAFETY_SCHEMA_VERSION,
            protocol_version=SAFETY_PROTOCOL_VERSION,
            state="HELD",
            provenance=decision.envelope.provenance,
        ).with_integrity_hash()
        with self.assertRaises(CoreValidationError):
            FraudDecision.from_dict({
                "envelope": forged_envelope,
                "payload": decision.spec.to_dict(),
                "integrity_hash": decision.integrity_hash,
            })


# ---------------------------------------------------------------------------
# compliance: constraint precedence and the assessment lifecycle
# ---------------------------------------------------------------------------


class ComplianceConstraintTests(unittest.TestCase):
    def test_constraint_validation_fails_closed(self) -> None:
        base = dict(
            constraint_id="safety/constraint/x",
            requirement="sanctions_screening",
            precedence=ConstraintPrecedence.LEGAL,
            outcome=ConstraintOutcome.SATISFIED,
            version=1,
            effective_from="2026-09-01T00:00:00Z",
            effective_until="2026-12-31T00:00:00Z",
            evidence_refs=("evidence/constraint/x",),
        )
        ComplianceConstraint(**base)
        bad = dict(base, evidence_refs=())
        with self.assertRaises(CoreValidationError):
            ComplianceConstraint(**bad)
        bad = dict(base, version=0)
        with self.assertRaises(CoreValidationError):
            ComplianceConstraint(**bad)
        bad = dict(base, precedence="JURISPRUDENTIAL")  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            ComplianceConstraint(**bad)
        bad = dict(base, outcome="PENDING")  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            ComplianceConstraint(**bad)
        bad = dict(base, effective_from="2026-12-31T00:00:00Z",
                   effective_until="2026-09-01T00:00:00Z")
        with self.assertRaises(CoreValidationError):
            ComplianceConstraint(**bad)

    def test_constraint_round_trip(self) -> None:
        constraint = build_constraint("safety/constraint/rt", "transaction_limit",
                                      ConstraintPrecedence.CONTRACTUAL,
                                      ConstraintOutcome.VIOLATED, version=4)
        restored = ComplianceConstraint.from_dict(constraint.to_dict())
        self.assertEqual(restored, constraint)


class ComplianceLifecycleTests(unittest.TestCase):
    def test_request_creates_requested_state_without_result(self) -> None:
        request = build_compliance_request()
        self.assertIs(request.state, ComplianceAssessmentState.REQUESTED)
        self.assertIsNone(request.spec.result)
        self.assertIsNone(request.spec.invalidation)

    def test_request_requires_provenance_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            request_compliance_assessment(
                assessment_id="safety/compliance/unit-2",
                subject_id="intent/pay-unit-1",
                jurisdiction="jurisdiction/EU",
                constraints=[
                    build_constraint("safety/constraint/sanctions", "sanctions_screening",
                                     ConstraintPrecedence.REGULATORY,
                                     ConstraintOutcome.SATISFIED),
                ],
                as_of=AS_OF,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance("principal/x", "safety/compliance-request", STAMP),
            )

    def test_request_requires_at_least_one_constraint(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_compliance_request(constraints=[])

    def test_constraints_must_be_effective_at_the_request_instant(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_compliance_request(constraints=[
                build_constraint("safety/constraint/future", "sanctions_screening",
                                 ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED,
                                 effective_from="2026-09-04T00:00:00Z",
                                 effective_until="2026-12-31T00:00:00Z"),
            ])
        with self.assertRaises(CoreValidationError):
            build_compliance_request(constraints=[
                build_constraint("safety/constraint/expired", "sanctions_screening",
                                 ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED,
                                 effective_from="2026-09-01T00:00:00Z",
                                 effective_until=AS_OF),  # half-open: as_of == until is out
            ])
        ok = build_compliance_request(constraints=[
            build_constraint("safety/constraint/edge", "sanctions_screening",
                             ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED,
                             effective_from=AS_OF),
        ], assessment_id="safety/compliance/edge")
        self.assertIs(ok.state, ComplianceAssessmentState.REQUESTED)

    def test_ambiguous_precedence_fails_closed_at_request_time(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_compliance_request(constraints=[
                build_constraint("safety/constraint/a", "sanctions_screening",
                                 ConstraintPrecedence.POLICY, ConstraintOutcome.SATISFIED),
                build_constraint("safety/constraint/b", "sanctions_screening",
                                 ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
            ])

    def test_duplicate_constraint_ids_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_compliance_request(constraints=[
                build_constraint("safety/constraint/dup", "sanctions_screening",
                                 ConstraintPrecedence.POLICY, ConstraintOutcome.SATISFIED),
                build_constraint("safety/constraint/dup", "transaction_limit",
                                 ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
            ])

    def test_record_result_satisfied(self) -> None:
        request = build_compliance_request()
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        self.assertIs(recorded.state, ComplianceAssessmentState.RECORDED)
        self.assertIs(recorded.spec.result.verdict, ComplianceVerdict.SATISFIED)
        self.assertIsNone(recorded.spec.result.binding_constraint_id)
        self.assertEqual(len(recorded.spec.result.resolution), 2)
        self.assertEqual(recorded.spec.result.recorded_as_of, "2026-09-03T00:10:30Z")

    def test_higher_precedence_overrides_lower_deterministically(self) -> None:
        request = build_compliance_request(constraints=[
            build_constraint("safety/constraint/policy-watchlist", "sanctions_screening",
                             ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/regulatory-clear", "sanctions_screening",
                             ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
        ])
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        result = recorded.spec.result
        self.assertIs(result.verdict, ComplianceVerdict.SATISFIED)
        resolution = result.resolution[0]
        self.assertEqual(resolution.requirement, "sanctions_screening")
        self.assertEqual(resolution.authoritative_constraint_id,
                         "safety/constraint/regulatory-clear")
        self.assertEqual(len(resolution.overridden), 1)
        override = resolution.overridden[0]
        self.assertEqual(override.constraint_id, "safety/constraint/policy-watchlist")
        self.assertEqual(override.overridden_by, "safety/constraint/regulatory-clear")
        self.assertIs(override.outcome, ConstraintOutcome.VIOLATED)

    def test_violated_higher_precedence_cannot_be_overridden(self) -> None:
        request = build_compliance_request(constraints=[
            build_constraint("safety/constraint/legal-hit", "sanctions_screening",
                             ConstraintPrecedence.LEGAL, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/policy-clear", "sanctions_screening",
                             ConstraintPrecedence.POLICY, ConstraintOutcome.SATISFIED),
        ])
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        result = recorded.spec.result
        self.assertIs(result.verdict, ComplianceVerdict.BLOCKED)
        self.assertEqual(result.binding_constraint_id, "safety/constraint/legal-hit")

    def test_binding_constraint_picks_highest_precedence_then_lowest_id(self) -> None:
        request = build_compliance_request(constraints=[
            build_constraint("safety/constraint/z-reg", "sanctions_screening",
                             ConstraintPrecedence.REGULATORY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/a-reg", "transaction_limit",
                             ConstraintPrecedence.REGULATORY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/legal-clear", "sanctions_screening",
                             ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
        ])
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        # LEGAL is authoritative on sanctions_screening (satisfied); both
        # REGULATORY constraints bind on their own requirements; the binding
        # pick is the lexicographically smallest violated authoritative id.
        self.assertIs(recorded.spec.result.verdict, ComplianceVerdict.BLOCKED)
        self.assertEqual(recorded.spec.result.binding_constraint_id,
                         "safety/constraint/a-reg")

    def test_requirements_are_resolved_independently(self) -> None:
        request = build_compliance_request(constraints=[
            build_constraint("safety/constraint/legal-clear", "sanctions_screening",
                             ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
            build_constraint("safety/constraint/policy-hit", "sanctions_screening",
                             ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/contract-hit", "reporting_obligation",
                             ConstraintPrecedence.CONTRACTUAL, ConstraintOutcome.VIOLATED),
        ])
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        self.assertIs(recorded.spec.result.verdict, ComplianceVerdict.BLOCKED)
        self.assertEqual(recorded.spec.result.binding_constraint_id,
                         "safety/constraint/contract-hit")
        by_requirement = {r.requirement: r for r in recorded.spec.result.resolution}
        self.assertEqual(len(by_requirement), 2)
        self.assertEqual(
            by_requirement["sanctions_screening"].authoritative_constraint_id,
            "safety/constraint/legal-clear",
        )

    def test_resolution_is_constraint_order_independent(self) -> None:
        constraints = [
            build_constraint("safety/constraint/a", "sanctions_screening",
                            ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/b", "sanctions_screening",
                            ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
            build_constraint("safety/constraint/c", "transaction_limit",
                            ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
        ]
        # Same assessment id + same as_of + same provenance: only the input
        # order of the constraint set differs, so the canonicalized records
        # must be byte-identical (envelope, payload and integrity hashes).
        first = record_compliance_result(
            build_compliance_request(constraints=constraints,
                                     assessment_id="safety/compliance/order"),
            as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        second = record_compliance_result(
            build_compliance_request(constraints=list(reversed(constraints)),
                                     assessment_id="safety/compliance/order"),
            as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        self.assertEqual(first.to_json(), second.to_json())

    def test_record_result_is_reproducible_and_digest_stable(self) -> None:
        request = build_compliance_request()
        first = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        again = record_compliance_result(
            build_compliance_request(), as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        self.assertEqual(first.to_json(), again.to_json())
        expected = canonical_sha256({
            "constraints": [c.to_dict() for c in sorted(
                request.spec.constraints, key=lambda c: c.constraint_id)],
            "subject_id": "intent/pay-unit-1",
            "jurisdiction": "jurisdiction/EU",
            "as_of": AS_OF,
        })
        self.assertEqual(first.spec.constraint_set_digest, expected)

    def test_record_result_rejects_time_travel_and_wrong_states(self) -> None:
        request = build_compliance_request()
        with self.assertRaises(CoreValidationError):
            record_compliance_result(request, as_of="2026-09-03T00:09:59Z",
                                     provenance=prov("safety/compliance-record"))
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        with self.assertRaises(CoreValidationError):
            record_compliance_result(recorded, as_of="2026-09-03T00:11:00Z",
                                     provenance=prov("safety/compliance-record"))
        invalidated = invalidate_compliance_result(
            build_compliance_request(assessment_id="safety/compliance/unit-3"),
            as_of="2026-09-03T00:12:00Z", reason="constraint set superseded",
            provenance=prov("safety/compliance-invalidate"),
        )
        with self.assertRaises(CoreValidationError):
            record_compliance_result(invalidated, as_of="2026-09-03T00:13:00Z",
                                     provenance=prov("safety/compliance-record"))

    def test_record_result_requires_provenance_evidence(self) -> None:
        request = build_compliance_request()
        with self.assertRaises(CoreValidationError):
            record_compliance_result(
                request, as_of="2026-09-03T00:10:30Z",
                provenance=Provenance("principal/x", "safety/compliance-record", STAMP),
            )

    def test_invalidate_result_is_terminal_and_keeps_the_record(self) -> None:
        request = build_compliance_request()
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        invalidated = invalidate_compliance_result(
            recorded, as_of="2026-09-03T00:12:00Z", reason="screening evidence revoked",
            provenance=prov("safety/compliance-invalidate"),
        )
        self.assertIs(invalidated.state, ComplianceAssessmentState.INVALIDATED)
        self.assertIsNotNone(invalidated.spec.result)  # the record is retained
        self.assertEqual(invalidated.spec.invalidation.reason, "screening evidence revoked")
        self.assertEqual(invalidated.spec.invalidation.invalidated_as_of,
                         "2026-09-03T00:12:00Z")
        with self.assertRaises(CoreValidationError):
            invalidate_compliance_result(
                invalidated, as_of="2026-09-03T00:13:00Z", reason="again",
                provenance=prov("safety/compliance-invalidate"),
            )

    def test_invalidate_requested_assessment_without_result(self) -> None:
        request = build_compliance_request()
        invalidated = invalidate_compliance_result(
            request, as_of="2026-09-03T00:12:00Z", reason="abandoned request",
            provenance=prov("safety/compliance-invalidate"),
        )
        self.assertIs(invalidated.state, ComplianceAssessmentState.INVALIDATED)
        self.assertIsNone(invalidated.spec.result)
        self.assertIsNotNone(invalidated.spec.invalidation)

    def test_compliance_round_trip_all_states(self) -> None:
        request = build_compliance_request()
        self.assertEqual(ComplianceAssessment.from_json(request.to_json()), request)
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        self.assertEqual(ComplianceAssessment.from_json(recorded.to_json()), recorded)
        invalidated = invalidate_compliance_result(
            recorded, as_of="2026-09-03T00:12:00Z", reason="revoked",
            provenance=prov("safety/compliance-invalidate"),
        )
        self.assertEqual(ComplianceAssessment.from_json(invalidated.to_json()), invalidated)

    def test_compliance_tamper_rejection(self) -> None:
        recorded = record_compliance_result(
            build_compliance_request(), as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        decoded = loads_canonical(recorded.to_json())
        decoded["payload"]["result"]["verdict"] = "BLOCKED"
        with self.assertRaises(CoreValidationError):
            ComplianceAssessment.from_json(canonical_json(decoded))

    def test_state_payload_consistency_fails_closed(self) -> None:
        request = build_compliance_request()
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        # A REQUESTED envelope paired with a recorded result payload fails.
        with self.assertRaises(CoreValidationError):
            ComplianceAssessment(
                envelope=request.envelope,
                spec=recorded.spec,
                integrity_hash=recorded.integrity_hash,
            )
        # A RECORDED envelope paired with a resultless payload fails.
        with self.assertRaises(CoreValidationError):
            ComplianceAssessment(
                envelope=recorded.envelope,
                spec=request.spec,
                integrity_hash=request.integrity_hash,
            )

    def test_result_and_resolution_records_round_trip(self) -> None:
        request = build_compliance_request(constraints=[
            build_constraint("safety/constraint/policy-hit", "sanctions_screening",
                             ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
            build_constraint("safety/constraint/regulatory-clear", "sanctions_screening",
                             ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
        ])
        recorded = record_compliance_result(
            request, as_of="2026-09-03T00:10:30Z",
            provenance=prov("safety/compliance-record"),
        )
        result = recorded.spec.result
        restored = ComplianceResult.from_dict(result.to_dict())
        self.assertEqual(restored, result)
        resolution = result.resolution[0]
        self.assertEqual(
            ResolutionRecord.from_dict(resolution.to_dict()), resolution)
        self.assertEqual(
            OverrideRecord.from_dict(resolution.overridden[0].to_dict()),
            resolution.overridden[0],
        )
        record = InvalidationRecord("reason", "2026-09-03T00:12:00Z")
        self.assertEqual(InvalidationRecord.from_dict(record.to_dict()), record)


# ---------------------------------------------------------------------------
# systemic exposure interface
# ---------------------------------------------------------------------------


class SystemicExposureTests(unittest.TestCase):
    def _assessment(self, subject: str, inputs: list[RiskInput],
                    exposure: Amount | None = None,
                    as_of: str = AS_OF) -> RiskAssessment:
        return evaluate_risk(
            assessment_id=f"safety/risk/systemic-{subject}",
            subject_id=subject,
            inputs=inputs,
            policy=build_policy(),
            as_of=as_of,
            rounding=RoundingMode.HALF_UP,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("safety/risk-evaluation"),
            exposure=exposure,
        )

    def test_summary_aggregates_bands_and_exposure_exactly(self) -> None:
        # Weighted aggregates under the default policy (COUNTERPARTY 3000 bps,
        # FRAUD 4000 bps, band thresholds 4000/7000/9000, inclusive-lower
        # banding pinned by test_banding_uses_exact_rational_comparison):
        # a -> 2000*0.3 = 600 LOW; b -> 10000*0.4 = 4000 MEDIUM;
        # c -> 10000*0.3 + 10000*0.4 = 7000 HIGH.
        policy = build_policy(systemic_exposure_cap=Amount(USD, 2500000, 2))
        assessments = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 2000, ("evidence/a",)),
            ], Amount(USD, 500000, 2)),
            self._assessment("principal/b", [
                RiskInput(RiskDimension.FRAUD, 10000, ("evidence/b",)),
            ], Amount(USD, 1250000, 2)),
            self._assessment("principal/c", [
                RiskInput(RiskDimension.COUNTERPARTY, 10000, ("evidence/c",)),
                RiskInput(RiskDimension.FRAUD, 10000, ("evidence/c",)),
            ], None),
        ]
        summary = assess_systemic_exposure(assessments, policy=policy, as_of=LATER)
        self.assertEqual(summary.subject_count, 3)
        self.assertEqual(summary.low_count, 1)
        self.assertEqual(summary.medium_count, 1)
        self.assertEqual(summary.high_count, 1)
        self.assertEqual(summary.critical_count, 0)
        self.assertEqual(summary.max_aggregate_score, 7000)
        self.assertEqual(summary.total_exposure, Amount(USD, 1750000, 2))
        self.assertFalse(summary.breached)
        self.assertEqual(summary.breach_reasons, ())
        self.assertEqual(summary.as_of, LATER)

    def test_breach_by_high_risk_subject_count(self) -> None:
        policy = build_policy(systemic_breach_subject_count=2)
        # Both subjects aggregate to 7000 bps (HIGH) under the default
        # weights: 10000*0.3 + 10000*0.4 = 7000 >= the 7000 HIGH threshold.
        assessments = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 10000, ("evidence/a",)),
                RiskInput(RiskDimension.FRAUD, 10000, ("evidence/a",)),
            ]),
            self._assessment("principal/b", [
                RiskInput(RiskDimension.COUNTERPARTY, 10000, ("evidence/b",)),
                RiskInput(RiskDimension.FRAUD, 10000, ("evidence/b",)),
            ]),
        ]
        summary = assess_systemic_exposure(assessments, policy=policy, as_of=LATER)
        self.assertTrue(summary.breached)
        self.assertIn(SystemicBreachReason.HIGH_RISK_SUBJECT_COUNT, summary.breach_reasons)

    def test_breach_by_aggregate_exposure_cap(self) -> None:
        policy = build_policy(systemic_exposure_cap=Amount(USD, 1000000, 2))
        assessments = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/a",)),
            ], Amount(USD, 600000, 2)),
            self._assessment("principal/b", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/b",)),
            ], Amount(USD, 500000, 2)),
        ]
        summary = assess_systemic_exposure(assessments, policy=policy, as_of=LATER)
        self.assertTrue(summary.breached)
        self.assertIn(SystemicBreachReason.AGGREGATE_EXPOSURE, summary.breach_reasons)
        self.assertEqual(summary.total_exposure, Amount(USD, 1100000, 2))

    def test_mixed_currency_exposure_fails_closed(self) -> None:
        policy = build_policy(systemic_exposure_cap=Amount(USD, 1000000, 2))
        assessments = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/a",)),
            ], Amount(USD, 100, 2)),
            self._assessment("principal/b", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/b",)),
            ], Amount(EUR, 100, 2)),
        ]
        with self.assertRaises(CoreValidationError):
            assess_systemic_exposure(assessments, policy=policy, as_of=LATER)

    def test_summary_is_order_independent_and_reproducible(self) -> None:
        policy = build_policy(systemic_exposure_cap=Amount(USD, 1000000, 2))
        assessments = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/a",)),
            ], Amount(USD, 600000, 2)),
            self._assessment("principal/b", [
                RiskInput(RiskDimension.FRAUD, 3000, ("evidence/b",)),
            ], Amount(USD, 500000, 2)),
        ]
        first = assess_systemic_exposure(assessments, policy=policy, as_of=LATER)
        second = assess_systemic_exposure(list(reversed(assessments)), policy=policy,
                                          as_of=LATER)
        self.assertEqual(first.digest(), second.digest())

    def test_duplicate_subjects_and_time_travel_fail_closed(self) -> None:
        policy = build_policy()
        duplicate = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/a",)),
            ]),
            self._assessment("principal/a", [
                RiskInput(RiskDimension.FRAUD, 1000, ("evidence/b",)),
            ]),
        ]
        with self.assertRaises(CoreValidationError):
            assess_systemic_exposure(duplicate, policy=policy, as_of=LATER)
        # Time travel: the assessment is recorded at LATER; aggregating at
        # the earlier AS_OF instant must fail closed.
        future = [
            self._assessment("principal/a", [
                RiskInput(RiskDimension.COUNTERPARTY, 1000, ("evidence/a",)),
            ], as_of=LATER),
        ]
        with self.assertRaises(CoreValidationError):
            assess_systemic_exposure(future, policy=policy, as_of=AS_OF)

    def test_empty_input_yields_an_unbreached_summary(self) -> None:
        summary = assess_systemic_exposure([], policy=build_policy(), as_of=LATER)
        self.assertEqual(summary.subject_count, 0)
        self.assertFalse(summary.breached)
        self.assertIsNone(summary.total_exposure)

    def test_interface_only_no_durable_federation_objects(self) -> None:
        summary = assess_systemic_exposure([], policy=build_policy(), as_of=LATER)
        self.assertIsInstance(summary, SystemicExposureSummary)
        self.assertFalse(hasattr(summary, "envelope"))
        self.assertFalse(hasattr(summary, "to_json"))
        self.assertTrue(hasattr(summary, "digest"))
        self.assertIsInstance(summary.digest(), str)

    def test_summary_fails_closed_on_retired_policy(self) -> None:
        retired = build_policy().retire(provenance=prov("safety/policy-retire"))
        with self.assertRaises(CoreValidationError):
            assess_systemic_exposure([], policy=retired, as_of=LATER)


# ---------------------------------------------------------------------------
# dogfooding
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    def test_transcript_is_deterministic(self) -> None:
        from src.safety.dogfooding import build_transcript

        first_transcript, first_digest = build_transcript()
        second_transcript, second_digest = build_transcript()
        self.assertEqual(first_transcript, second_transcript)
        self.assertEqual(first_digest, second_digest)

    def test_transcript_covers_the_four_payment_cases(self) -> None:
        from src.safety.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("DOGFOOD-017: PASS", transcript)
        for marker in ("case=approved", "case=stepped-up",
                       "case=held", "case=blocked"):
            self.assertIn(marker, transcript)
        self.assertIn("state=HELD", transcript)
        self.assertIn("verdict=BLOCKED", transcript)
        self.assertIn("verdict=SATISFIED", transcript)

    def test_main_returns_the_digest(self) -> None:
        from src.safety.dogfooding import build_transcript, main

        _, expected = build_transcript()
        self.assertEqual(main(), expected)


if __name__ == "__main__":  # pragma: no cover - manual suite run
    unittest.main()
