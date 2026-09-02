"""DOGFOOD-017: four payment cases through the safety decision plane.

The dogfooding/conformance contract of WORK-017: drive four real payments
(approved, stepped-up, held by the fraud circuit breaker, hard-blocked
by compliance) through the full safety decision path — policy evaluation,
risk assessment, fraud signals -> fraud assessment -> fraud decision,
compliance request -> recorded result — and print a deterministic
transcript. Each case carries full provenance, explicit evidence
references and an explicit ``as_of`` instant.

The harness is a real supported product path of this package: it
consumes the public boundary only (plus the merged intent domain to
build the payment fixtures, mirroring the sibling dogfooding
convention). It is fully deterministic: two clean-process runs produce
byte-identical output and the same SHA-256 digest. The safety plane is
advisory/control-signalling only: no ledger, hold or posting is touched
and no fund moves anywhere in this experiment.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.serialization import canonical_sha256
from src.money import Amount as MoneyAmount, RoundingMode, get_currency

from . import (
    ComplianceAssessment,
    ComplianceConstraint,
    ComplianceVerdict,
    ConstraintOutcome,
    ConstraintPrecedence,
    FraudDecisionState,
    FraudKind,
    FraudSeverity,
    RiskBand,
    RiskDimension,
    RiskInput,
    SafetyPolicy,
    SafetyPolicySpec,
    assess_fraud,
    assess_systemic_exposure,
    decide_fraud,
    evaluate_risk,
    hold_active,
    record_compliance_result,
    request_compliance_assessment,
    submit_fraud_signal,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-03T00:00:00Z"
DEADLINE = "2026-09-03T12:00:00Z"
ASSET = "asset/USD"
USD = get_currency("USD")
ISSUER = "principal/safety-operator"
CASES = ("approved", "stepped-up", "held", "blocked")
CASE_AS_OF = {
    "approved": "2026-09-03T00:10:00Z",
    "stepped-up": "2026-09-03T00:20:00Z",
    "held": "2026-09-03T00:30:00Z",
    "blocked": "2026-09-03T00:40:00Z",
}
CASE_AMOUNTS = {
    "approved": 1250000,    # 12,500.00 USD (minor units)
    "stepped-up": 900000,   # 9,000.00 USD
    "held": 4000000,        # 40,000.00 USD
    "blocked": 75000,       # 750.00 USD
}
EXPECTED_FRAUD_STATE = {
    "approved": FraudDecisionState.ALLOW,
    "stepped-up": FraudDecisionState.STEP_UP,
    "held": FraudDecisionState.HELD,
    "blocked": FraudDecisionState.ALLOW,
}
EXPECTED_COMPLIANCE_VERDICT = {
    "approved": ComplianceVerdict.SATISFIED,
    "stepped-up": ComplianceVerdict.SATISFIED,
    "held": ComplianceVerdict.SATISFIED,
    "blocked": ComplianceVerdict.BLOCKED,
}


def prov(source: str, evidence: str) -> Provenance:
    return Provenance(
        issuer=ISSUER,
        source=source,
        recorded_at=STAMP,
        evidence_refs=(evidence,),
    )


def build_policy() -> SafetyPolicy:
    return SafetyPolicy.build(
        object_id="safety/policy/w017-dogfood",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=SafetyPolicySpec.build(
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
            systemic_exposure_cap=MoneyAmount(USD, 2500000, 2),
        ),
        provenance=prov("safety/policy", "evidence/w017-policy-baseline"),
    )


def _intent_fixture(case: str):
    """Build the real payment intent for one case (merged intent domain)."""
    from src.intent import (
        Amount,
        EconomicSlack,
        FundingBinding,
        FundingSourceRef,
        FulfillmentPolicy,
        Intent,
        IntentSpec,
        OptimizationObjective,
        PolicySpec,
        SlackSpec,
    )

    policy = FulfillmentPolicy.build(
        object_id="intent/policy/w017-safety-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=PolicySpec(
            objectives=(
                OptimizationObjective.RISK,
                OptimizationObjective.COST,
            ),
            allow_split=True,
            allow_asset_substitution=True,
            allow_route_substitution=True,
        ),
        provenance=prov("intent/fulfillment-policy", "evidence/w017-intent-policy"),
        correlation_id="corr/w017-safety-dogfood",
    )
    amount = Amount(CASE_AMOUNTS[case], 2, ASSET)
    slack_spec = SlackSpec(
        amount_min=Amount(75000, 2, ASSET),
        amount_max=Amount(4000000, 2, ASSET),
        earliest_completion="2026-09-03T00:00:00Z",
        latest_completion=DEADLINE,
        max_payment_count=2,
        substitute_assets=("asset/USDC",),
    )
    intent = Intent.build(
        object_id=f"intent/pay-w017-{case}",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=IntentSpec(
            destination_id="endpoint/merchant-42",
            amount=amount,
            deadline=DEADLINE,
            funding=FundingBinding.build(
                [
                    FundingSourceRef(
                        "value/funding-source/wallet-w017",
                        Amount(4000000, 2, ASSET),
                    ),
                    FundingSourceRef("value/funding-source/bank-w017"),
                ]
            ),
            policy_id=policy.object_id,
            slack_id="intent/slack/w017-safety-fixture",
        ),
        provenance=prov(f"intent/merchant-checkout-{case}",
                        f"evidence/w017-intent-{case}"),
        correlation_id="corr/w017-safety-dogfood",
    )
    slack = EconomicSlack.build(
        object_id="intent/slack/w017-safety-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=slack_spec,
        provenance=prov("intent/economic-slack", "evidence/w017-slack"),
        correlation_id="corr/w017-safety-dogfood",
    )
    authorized = intent.authorize(
        provenance=prov(f"intent/authorize-{case}", f"evidence/w017-authorization-{case}"),
        causation_id=f"command/authorize-w017-{case}",
    )
    return authorized, policy, slack


RISK_INPUTS = {
    "approved": [
        (RiskDimension.COUNTERPARTY, 2000, "evidence/w017-cp-profile-approve"),
        (RiskDimension.FRAUD, 1000, "evidence/w017-fraud-profile-approve"),
    ],
    "stepped-up": [
        (RiskDimension.COUNTERPARTY, 3000, "evidence/w017-cp-profile-stepup"),
        (RiskDimension.FRAUD, 8000, "evidence/w017-fraud-profile-stepup"),
    ],
    "held": [
        (RiskDimension.COUNTERPARTY, 10000, "evidence/w017-cp-profile-hold"),
        (RiskDimension.FRAUD, 10000, "evidence/w017-fraud-profile-hold"),
    ],
    "blocked": [
        (RiskDimension.COUNTERPARTY, 1200, "evidence/w017-cp-profile-block"),
        (RiskDimension.SETTLEMENT, 400, "evidence/w017-settlement-profile-block"),
    ],
}

FRAUD_SIGNALS = {
    "approved": [(FraudKind.AUTHORIZED_PUSH_SCAM,
                  FraudSeverity.LOW, "2026-09-03T00:05:00Z")],
    "stepped-up": [(FraudKind.ACCOUNT_TAKEOVER,
                    FraudSeverity.MEDIUM, "2026-09-03T00:15:00Z")],
    "held": [(FraudKind.CREDENTIAL_COMPROMISE,
              FraudSeverity.HIGH, "2026-09-03T00:25:00Z")],
    "blocked": [(FraudKind.MERCHANT_FRAUD,
                 FraudSeverity.LOW, "2026-09-03T00:35:00Z")],
}

CASE_RECORD_AS_OF = {
    "approved": "2026-09-03T00:10:30Z",
    "stepped-up": "2026-09-03T00:20:30Z",
    "held": "2026-09-03T00:30:30Z",
    "blocked": "2026-09-03T00:40:30Z",
}

CONSTRAINTS = {
    "approved": [
        ("safety/constraint/w017-sanctions-1", "sanctions_screening",
         ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
        ("safety/constraint/w017-limit-1", "transaction_limit",
         ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
    ],
    "stepped-up": [
        ("safety/constraint/w017-sanctions-2", "sanctions_screening",
         ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
        ("safety/constraint/w017-watchlist-2", "sanctions_screening",
         ConstraintPrecedence.POLICY, ConstraintOutcome.VIOLATED),
        ("safety/constraint/w017-limit-2", "transaction_limit",
         ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
    ],
    "held": [
        ("safety/constraint/w017-sanctions-3", "sanctions_screening",
         ConstraintPrecedence.REGULATORY, ConstraintOutcome.SATISFIED),
        ("safety/constraint/w017-limit-3", "transaction_limit",
         ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
    ],
    "blocked": [
        ("safety/constraint/w017-sanctions-4", "sanctions_screening",
         ConstraintPrecedence.REGULATORY, ConstraintOutcome.VIOLATED),
        ("safety/constraint/w017-watchlist-4", "sanctions_screening",
         ConstraintPrecedence.POLICY, ConstraintOutcome.SATISFIED),
        ("safety/constraint/w017-travel-4", "travel_rule_reporting",
         ConstraintPrecedence.LEGAL, ConstraintOutcome.SATISFIED),
    ],
}

CONSTRAINT_EFFECTIVE_FROM = "2026-09-01T00:00:00Z"
CONSTRAINT_EFFECTIVE_UNTIL = "2026-12-31T00:00:00Z"


def _build_constraints(case: str):
    return [
        ComplianceConstraint(
            constraint_id=constraint_id,
            requirement=requirement,
            precedence=precedence,
            outcome=outcome,
            version=1,
            effective_from=CONSTRAINT_EFFECTIVE_FROM,
            effective_until=CONSTRAINT_EFFECTIVE_UNTIL,
            evidence_refs=(f"evidence/w017-constraint-{constraint_id.rsplit('-', 1)[-1]}",),
        )
        for constraint_id, requirement, precedence, outcome in CONSTRAINTS[case]
    ]


def _run_case(case: str, policy: SafetyPolicy):
    """Run one payment case through risk, fraud and compliance; transcript lines."""
    as_of = CASE_AS_OF[case]
    intent, _, _ = _intent_fixture(case)
    subject_id = intent.object_id

    risk = evaluate_risk(
        assessment_id=f"safety/risk/w017-{case}",
        subject_id=subject_id,
        inputs=[
            RiskInput(dimension, score, (evidence,))
            for dimension, score, evidence in RISK_INPUTS[case]
        ],
        policy=policy,
        as_of=as_of,
        rounding=RoundingMode.HALF_UP,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(f"safety/risk-evaluation-{case}",
                        f"evidence/w017-risk-evaluation-{case}"),
        exposure=MoneyAmount(USD, CASE_AMOUNTS[case], 2),
    )
    signals = [
        submit_fraud_signal(
            signal_id=f"safety/fraud-signal/w017-{case}-{index}",
            subject_id=subject_id,
            kind=kind,
            severity=severity,
            observed_at=observed_at,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(
                f"safety/fraud-signal-{case}",
                f"evidence/w017-fraud-signal-{case}-{index}",
            ),
        )
        for index, (kind, severity, observed_at) in enumerate(FRAUD_SIGNALS[case], start=1)
    ]
    assessment = assess_fraud(
        assessment_id=f"safety/fraud-assessment/w017-{case}",
        subject_id=subject_id,
        signals=signals,
        policy=policy,
        as_of=as_of,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(f"safety/fraud-assessment-{case}",
                        f"evidence/w017-fraud-assessment-{case}"),
    )
    decision = decide_fraud(
        decision_id=f"safety/fraud-decision/w017-{case}",
        assessment=assessment,
        policy=policy,
        as_of=as_of,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(f"safety/fraud-decision-{case}",
                        f"evidence/w017-fraud-decision-{case}"),
    )
    request = request_compliance_assessment(
        assessment_id=f"safety/compliance/w017-{case}",
        subject_id=subject_id,
        jurisdiction="jurisdiction/EU",
        constraints=_build_constraints(case),
        as_of=as_of,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(f"safety/compliance-request-{case}",
                        f"evidence/w017-compliance-request-{case}"),
    )
    recorded = record_compliance_result(
        request,
        as_of=CASE_RECORD_AS_OF[case],
        provenance=prov(f"safety/compliance-record-{case}",
                        f"evidence/w017-compliance-record-{case}"),
    )
    result = recorded.spec.result
    overrides = sum(len(r.overridden) for r in result.resolution)

    lines = [
        f"case={case} intent={subject_id} as_of={as_of}",
        f"  risk.band={risk.spec.band.value} risk.score={risk.spec.aggregate_score} "
        f"risk.inputs={len(risk.spec.scores)}",
        f"  fraud.score={assessment.spec.fraud_score} "
        f"fraud.signals={len(assessment.spec.signal_refs)}",
        f"  fraud.state={decision.state.value}"
        + (
            " fraud.requires_verification=true"
            if decision.state is FraudDecisionState.STEP_UP else ""
        )
        + (
            f" fraud.hold_window=[{decision.spec.hold_from},{decision.spec.hold_until})"
            f" fraud.hold_active={str(hold_active(decision, as_of)).lower()}"
            if decision.state is FraudDecisionState.HELD else ""
        ),
        f"  compliance.verdict={result.verdict.value} "
        f"compliance.binding={result.binding_constraint_id or 'none'} "
        f"compliance.overrides={overrides}",
        f"  decision.issuer={decision.envelope.provenance.issuer} "
        f"decision.evidence={len(decision.envelope.provenance.evidence_refs)} "
        f"policy={decision.spec.assessment_ref}",
    ]
    return lines, risk, decision, recorded


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-017 transcript and its digest."""
    policy = build_policy()
    lines = [
        "DOGFOOD-017: four payment cases through the safety decision plane",
        f"policy={policy.object_id} version={policy.policy_version}",
    ]
    risks = []
    decisions = {}
    compliances: dict[str, ComplianceAssessment] = {}
    for case in CASES:
        case_lines, risk, decision, recorded = _run_case(case, policy)
        lines.extend(case_lines)
        risks.append(risk)
        decisions[case] = decision
        compliances[case] = recorded
    summary = assess_systemic_exposure(risks, policy=policy, as_of="2026-09-03T01:00:00Z")
    lines.extend([
        f"systemic.subjects={summary.subject_count} "
        f"systemic.high_risk={summary.high_count + summary.critical_count}",
        f"systemic.total_exposure={summary.total_exposure.value} "
        f"systemic.max_score={summary.max_aggregate_score}",
        f"systemic.breached={str(summary.breached).lower()} "
        f"systemic.reasons={','.join(r.value for r in summary.breach_reasons) or 'none'}",
    ])
    passed = all(
        decisions[case].state is EXPECTED_FRAUD_STATE[case] for case in CASES
    ) and all(
        compliances[case].spec.result.verdict is EXPECTED_COMPLIANCE_VERDICT[case]
        for case in CASES
    ) and hold_active(decisions["held"], CASE_AS_OF["held"])
    lines.append(
        "classification: approved=%s stepped-up=%s held=%s blocked=%s"
        % (
            decisions["approved"].state.value,
            decisions["stepped-up"].state.value,
            decisions["held"].state.value,
            compliances["blocked"].spec.result.verdict.value,
        )
    )
    lines.append("DOGFOOD-017: PASS" if passed else "DOGFOOD-017: FAIL")
    transcript = "\n".join(lines)
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> str:
    """Run DOGFOOD-017, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
