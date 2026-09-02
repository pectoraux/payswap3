"""PaySwap safety domain (WORK-017): risk, fraud, compliance and policy engine.

The public boundary is typed and versioned:

- every durable object composes the canonical :class:`~src.core.envelope.ObjectEnvelope`
  (identity, state, provenance, version chain, integrity hash) owned by
  ``src.core`` and carries a domain seal computed with the single
  canonical hash authority, so tampered or spliced objects fail closed
  on the trusted deserialization path;
- no safety object type is protocol-visible in the frozen registry, so —
  per the sibling convention — object types use internal non-registry
  ``safety/...`` formats and no new registry name is invented;
- risk scores, fraud scores and policy weights are exact integers in
  basis points on the explicit 0..10000 scale; aggregate risk banding
  uses exact integer cross-multiplication (never the rounded value), and
  the recorded aggregate is divided under an explicit money-domain
  rounding mode — no floating-point value is ever constructed; monetary
  exposures are typed money-domain amounts (WORK-006);
- policy evaluation is reproducible: the same inputs, the same policy
  object version and the same explicit ``as_of`` instant always produce
  a byte-identical decision, and every decision pins its policy
  version; retired policies fail closed;
- every decision is evidence-backed: creating provenance without
  explicit evidence references fails closed, per-score and
  per-constraint evidence references are typed and non-empty, and
  provenance is preserved across the version chain (invariant 13);
- lifecycles implement the frozen v0.1 command families: Safety
  ``SubmitFraudSignal/CreateFraudAssessment/CreateFraudDecision/Hold/
  Release/Block`` (signals are immutable observations, assessments are
  derived records, decisions are the stateful circuit breaker with
  explicit half-open hold windows and release reasons) and Compliance
  ``RequestAssessment/RecordResult/InvalidateResult`` (REQUESTED ->
  RECORDED -> terminal INVALIDATED, with the constraint precedence
  engine LEGAL > REGULATORY > CONTRACTUAL > POLICY, deterministic
  override provenance and fail-closed ambiguity);
- the systemic exposure interface is typed only: it exposes a summary
  predicate over aggregated risk inputs, never a federation object;
- this package is a CONTROL/DECISION domain: it emits typed verdicts
  (allow, step-up, hold, block, satisfied, blocked) that other domains
  consume as binding inputs; it NEVER touches ledgers, holds or
  postings, never moves funds and never becomes an execution authority.
  Value-domain, intent-domain, trust-domain and capability-domain
  objects are referenced by opaque identifiers only; unmerged sibling
  implementations are never imported.
"""

from __future__ import annotations

from ..core import CoreValidationError, Provenance

from .contracts import (
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
    ComplianceAssessmentState,
    ComplianceVerdict,
    ConstraintOutcome,
    ConstraintPrecedence,
    FraudDecisionState,
    FraudKind,
    FraudReleaseReason,
    FraudSeverity,
    RiskBand,
    RiskDimension,
    SafetyPolicyState,
    SystemicBreachReason,
)
from .compliance import (
    ComplianceAssessment,
    ComplianceConstraint,
    ComplianceResult,
    InvalidationRecord,
    OverrideRecord,
    ResolutionRecord,
    invalidate_compliance_result,
    record_compliance_result,
    request_compliance_assessment,
)
from .fraud import (
    FraudAssessment,
    FraudDecision,
    FraudSignal,
    assess_fraud,
    block_fraud_decision,
    create_fraud_decision,
    decide_fraud,
    hold_active,
    hold_fraud_decision,
    release_fraud_decision,
    submit_fraud_signal,
)
from .policy import SafetyPolicy, SafetyPolicySpec
from .risk import RiskAssessment, RiskInput, evaluate_risk
from .systemic import SystemicExposureSummary, assess_systemic_exposure

__all__ = [
    # versioned public boundary contracts
    "SAFETY_API_VERSION",
    "SAFETY_PROTOCOL_VERSION",
    "SAFETY_SCHEMA_VERSION",
    "RISK_ASSESSMENT_OBJECT_TYPE",
    "FRAUD_SIGNAL_OBJECT_TYPE",
    "FRAUD_ASSESSMENT_OBJECT_TYPE",
    "FRAUD_DECISION_OBJECT_TYPE",
    "COMPLIANCE_ASSESSMENT_OBJECT_TYPE",
    "SAFETY_POLICY_OBJECT_TYPE",
    # explicit risk scale and precedence vocabulary
    "RISK_SCALE_MIN",
    "RISK_SCALE_MAX",
    "RISK_WEIGHT_TOTAL_BPS",
    "CONSTRAINT_PRECEDENCE_ORDER",
    "FRAUD_DECISION_TERMINAL_STATES",
    "COMPLIANCE_TERMINAL_STATES",
    # closed vocabularies
    "RiskDimension",
    "RiskBand",
    "FraudKind",
    "FraudSeverity",
    "FraudDecisionState",
    "FraudReleaseReason",
    "ConstraintPrecedence",
    "ConstraintOutcome",
    "ComplianceVerdict",
    "ComplianceAssessmentState",
    "SafetyPolicyState",
    "SystemicBreachReason",
    # risk assessments
    "RiskInput",
    "RiskAssessment",
    "evaluate_risk",
    # fraud signals, assessments and decisions
    "FraudSignal",
    "submit_fraud_signal",
    "FraudAssessment",
    "assess_fraud",
    "FraudDecision",
    "create_fraud_decision",
    "decide_fraud",
    "hold_fraud_decision",
    "release_fraud_decision",
    "block_fraud_decision",
    "hold_active",
    # compliance
    "ComplianceConstraint",
    "ComplianceResult",
    "ResolutionRecord",
    "OverrideRecord",
    "InvalidationRecord",
    "ComplianceAssessment",
    "request_compliance_assessment",
    "record_compliance_result",
    "invalidate_compliance_result",
    # policy
    "SafetyPolicySpec",
    "SafetyPolicy",
    # systemic exposure interface
    "SystemicExposureSummary",
    "assess_systemic_exposure",
    # re-exported owning authorities (single source: src.core)
    "CoreValidationError",
    "Provenance",
]
