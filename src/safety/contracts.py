"""Frozen public-boundary contracts for the safety domain (WORK-017).

The safety domain is the control/decision plane of PaySwap: it produces
evidence-backed risk assessments, fraud signals/assessments/decisions and
compliance assessments as typed verdicts that other domains consume. It
never touches ledgers, holds or postings and never moves funds.

No safety object type is listed in the frozen protocol registry (the
registry lists protocol-visible ``payswap/...`` object types and event
namespaces only), so — following the sibling convention — every safety
object type below uses an internal non-registry ``safety/...`` format.
No new protocol-visible name is invented here.

The constraint precedence vocabulary (legal > regulatory > contractual >
policy) is frozen here as an ordered, versioned vocabulary: compliance
constraints are resolved deterministically and can never be bypassed
through routing (constitution hard invariant 10).
"""

from __future__ import annotations

from enum import StrEnum

# -- typed, versioned public boundary --------------------------------------

#: Version of the safety public boundary API.
SAFETY_API_VERSION = "v0.1"

#: Governing protocol version (frozen architecture v0.1).
SAFETY_PROTOCOL_VERSION = "v0.1"

#: Canonical schema version of every safety durable object.
SAFETY_SCHEMA_VERSION = 1

# Internal (non-registry) object types of the safety domain.
RISK_ASSESSMENT_OBJECT_TYPE = "safety/risk-assessment/v1"
FRAUD_SIGNAL_OBJECT_TYPE = "safety/fraud-signal/v1"
FRAUD_ASSESSMENT_OBJECT_TYPE = "safety/fraud-assessment/v1"
FRAUD_DECISION_OBJECT_TYPE = "safety/fraud-decision/v1"
COMPLIANCE_ASSESSMENT_OBJECT_TYPE = "safety/compliance-assessment/v1"
SAFETY_POLICY_OBJECT_TYPE = "safety/policy/v1"

# -- explicit risk scale ---------------------------------------------------

#: Minimum representable risk score (basis points of risk).
RISK_SCALE_MIN = 0

#: Maximum representable risk score (basis points of risk).
RISK_SCALE_MAX = 10000

#: Policy risk weights are basis-point shares and must sum to exactly this.
RISK_WEIGHT_TOTAL_BPS = 10000


class RiskDimension(StrEnum):
    """Closed multidimensional risk vocabulary (security-risk model)."""

    COUNTERPARTY = "COUNTERPARTY"
    LIQUIDITY = "LIQUIDITY"
    CREDIT = "CREDIT"
    SETTLEMENT = "SETTLEMENT"
    OPERATIONAL = "OPERATIONAL"
    CONCENTRATION = "CONCENTRATION"
    SYSTEMIC = "SYSTEMIC"
    MODEL = "MODEL"
    EXTENSION = "EXTENSION"
    FRAUD = "FRAUD"


class RiskBand(StrEnum):
    """Closed risk band vocabulary (LOW < MEDIUM < HIGH < CRITICAL)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SafetyPolicyState(StrEnum):
    """Closed lifecycle of the versioned safety policy (VERSIONED object)."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


# -- fraud plane ------------------------------------------------------------


class FraudKind(StrEnum):
    """Closed fraud plane vocabulary (security-risk model)."""

    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    AUTHORIZED_PUSH_SCAM = "AUTHORIZED_PUSH_SCAM"
    MERCHANT_FRAUD = "MERCHANT_FRAUD"
    PROVIDER_FRAUD = "PROVIDER_FRAUD"
    COLLUSION = "COLLUSION"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"


class FraudSeverity(StrEnum):
    """Closed fraud signal severity vocabulary."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FraudDecisionState(StrEnum):
    """Closed lifecycle/verdict vocabulary of a fraud decision.

    The verdict IS the state: ``ALLOW``/``STEP_UP``/``DELAY``/
    ``RECONFIRM``/``ESCALATE`` are issued verdicts; ``HELD`` is an active
    circuit-breaker hold with an explicit half-open window;
    ``RELEASED`` and ``BLOCKED`` are terminal.

    This models the frozen Safety command family
    ``SubmitFraudSignal/CreateFraudAssessment/CreateFraudDecision/Hold/
    Release/Block`` as explicit state machines.
    """

    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DELAY = "DELAY"
    RECONFIRM = "RECONFIRM"
    ESCALATE = "ESCALATE"
    HELD = "HELD"
    RELEASED = "RELEASED"
    BLOCKED = "BLOCKED"


#: Terminal fraud decision states (the decision object ends here; further
#: control requires a new decision object, preserving append-only history).
FRAUD_DECISION_TERMINAL_STATES = frozenset(
    {FraudDecisionState.RELEASED, FraudDecisionState.BLOCKED}
)


class FraudReleaseReason(StrEnum):
    """Closed release provenance vocabulary of the ``Release`` command."""

    #: Operator-initiated release while the hold window is still active.
    OPERATOR = "OPERATOR"

    #: System-trigger release once the hold window has elapsed.
    WINDOW_ELAPSED = "WINDOW_ELAPSED"


# -- compliance plane --------------------------------------------------------


class ConstraintPrecedence(StrEnum):
    """Closed, ORDERED constraint precedence vocabulary.

    ``LEGAL`` binds hardest, then ``REGULATORY``, ``CONTRACTUAL`` and
    ``POLICY``. Higher precedence overrides lower deterministically;
    ambiguous precedence (two constraints on the same requirement at the
    same precedence level) fails closed.
    """

    LEGAL = "LEGAL"
    REGULATORY = "REGULATORY"
    CONTRACTUAL = "CONTRACTUAL"
    POLICY = "POLICY"


#: Frozen precedence order, highest first.
CONSTRAINT_PRECEDENCE_ORDER = (
    ConstraintPrecedence.LEGAL.value,
    ConstraintPrecedence.REGULATORY.value,
    ConstraintPrecedence.CONTRACTUAL.value,
    ConstraintPrecedence.POLICY.value,
)

#: Rank helper: higher rank = stronger precedence.
CONSTRAINT_PRECEDENCE_RANK: dict[ConstraintPrecedence, int] = {
    ConstraintPrecedence.LEGAL: 4,
    ConstraintPrecedence.REGULATORY: 3,
    ConstraintPrecedence.CONTRACTUAL: 2,
    ConstraintPrecedence.POLICY: 1,
}


class ConstraintOutcome(StrEnum):
    """Closed per-constraint check outcome."""

    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"


class ComplianceAssessmentState(StrEnum):
    """Closed lifecycle of a compliance assessment.

    Models the frozen Compliance command family
    ``RequestAssessment/RecordResult/InvalidateResult``: the request is
    created, the resolved result is recorded, and a recorded or requested
    assessment may be invalidated (a correction appended as a new version,
    never a rewrite).
    """

    REQUESTED = "REQUESTED"
    RECORDED = "RECORDED"
    INVALIDATED = "INVALIDATED"


#: Terminal compliance assessment state.
COMPLIANCE_TERMINAL_STATES = frozenset({ComplianceAssessmentState.INVALIDATED})


class ComplianceVerdict(StrEnum):
    """Closed compliance verdict vocabulary.

    ``BLOCKED`` is binding: compliance cannot be bypassed through
    routing, so a blocked verdict is a hard input for any routing or
    execution decision made in other domains.
    """

    SATISFIED = "SATISFIED"
    BLOCKED = "BLOCKED"


# -- systemic exposure interface ---------------------------------------------


class SystemicBreachReason(StrEnum):
    """Closed systemic exposure breach reasons (interface only)."""

    HIGH_RISK_SUBJECT_COUNT = "HIGH_RISK_SUBJECT_COUNT"
    AGGREGATE_EXPOSURE = "AGGREGATE_EXPOSURE"
