"""IG-006 gate contracts: identity, vocabulary and boundary constants.

The merchant/global end-to-end dogfood gate
(``spec/integration-gates.md`` row IG-006: "merchant/global end-to-end
dogfood | WORK-025, 028, 030") proves *a real user-facing merchant
outcome through the complete network, including delay/credit,
recovery and evidence* (``spec/work-orders/WORK-031.md``) by
composing ONLY already-merged implementations:

* the WORK-025 merchant checkout/settlement-promise surface (the real
  ``MerchantEngine`` record boundary — checkout, acceptance, the
  settlement promise whose ``PENDING`` state and ``credit_limit`` ARE
  the explicit delayed/credited settlement condition, and the refund
  route);
* the WORK-027 IG-002 fulfillment lifecycle harness (the canonical
  intent/fulfillment path — compile, plan, execute, clear, settle,
  finality — driven here twice: once on the primary rail that is
  killed mid-flight, once through the declared redundancy rail after
  the governed failover);
* the WORK-030 IG-005 rail sandbox discipline (the merged
  ``LocalDeterministicRail`` public re-export and the sandbox rail
  failure/investigation semantics: transport ambiguity, reconciliation
  NOT_FOUND, retry-safe fresh-key discipline);
* the WORK-028 IG-003 parity discipline (the merged environment-role
  vocabulary this gate declares its environment binding through: the
  dogfood runs the production protocol path in a sandbox environment
  of the same protocol — the environment class the parity gate proved
  semantically identical);
* the WORK-024 operations authority (the real ``OperationsEngine``:
  dependency graph, resilience profile, incident → degradation →
  failover → recovery → resolve orchestration with digest-bound
  authority conservation);
* the merged WORK-018 evidence domain (the durable journey-outcome
  evidence: the merchant outcome ``Observation`` and the ``Evidence``
  record that binds promise ↔ settlement ↔ finality).

This module declares the gate's typed, versioned identity and freezes
the vocabularies the composition uses. It introduces no domain
semantics of its own: every behavioral authority stays with the
consumed implementations.

Identity discipline:

* ``IG-006`` is the gate identifier listed in
  ``spec/integration-gates.md``; unknown gate ids fail closed
  everywhere. The IG-001..IG-005 gate ids stay unknown HERE on
  purpose (one validator per gate, no shared mutation of the merged
  sibling gates' contract surfaces — the house discipline of every
  integration subpackage).
* The gate projects NO new protocol-visible name and NO new durable
  object type: every object it records (checkout, acceptance,
  settlement promise, refund route, plans, steps, obligations,
  settlement, finality, incidents, the outcome observation, the
  journey evidence) belongs to a consumed domain's own registered or
  internal object types, produced through the consumed domains' public
  record factories. The gate's own artifacts are its stage journal
  and typed journey report (in-memory harness projections, exactly the
  sibling-gate convention).
* The journey runs in ONE sandbox environment of the same protocol
  (``env/sandbox-ig006-flywheel``); the two rail compositions and the
  merchant/operations/evidence boundaries keep their own kernel-bound
  domains inside that environment (the federated-domains frozen rule).
  No production financial state is reachable from this environment.
"""

from __future__ import annotations

from enum import StrEnum

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-006 row).
FLYWHEEL_GATE_ID = "IG-006"

#: Typed, versioned public boundary version of the gate package.
FLYWHEEL_API_VERSION = "v0.1"

#: Schema version of the gate's canonical journey-report representation.
FLYWHEEL_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_FLYWHEEL_GATES = frozenset({FLYWHEEL_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by
#: the contract suite). Anything else is a second authority or an
#: unmerged sibling and is forbidden. ``src.merchant`` is the merged
#: WORK-025 public boundary (the demand/outcome surface);
#: ``src.integration.lifecycle`` is the merged WORK-027 IG-002 harness
#: (the canonical fulfillment path); ``src.integration.rails`` is the
#: merged WORK-030 IG-005 public boundary (the sandbox-rail discipline
#: and the ``LocalDeterministicRail`` re-export this gate composes);
#: ``src.integration.parity`` is the merged WORK-028 IG-003 public
#: boundary (the environment-role vocabulary of the environment
#: binding); ``src.operations`` is the merged WORK-024 authority
#: (incident/degradation/failover/recovery orchestration);
#: ``src.evidence`` is the merged WORK-018 authority (the durable
#: journey-outcome evidence); ``src.simulation`` supplies the frozen
#: environment-mode/epistemic vocabulary;
#: ``src.interoperability``/``src.execution``/``src.clearing`` are the
#: merged domain authorities the gate touches DIRECTLY while composing
#: the lifecycle path (the typed adapter contracts and bindings, the
#: execution-authority journal-only rebuild proof, the obligation
#: record reads) — each is also a declared consumed root of the merged
#: IG-002 lifecycle harness the gate composes; the remaining roots are
#: the shared core the consumed boundaries themselves build on.
CONSUMED_SURFACES = (
    "src.core",
    "src.transition",
    "src.value",
    "src.evidence",
    "src.merchant",
    "src.operations",
    "src.simulation",
    "src.interoperability",
    "src.execution",
    "src.clearing",
    "src.integration.lifecycle",
    "src.integration.parity",
    "src.integration.rails",
)

# -- the composed environment -------------------------------------------------

#: The ONE environment of the journey (sandbox class — the parity
#: vocabulary's simulation role: the production protocol path running
#: in a sandbox environment of the same protocol; the parity gate
#: proved exactly this class pairing semantically identical).
FLYWHEEL_ENVIRONMENT_ID = "env/sandbox-ig006-flywheel"

#: The environment role binding, declared through the merged IG-003
#: parity vocabulary (a sandbox environment of the same protocol).
FLYWHEEL_ENVIRONMENT_ROLE = "simulation"

#: The kernel-bound domains inside the composed environment (the
#: federated-domains frozen rule: each authority keeps its own domain).
MERCHANT_DOMAIN_ID = "domain/ig006-merchant"
PRIMARY_DOMAIN_ID = "domain/ig006-primary-rail"
REDUNDANCY_DOMAIN_ID = "domain/ig006-redundancy-rail"
OPERATIONS_DOMAIN_ID = "domain/ig006-operations"
EVIDENCE_DOMAIN_ID = "domain/ig006-evidence"

# -- declared principals ------------------------------------------------------

#: The gate operator driving the composed engines (authorized actor of
#: every composed kernel).
DEFAULT_FLYWHEEL_ACTOR = "principal/ig006-ops"

#: The merchant principal owning the checkout (the journey's payee).
MERCHANT_ACTOR = "principal/merchant-ig006-aurora"

#: The customer principal initiating the checkout (the journey's payer).
CUSTOMER_ACTOR = "principal/customer-ig006-ama"

#: The actors the composed engines authorize (the operator plus the
#: merchant principal driving the merchant engine's commands).
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {DEFAULT_FLYWHEEL_ACTOR, MERCHANT_ACTOR}
)

# -- the declared rails (the network composition) -----------------------------

#: The primary rail's typed adapter contract id (bound through the
#: merged lifecycle harness's typed ``AdapterBinding``).
PRIMARY_ADAPTER_ID = "interoperability/adapter/ig006-primary-rail"

#: The declared redundancy rail's typed adapter contract id.
REDUNDANCY_ADAPTER_ID = "interoperability/adapter/ig006-redundancy-rail"

#: The operations-side dependency ids of the two rails (the WORK-024
#: dependency graph entries the resilience profile declares: the
#: redundancy rail is the declared failover target).
PRIMARY_RAIL_DEPENDENCY_ID = "operations/dependency/ig006-primary-rail"
REDUNDANCY_RAIL_DEPENDENCY_ID = "operations/dependency/ig006-redundancy-rail"

#: The composed payment-execution service the two rails serve.
EXECUTION_SERVICE_ID = "operations/service/ig006-payment-execution"

#: The execution authority reference of the primary rail composition
#: (the digest-bound authority the degradation/failover/resolve
#: evidence conserves).
EXECUTION_AUTHORITY_REF = "authority/ig006-execution"

# -- declared journey fixture identities (deterministic) ----------------------

#: The merchant checkout record id.
CHECKOUT_ID = "checkout/ig006-1"

#: The settlement promise record id (the delayed/credited condition).
PROMISE_ID = "promise/ig006-1"

#: The refund route record id.
REFUND_ROUTE_ID = "refund-route/ig006-1"

#: The canonical intent id the checkout binds to (the fulfillment
#: demand reference).
INTENT_ID = "intent/ig006-flywheel-1"

#: The primary journey's plan/execution/step identities.
PRIMARY_PLAN_ID = "plan/ig006-primary-1"
PRIMARY_EXECUTION_PLAN_ID = "execution/plan/ig006-primary-1"
PRIMARY_STEP_ID = "execution/plan/ig006-primary-1/step/1"
PRIMARY_IDEMPOTENCY_KEY = "ig006-primary-1"

#: The redundancy journey's identities (the fresh-key retry discipline:
#: never a reuse of the killed key).
REDUNDANCY_PLAN_ID = "plan/ig006-redundancy-2"
REDUNDANCY_EXECUTION_PLAN_ID = "execution/plan/ig006-redundancy-2"
REDUNDANCY_STEP_ID = "execution/plan/ig006-redundancy-2/step/1"
REDUNDANCY_IDEMPOTENCY_KEY = "ig006-redundancy-2"

#: The clearing cycle of the journey (the recognition window whose
#: due-range IS the declared settlement delay).
CLEARING_CYCLE_ID = "clearing/ig006/cycle-flywheel-1"

#: The settlement batch the merchant promise binds to (the promise's
#: ``settlement_id`` — the binding the invariant battery proves).
SETTLEMENT_ID = "settlement/ig006/batch-flywheel-1"

#: The finality certificate id of the settlement.
FINALITY_ID = "settlement/ig006/finality-flywheel-1"

#: The operations incident id of the rail kill.
INCIDENT_ID = "operations/incident/ig006-inc-1"

#: The merchant-outcome observation record id (the user-facing outcome
#: evidence — an ``evidence/observation/v1`` record of the merged
#: evidence domain, OBSERVED epistemic class).
OUTCOME_OBSERVATION_ID = "observation/ig006-merchant-outcome-1"

#: The durable journey evidence record id (an ``evidence/evidence/v1``
#: record of the merged evidence domain resting on the outcome
#: observation).
JOURNEY_EVIDENCE_ID = "evidence/ig006-journey-1"

# -- the declared economic data (exact integers, shared by every leg) ---------

#: The checkout amount: 84.50 USD (minor units, scale 2). The SAME
#: integer flows through checkout → promise → world → hop → step →
#: obligation → settlement leg (the conservation the battery proves).
JOURNEY_AMOUNT_MINOR = 8450
JOURNEY_ASSET_CODE = "USD"
JOURNEY_SCALE = 2

#: The merchant credit limit: 100.00 USD. The promise amount stays
#: within it; the discrimination battery proves the constraint bites.
CREDIT_LIMIT_MINOR = 10000

# -- declared instants (no clock reads anywhere) ------------------------------

#: Every instant is declared data. The execution-phase instants live
#: inside the declared world's frozen authorization window
#: (2026-09-04T00:00:00Z..06:00:00Z — the lifecycle harness's own
#: declared-world constant), and the settlement delay window extends
#: beyond it exactly as the merged IG-005 rails delay discipline does.

#: Act 1 — the merchant demand.
T_CHECKOUT = "2026-09-04T00:00:00Z"
T_ACCEPT = "2026-09-04T00:00:10Z"
T_PROMISE = "2026-09-04T00:00:20Z"
T_REFUND_ROUTE = "2026-09-04T00:00:30Z"

#: Act 2 — the canonical fulfillment on the primary rail, then the kill.
T_COMPILE = "2026-09-04T01:31:00Z"
T_ACCEPT_PLAN = "2026-09-04T01:32:00Z"
T_PLAN_CREATE = "2026-09-04T01:33:00Z"
T_PLAN_AUTHORIZE = "2026-09-04T01:34:00Z"
T_PLAN_START = "2026-09-04T01:35:00Z"
T_EFFECT_REQUEST = "2026-09-04T01:36:00Z"
T_KILL = "2026-09-04T01:37:00Z"
T_CANARY = "2026-09-04T01:38:00Z"
T_DEGRADE = "2026-09-04T01:40:00Z"
T_FAILOVER = "2026-09-04T01:42:00Z"

#: Act 3 — recovery through the redundancy, then the delayed settlement.
T_RECONCILE = "2026-09-04T01:43:00Z"
T_RETRY_COMPILE = "2026-09-04T01:44:00Z"
T_RETRY_ACCEPT = "2026-09-04T01:45:00Z"
T_RETRY_CREATE = "2026-09-04T01:46:00Z"
T_RETRY_AUTHORIZE = "2026-09-04T01:47:00Z"
T_RETRY_START = "2026-09-04T01:48:00Z"
T_RETRY_REQUEST = "2026-09-04T01:49:00Z"
T_RETRY_SUBMIT = "2026-09-04T01:50:00Z"
T_RETRY_ACK = "2026-09-04T01:51:00Z"
T_RETRY_QUERY = "2026-09-04T01:51:30Z"
T_RETRY_STATUS = "2026-09-04T01:52:00Z"
T_RETRY_RESULT = "2026-09-04T01:53:00Z"
T_RETRY_COMPLETE = "2026-09-04T01:54:00Z"
T_RETRY_CLAIM = "2026-09-04T01:55:00Z"
T_CYCLE_OPEN = "2026-09-04T01:56:00Z"
T_RECOGNIZE = "2026-09-04T01:56:30Z"

#: The declared settlement delay: the obligation is due only inside
#: this window (delayed settlement, represented explicitly by the
#: clearing authority's own due-range), and the settlement batch
#: carries the matching deadlines — the delay extends beyond the
#: world's execution window exactly as the merged IG-005 discipline.
T_DUE_FROM = "2026-09-04T02:20:00Z"
T_DUE_UNTIL = "2026-09-05T06:00:00Z"
#: The mark-due command instant (validation opens the window; the due
#: marking happens inside it).
T_MARK_DUE = "2026-09-04T02:30:00Z"
T_CYCLE_VALIDATE = "2026-09-04T02:40:00Z"
T_CYCLE_FINALIZE = "2026-09-04T02:50:00Z"
T_SETTLE = "2026-09-04T03:20:00Z"
T_SETTLE_RECONCILE = "2026-09-04T03:50:00Z"
T_FINALITY_VALIDATE = "2026-09-04T04:20:00Z"
T_FINALITY_ESTABLISH = "2026-09-04T04:50:00Z"
T_OBLIGATION_RESOLVE = "2026-09-04T05:20:00Z"

#: Act 4 — incident closure and the merchant outcome.
T_REPROBE = "2026-09-04T02:05:00Z"
T_OUTCOME = "2026-09-04T05:50:00Z"

#: Freshness window of the outcome observation/evidence records.
T_VALID_FROM = "2026-09-04T05:50:00Z"
T_VALID_UNTIL = "2026-09-05T06:00:00Z"

#: The settlement batch deadlines (the rails-gate convention).
SUBMIT_BY = "2026-09-04T12:00:00Z"
SETTLE_BY = "2026-09-05T06:00:00Z"

#: The clearing cycle's recognition window (the lifecycle-gate
#: convention: the cycle's own opens/closes bounds).
CYCLE_OPENS_AT = "2026-09-04T00:00:00Z"
CYCLE_CLOSES_AT = "2026-09-04T06:00:00Z"

#: The resilience profile of the composed payment-execution service.
AVAILABILITY_TARGET_BPS = 9990
DEGRADED_BELOW_BPS = 9500
UNAVAILABLE_BELOW_BPS = 5000
RECOVERY_TIME_OBJECTIVE_SECONDS = 3600
RECOVERY_POINT_OBJECTIVE_SECONDS = 60


class JourneyOutcome(StrEnum):
    """The closed vocabulary of the final merchant/customer outcome.

    The outcome classification is OBSERVED, never claimed: each member
    is derived exclusively from real authority reads of the composed
    journey (the settlement state, the finality state, the resolved
    obligations and the merchant promise binding).
    """

    #: The delayed settlement completed through the network: the
    #: settlement batch COMPLETED, finality ESTABLISHED, every
    #: obligation RESOLVED, and the merchant promise binding intact.
    DELAYED_SETTLEMENT_COMPLETED = "delayed-settlement-completed"

    #: The settlement failed definitively (the failure path — the
    #: merchant promise's delay condition resolves to explicit failure,
    #: never silently).
    SETTLEMENT_FAILED = "settlement-failed"

    @classmethod
    def parse(cls, value: object) -> "JourneyOutcome":
        if not isinstance(value, cls):
            raise CoreValidationError(
                f"journey outcome must be a JourneyOutcome member, got {value!r}"
            )
        return value


class JourneyStage(StrEnum):
    """The closed stage vocabulary of the composed merchant journey."""

    MERCHANT_CHECKOUT = "merchant-checkout"
    MERCHANT_PROMISE = "merchant-promise"
    PRIMARY_COMPILE = "primary-compile"
    PRIMARY_PLAN = "primary-plan"
    PRIMARY_SUBMIT = "primary-submit"
    RAIL_INCIDENT = "rail-incident"
    RAILOVER = "failover"
    RECOVERY_RECONCILE = "recovery-reconcile"
    RECOVERY_RETRY = "recovery-retry"
    OBLIGATION_RECOGNITION = "obligation-recognition"
    DELAYED_SETTLEMENT = "delayed-settlement"
    SETTLEMENT_RECONCILIATION = "settlement-reconciliation"
    FINALITY = "finality"
    OBLIGATION_RESOLUTION = "obligation-resolution"
    INCIDENT_RESOLUTION = "incident-resolution"
    MERCHANT_OUTCOME = "merchant-outcome"


#: The closed stage-vocabulary token set (journal honesty: every
#: journal entry's stage must be a declared member).
JOURNEY_STAGE_TOKENS = frozenset(stage.value for stage in JourneyStage)


#: The closed containment-probe vocabulary of the discrimination
#: battery: every probe must be CONTAINED — rejected/failed closed —
#: with the composed state byte-unchanged.
CONTAINMENT_PROBES = frozenset(
    {
        "merchant-credit-limit",
        "unknown-outcome-obligation",
        "failover-authority-conservation",
        "resolve-without-recovery",
        "outcome-before-finality",
        "outcome-binding-mismatch",
    }
)


def validate_flywheel_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names the merchant flywheel gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_FLYWHEEL_GATES:
        raise CoreValidationError(
            f"unknown flywheel gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_FLYWHEEL_GATES)}"
        )
    return gate_id
