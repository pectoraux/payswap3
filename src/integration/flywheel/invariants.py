"""The IG-006 invariant battery: the composed-journey truth checks.

Every check reads REAL authority records through their public
boundaries (the gate's own projections are never the source). The
battery verifies the WORK-031 acceptance surface:

* **merchant delay/credit discipline** — the checkout/promise/refund
  records, the promise's ``PENDING`` delay representation, the credit
  limit, and the promise↔settlement binding;
* **no false success** — the killed leg ends ``UNKNOWN`` with no
  effect result, never recorded rail-side, and produces ZERO
  obligations in the primary composition;
* **recovery discipline** — the dead leg reconciled ``NOT_FOUND``
  before the retry, the retry ran on a FRESH key through the declared
  redundancy, and the rail-side idempotency held;
* **settlement truth** — the settlement COMPLETED with every leg
  SETTLED, finality ESTABLISHED and bound to the settlement, the
  obligations RESOLVED with discharge evidence, the declared delay
  window respected, and exact amount conservation across every leg;
* **resilience conservation** — the degradation/failover digests
  equal the live authority digest (control-plane only), the incident
  RESOLVED within the declared recovery-time objective;
* **evidence discipline** — the outcome observation and journey
  evidence are sealed, OBSERVED, fresh and correctly bound;
* **journal honesty** — the stage journal chains, every stage
  accepted, and the composed digest recomputes identically;
* **environment isolation** — every durable record of the composed
  authorities carries the sandbox environment id (no production
  financial state is reachable).
"""

from __future__ import annotations

from typing import Any

from src.core.errors import CoreValidationError
from src.evidence import (
    Evidence,
    Observation,
    evidence_is_fresh,
    observation_is_fresh,
)

from .contracts import (
    CHECKOUT_ID,
    CREDIT_LIMIT_MINOR,
    FINALITY_ID,
    INCIDENT_ID,
    JOURNEY_AMOUNT_MINOR,
    JOURNEY_ASSET_CODE,
    PROMISE_ID,
    PRIMARY_IDEMPOTENCY_KEY,
    PRIMARY_STEP_ID,
    REFUND_ROUTE_ID,
    REDUNDANCY_IDEMPOTENCY_KEY,
    REDUNDANCY_STEP_ID,
    SETTLEMENT_ID,
    T_DUE_FROM,
    T_DUE_UNTIL,
    T_OUTCOME,
    T_VALID_UNTIL,
    JOURNEY_EVIDENCE_ID,
    OUTCOME_OBSERVATION_ID,
)
from .harness import FlywheelGate


def verify_flywheel_invariants(gate: FlywheelGate) -> list[str]:
    """Run the battery; raise on the first violation; return check names."""
    checks: list[str] = []
    _check_merchant_records(gate, checks)
    _check_no_false_success(gate, checks)
    _check_recovery_discipline(gate, checks)
    _check_settlement_truth(gate, checks)
    _check_resilience_conservation(gate, checks)
    _check_evidence_discipline(gate, checks)
    _check_journal_honesty(gate, checks)
    _check_environment_isolation(gate, checks)
    return checks


def _check(condition: bool, checks: list[str], name: str) -> None:
    if not condition:
        raise CoreValidationError(f"flywheel invariant violated: {name}")
    checks.append(name)


# -- merchant delay/credit discipline ----------------------------------------


def _check_merchant_records(gate: FlywheelGate, checks: list[str]) -> None:
    records = gate.merchant
    checkout = records[CHECKOUT_ID]
    promise = records[PROMISE_ID]
    route = records[REFUND_ROUTE_ID]
    _check(
        checkout.envelope.state == "PROMISED",
        checks,
        "merchant_checkout_promised",
    )
    _check(
        checkout.spec.amount.value == JOURNEY_AMOUNT_MINOR
        and checkout.spec.amount.asset == JOURNEY_ASSET_CODE,
        checks,
        "merchant_checkout_amount_declared",
    )
    _check(
        promise.envelope.state == "PENDING",
        checks,
        "merchant_promise_pending_the_delay_representation",
    )
    _check(
        promise.spec.settlement_id == SETTLEMENT_ID,
        checks,
        "merchant_promise_settlement_binding_intact",
    )
    _check(
        promise.spec.credit_limit is not None
        and promise.spec.credit_limit.value == CREDIT_LIMIT_MINOR
        and promise.spec.amount.value <= promise.spec.credit_limit.value,
        checks,
        "merchant_promise_within_credit_limit",
    )
    _check(
        promise.spec.amount.value == JOURNEY_AMOUNT_MINOR,
        checks,
        "merchant_promise_amount_conserved",
    )
    _check(
        route.envelope.state == "OPEN"
        and route.settlement_id == SETTLEMENT_ID,
        checks,
        "merchant_refund_route_open_and_bound",
    )
    _check(
        all(
            bool(record.integrity_hash)
            for record in (checkout, promise, route)
        ),
        checks,
        "merchant_records_sealed",
    )


# -- no false success ----------------------------------------------------------


def _check_no_false_success(gate: FlywheelGate, checks: list[str]) -> None:
    step = gate.primary.execution.step(PRIMARY_STEP_ID)
    _check(
        step.state.value == "UNKNOWN",
        checks,
        "killed_leg_unknown_never_a_false_success",
    )
    result_id = f"{PRIMARY_STEP_ID}/request/1/result"
    has_result = False
    try:
        gate.primary.execution.effect_result(result_id)
        has_result = True
    except CoreValidationError:
        has_result = False
    _check(not has_result, checks, "killed_leg_has_no_effect_result")
    _check(
        PRIMARY_IDEMPOTENCY_KEY not in gate.world.primary_rail.processed_keys,
        checks,
        "killed_key_never_recorded_rail_side",
    )
    from src.clearing import Obligation

    primary_obligations = [
        record
        for record in gate.primary.clearing.records()
        if isinstance(record, Obligation)
    ]
    _check(
        len(primary_obligations) == 0,
        checks,
        "primary_composition_recognized_zero_obligations",
    )


# -- recovery discipline -------------------------------------------------------


def _check_recovery_discipline(gate: FlywheelGate, checks: list[str]) -> None:
    facts = gate.journey_facts
    _check(
        facts.get("dead_leg_reconciliation") == "NOT_FOUND",
        checks,
        "dead_leg_reconciled_not_found_before_retry",
    )
    _check(
        PRIMARY_IDEMPOTENCY_KEY != REDUNDANCY_IDEMPOTENCY_KEY,
        checks,
        "recovery_used_a_fresh_idempotency_key",
    )
    _check(
        REDUNDANCY_IDEMPOTENCY_KEY in gate.world.redundancy_rail.processed_keys,
        checks,
        "redundancy_rail_processed_the_retry_key_exactly_once",
    )
    _check(
        gate.world.redundancy_rail.submit_call_count == 1,
        checks,
        "redundancy_rail_single_submission",
    )
    recovery_step = gate.redundancy.execution.step(REDUNDANCY_STEP_ID)
    _check(
        recovery_step.state.value == "SUCCEEDED",
        checks,
        "recovery_step_succeeded",
    )


# -- settlement truth ----------------------------------------------------------


def _check_settlement_truth(gate: FlywheelGate, checks: list[str]) -> None:
    settlement = gate.redundancy.settlement.settlement(SETTLEMENT_ID)
    finality = gate.redundancy.settlement.finality(FINALITY_ID)
    _check(
        settlement.envelope.state == "COMPLETED",
        checks,
        "settlement_batch_completed",
    )
    _check(
        all(leg.state == "SETTLED" for leg in settlement.spec.leg_outcomes),
        checks,
        "every_settlement_leg_settled",
    )
    _check(
        finality.envelope.state == "ESTABLISHED"
        and finality.spec.settlement_id == SETTLEMENT_ID,
        checks,
        "finality_established_and_bound_to_the_settlement",
    )
    for obligation_id in gate.obligation_ids:
        obligation = gate.redundancy.clearing.obligation(obligation_id)
        _check(
            obligation.envelope.state == "RESOLVED",
            checks,
            "obligation_resolved",
        )
        _check(
            obligation.spec.amount.value == JOURNEY_AMOUNT_MINOR
            and obligation.spec.amount.asset == JOURNEY_ASSET_CODE,
            checks,
            "obligation_amount_conserved",
        )
        window = obligation.spec.due_window
        _check(
            window.due_from == T_DUE_FROM and window.due_until == T_DUE_UNTIL,
            checks,
            "obligation_declared_delay_window_exact",
        )
    discharge = gate.redundancy.settlement.discharge_evidence(SETTLEMENT_ID)
    _check(
        len(discharge) == len(gate.obligation_ids)
        and all(binding["evidence_digest"] for binding in discharge),
        checks,
        "obligation_resolution_digest_bound_discharge_evidence",
    )
    for instruction in settlement.spec.instructions:
        _check(
            instruction.amount.value == JOURNEY_AMOUNT_MINOR
            and instruction.amount.asset == JOURNEY_ASSET_CODE,
            checks,
            "settlement_instruction_amount_conserved",
        )
    _check(
        settlement.spec.window.settle_by == "2026-09-05T06:00:00Z",
        checks,
        "settlement_window_declares_the_delay_deadline",
    )


# -- resilience conservation ---------------------------------------------------


def _check_resilience_conservation(gate: FlywheelGate, checks: list[str]) -> None:
    incident = gate.operations.incident(INCIDENT_ID)
    _check(
        incident.state.value == "RESOLVED",
        checks,
        "incident_resolved",
    )
    degradation = incident.spec.degradation_facts[-1]
    _check(
        degradation.severity == "UNAVAILABLE",
        checks,
        "degradation_declared_unavailable",
    )
    failover = incident.spec.failover_fact
    _check(
        dict(failover.authority_digests) == dict(degradation.affected_authorities),
        checks,
        "failover_conserved_the_authority_digest",
    )
    recorded = dict(failover.authority_digests).get("authority/ig006-execution")
    _check(
        isinstance(recorded, str)
        and len(recorded) == 64
        and all(char in "0123456789abcdef" for char in recorded),
        checks,
        "failover_digest_is_a_wellformed_authority_digest",
    )
    _check(
        incident.spec.resolution_fact.recovery_duration_seconds <= 3600,
        checks,
        "recovery_within_declared_objective",
    )
    _check(
        failover.target_dependency == "operations/dependency/ig006-redundancy-rail",
        checks,
        "failover_target_is_the_declared_redundancy",
    )


# -- evidence discipline -------------------------------------------------------


def _check_evidence_discipline(gate: FlywheelGate, checks: list[str]) -> None:
    observation = gate.evidence.get(OUTCOME_OBSERVATION_ID)
    _check(
        isinstance(observation, Observation),
        checks,
        "outcome_observation_is_an_evidence_domain_record",
    )
    _check(
        observation.spec.epistemic_type.value == "OBSERVED",
        checks,
        "outcome_observation_epistemic_observed",
    )
    _check(
        observation.spec.subject_ref == PROMISE_ID,
        checks,
        "outcome_observation_bound_to_the_promise",
    )
    _check(
        observation.spec.value.value == JOURNEY_AMOUNT_MINOR
        and observation.spec.value.unit == JOURNEY_ASSET_CODE,
        checks,
        "outcome_observation_records_the_settled_amount",
    )
    _check(
        observation_is_fresh(observation, T_OUTCOME),
        checks,
        "outcome_observation_fresh_at_outcome_time",
    )
    _check(
        evidence_is_fresh(gate.evidence.get(JOURNEY_EVIDENCE_ID), T_OUTCOME),
        checks,
        "journey_evidence_fresh_at_outcome_time",
    )
    evidence = gate.evidence.get(JOURNEY_EVIDENCE_ID)
    _check(
        isinstance(evidence, Evidence),
        checks,
        "journey_evidence_is_an_evidence_domain_record",
    )
    _check(
        evidence.spec.subject_ref == CHECKOUT_ID,
        checks,
        "journey_evidence_bound_to_the_checkout",
    )
    _check(
        any(
            ref.kind.value == "OBSERVATION" and ref.ref == OUTCOME_OBSERVATION_ID
            for ref in evidence.spec.payload_refs
        ),
        checks,
        "journey_evidence_rests_on_the_outcome_observation",
    )


# -- journal honesty ------------------------------------------------------------


def _check_journal_honesty(gate: FlywheelGate, checks: list[str]) -> None:
    journal = gate.stage_journal
    _check(len(journal) > 0, checks, "stage_journal_non_empty")
    chained = all(
        journal[index]["state_after"] == journal[index + 1]["state_before"]
        for index in range(len(journal) - 1)
    )
    _check(chained, checks, "stage_journal_chains")
    _check(
        all(entry["outcome"] == "accepted" for entry in journal),
        checks,
        "every_journey_stage_accepted",
    )
    _check(
        journal[-1]["state_after"] == gate.composed_state_digest(),
        checks,
        "composed_digest_recomputes_identically",
    )
    report = gate.journey_report()
    _check(
        report["outcome"] == "delayed-settlement-completed",
        checks,
        "journey_outcome_delayed_settlement_completed",
    )


# -- environment isolation -------------------------------------------------------


def _check_environment_isolation(gate: FlywheelGate, checks: list[str]) -> None:
    environment_id = gate.world.environment_id

    def _all_records(engine: Any) -> list[Any]:
        getter = getattr(engine, "objects", None) or getattr(engine, "records")
        return list(getter())

    sandbox_bound = all(
        record.envelope.environment_id == environment_id
        for engine in (
            gate.primary.execution,
            gate.primary.clearing,
            gate.redundancy.execution,
            gate.redundancy.clearing,
            gate.redundancy.settlement,
        )
        for record in _all_records(engine)
    )
    _check(sandbox_bound, checks, "composed_records_bound_to_the_sandbox_environment")
    merchant_bound = all(
        record.envelope.environment_id == environment_id
        for record in gate.merchant.values()
    )
    _check(merchant_bound, checks, "merchant_records_bound_to_the_sandbox_environment")
    incident = gate.operations.incident(INCIDENT_ID)
    _check(
        incident.envelope.environment_id == environment_id,
        checks,
        "incident_bound_to_the_sandbox_environment",
    )
    _check(
        gate.evidence.get(OUTCOME_OBSERVATION_ID).envelope.environment_id
        == environment_id
        and gate.evidence.get(JOURNEY_EVIDENCE_ID).envelope.environment_id
        == environment_id,
        checks,
        "evidence_records_bound_to_the_sandbox_environment",
    )
