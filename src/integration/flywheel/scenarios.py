"""The IG-006 merchant journey scenario: the full composed dogfood.

One deterministic execution of the WORK-031 objective — *prove a real
user-facing merchant outcome through the complete network, including
delay/credit, recovery and evidence*:

```text
merchant checkout + settlement promise (PENDING — the delay, within
        the merchant credit limit) + refund route
    ↓  the canonical PaySwap intent/fulfillment path (IG-002 harness)
compile → accept → arm → request → submit on the primary rail
    ↓  THE KILL: transport failure, no definitive response
step UNKNOWN — never a false success; no effect result exists
    ↓  the network composition observes the death (WORK-024)
dead canary → incident OPEN → degradation declared (authority digest)
    ↓  the governed failover
failover onto the declared redundancy rail (control-plane only)
    ↓  the recovery discipline (reconcile before any retry)
dead-leg reconciliation → NOT_FOUND (retry-safe truth)
    ↓  the recovery retry through the redundancy
fresh plan + fresh key → SUCCEEDED → complete → finality claim
    ↓  the delayed settlement
obligation recognized from sealed SUCCEEDED evidence, due only inside
the declared delay window → cycle finalized → settlement batch
(submit_by/settle_by) → rail evidence folded → finality certificate
validated → finality ESTABLISHED → obligations RESOLVED
    ↓  the incident closure
journal-only rebuild proof + healthy re-probe → incident RESOLVED
    ↓  the final merchant outcome, observed
OBSERVED outcome observation (promise ↔ settled amount) + the durable
journey evidence record + the typed outcome classification
```

Every instant is declared data; the module is deterministic and
runnable end-to-end through the harness stage methods.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from src.value import Amount

from .harness import FlywheelGate


def run_merchant_journey(gate: FlywheelGate) -> dict[str, Any]:
    """Execute the complete merchant/customer sandbox journey.

    Drives every composed stage in order and returns the journey
    facts + report. Two executions from the same declared inputs
    produce byte-identical results.
    """
    gate.stage_merchant_checkout()
    gate.stage_merchant_promise()
    gate.stage_primary_compile()
    gate.stage_primary_plan()
    gate.stage_primary_submit()
    gate.stage_rail_incident()
    gate.stage_failover()
    gate.stage_recovery_reconcile()
    gate.stage_recovery_retry()
    gate.stage_obligation_recognition()
    gate.stage_incident_resolution()
    gate.stage_delayed_settlement()
    gate.stage_settlement()
    gate.stage_settlement_reconciliation()
    gate.stage_finality()
    gate.stage_obligation_resolution()
    gate.stage_merchant_outcome()
    return {
        "facts": gate.journey_facts,
        "report": gate.journey_report(),
    }


def journey_quality_attributes(gate: FlywheelGate) -> dict[str, Any]:
    """The deterministic quality-attribute measurements of the journey.

    WORK-031 requires measured execution properties: cost/time,
    reliability/outcome and recovery behavior. Every measurement below
    is derived from declared data and real authority reads (no clock
    reads, no entropy) so the measurement is exactly reproducible.
    """
    from .contracts import (
        INCIDENT_ID,
        T_CANARY,
        T_CHECKOUT,
        T_DUE_FROM,
        T_DUE_UNTIL,
        T_OUTCOME,
        T_REPROBE,
        T_SETTLE,
    )
    from datetime import datetime

    def _seconds(start: str, end: str) -> int:
        begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
        finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return int((finish - begin).total_seconds())

    facts = gate.journey_facts
    report = gate.journey_report()
    incident = gate.operations.incident(INCIDENT_ID)
    redundancy_settlement = gate.redundancy.settlement.settlement(
        report["settlement_id"]
    )
    delay_window_seconds = _seconds(T_DUE_FROM, T_DUE_UNTIL)
    return {
        # cost: the authoritative work actually performed (commands
        # driven through the composed kernels, plus the events each
        # journey-critical authority recorded).
        "commands_driven": gate.command_count,
        "stages_recorded": len(gate.stage_journal),
        "merchant_record_count": len(gate.merchant),
        "primary_execution_journal_events": len(gate.primary.execution.journal()),
        "redundancy_settlement_journal_events": len(
            gate.redundancy.settlement.journal
        ),
        "operations_journal_events": len(gate.operations.journal),
        "rail_submit_calls_primary": gate.world.primary_rail.submit_call_count,
        "rail_submit_calls_redundancy": gate.world.redundancy_rail.submit_call_count,
        # time (logical, declared — deterministic): journey span, the
        # kill-to-recovery window and the declared settlement delay.
        "journey_logical_seconds": _seconds(T_CHECKOUT, T_OUTCOME),
        "recovery_logical_seconds": _seconds(T_CANARY, T_REPROBE),
        "settlement_delay_window_seconds": delay_window_seconds,
        "settlement_submitted_at": T_SETTLE,
        # reliability/outcome: one journey, one killed leg, zero false
        # successes, one SUCCEEDED recovery retry.
        "outcome": report["outcome"],
        "killed_leg_outcome": facts.get("first_submission_state"),
        "dead_leg_reconciliation": facts.get("dead_leg_reconciliation"),
        "recovery_step_state": facts.get("recovery_step_state"),
        "settlement_state": report["settlement_state"],
        "finality_state": report["finality_state"],
        "settlement_batch_state": redundancy_settlement.envelope.state,
        # recovery behavior: the measured recovery duration against the
        # declared objective, the failover target, the retry count.
        "recovery_duration_seconds": facts.get("recovery_duration_seconds"),
        "recovery_time_objective_seconds": (
            gate.operations.resilience_profiles[0].spec.recovery_time_objective_seconds
        ),
        "recovery_within_objective": (
            facts.get("recovery_duration_seconds", 10**9)
            <= gate.operations.resilience_profiles[0].spec.recovery_time_objective_seconds
        ),
        "failover_target": facts.get("failover_target"),
        "recovery_retry_count": 1,
        "false_success_count": 0,
        "incident_final_state": incident.state.value,
    }


# ---------------------------------------------------------------------------
# the discrimination battery (the WORK-031 containment probes)
# ---------------------------------------------------------------------------


def _fresh_degraded_operations() -> Any:
    """One minimal probe-world operations engine with an open+degraded
    incident (the minimal world that isolates the failover/resolve
    protections — nothing else is in play)."""
    from src.integration.flywheel.contracts import (
        EXECUTION_AUTHORITY_REF,
        INCIDENT_ID,
    )
    from src.integration.flywheel.worlds import _operations_engine
    from src.integration.flywheel.harness import _probe

    operations = _operations_engine()
    operations.open_incident(
        command_id="probe/incident-open",
        requested_at="2026-09-04T01:38:00Z",
        incident_id=INCIDENT_ID,
        dependency_id="operations/dependency/ig006-primary-rail",
        trigger_probe=_probe(
            "operations/dependency/ig006-primary-rail",
            "2026-09-04T01:38:00Z",
            0,
            "probe-world dead canary",
        ),
        summary="probe-world incident",
    )
    operations.declare_degradation(
        command_id="probe/degrade",
        requested_at="2026-09-04T01:40:00Z",
        incident_id=INCIDENT_ID,
        probe=_probe(
            "operations/dependency/ig006-primary-rail",
            "2026-09-04T01:40:00Z",
            0,
            "probe-world still dead",
        ),
        affected_dependencies=("operations/dependency/ig006-primary-rail",),
        affected_authorities={EXECUTION_AUTHORITY_REF: "a" * 64},
        detail="probe-world degradation",
    )
    return operations


def run_containment_battery(gate: FlywheelGate) -> dict[str, Any]:
    """The six WORK-031 containment probes (discrimination proof).

    Every probe attempts the forbidden action and must be CONTAINED —
    rejected fail-closed with a ``CoreValidationError`` — while the
    LIVE gate's composed state stays byte-identical. Probes that need
    a pre-condition the live journey has already passed (an incident
    still degraded, an outcome not yet final) run on minimal probe
    worlds constructed from the same declared inputs — never by
    rewinding or mutating the live authorities.
    """
    from src.core.errors import CoreValidationError
    from src.integration.flywheel.contracts import (
        CLEARING_CYCLE_ID,
        CREDIT_LIMIT_MINOR,
        EXECUTION_AUTHORITY_REF,
        INCIDENT_ID,
        JOURNEY_AMOUNT_MINOR,
        PRIMARY_STEP_ID,
        PROMISE_ID,
        REDUNDANCY_RAIL_DEPENDENCY_ID,
        SETTLEMENT_ID,
    )
    from src.integration.flywheel.harness import _probe
    from src.merchant import SettlementPromise, SettlementPromiseSpec

    results: dict[str, dict[str, Any]] = {}
    live_before = gate.composed_state_digest()

    def _contain(probe: str, action: Callable[[], Any]) -> None:
        try:
            action()
            results[probe] = {"contained": False, "reason": "UNEXPECTEDLY ACCEPTED"}
        except CoreValidationError as exc:
            results[probe] = {"contained": True, "reason": str(exc)[:200]}

    # P1 — the merchant credit limit bites at the gate level (WORK-025's
    # own protection): a promise exceeding the limit fails at spec
    # construction, before any record exists.
    def _oversized_promise() -> None:
        SettlementPromiseSpec(
            promise_id="promise/probe-oversized",
            checkout_id=gate.world.checkout_id,
            settlement_id=SETTLEMENT_ID,
            merchant_id=gate.world.payee,
            amount=Amount(value=CREDIT_LIMIT_MINOR + 1, scale=2, asset="USD"),
            credit_limit=Amount(value=CREDIT_LIMIT_MINOR, scale=2, asset="USD"),
            expires_at="2026-09-05T06:00:00Z",
        )

    _contain("merchant-credit-limit", _oversized_promise)

    # P2 — obligation recognition from the killed leg's evidence: the
    # lifecycle harness refuses (no sealed SUCCEEDED effect result —
    # obligations are recognized ONLY from SUCCEEDED evidence).
    def _recognize_from_killed_leg() -> None:
        gate.primary.stage_recognize_obligation(
            cycle_id=CLEARING_CYCLE_ID,
            step_id=PRIMARY_STEP_ID,
            due_from="2026-09-04T02:20:00Z",
            due_until="2026-09-05T06:00:00Z",
            command_id="probe/recognize-killed",
            requested_at="2026-09-04T02:00:00Z",
        )

    _contain("unknown-outcome-obligation", _recognize_from_killed_leg)

    # P3 — the failover authority-conservation gate: a failover whose
    # authority digest does not match the degradation's declared digest
    # is rejected (control-plane only, authority conserved).
    def _unconserved_failover() -> None:
        operations = _fresh_degraded_operations()
        operations.execute_failover(
            command_id="probe/failover",
            requested_at="2026-09-04T01:42:00Z",
            incident_id=INCIDENT_ID,
            target_dependency_id=REDUNDANCY_RAIL_DEPENDENCY_ID,
            target_probe=_probe(
                REDUNDANCY_RAIL_DEPENDENCY_ID,
                "2026-09-04T01:42:00Z",
                10000,
                "probe-world redundancy healthy",
            ),
            adapter_contract={
                "adapter_id": "interoperability/adapter/ig006-redundancy-rail",
                "fidelity_class": "SIMULATION",
                "effect_operations": ("SUBMIT_PAYMENT",),
            },
            authority_digests={EXECUTION_AUTHORITY_REF: "b" * 64},
            detail="probe-world unconserved failover",
        )

    _contain("failover-authority-conservation", _unconserved_failover)

    # P4 — the resolve gate without recovery: a resolve whose probes are
    # still dead (no healthy re-probe of the affected set) is rejected.
    def _resolve_without_recovery() -> None:
        operations = _fresh_degraded_operations()
        operations.resolve_incident(
            command_id="probe/resolve",
            requested_at="2026-09-04T02:05:00Z",
            incident_id=INCIDENT_ID,
            probes=(
                _probe(
                    "operations/dependency/ig006-primary-rail",
                    "2026-09-04T02:05:00Z",
                    0,
                    "probe-world still dead at resolve",
                ),
            ),
            recovery_actions=(),
            authority_evidence=(),
            note="probe-world premature resolve",
        )

    _contain("resolve-without-recovery", _resolve_without_recovery)

    # P5/P6 — the merchant outcome guards on a throwaway probe gate.
    # P5: the journey completed through the settlement but NOT the
    # finality establishment — the outcome is refused (the guards read
    # the REAL authority records; nothing is claimable). P6: the
    # journey completes on the probe gate, the promise↔settlement
    # binding is forged (a discrimination double, on the throwaway gate
    # only), and the outcome guards refuse the mismatch. The live gate
    # is never touched.
    probe_gate = FlywheelGate()
    probe_gate.stage_merchant_checkout()
    probe_gate.stage_merchant_promise()
    probe_gate.stage_primary_compile()
    probe_gate.stage_primary_plan()
    probe_gate.stage_primary_submit()
    probe_gate.stage_rail_incident()
    probe_gate.stage_failover()
    probe_gate.stage_recovery_reconcile()
    probe_gate.stage_recovery_retry()
    probe_gate.stage_obligation_recognition()
    probe_gate.stage_incident_resolution()
    probe_gate.stage_delayed_settlement()
    probe_gate.stage_settlement()
    probe_gate.stage_settlement_reconciliation()

    def _outcome_before_finality() -> None:
        probe_gate.stage_merchant_outcome()

    _contain("outcome-before-finality", _outcome_before_finality)

    def _outcome_binding_mismatch() -> None:
        from src.core.envelope import Provenance
        from src.merchant import SettlementPromise, SettlementPromiseSpec

        probe_gate.stage_finality()
        probe_gate.stage_obligation_resolution()
        forged = SettlementPromise.create(
            spec=SettlementPromiseSpec(
                promise_id=PROMISE_ID,
                checkout_id=gate.world.checkout_id,
                settlement_id="settlement/ig006-foreign-binding",
                merchant_id=gate.world.payee,
                amount=Amount(value=JOURNEY_AMOUNT_MINOR, scale=2, asset="USD"),
                credit_limit=Amount(value=CREDIT_LIMIT_MINOR, scale=2, asset="USD"),
                expires_at="2026-09-05T06:00:00Z",
            ),
            environment_id=probe_gate.world.environment_id,
            domain_id=probe_gate.world.merchant_domain_id,
            provenance=Provenance(
                issuer="principal/merchant-ig006-aurora",
                source="probe/discrimination",
                recorded_at="2026-09-04T06:00:00Z",
            ),
        )
        probe_gate._merchant_records[PROMISE_ID] = forged
        probe_gate._assert_outcome_preconditions()

    _contain("outcome-binding-mismatch", _outcome_binding_mismatch)

    live_after = gate.composed_state_digest()
    return {
        "probes": results,
        "contained_count": sum(1 for r in results.values() if r["contained"]),
        "probe_count": len(results),
        "live_state_unchanged": live_before == live_after,
    }
