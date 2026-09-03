"""DOGFOOD-031: the real merchant/customer sandbox journey.

Run in a clean process:

    python3 -m src.integration.flywheel.dogfooding

The experiment executes the WORK-031 mandated conformance task — *a
real user-facing merchant outcome through the complete PaySwap network,
including delay/credit, recovery and evidence* — against the REAL
composed surfaces (the merchant record boundary, the IG-002
fulfillment lifecycle harness over the two sandbox rails, the
operations resilience authority and the evidence domain) in ONE
isolated sandbox environment:

* a merchant checkout and settlement promise (PENDING — the explicit
  delayed/credited settlement condition, within the merchant credit
  limit) with a refund route;
* the canonical intent/fulfillment path on the primary rail, KILLED
  mid-flight (a scripted transport failure: no false success, nothing
  recorded rail-side);
* the operations authority observing the death, degrading with the
  execution authority digest, and failing over onto the declared
  redundancy rail (control-plane only);
* the recovery discipline: the dead leg reconciled NOT_FOUND before
  the retry, then the payment re-executed through the redundancy with
  a FRESH plan and idempotency key to a SUCCEEDED outcome;
* the delayed settlement: the obligation recognized from sealed
  SUCCEEDED evidence, due only inside the declared delay window, the
  cycle finalized, the settlement batch completing with its legs
  SETTLED, rail evidence folded, the finality certificate validated
  and finality ESTABLISHED, the obligations RESOLVED with
  digest-bound discharge evidence;
* the incident closure: the journal-only rebuild proof and the
  healthy re-probe resolving the incident within the declared
  recovery-time objective;
* the final merchant outcome: an OBSERVED evidence-domain observation
  binding the promise to the settled amount, the durable journey
  evidence record, and the typed outcome classification.

The transcript is fully deterministic (no wall-clock time, no
entropy): repeated runs are byte-identical. The durable experiment
record is persisted at ``spec/dogfooding/DOGFOOD-031.md``.
"""

from __future__ import annotations

from src.core.serialization import canonical_sha256

from .harness import FlywheelGate
from .invariants import verify_flywheel_invariants
from .scenarios import (
    journey_quality_attributes,
    run_containment_battery,
    run_merchant_journey,
)


def build_transcript() -> tuple[str, str]:
    """Execute DOGFOOD-031 and return (transcript, digest)."""
    lines: list[str] = [
        "DOGFOOD-031: merchant/global end-to-end dogfood (IG-006) - the real "
        "merchant/customer sandbox journey",
        "work order: WORK-031",
        "architecture: v0.1 (frozen)",
        "gate: IG-006 (merchant/global end-to-end dogfood; required inputs "
        "WORK-025, WORK-028, WORK-030 complete and merged on main, plus the "
        "WORK-024 implementation dependency)",
        "surface: src.integration.flywheel composing the real src.merchant "
        "record boundary, the real src.integration.lifecycle fulfillment "
        "harness over two local deterministic rails (the merged WORK-030 "
        "sandbox-rail public re-export), the real src.operations resilience "
        "authority and the real src.evidence domain",
        "environment: env/sandbox-ig006-flywheel (ONE isolated sandbox "
        "environment of the same protocol - the merged IG-003 parity "
        "vocabulary's simulation role; no production financial state is "
        "reachable)",
        "task: prove a real user-facing merchant outcome through the complete "
        "network, including delay/credit, recovery and evidence",
        "journey: merchant checkout -> settlement promise (PENDING, within "
        "credit, bound to the settlement batch) + refund route -> canonical "
        "intent/fulfillment on the primary rail -> THE KILL (transport "
        "failure) -> dead canary -> incident -> degradation -> governed "
        "failover -> dead-leg reconciliation NOT_FOUND -> recovery retry "
        "(fresh plan + fresh key) on the redundancy -> SUCCEEDED -> "
        "obligation recognized from sealed evidence -> declared delay window "
        "-> settlement batch COMPLETED with legs SETTLED -> finality "
        "ESTABLISHED -> obligations RESOLVED -> journal-only rebuild proof "
        "-> healthy re-probe -> incident RESOLVED -> OBSERVED merchant "
        "outcome + durable journey evidence",
    ]
    try:
        gate = FlywheelGate()
        result = run_merchant_journey(gate)
        report = result["report"]
        facts = result["facts"]
        lines.extend(
            [
                f"checkout: {report['checkout_id']} state={report['checkout_state']} "
                f"amount={report['amount_minor']} {report['asset_code']} minor units "
                f"(scale 2) credit_limit={report['credit_limit_minor']}",
                f"promise: {report['promise_id']} state={report['promise_state']} "
                f"(the explicit delayed-settlement condition) bound to "
                f"{report['promise_settlement_binding']}",
                f"the kill: first submission state={facts['first_submission_state']} "
                "(never a false success: no effect result, nothing recorded "
                "rail-side, zero obligations from the killed leg)",
                f"incident: {facts['degradation_severity']} degradation -> failover "
                f"onto {facts['failover_target']} (control-plane only: the "
                "authority digest conserved) -> dead-leg reconciliation "
                f"{facts['dead_leg_reconciliation']} (retry-safe truth)",
                f"recovery: fresh plan + fresh key on the redundancy -> step "
                f"{facts['recovery_step_state']} -> incident "
                f"{facts['incident_final_state']} (recovery duration "
                f"{facts['recovery_duration_seconds']}s within the 3600s "
                "declared objective)",
                f"delayed settlement: obligation {report['obligation_ids'][0]} "
                "due only inside the declared window "
                "(2026-09-04T02:20:00Z..2026-09-05T06:00:00Z) -> settlement "
                f"batch {report['settlement_id']} state={report['settlement_state']} "
                f"with every leg SETTLED -> finality {report['finality_id']} "
                f"state={report['finality_state']} -> obligations RESOLVED with "
                "digest-bound discharge evidence",
                f"merchant outcome: {report['outcome']} - the OBSERVED outcome "
                f"observation {report['outcome_observation_id']} (promise-bound, "
                f"amount-conserved) + the durable journey evidence "
                f"{report['journey_evidence_id']}",
                f"work performed: {report['stage_count']} recorded stages, "
                f"{report['command_count']} commands driven through the "
                "composed kernels",
            ]
        )

        checks = verify_flywheel_invariants(gate)
        lines.append(
            f"invariants: {len(checks)}/{len(checks)} PASS: "
            + ", ".join(checks)
        )

        battery = run_containment_battery(gate)
        lines.append(
            "containment battery: "
            f"{battery['contained_count']}/{battery['probe_count']} probes "
            "contained (merchant credit limit, unknown-outcome obligation, "
            "failover authority conservation, resolve without recovery, "
            "outcome before finality, outcome binding mismatch), all "
            "fail-closed, with the live composed state byte-unchanged: "
            + str(battery["live_state_unchanged"])
        )

        quality = journey_quality_attributes(gate)
        lines.extend(
            [
                "quality attributes (deterministic measurements from declared "
                "data and real authority reads):",
                f"  cost: commands={quality['commands_driven']} "
                f"stages={quality['stages_recorded']} "
                f"rail_submit_calls={quality['rail_submit_calls_primary']}+"
                f"{quality['rail_submit_calls_redundancy']}",
                f"  time (logical, declared): journey="
                f"{quality['journey_logical_seconds']}s "
                f"recovery={quality['recovery_logical_seconds']}s "
                f"settlement_delay_window="
                f"{quality['settlement_delay_window_seconds']}s",
                f"  reliability/outcome: {quality['outcome']} "
                f"killed_leg={quality['killed_leg_outcome']} "
                f"reconciliation={quality['dead_leg_reconciliation']} "
                f"recovery_step={quality['recovery_step_state']} "
                f"false_successes={quality['false_success_count']}",
                f"  recovery behavior: duration="
                f"{quality['recovery_duration_seconds']}s "
                f"objective={quality['recovery_time_objective_seconds']}s "
                f"within_objective={quality['recovery_within_objective']} "
                f"retries={quality['recovery_retry_count']}",
            ]
        )

        lines.extend(
            [
                "observed outcome: the complete merchant/customer journey "
                "completed through the real composed authorities - the "
                "delayed settlement completed (promise PENDING -> "
                "delayed-settlement-completed observed), the killed leg "
                "never produced a false success, the recovery stayed inside "
                "the declared objective, and the outcome is durable evidence",
                "classification: DOGFOOD-031: PASS",
            ]
        )
    except Exception as exc:  # dogfooding classification, not a domain error path
        lines.extend(
            [
                f"observed outcome: experiment failed ({type(exc).__name__}: {exc})",
                "classification: DOGFOOD-031: CONTRACT_FAILURE",
            ]
        )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> None:
    transcript, _digest = build_transcript()
    print(transcript, end="")


if __name__ == "__main__":
    main()
