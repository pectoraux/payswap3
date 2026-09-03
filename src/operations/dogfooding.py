"""DOGFOOD-024 — kill a simulated provider and observe safe degradation/recovery.

The Work Order's mandated dogfooding experiment: **kill a simulated
provider/dependency and observe safe degradation and recovery.**

This module is a clearly-marked TEST-SIDE ARTIFACT of the operations
domain (the sibling convention): it is not imported by the
authoritative package surface and contributes no domain semantics.

Scenario (every instant is declared data; the module is deterministic
and runnable as ``python3 -m src.operations.dogfooding``):

* The payment-execution service declares two provider adapters — the
  primary rail A (``interoperability/adapter/provider-a``) and the
  declared redundancy rail B (``interoperability/adapter/provider-b``),
  both bound through the REAL public adapter path
  (:class:`src.execution.adapters.AdapterBinding` over the typed
  ``EffectSubmissionPort``/``EffectReconciliationPort``). The local
  deterministic fake rail of the execution domain's own dogfooding
  artifact stands in for each provider.
* A one-leg payment plan runs against rail A. At submission the
  provider is KILLED mid-flight (the scripted rail returns a transport
  failure: no definitive submission response). The in-flight step ends
  ``UNKNOWN`` — never a false success: no effect result exists, the
  step cannot complete, and the clearing authority REFUSES the
  unknown-outcome evidence (obligations are recognized only from
  ``SUCCEEDED`` effect results).
* Operations observes the dead canary (probe: 0 bps → ``UNAVAILABLE``),
  opens an incident, declares the degradation with the digest of the
  execution authority's live public record index as the affected
  authority, and executes the failover onto the declared redundancy
  rail B — the failover conservation gate proves the authority digest
  is unchanged (a failover decision never mutates authoritative state).
* Recovery orchestration runs the declared recovery plan:
  RECONCILE (the reconciled-before-retry discipline: query the dead
  leg through the public reconciliation port → ``NOT_FOUND``, the
  effect never happened), RETRY (the payment is re-submitted through
  the redundancy rail B via a fresh plan and idempotency key, to an
  acknowledged ``SUCCEEDED`` effect result and a ``COMPLETED`` step —
  and the clearing authority now recognizes the REAL obligation),
  REBUILD (a journal-only rebuild of the execution authority proves
  the live index digest equals the rebuilt index digest — no silent
  state loss), REPROBE (rail A is restored and probes healthy).
* The incident is RESOLVED through the real resolve gate: fresh
  HEALTHY probes of the exact affected set, exact declared-plan
  recovery coverage, journal-only rebuild evidence for every affected
  authority, and recovery within the declared recovery-time objective.

``build_transcript`` returns a deterministic structured transcript
(scenario facts and PASS/FAIL checks); it never reads the wall clock
and never uses entropy.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.execution.adapters import AdapterBinding
from src.execution.contracts import EffectOutcome
from src.execution.dogfooding import SandboxRail
from src.interoperability import (
    EFFECT_CAPABLE_FIDELITY_CLASSES,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    WorldAdapter,
)
from src.simulation.effects import EffectAuthorization

from .contracts import DependencyKind, HealthStatus, RecoveryActionKind
from .engine import OperationsEngine
from .graph import DependencyGraph, make_dependency_record
from .incidents import AuthorityRebuild, RecoveryActionRecord
from .metrics import ProbeResult, economic_exposure
from .profiles import classify_health, make_profile_record

# -- declared experiment constants (all data; no clock reads) ---------------

ENV = "env/dogfood-operations-024"
DOMAIN = "domain/operations"
EXECUTION_DOMAIN = "domain/payments"
CLEARING_DOMAIN = "domain/clearing"

RAIL_A = "operations/dependency/provider-a"
RAIL_B = "operations/dependency/provider-b"
EXECUTION_SERVICE = "operations/service/payment-execution"

ADAPTER_A = "interoperability/adapter/provider-a"
ADAPTER_B = "interoperability/adapter/provider-b"
CAPABILITY_A = "capability/provider-a"
CAPABILITY_B = "capability/provider-b"

EXECUTION_AUTHORITY = "authority/execution"

PLAN_1 = "execution/plan/dogfood-024-payment-1"
STEP_1 = "execution/plan/dogfood-024-payment-1/step/1"
PLAN_2 = "execution/plan/dogfood-024-recovery-2"
STEP_2 = "execution/plan/dogfood-024-recovery-2/step/1"

KEY_1 = "dogfood-024-pay-1"
KEY_2 = "dogfood-024-pay-1-recovery"

INCIDENT_ID = "operations/incident/dogfood-024-inc-1"
CYCLE_ID = "clearing/cycle/dogfood-024-ops-1"

PAYER = "principal/accra-payout"
PAYEE = "principal/nyc-payout"
ASSET = "value/asset/usd-usdclearing"
AMOUNT_MINOR = 900_000

#: Declared experiment instants (deterministic: every instant is data).
T_CREATE = "2026-09-10T00:00:00Z"
T_AUTHORIZE = "2026-09-10T00:00:10Z"
T_START = "2026-09-10T00:00:20Z"
T_REQUEST = "2026-09-10T00:00:30Z"
T_KILL = "2026-09-10T00:01:00Z"  # the provider dies mid-flight
T_CANARY = "2026-09-10T00:02:00Z"  # dead probe; incident opened
T_DEGRADE = "2026-09-10T00:04:00Z"  # degradation declared
T_FAILOVER = "2026-09-10T00:06:00Z"  # failover onto the redundancy
T_RECONCILE = "2026-09-10T00:08:00Z"  # rail A restored; query the dead leg
T_RECOVERY_CREATE = "2026-09-10T00:08:10Z"
T_RECOVERY_AUTHORIZE = "2026-09-10T00:08:20Z"
T_RECOVERY_START = "2026-09-10T00:08:30Z"
T_RECOVERY_REQUEST = "2026-09-10T00:08:40Z"
T_RECOVERY_SUBMIT = "2026-09-10T00:08:50Z"
T_RECOVERY_ACK = "2026-09-10T00:09:00Z"
T_RECOVERY_RESULT = "2026-09-10T00:09:10Z"
T_RECOVERY_COMPLETE = "2026-09-10T00:09:20Z"
T_RECOVERY_RECOGNIZE = "2026-09-10T00:09:30Z"
T_REPROBE = "2026-09-10T00:10:00Z"  # restored probe; rebuild; resolve

FRAUD_GATE = {
    "decision_id": "safety/fraud-decision-dogfood-024",
    "verdict": "ALLOW",
    "object_version": 2,
}
COMPLIANCE_GATE = {
    "assessment_id": "safety/compliance-dogfood-024",
    "verdict": "SATISFIED",
    "object_version": 1,
}
HOLD_GATE = {
    "reservation_id": "reservation/dogfood-024-hold",
    "state": "HELD",
    "object_version": 3,
}

#: The declared adapter contract of the redundancy rail B (the public
#: world-adapter contract consumed exactly as declared).
ADAPTER_B_CONTRACT = {
    "adapter_id": ADAPTER_B,
    "fidelity_class": "SIMULATION",
    "effect_operations": ("SUBMIT_PAYMENT",),
}

_RECOVERY_ACTIONS = (
    RecoveryActionKind.REPROBE,
    RecoveryActionKind.RECONCILE,
    RecoveryActionKind.RETRY,
    RecoveryActionKind.REBUILD,
)


def _authorization() -> EffectAuthorization:
    return EffectAuthorization(
        authorizer="principal/dogfood-ops-024",
        authority_class="A2",
        authorized_types=frozenset({"payment/submit"}),
        valid_from=T_CREATE,
        valid_until=T_REPROBE,
    )


def _steps(adapter_id: str) -> list[dict[str, Any]]:
    return [
        {
            "step_id": None,  # filled by the caller (derived ids differ per plan)
            "adapter_id": adapter_id,
            "effect_type": "payment/submit",
            "payload": {
                "currency": "USD",
                "amount_value": AMOUNT_MINOR,
                "amount_scale": 2,
                "destination": "alias/payee-1",
            },
            "reservation_ref": HOLD_GATE["reservation_id"],
            "max_attempts": 2,
        }
    ]


def _payment_leg_detail() -> dict[str, Any]:
    return {
        "payer": PAYER,
        "payee": PAYEE,
        "asset": ASSET,
        "amount": {"value": AMOUNT_MINOR, "scale": 2, "asset": ASSET},
    }


def _binding(adapter_id: str, capability_id: str, rail: SandboxRail) -> AdapterBinding:
    """Bind one fake provider through the PUBLIC adapter path."""
    world_adapter = WorldAdapter(
        adapter_id=adapter_id,
        capability_id=capability_id,
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )
    if world_adapter.fidelity_class not in EFFECT_CAPABLE_FIDELITY_CLASSES:
        raise ValueError("dogfooding providers must declare effect-capable fidelity")
    return AdapterBinding(
        adapter_id=adapter_id,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=world_adapter,
    )


def _index_digest(engine: Any) -> str:
    """Canonical digest over an authority's public record index.

    Computed purely through the sibling's public ``objects()`` accessor
    (the observer pattern — operations never re-derives sibling state,
    it digests the public boundary).
    """
    entries = sorted(
        (record.object_id, record.to_dict()) for record in engine.objects()
    )
    return canonical_sha256({"index": entries})


def _probe(dependency_id: str, as_of: str, availability_bps: int, detail: str) -> ProbeResult:
    return ProbeResult(
        probe_id=f"operations/probe/dogfood-024/{dependency_id.rsplit('/', 1)[-1]}",
        dependency_id=dependency_id,
        as_of=as_of,
        epistemic="OBSERVED",
        availability_bps=availability_bps,
        samples=5,
        detail=detail,
    )


def _operations_engine() -> OperationsEngine:
    graph = DependencyGraph.build(
        (
            make_dependency_record(
                dependency_id=RAIL_A,
                kind=DependencyKind.PROVIDER_ADAPTER,
                service_id=EXECUTION_SERVICE,
                depends_on=(),
                critical=True,
                note="primary payment rail (dogfood scenario)",
                environment_id=ENV,
                domain_id=DOMAIN,
            ),
            make_dependency_record(
                dependency_id=RAIL_B,
                kind=DependencyKind.PROVIDER_ADAPTER,
                service_id=EXECUTION_SERVICE,
                depends_on=(),
                critical=True,
                note="declared redundancy rail (dogfood scenario)",
                environment_id=ENV,
                domain_id=DOMAIN,
            ),
        )
    )
    profile = make_profile_record(
        service_id=EXECUTION_SERVICE,
        availability_target_bps=9990,
        degraded_below_bps=9500,
        unavailable_below_bps=5000,
        redundancy=(RAIL_B,),
        recovery_actions=_RECOVERY_ACTIONS,
        recovery_time_objective_seconds=3600,
        recovery_point_objective_seconds=60,
        note="dogfooding resilience profile of the payment-execution service",
        environment_id=ENV,
        domain_id=DOMAIN,
    )
    return OperationsEngine(
        environment_id=ENV,
        domain_id=DOMAIN,
        dependency_graph=graph,
        resilience_profiles={EXECUTION_SERVICE: profile},
    )


def build_transcript() -> dict[str, Any]:
    """Execute DOGFOOD-024 and return the deterministic structured transcript."""
    from src.clearing import ClearingEngine
    from src.execution import ExecutionEngine
    from src.execution.effects import EffectResultSpec, make_result_record
    from src.core.envelope import Provenance

    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    facts: dict[str, Any] = {}

    # -- the two providers, bound through the public adapter path --------
    rail_a = SandboxRail(
        # the KILL: the primary provider dies mid-flight (transport
        # failure, no definitive submission response). Once restored it
        # truthfully reports the effect never arrived (NOT_FOUND).
        submissions={KEY_1: ("unknown",)},
        queries={KEY_1: ("not-found",)},
    )
    rail_b = SandboxRail()  # the healthy declared redundancy
    bindings = {
        ADAPTER_A: _binding(ADAPTER_A, CAPABILITY_A, rail_a),
        ADAPTER_B: _binding(ADAPTER_B, CAPABILITY_B, rail_b),
    }
    execution = ExecutionEngine(
        environment_id=ENV,
        domain_id=EXECUTION_DOMAIN,
        bindings=bindings,
    )
    operations = _operations_engine()
    clearing = ClearingEngine(environment_id=ENV, domain_id=CLEARING_DOMAIN)
    clearing.create_cycle(
        command_id="dogfood-024/cycle-1",
        requested_at=T_CREATE,
        cycle_id=CYCLE_ID,
        opens_at=T_CREATE,
        closes_at=T_REPROBE,
    )

    # -- baseline: everything healthy, the payment is in flight ----------
    baseline_probe = _probe(RAIL_A, T_CREATE, 10000, "canary healthy before the kill")
    baseline_status = classify_health(
        baseline_probe,
        operations.resilience_profiles[0],
        dependency_service=EXECUTION_SERVICE,
    )
    check(
        "baseline_probe_classifies_healthy",
        baseline_status is HealthStatus.HEALTHY,
        f"baseline classification={baseline_status.value}",
    )

    plan_steps = _steps(ADAPTER_A)
    plan_steps[0]["step_id"] = STEP_1
    execution.create_plan(
        command_id="dogfood-024/create-1",
        requested_at=T_CREATE,
        plan_id=PLAN_1,
        steps=plan_steps,
        source_ref="intent/dogfood-024-payment",
        summary="dogfooding payment on the primary rail",
    )
    execution.authorize_plan(
        command_id="dogfood-024/authorize-1",
        requested_at=T_AUTHORIZE,
        plan_id=PLAN_1,
        authority_class="A2",
        fraud_decision=FRAUD_GATE,
        compliance_assessment=COMPLIANCE_GATE,
    )
    execution.start_plan(
        command_id="dogfood-024/start-1", requested_at=T_START, plan_id=PLAN_1
    )
    check(
        "payment_plan_running_before_kill",
        execution.plan(PLAN_1).state.value == "RUNNING",
        f"plan_state={execution.plan(PLAN_1).state.value}",
    )

    execution.request_effect(
        command_id="dogfood-024/req-1",
        requested_at=T_REQUEST,
        step_id=STEP_1,
        idempotency_key=KEY_1,
        authorization=_authorization(),
        hold=HOLD_GATE,
    )
    # THE KILL: the provider dies mid-flight (scripted transport failure).
    execution.submit_step(
        command_id="dogfood-024/submit-1",
        requested_at=T_KILL,
        step_id=STEP_1,
    )
    killed_step = execution.step(STEP_1)
    facts["inflight_step_state"] = killed_step.state.value

    # No false success: no effect result exists for the killed leg, and
    # the step can never complete without one.
    result_id_1 = f"{STEP_1}/request/1/result"
    try:
        execution.effect_result(result_id_1)
        has_result = True
    except CoreValidationError:
        has_result = False
    check(
        "killed_submission_has_no_effect_result",
        not has_result,
        "the dead provider produced no rail outcome record (fail closed)",
    )
    try:
        execution.complete_step(
            command_id="dogfood-024/complete-refused",
            requested_at=T_CANARY,
            step_id=STEP_1,
        )
        complete_refused = False
    except CoreValidationError:
        complete_refused = True
    check(
        "killed_step_cannot_complete_no_false_success",
        complete_refused,
        "complete on an UNKNOWN step without a SUCCEEDED result fails closed",
    )
    facts["inflight_step_succeeded"] = bool(has_result) and bool(
        killed_step.state.value == "COMPLETED"
    )

    # -- the clearing authority refuses the unknown-outcome evidence ------
    unknown_result = make_result_record(
        spec=EffectResultSpec(
            result_id=result_id_1,
            request_id=f"{STEP_1}/request/1",
            step_id=STEP_1,
            effect_type="payment/submit",
            outcome=EffectOutcome.UNKNOWN,
            native_reference=None,
            error_code=None,
            observed_at=T_KILL,
            request_digest="f" * 64,
            detail=_payment_leg_detail(),
        ),
        environment_id=ENV,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/provider-a",
            source="execution/domain",
            recorded_at=T_KILL,
        ),
    )
    try:
        clearing.recognize_obligation(
            command_id="dogfood-024/recognize-refused",
            requested_at=T_CANARY,
            cycle_id=CYCLE_ID,
            effect_result=unknown_result.to_dict(),
            due_from=T_DEGRADE,
            due_until=T_REPROBE,
        )
        clearing_refused = False
    except CoreValidationError:
        clearing_refused = True
    facts["clearing_refused_unknown_evidence"] = clearing_refused
    check(
        "clearing_refuses_unknown_outcome_evidence",
        clearing_refused,
        "obligations are recognized only from SUCCEEDED effect results",
    )

    # -- operations observes the death and degrades safely ----------------
    dead_probe = _probe(RAIL_A, T_CANARY, 0, "canary submission transport failure")
    operations.open_incident(
        command_id="dogfood-024/incident-1",
        requested_at=T_CANARY,
        incident_id=INCIDENT_ID,
        dependency_id=RAIL_A,
        trigger_probe=dead_probe,
        summary="provider A transport outage (dogfood kill)",
    )
    check(
        "incident_opened_on_dead_canary",
        operations.incident(INCIDENT_ID).state.value == "OPEN",
        f"incident_state={operations.incident(INCIDENT_ID).state.value}",
    )

    live_digest_at_degradation = _index_digest(execution)
    operations.declare_degradation(
        command_id="dogfood-024/degrade-1",
        requested_at=T_DEGRADE,
        incident_id=INCIDENT_ID,
        probe=_probe(RAIL_A, T_DEGRADE, 0, "provider still dead at degradation"),
        affected_dependencies=(RAIL_A,),
        affected_authorities={EXECUTION_AUTHORITY: live_digest_at_degradation},
        detail="primary rail dead; payment execution degraded",
    )
    degraded = operations.incident(INCIDENT_ID)
    degradation_fact = degraded.spec.degradation_facts[-1]
    check(
        "degradation_declared_unavailable_with_authority_digest",
        degradation_fact.severity == "UNAVAILABLE"
        and dict(degradation_fact.affected_authorities)[EXECUTION_AUTHORITY]
        == live_digest_at_degradation,
        f"severity={degradation_fact.severity} "
        f"authority_digest={live_digest_at_degradation[:16]}...",
    )

    # -- failover onto the declared redundancy (authority conserved) -----
    target_probe = _probe(RAIL_B, T_FAILOVER, 10000, "redundancy rail healthy")
    target_status = classify_health(
        target_probe,
        operations.resilience_profiles[0],
        dependency_service=EXECUTION_SERVICE,
    )
    check(
        "failover_target_classifies_healthy",
        target_status is HealthStatus.HEALTHY,
        f"target classification={target_status.value}",
    )
    check(
        "failover_adapter_contract_effect_capable",
        ADAPTER_B_CONTRACT["fidelity_class"] in EFFECT_CAPABLE_FIDELITY_CLASSES
        and "SUBMIT_PAYMENT" in ADAPTER_B_CONTRACT["effect_operations"],
        "the redundancy adapter declares an effect-capable SIMULATION contract",
    )
    live_digest_at_failover = _index_digest(execution)
    operations.execute_failover(
        command_id="dogfood-024/failover-1",
        requested_at=T_FAILOVER,
        incident_id=INCIDENT_ID,
        target_dependency_id=RAIL_B,
        target_probe=target_probe,
        adapter_contract=ADAPTER_B_CONTRACT,
        authority_digests={EXECUTION_AUTHORITY: live_digest_at_failover},
        detail="failover onto the declared redundancy rail B",
    )
    failed_over = operations.incident(INCIDENT_ID)
    failover_fact = failed_over.spec.failover_fact
    conserved = (
        dict(failover_fact.authority_digests)
        == dict(degradation_fact.affected_authorities)
        == {EXECUTION_AUTHORITY: live_digest_at_failover}
    )
    facts["failover_conserved_authority_digest"] = conserved
    check(
        "failover_conserves_authority_digest",
        conserved and failed_over.state.value == "FAILED_OVER",
        "the failover decision is control-plane only: the affected authority "
        "digest is unchanged from degradation time",
    )

    # -- recovery orchestration: reconcile, retry, rebuild, reprobe -------
    # RECONCILE first (the unknown-outcome discipline): rail A is restored
    # and truthfully reports the killed effect never arrived.
    execution.reconcile_step(
        command_id="dogfood-024/reconcile-1",
        requested_at=T_RECONCILE,
        step_id=STEP_1,
    )
    reconcile_outcome = execution.observations()[-1].spec.query_outcome.value
    check(
        "reconcile_before_retry_reports_not_found",
        reconcile_outcome == "NOT_FOUND",
        f"reconciliation outcome={reconcile_outcome} (retry-safe: the effect "
        "never happened rail-side)",
    )

    # RETRY: the payment is re-submitted through the redundancy rail B
    # (a fresh plan with a fresh idempotency key — never a blind retry
    # of the killed key).
    recovery_steps = _steps(ADAPTER_B)
    recovery_steps[0]["step_id"] = STEP_2
    execution.create_plan(
        command_id="dogfood-024/create-2",
        requested_at=T_RECOVERY_CREATE,
        plan_id=PLAN_2,
        steps=recovery_steps,
        source_ref="intent/dogfood-024-payment",
        summary="dogfooding recovery payment on the redundancy rail",
    )
    execution.authorize_plan(
        command_id="dogfood-024/authorize-2",
        requested_at=T_RECOVERY_AUTHORIZE,
        plan_id=PLAN_2,
        authority_class="A2",
        fraud_decision=FRAUD_GATE,
        compliance_assessment=COMPLIANCE_GATE,
    )
    execution.start_plan(
        command_id="dogfood-024/start-2", requested_at=T_RECOVERY_START, plan_id=PLAN_2
    )
    execution.request_effect(
        command_id="dogfood-024/req-2",
        requested_at=T_RECOVERY_REQUEST,
        step_id=STEP_2,
        idempotency_key=KEY_2,
        authorization=_authorization(),
        hold=HOLD_GATE,
    )
    execution.submit_step(
        command_id="dogfood-024/submit-2",
        requested_at=T_RECOVERY_SUBMIT,
        step_id=STEP_2,
    )
    execution.acknowledge_step(
        command_id="dogfood-024/ack-2",
        requested_at=T_RECOVERY_ACK,
        step_id=STEP_2,
        native_reference=f"sandbox/{KEY_2}",
    )
    execution.record_effect_result(
        command_id="dogfood-024/result-2",
        requested_at=T_RECOVERY_RESULT,
        step_id=STEP_2,
        outcome="SUCCEEDED",
        native_reference=f"sandbox/{KEY_2}",
        observed_at=T_RECOVERY_RESULT,
        detail=_payment_leg_detail(),
    )
    execution.complete_step(
        command_id="dogfood-024/complete-2",
        requested_at=T_RECOVERY_COMPLETE,
        step_id=STEP_2,
    )
    recovered_step = execution.step(STEP_2)
    recovered_plan = execution.plan(PLAN_2)
    recovered_result = execution.effect_result(f"{STEP_2}/request/1/result")
    facts["recovery_completed_step_succeeded"] = (
        recovered_step.state.value == "SUCCEEDED"
        and recovered_plan.state.value == "COMPLETED"
        and recovered_result.spec.outcome is EffectOutcome.SUCCEEDED
    )
    check(
        "recovered_payment_completed_on_redundancy",
        facts["recovery_completed_step_succeeded"],
        f"recovery step_state={recovered_step.state.value} "
        f"plan_state={recovered_plan.state.value} "
        f"outcome={recovered_result.spec.outcome.value}",
    )

    # The clearing authority now recognizes the REAL obligation from the
    # redundancy rail's sealed SUCCEEDED effect result.
    clearing.recognize_obligation(
        command_id="dogfood-024/recognize-1",
        requested_at=T_RECOVERY_RECOGNIZE,
        cycle_id=CYCLE_ID,
        effect_result=recovered_result.to_dict(),
        due_from=T_RECOVERY_RECOGNIZE,
        due_until=T_REPROBE,
    )
    obligations = [
        record
        for record in clearing.records()
        if record.envelope.object_type == "payswap/obligation/v1"
    ]
    exposure = economic_exposure(obligations)
    check(
        "clearing_recognizes_recovered_real_obligation",
        exposure.obligation_count == 1
        and exposure.outstanding_count == 1
        and exposure.asset_totals == ((ASSET, AMOUNT_MINOR, 1),),
        f"exposure obligations={exposure.obligation_count} "
        f"outstanding={exposure.outstanding_count}",
    )

    # REBUILD: journal-only rebuild of the execution authority.
    live_digest_final = _index_digest(execution)
    rebuilt_execution = ExecutionEngine.rebuild_from_journal(
        environment_id=ENV,
        domain_id=EXECUTION_DOMAIN,
        bindings=bindings,
        journal=execution.journal(),
    )
    rebuilt_digest = _index_digest(rebuilt_execution)
    facts["authority_live_digest"] = live_digest_final
    facts["authority_rebuilt_digest"] = rebuilt_digest
    check(
        "execution_authority_rebuild_equals_live",
        live_digest_final == rebuilt_digest,
        "journal-only rebuild reproduces the authority index exactly "
        "(no silent state loss, constitution invariant 12)",
    )
    check(
        "execution_rebuild_covers_every_record",
        len(rebuilt_execution.objects()) == len(execution.objects()),
        f"live_records={len(execution.objects())} "
        f"rebuilt_records={len(rebuilt_execution.objects())}",
    )

    # REPROBE: the killed provider is restored and probes healthy again.
    restored_probe = _probe(RAIL_A, T_REPROBE, 10000, "provider restored after repair")
    restored_status = classify_health(
        restored_probe,
        operations.resilience_profiles[0],
        dependency_service=EXECUTION_SERVICE,
    )
    check(
        "reprobe_restores_healthy_classification",
        restored_status is HealthStatus.HEALTHY,
        f"restored classification={restored_status.value}",
    )

    # -- resolve through the real gates -----------------------------------
    recovery_actions = tuple(
        RecoveryActionRecord(
            action=kind,
            authority_ref=None
            if kind is RecoveryActionKind.REPROBE
            else EXECUTION_AUTHORITY,
            detail={
                RecoveryActionKind.REPROBE: "fresh probes of the affected dependency",
                RecoveryActionKind.RECONCILE: "killed leg queried through the "
                "reconciliation port: NOT_FOUND (retry-safe)",
                RecoveryActionKind.RETRY: "payment re-submitted through the "
                "redundancy rail B (fresh plan and idempotency key)",
                RecoveryActionKind.REBUILD: "journal-only rebuild of the "
                "execution authority: live digest equals rebuilt digest",
            }[kind],
            at=T_REPROBE,
        )
        for kind in _RECOVERY_ACTIONS
    )
    operations.resolve_incident(
        command_id="dogfood-024/resolve-1",
        requested_at=T_REPROBE,
        incident_id=INCIDENT_ID,
        probes=(restored_probe,),
        recovery_actions=recovery_actions,
        authority_evidence=(
            AuthorityRebuild(
                authority_ref=EXECUTION_AUTHORITY,
                live_index_digest=live_digest_final,
                rebuilt_index_digest=rebuilt_digest,
            ),
        ),
        note="provider restored; payment recovered through the redundancy",
    )
    resolved = operations.incident(INCIDENT_ID)
    facts["incident_final_state"] = resolved.state.value
    check(
        "incident_resolved_after_recovery",
        resolved.state.value == "RESOLVED",
        f"incident_state={resolved.state.value}",
    )
    recovery_duration = resolved.spec.resolution_fact.recovery_duration_seconds
    facts["recovery_duration_seconds"] = recovery_duration
    check(
        "recovery_within_declared_objective",
        recovery_duration <= 3600,
        f"recovery_duration={recovery_duration}s rto=3600s",
    )

    # The operations authority itself is journal-only rebuildable.
    rebuilt_operations = OperationsEngine.rebuild_from_journal(
        environment_id=ENV,
        domain_id=DOMAIN,
        dependency_graph=operations.dependency_graph,
        resilience_profiles={
            EXECUTION_SERVICE: operations.resilience_profiles[0]
        },
        journal=operations.journal,
    )
    check(
        "operations_authority_rebuild_equals_live",
        rebuilt_operations.incident(INCIDENT_ID).to_dict()
        == operations.incident(INCIDENT_ID).to_dict(),
        "the incident index rebuilds identically from the journal alone",
    )

    # The sealed incident record round-trips through the trusted decode
    # path (the domain seal verifies; tampered objects would fail closed).
    from . import Incident as _Incident  # trusted decode path

    _Incident.from_dict(resolved.to_dict())
    check(
        "resolved_incident_seal_verifies_on_trusted_decode",
        True,
        "the sealed incident composite decodes through the trusted path",
    )

    facts["checks_total"] = len(checks)
    facts["checks_failed"] = sum(1 for entry in checks if not entry["ok"])
    return {
        "work_order": "WORK-024",
        "experiment": "DOGFOOD-024",
        "scenario": (
            "kill a simulated provider mid-flight; observe fail-closed "
            "degradation (no false success, no silent authoritative loss), "
            "explicit incident/degradation/failover records, and recovery "
            "orchestration back to healthy with authority conservation"
        ),
        "killed_dependency": RAIL_A,
        "failover_target": RAIL_B,
        "environment": ENV,
        "instants": f"{T_CREATE}..{T_REPROBE} (declared data)",
        "facts": facts,
        "checks": checks,
    }


def main() -> int:
    transcript = build_transcript()
    lines: list[str] = []
    lines.append("DOGFOOD-024 — kill a simulated provider, observe safe degradation/recovery")
    lines.append(f"work_order={transcript['work_order']}")
    lines.append(f"environment={transcript['environment']}")
    lines.append(f"instants={transcript['instants']}")
    lines.append(f"scenario={transcript['scenario']}")
    lines.append(f"killed_dependency={transcript['killed_dependency']}")
    lines.append(f"failover_target={transcript['failover_target']}")
    facts = transcript["facts"]
    for name in sorted(facts):
        lines.append(f"fact.{name}={facts[name]}")
    checks = transcript["checks"]
    failed = [entry for entry in checks if not entry["ok"]]
    for entry in checks:
        lines.append(
            f"{'PASS' if entry['ok'] else 'FAIL'} {entry['name']}: {entry['detail']}"
        )
    lines.append(f"checks_total={len(checks)} checks_failed={len(failed)}")
    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
