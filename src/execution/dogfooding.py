"""DOGFOOD-014 — external effect adapters and execution, sandbox conformance.

This module is a clearly-marked TEST-SIDE ARTIFACT, not part of the
authoritative package surface: it provides the local deterministic fake
rail (the "sandbox rail") used by the test suite and the dogfooding
experiment to exercise the PUBLIC adapter path
(:class:`~src.execution.adapters.EffectSubmissionPort` /
:class:`~src.execution.adapters.EffectReconciliationPort` bound through
:class:`~src.execution.adapters.AdapterBinding`). Production rails
implement the same typed ports behind their own adapters — ports over
providers (implementation principle 4).

The sandbox rail is deterministic by construction:

* submissions and queries are scripted per idempotency key from fixed
  tables (missing keys default to a deterministic outcome; exhausted
  scripts repeat their last outcome);
* native references are derived from declared data
  (``sandbox/<idempotency_key>``);
* the rail deduplicates submissions on the idempotency key exactly as
  the port contract demands (a second call for the same key returns the
  recorded submission and never causes a second rail-side effect).

``build_transcript`` executes the WORK-014 dogfooding experiment — a
realistic multi-step execution against this rail through the public
adapter path, including an UNKNOWN-result effect followed by recovery
(reconcile via observation → safe retry → idempotent convergence) — at
fully declared instants, and returns a byte-stable transcript plus its
SHA-256 digest.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from src.core.serialization import canonical_sha256
from src.interoperability import (
    AdapterStatusMap,
    EFFECT_CAPABLE_FIDELITY_CLASSES,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    StatusMapEntry,
    WorldAdapter,
)
from src.interoperability.status import CanonicalPaymentStatus
from src.simulation.effects import EffectAuthorization

from .adapters import (
    AdapterBinding,
    AdapterQueryResult,
    AdapterSubmission,
    EffectReconciliationPort,
    EffectSubmissionPort,
)
from .contracts import QueryOutcome, SubmissionStatus
from .effects import EffectRequest

#: The sandbox rail's adapter identity (also its binding key). The id
#: follows the internal adapter identifier format owned by the
#: interoperability domain ("interoperability/adapter/<local_id>").
SANDBOX_ADAPTER_ID = "interoperability/adapter/sandbox-rail"

SANDBOX_CAPABILITY_ID = "capability/sandbox-rail"

#: Scripted outcome vocabularies (fail closed on unknown script words).
_SUBMISSION_SCRIPTS = frozenset({"accept", "reject", "unknown"})
_QUERY_SCRIPTS = frozenset({"succeeded", "failed", "not-found", "unknown"})

#: The sandbox rail's declared native status vocabulary, mapped into the
#: canonical payment lifecycle owned by the interoperability domain.
SANDBOX_STATUS_MAP = (
    StatusMapEntry("ACSD", CanonicalPaymentStatus.ACKNOWLEDGED),
    StatusMapEntry("PDNG", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("UKWN", CanonicalPaymentStatus.UNKNOWN),
    StatusMapEntry("RJCT", CanonicalPaymentStatus.FAILED),
    StatusMapEntry("STLD", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("FINL", CanonicalPaymentStatus.FINAL),
)

# Declared experiment instants (deterministic: every instant is data).
T_CREATE = "2026-09-02T01:00:00Z"
T_AUTHORIZE = "2026-09-02T01:01:00Z"
T_START = "2026-09-02T01:02:00Z"
T_REQUEST_1 = "2026-09-02T01:03:00Z"
T_SUBMIT_1 = "2026-09-02T01:04:00Z"
T_RECONCILE = "2026-09-02T01:05:00Z"
T_RETRY = "2026-09-02T01:06:00Z"
T_REQUEST_2 = "2026-09-02T01:07:00Z"
T_SUBMIT_2 = "2026-09-02T01:08:00Z"
T_ACK_1 = "2026-09-02T01:09:00Z"
T_RESULT_1 = "2026-09-02T01:10:00Z"
T_COMPLETE_1 = "2026-09-02T01:11:00Z"
T_REQUEST_3 = "2026-09-02T01:12:00Z"
T_SUBMIT_3 = "2026-09-02T01:13:00Z"
T_ACK_2 = "2026-09-02T01:14:00Z"
T_RESULT_2 = "2026-09-02T01:15:00Z"
T_COMPLETE_2 = "2026-09-02T01:16:00Z"
T_FINALITY = "2026-09-02T01:17:00Z"
T_DUPLICATE = "2026-09-02T01:18:00Z"

DOGFOOD_PLAN_ID = "execution/plan/dogfood-1"
DOGFOOD_STEP_1 = "execution/plan/dogfood-1/step/1"
DOGFOOD_STEP_2 = "execution/plan/dogfood-1/step/2"

DOGFOOD_ENVIRONMENT = "env/dogfood-014"
DOGFOOD_DOMAIN = "domain/payments"

DOGFOOD_FRAUD_GATE = {
    "decision_id": "safety/fraud-decision-dogfood",
    "verdict": "ALLOW",
    "object_version": 2,
}
DOGFOOD_COMPLIANCE_GATE = {
    "assessment_id": "safety/compliance-dogfood",
    "verdict": "SATISFIED",
    "object_version": 1,
}
DOGFOOD_HOLD_GATE = {
    "reservation_id": "reservation/dogfood-hold",
    "state": "HELD",
    "object_version": 3,
}


def _scripted(table: Mapping[str, Iterable[str]], key: str, default: str) -> str:
    outcomes = table.get(key)
    if not outcomes:
        return default
    remaining = list(outcomes)
    outcome = remaining.pop(0)
    table[key] = remaining if remaining else [outcome]
    return outcome


class SandboxRail(EffectSubmissionPort, EffectReconciliationPort):
    """The local deterministic fake rail (test-side artifact).

    ``submissions``/``queries`` map idempotency keys to ordered scripted
    outcomes (``accept``/``reject``/``unknown`` for submissions;
    ``succeeded``/``failed``/``not-found``/``unknown`` for queries). The
    rail deduplicates submissions on the idempotency key: a second call
    for an already-processed key returns the recorded submission — the
    same discipline the port contract demands of a real rail.
    """

    def __init__(
        self,
        *,
        submissions: Mapping[str, Iterable[str]] | None = None,
        queries: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self._submissions: dict[str, list[str]] = {
            key: list(outcomes) for key, outcomes in (submissions or {}).items()
        }
        self._queries: dict[str, list[str]] = {
            key: list(outcomes) for key, outcomes in (queries or {}).items()
        }
        self._processed: dict[str, AdapterSubmission] = {}
        self.submit_call_count = 0

    @property
    def processed_key_count(self) -> int:
        return len(self._processed)

    def submit_effect(self, request: EffectRequest) -> AdapterSubmission:
        self.submit_call_count += 1
        key = request.spec.idempotency_key
        recorded = self._processed.get(key)
        if recorded is not None:
            # Rail-side idempotency: the same key never causes a second
            # rail-side effect (constitution invariant 9).
            return recorded
        script = _scripted(self._submissions, key, "accept")
        if script not in _SUBMISSION_SCRIPTS:
            raise ValueError(f"unknown sandbox submission script {script!r}")
        if script == "accept":
            submission = AdapterSubmission(
                status=SubmissionStatus.ACCEPTED,
                native_reference=f"sandbox/{key}",
                reason=None,
            )
        elif script == "reject":
            submission = AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason="rail rejected the effect (sandbox script)",
            )
        else:
            submission = AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason="transport failure: no definitive submission response",
            )
        self._processed[key] = submission
        return submission

    def query_effect(self, request: EffectRequest) -> AdapterQueryResult:
        key = request.spec.idempotency_key
        script = _scripted(self._queries, key, "not-found")
        if script not in _QUERY_SCRIPTS:
            raise ValueError(f"unknown sandbox query script {script!r}")
        if script == "succeeded":
            return AdapterQueryResult(
                outcome=QueryOutcome.SUCCEEDED,
                native_reference=f"sandbox/{key}",
                detail=None,
            )
        if script == "failed":
            return AdapterQueryResult(
                outcome=QueryOutcome.FAILED,
                native_reference=f"sandbox/{key}",
                detail=None,
            )
        if script == "unknown":
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail="rail reconciliation still open (sandbox script)",
            )
        return AdapterQueryResult(
            outcome=QueryOutcome.NOT_FOUND,
            native_reference=None,
            detail="the rail never received or processed this effect",
        )


def make_sandbox_world_adapter() -> WorldAdapter:
    """The sandbox rail's declared world-adapter contract.

    A SIMULATION-fidelity, effect-capable contract (the same semantic
    interface a production rail declares, differing exactly in world
    coupling): payment submission effects over alias destinations, plus
    endpoint/status/finality observations.
    """
    return WorldAdapter(
        adapter_id=SANDBOX_ADAPTER_ID,
        capability_id=SANDBOX_CAPABILITY_ID,
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )


def make_sandbox_status_map() -> AdapterStatusMap:
    """The sandbox rail's declared native status vocabulary."""
    return AdapterStatusMap(
        adapter_id=SANDBOX_ADAPTER_ID,
        entries=SANDBOX_STATUS_MAP,
    )


def make_sandbox_binding(rail: SandboxRail) -> AdapterBinding:
    """Bind the sandbox rail's ports through the PUBLIC adapter path."""
    world_adapter = make_sandbox_world_adapter()
    if world_adapter.fidelity_class not in EFFECT_CAPABLE_FIDELITY_CLASSES:
        raise ValueError("sandbox world adapter must be effect-capable")
    return AdapterBinding(
        adapter_id=SANDBOX_ADAPTER_ID,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=world_adapter,
        status_map=make_sandbox_status_map(),
    )


def _dogfood_authorization() -> EffectAuthorization:
    return EffectAuthorization(
        authorizer="principal/dogfood-ops",
        authority_class="A2",
        authorized_types=frozenset({"payment/submit", "payment/fee"}),
        valid_from="2026-09-02T00:00:00Z",
        valid_until="2026-09-02T02:00:00Z",
    )


def _dogfood_steps() -> list[dict[str, Any]]:
    return [
        {
            "step_id": DOGFOOD_STEP_1,
            "adapter_id": SANDBOX_ADAPTER_ID,
            "effect_type": "payment/submit",
            "payload": {
                "currency": "USD",
                "amount_value": 900000,
                "amount_scale": 2,
                "destination": "alias/payee-1",
            },
            "reservation_ref": DOGFOOD_HOLD_GATE["reservation_id"],
            "max_attempts": 2,
        },
        {
            "step_id": DOGFOOD_STEP_2,
            "adapter_id": SANDBOX_ADAPTER_ID,
            "effect_type": "payment/fee",
            "payload": {
                "currency": "USD",
                "amount_value": 25000,
                "amount_scale": 2,
                "destination": "alias/payee-1",
            },
            "reservation_ref": DOGFOOD_HOLD_GATE["reservation_id"],
            "max_attempts": 2,
        },
    ]


def build_transcript() -> tuple[str, str]:
    """Execute DOGFOOD-014 and return (transcript, sha256 digest).

    The experiment runs the realistic multi-step execution through the
    public adapter path against the sandbox rail, including an
    UNKNOWN-result effect followed by recovery, then proves journal
    rebuild equivalence and idempotent duplicate convergence.
    """
    from .engine import ExecutionEngine

    lines: list[str] = []
    rail = SandboxRail(
        submissions={
            "dogfood-pay-1": ("unknown",),
            "dogfood-pay-1-retry": ("accept",),
            "dogfood-fee-1": ("accept",),
        },
        queries={"dogfood-pay-1": ("not-found",)},
    )
    binding = make_sandbox_binding(rail)
    engine = ExecutionEngine(
        environment_id=DOGFOOD_ENVIRONMENT,
        domain_id=DOGFOOD_DOMAIN,
        bindings={SANDBOX_ADAPTER_ID: binding},
    )
    authorization = _dogfood_authorization()

    lines.append("DOGFOOD-014 external effect adapters and execution — sandbox conformance")
    lines.append("work_order=WORK-014")
    lines.append("architecture_version=v0.1")
    lines.append("execution_api_version=v0.1")
    lines.append(f"adapter={SANDBOX_ADAPTER_ID}")
    lines.append(f"environment={DOGFOOD_ENVIRONMENT}")
    lines.append(f"domain={DOGFOOD_DOMAIN}")
    lines.append("instants=2026-09-02T01:00:00Z..2026-09-02T01:18:00Z (declared data)")
    lines.append(
        "scenario=two-step payment: leg 1 unknown submission -> reconcile -> safe "
        "retry -> complete; leg 2 acknowledged; finality recorded as evidence"
    )

    # Create → authorize → start.
    engine.create_plan(
        command_id="dogfood/create-1",
        requested_at=T_CREATE,
        plan_id=DOGFOOD_PLAN_ID,
        steps=_dogfood_steps(),
        source_ref="intent/dogfood-1",
        summary="dogfood two-leg sandbox payment",
    )
    engine.authorize_plan(
        command_id="dogfood/authorize-1",
        requested_at=T_AUTHORIZE,
        plan_id=DOGFOOD_PLAN_ID,
        authority_class="A2",
        fraud_decision=DOGFOOD_FRAUD_GATE,
        compliance_assessment=DOGFOOD_COMPLIANCE_GATE,
    )
    engine.start_plan(
        command_id="dogfood/start-1", requested_at=T_START, plan_id=DOGFOOD_PLAN_ID
    )
    lines.append(f"plan={DOGFOOD_PLAN_ID}")
    lines.append("plan_state_after_start=RUNNING")

    # Leg 1: request → submit → UNKNOWN (transport failure).
    engine.request_effect(
        command_id="dogfood/req-1",
        requested_at=T_REQUEST_1,
        step_id=DOGFOOD_STEP_1,
        idempotency_key="dogfood-pay-1",
        authorization=authorization,
        hold=DOGFOOD_HOLD_GATE,
    )
    engine.submit_step(
        command_id="dogfood/submit-1",
        requested_at=T_SUBMIT_1,
        step_id=DOGFOOD_STEP_1,
    )
    lines.append(
        f"step1={DOGFOOD_STEP_1} payment/submit key=dogfood-pay-1"
    )
    lines.append(f"step1_submission1={engine.step(DOGFOOD_STEP_1).state.value}")
    lines.append("step1_submission1_detail=transport failure: no definitive response")

    # Recovery: reconcile through the public port → NOT_FOUND (retry-safe).
    reconcile = engine.reconcile_step(
        command_id="dogfood/reconcile-1",
        requested_at=T_RECONCILE,
        step_id=DOGFOOD_STEP_1,
    )
    observation = engine.observations()[-1]
    lines.append(
        f"step1_reconciliation={reconcile.outcome.value} "
        f"{observation.spec.query_outcome.value} (retry-safe)"
    )

    # Safe retry → fresh key → accepted submission.
    engine.retry_step(
        command_id="dogfood/retry-1",
        requested_at=T_RETRY,
        step_id=DOGFOOD_STEP_1,
        reason="rail reported NOT_FOUND; effect never happened",
    )
    engine.request_effect(
        command_id="dogfood/req-2",
        requested_at=T_REQUEST_2,
        step_id=DOGFOOD_STEP_1,
        idempotency_key="dogfood-pay-1-retry",
        authorization=authorization,
        hold=DOGFOOD_HOLD_GATE,
    )
    engine.submit_step(
        command_id="dogfood/submit-2",
        requested_at=T_SUBMIT_2,
        step_id=DOGFOOD_STEP_1,
    )
    lines.append("step1_submission2=key dogfood-pay-1-retry (fresh key after reconciliation)")

    # Acknowledge → record result → complete.
    engine.acknowledge_step(
        command_id="dogfood/ack-1",
        requested_at=T_ACK_1,
        step_id=DOGFOOD_STEP_1,
        native_reference="sandbox/dogfood-pay-1-retry",
    )
    engine.record_effect_result(
        command_id="dogfood/result-1",
        requested_at=T_RESULT_1,
        step_id=DOGFOOD_STEP_1,
        outcome="SUCCEEDED",
        native_reference="sandbox/dogfood-pay-1-retry",
        observed_at=T_RESULT_1,
    )
    engine.complete_step(
        command_id="dogfood/complete-1",
        requested_at=T_COMPLETE_1,
        step_id=DOGFOOD_STEP_1,
    )
    lines.append(f"step1_state={engine.step(DOGFOOD_STEP_1).state.value}")

    # Leg 2: request → duplicate declaration convergence → submit → ack → complete.
    duplicate_declaration = engine.request_effect(
        command_id="dogfood/req-3",
        requested_at=T_REQUEST_3,
        step_id=DOGFOOD_STEP_2,
        idempotency_key="dogfood-fee-1",
        authorization=authorization,
        hold=DOGFOOD_HOLD_GATE,
    )
    replayed_declaration = engine.request_effect(
        command_id="dogfood/req-3-replay",
        requested_at=T_REQUEST_3,
        step_id=DOGFOOD_STEP_2,
        idempotency_key="dogfood-fee-1",
        authorization=authorization,
        hold=DOGFOOD_HOLD_GATE,
    )
    engine.submit_step(
        command_id="dogfood/submit-3",
        requested_at=T_SUBMIT_3,
        step_id=DOGFOOD_STEP_2,
    )
    replayed_submission = engine.submit_step(
        command_id="dogfood/submit-3-replay",
        requested_at=T_DUPLICATE,
        step_id=DOGFOOD_STEP_2,
    )
    engine.acknowledge_step(
        command_id="dogfood/ack-2",
        requested_at=T_ACK_2,
        step_id=DOGFOOD_STEP_2,
        native_reference="sandbox/dogfood-fee-1",
    )
    engine.record_effect_result(
        command_id="dogfood/result-2",
        requested_at=T_RESULT_2,
        step_id=DOGFOOD_STEP_2,
        outcome="SUCCEEDED",
        native_reference="sandbox/dogfood-fee-1",
        observed_at=T_RESULT_2,
    )
    engine.complete_step(
        command_id="dogfood/complete-2",
        requested_at=T_COMPLETE_2,
        step_id=DOGFOOD_STEP_2,
    )
    lines.append(
        f"step2_state={engine.step(DOGFOOD_STEP_2).state.value} "
        f"(duplicate declaration outcome={replayed_declaration.outcome.value}; "
        f"duplicate submission outcome={replayed_submission.outcome.value})"
    )
    lines.append(
        f"declaration_first_outcome={duplicate_declaration.outcome.value}"
    )

    # Finality: recorded as external evidence only (never established here).
    engine.record_finality(
        command_id="dogfood/finality-1",
        requested_at=T_FINALITY,
        step_id=DOGFOOD_STEP_2,
        claim="FINAL",
        native_reference="sandbox/dogfood-fee-1",
    )
    final_observation = engine.observations()[-1]
    lines.append(
        f"finality_claim={final_observation.spec.finality_claim.value} "
        "(evidence only; settlement finality belongs to the settlement domain)"
    )

    plan_state = engine.plan(DOGFOOD_PLAN_ID).state.value
    lines.append(f"plan_state={plan_state}")
    lines.append(f"submit_calls={rail.submit_call_count}")
    lines.append(f"rail_processed_keys={rail.processed_key_count}")
    lines.append(
        "unknown_result_recovered="
        f"{engine.step(DOGFOOD_STEP_1).state.value == 'SUCCEEDED'}"
    )
    lines.append(f"journal_entries={len(engine.journal())}")

    # Transformation completeness: rebuild the composed domain state from
    # the kernel journal alone and compare canonical digests.
    rebuilt = ExecutionEngine.rebuild_from_journal(
        environment_id=DOGFOOD_ENVIRONMENT,
        domain_id=DOGFOOD_DOMAIN,
        bindings={SANDBOX_ADAPTER_ID: make_sandbox_binding(SandboxRail())},
        journal=engine.journal(),
    )
    live_index = canonical_sha256(
        {object_id: record.to_dict() for object_id, record in enumerate_index(engine)}
    )
    rebuilt_index = canonical_sha256(
        {object_id: record.to_dict() for object_id, record in enumerate_index(rebuilt)}
    )
    live_ledger = canonical_sha256(engine.submission_ledger().to_dict())
    rebuilt_ledger = canonical_sha256(rebuilt.submission_ledger().to_dict())
    lines.append(
        f"journal_rebuild_index_match={live_index == rebuilt_index}"
    )
    lines.append(
        f"journal_rebuild_ledger_match={live_ledger == rebuilt_ledger}"
    )
    lines.append(f"journal_rebuild_plan_state={rebuilt.plan(DOGFOOD_PLAN_ID).state.value}")

    checks = [
        plan_state == "COMPLETED",
        rail.submit_call_count == 3,
        rail.processed_key_count == 3,
        engine.step(DOGFOOD_STEP_1).state.value == "SUCCEEDED",
        engine.step(DOGFOOD_STEP_2).state.value == "SUCCEEDED",
        replayed_declaration.outcome.value == "duplicate",
        replayed_submission.outcome.value == "duplicate",
        live_index == rebuilt_index,
        live_ledger == rebuilt_ledger,
    ]
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    if all(checks):
        lines.append("DOGFOOD-014: PASS")
    else:
        lines.append("DOGFOOD-014: FAIL")
    transcript = "\n".join(lines) + "\n"
    digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    return transcript, digest


def enumerate_index(engine: Any) -> list[tuple[str, Any]]:
    """The engine's durable records in journal order (stable projection)."""
    return [(record.object_id, record) for record in engine.objects()]


def main() -> None:
    transcript, digest = build_transcript()
    print(transcript, end="")
    print(f"transcript_sha256={digest}")


if __name__ == "__main__":  # pragma: no cover
    main()
