"""Deterministic scenario drivers for the IG-002 composed lifecycle.

Every identifier, amount and instant is declared data; nothing reads a
clock or an entropy source, so two runs of the same scenario against
the same deterministic rail are byte-identical.

Drivers:

* :func:`run_fulfillment_lifecycle` — one intent through the full chain
  (compilation → execution → real rail port → clearing → settlement →
  finality → resolution), with ``stop_after`` checkpoints for the
  fail-closed probes;
* :func:`canonical_lifecycle` — the canonical happy path (the local
  deterministic rail, all stages accepted);
* :func:`recovery_lifecycle` — the unknown-outcome discipline: an
  UNKNOWN submission, a reconciliation query (NOT_FOUND — retry-safe),
  a retry of the SAME step on a FRESH idempotency key, then the full
  chain to finality;
* :func:`rejection_lifecycle` — an observed rail failure: the accepted
  submission's effect result is FAILED, the step and plan fail, no
  obligation is ever recognized;
* :func:`netting_lifecycle` — two reciprocal payments whose obligations
  net (gross 180.00 → net 20.00 USD) before the net obligation settles
  to finality;
* :func:`offline_lifecycle` — the offline mode contract: the provider is
  unreachable/unconfigured, the effect is NOT ATTEMPTED, the lifecycle
  halts in the reconciliation-required state and never reaches
  settlement or finality.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.errors import CoreValidationError

from .harness import FulfillmentLifecycleGate
from .world import build_declared_world

#: Canonical gate environment/domain of the scenario fixtures.
ENVIRONMENT = "env/sandbox-ig002-gate"
DOMAIN = "domain/ig002"

#: Canonical actors and amounts (minor units, exact integers).
WORLD_TAG = "pay-1"
PAYER = "principal/payer-ig2"
PAYEE = "principal/merchant-42"
AMOUNT_MINOR = 10000
CURRENCY = "USD"

#: Deterministic scenario instants (declared data; never a clock read).
T_COMPILE = "2026-09-04T00:10:00Z"
T_ACCEPT = "2026-09-04T00:11:00Z"
T_EXEC_CREATE = "2026-09-04T00:12:00Z"
T_EXEC_AUTHORIZE = "2026-09-04T00:13:00Z"
T_EXEC_START = "2026-09-04T00:14:00Z"
T_REQUEST = "2026-09-04T00:15:00Z"
T_SUBMIT = "2026-09-04T00:16:00Z"
T_ACK = "2026-09-04T00:17:00Z"
T_QUERY = "2026-09-04T00:17:30Z"
T_STATUS = "2026-09-04T00:18:00Z"
T_RESULT = "2026-09-04T00:19:00Z"
T_COMPLETE = "2026-09-04T00:20:00Z"
T_FINALITY_CLAIM = "2026-09-04T00:21:00Z"
T_CYCLE_OPEN = "2026-09-04T00:00:00Z"
T_CYCLE_CLOSE = "2026-09-04T06:00:00Z"
T_RECOGNIZE = "2026-09-04T00:30:00Z"
T_OBLIG_VALIDATE = "2026-09-04T01:00:00Z"
T_MARK_DUE = "2026-09-04T01:10:00Z"
T_CYCLE_VALIDATE = "2026-09-04T01:20:00Z"
T_CYCLE_FINALIZE = "2026-09-04T01:30:00Z"
T_NETTING = "2026-09-04T02:00:00Z"
T_SETTLEMENT = "2026-09-04T03:00:00Z"
T_RECONCILE = "2026-09-04T03:30:00Z"
T_FINALITY_VALIDATE = "2026-09-04T04:00:00Z"
T_FINALITY_ESTABLISH = "2026-09-04T04:30:00Z"
T_RESOLVE = "2026-09-04T05:00:00Z"

DUE_FROM = "2026-09-04T01:00:00Z"
DUE_UNTIL = "2026-09-05T06:00:00Z"
SUBMIT_BY = "2026-09-04T12:00:00Z"
SETTLE_BY = "2026-09-05T06:00:00Z"

_CHECKPOINTS = frozenset(
    {
        "compiled",
        "accepted",
        "created",
        "authorized",
        "running",
        "requested",
        "submitted",
        "acknowledged",
        "queried",
        "status",
        "result",
        "completed",
        "claimed",
        "recognized",
        "validated",
        "due",
        "closed",
        "settled",
        "reconciled",
        "claims",
        "finality",
        "resolved",
    }
)


def _ids(tag: str) -> dict[str, str]:
    plan_id = f"plan/ig002-{tag}"
    execution_plan_id = f"execution/{plan_id}"
    return {
        "tag": tag,
        "plan_id": plan_id,
        "execution_plan_id": execution_plan_id,
        "step_id": f"{execution_plan_id}/step/1",
        "cycle_id": f"clearing/ig002/cycle-{tag}",
        "settlement_id": f"settlement/ig002/batch-{tag}",
        "finality_id": f"settlement/ig002/finality-{tag}",
        "idempotency_key": f"ig002-{tag}",
    }


def run_fulfillment_lifecycle(
    gate: FulfillmentLifecycleGate,
    *,
    rail: Any,
    tag: str = WORLD_TAG,
    payer: str = PAYER,
    payee: str = PAYEE,
    amount_minor: int = AMOUNT_MINOR,
    stop_after: str = "resolved",
) -> dict[str, Any]:
    """Drive one intent through the composed lifecycle with checkpoints."""
    if stop_after not in _CHECKPOINTS:
        raise ValueError(f"unknown stop_after checkpoint {stop_after!r}")
    ids = _ids(tag)
    world = build_declared_world(
        environment_id=gate.environment_id,
        domain_id=gate.domain_id,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
    )
    plan_id = ids["plan_id"]
    execution_plan_id = ids["execution_plan_id"]
    step_id = ids["step_id"]
    key = ids["idempotency_key"]
    outcome: dict[str, Any] = {
        "tag": tag,
        "plan_id": plan_id,
        "execution_plan_id": execution_plan_id,
        "step_ids": [step_id],
        "idempotency_keys": [key],
        "cycle_id": ids["cycle_id"],
        "settlement_id": ids["settlement_id"],
        "finality_id": ids["finality_id"],
        "world": world,
    }

    gate.stage_compile(
        world,
        plan_id=plan_id,
        command_id=f"cmd/ig002-{tag}/compile",
        idempotency_key=f"key/ig002-{tag}/compile",
        nonce=f"nonce-ig002-{tag}-compile",
        requested_at=T_COMPILE,
    )
    if stop_after == "compiled":
        return outcome
    gate.stage_accept_plan(
        plan_id,
        command_id=f"cmd/ig002-{tag}/accept",
        idempotency_key=f"key/ig002-{tag}/accept",
        nonce=f"nonce-ig002-{tag}-accept",
        as_of=T_ACCEPT,
    )
    if stop_after == "accepted":
        return outcome
    gate.stage_create_execution_plan(
        plan_id, command_id=f"cmd/ig002-{tag}/exec-create", requested_at=T_EXEC_CREATE
    )
    if stop_after == "created":
        return outcome
    gate.stage_authorize_execution_plan(
        execution_plan_id,
        command_id=f"cmd/ig002-{tag}/exec-authorize",
        requested_at=T_EXEC_AUTHORIZE,
    )
    if stop_after == "authorized":
        return outcome
    gate.stage_start_execution_plan(
        execution_plan_id,
        command_id=f"cmd/ig002-{tag}/exec-start",
        requested_at=T_EXEC_START,
    )
    if stop_after == "running":
        return outcome
    gate.stage_request_effect(
        step_id,
        idempotency_key=key,
        command_id=f"cmd/ig002-{tag}/request",
        requested_at=T_REQUEST,
        world=world,
    )
    if stop_after == "requested":
        return outcome
    gate.stage_submit_effect(
        step_id, command_id=f"cmd/ig002-{tag}/submit", requested_at=T_SUBMIT
    )
    step = gate.execution.step(step_id)
    outcome["submission_state"] = step.state.value
    if stop_after == "submitted":
        return outcome
    return _continue_accepted(
        gate, rail=rail, ids=ids, outcome=outcome, stop_after=stop_after
    )


def _continue_accepted(
    gate: FulfillmentLifecycleGate,
    *,
    rail: Any,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    stop_after: str,
    key: str | None = None,
) -> dict[str, Any]:
    """Continue the chain for an ACCEPTED submission, to ``stop_after``."""
    tag = ids["tag"]
    step_id = ids["step_id"]
    key = key if key is not None else ids["idempotency_key"]
    step = gate.execution.step(step_id)
    if step.state.value != "SUBMITTED":
        raise AssertionError(
            "the post-submission chain continues only an ACCEPTED submission; "
            f"step {step_id} is {step.state.value}"
        )
    attempts = [
        record
        for record in gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
        and record.spec.step_id == step_id
    ]
    native_reference = attempts[-1].spec.native_reference
    if native_reference is None:
        raise AssertionError(
            "an ACCEPTED submission must carry the rail's native reference"
        )
    outcome["native_reference"] = native_reference
    gate.stage_acknowledge_effect(
        step_id,
        native_reference=native_reference,
        command_id=f"cmd/ig002-{tag}/ack",
        requested_at=T_ACK,
    )
    if stop_after == "acknowledged":
        return outcome
    gate.stage_reconcile_effect(
        step_id,
        command_id=f"cmd/ig002-{tag}/query",
        requested_at=T_QUERY,
    )
    if stop_after == "queried":
        return outcome
    gate.stage_record_payment_status(
        step_id,
        native_code=rail_native_status(rail, key),
        command_id=f"cmd/ig002-{tag}/status",
        requested_at=T_STATUS,
    )
    if stop_after == "status":
        return outcome
    gate.stage_observe_effect_result(
        step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id=f"cmd/ig002-{tag}/result",
    )
    if stop_after == "result":
        return outcome
    gate.stage_complete_step(
        step_id,
        command_id=f"cmd/ig002-{tag}/complete",
        requested_at=T_COMPLETE,
    )
    if stop_after == "completed":
        return outcome
    gate.stage_record_finality_claim(
        step_id,
        claim="FINAL",
        native_reference=native_reference,
        command_id=f"cmd/ig002-{tag}/claim",
        requested_at=T_FINALITY_CLAIM,
    )
    if stop_after == "claimed":
        return outcome

    # -- clearing stretch --------------------------------------------------
    gate.stage_open_clearing_cycle(
        ids["cycle_id"],
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id=f"cmd/ig002-{tag}/cycle-open",
        requested_at=T_RECOGNIZE,
        description=f"IG-002 recognition window for {tag}",
    )
    obligations_before = set(_obligation_ids(gate))
    gate.stage_recognize_obligation(
        cycle_id=ids["cycle_id"],
        step_id=step_id,
        due_from=DUE_FROM,
        due_until=DUE_UNTIL,
        command_id=f"cmd/ig002-{tag}/recognize",
        requested_at=T_RECOGNIZE,
    )
    obligation_ids = [
        obligation_id
        for obligation_id in _obligation_ids(gate)
        if obligation_id not in obligations_before
    ]
    outcome["obligation_ids"] = obligation_ids
    if stop_after == "recognized":
        return outcome
    for index, obligation_id in enumerate(obligation_ids, start=1):
        gate.stage_validate_obligation(
            obligation_id,
            command_id=f"cmd/ig002-{tag}/validate-{index}",
            requested_at=T_OBLIG_VALIDATE,
        )
    if stop_after == "validated":
        return outcome
    for index, obligation_id in enumerate(obligation_ids, start=1):
        gate.stage_mark_due_obligation(
            obligation_id,
            command_id=f"cmd/ig002-{tag}/due-{index}",
            requested_at=T_MARK_DUE,
        )
    if stop_after == "due":
        return outcome
    gate.stage_validate_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig002-{tag}/cycle-validate",
        requested_at=T_CYCLE_VALIDATE,
    )
    gate.stage_finalize_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig002-{tag}/cycle-finalize",
        requested_at=T_CYCLE_FINALIZE,
    )
    if stop_after == "closed":
        return outcome

    # -- settlement stretch -------------------------------------------------
    gate.stage_settle(
        ids["settlement_id"],
        obligation_ids,
        submit_by=SUBMIT_BY,
        settle_by=SETTLE_BY,
        command_prefix=f"cmd/ig002-{tag}/settle",
        requested_at=T_SETTLEMENT,
    )
    if stop_after == "settled":
        return outcome
    legs = _leg_bindings(gate, ids["settlement_id"], {step_id: obligation_ids[0]})
    gate.stage_fold_rail_evidence(
        ids["settlement_id"],
        legs,
        command_id=f"cmd/ig002-{tag}/reconcile",
        requested_at=T_RECONCILE,
    )
    if stop_after == "reconciled":
        return outcome
    gate.stage_validate_finality_certificate(
        ids["finality_id"],
        ids["settlement_id"],
        legs,
        command_prefix=f"cmd/ig002-{tag}/claim-validate",
        requested_at=T_FINALITY_VALIDATE,
    )
    if stop_after == "claims":
        return outcome
    gate.stage_establish_finality(
        ids["finality_id"],
        command_id=f"cmd/ig002-{tag}/finality",
        requested_at=T_FINALITY_ESTABLISH,
    )
    outcome["finality_established"] = True
    if stop_after == "finality":
        return outcome
    gate.stage_resolve_settled_obligations(
        ids["settlement_id"],
        command_prefix=f"cmd/ig002-{tag}/resolve",
        requested_at=T_RESOLVE,
    )
    outcome["obligation_resolved"] = True
    outcome["invariant_checks"] = list(gate.last_invariant_checks)
    outcome["stage_count"] = len(gate.stage_journal)
    return outcome


def canonical_lifecycle(gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    """The canonical happy path: every stage accepted, to finality."""
    rail = _rail_of(gate)
    return run_fulfillment_lifecycle(gate, rail=rail)


def recovery_lifecycle(gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    """UNKNOWN submission → reconciliation (NOT_FOUND) → safe retry → finality.

    The rail scripts the FIRST key as a transport failure and the retry
    key (fresh, as the recovery discipline demands) as a success. The
    retry re-arms the SAME step; the reconciliation query runs BEFORE
    the retry (reconcile before any unsafe retry).
    """
    rail = _rail_of(gate)
    rail.script_submissions(
        {
            "ig002-recover-1": ("unknown",),
            "ig002-recover-1-retry": ("accept",),
        }
    )
    rail.script_queries({"ig002-recover-1": ("not-found",)})
    outcome = run_fulfillment_lifecycle(
        gate, rail=rail, tag="recover-1", stop_after="submitted"
    )
    first_state = outcome["submission_state"]
    step_id = outcome["step_ids"][0]
    ids = _ids("recover-1")
    # The unknown outcome enters reconciliation BEFORE any retry.
    reconciliation = gate.stage_reconcile_effect(
        step_id,
        command_id="cmd/ig002-recover-1/query-1",
        requested_at=T_QUERY,
    )
    query_outcome = gate.execution.observations()[-1].spec.content["outcome"]
    # NOT_FOUND is retry-safe: the rail never received the effect, so
    # the retry re-arms the same step under a FRESH idempotency key.
    gate.stage_retry_step(
        step_id,
        reason="rail reported NOT_FOUND; the effect never happened",
        command_id="cmd/ig002-recover-1/retry",
        requested_at="2026-09-04T00:16:45Z",
    )
    retry_key = "ig002-recover-1-retry"
    gate.stage_request_effect(
        step_id,
        idempotency_key=retry_key,
        command_id="cmd/ig002-recover-1/request-retry",
        requested_at="2026-09-04T00:16:50Z",
        world=outcome["world"],
    )
    gate.stage_submit_effect(
        step_id,
        command_id="cmd/ig002-recover-1/submit-retry",
        requested_at="2026-09-04T00:16:55Z",
    )
    outcome["idempotency_keys"] = [ids["idempotency_key"], retry_key]
    completed = _continue_accepted(
        gate, rail=rail, ids=ids, outcome=outcome, stop_after="resolved", key=retry_key
    )
    completed["first_submission_state"] = first_state
    completed["reconciliation_outcome"] = query_outcome
    completed["recovered"] = True
    completed["reconciliation_entry"] = reconciliation
    return completed


def rejection_lifecycle(gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    """An observed rail failure: accepted submission, FAILED effect result."""
    rail = _rail_of(gate)
    ids = _ids("reject-1")
    outcome = run_fulfillment_lifecycle(
        gate, rail=rail, tag="reject-1", stop_after="acknowledged"
    )
    step_id = outcome["step_ids"][0]
    native_reference = outcome["native_reference"]
    gate.stage_observe_effect_result(
        step_id,
        outcome="FAILED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id="cmd/ig002-reject-1/result",
    )
    gate.stage_fail_step(
        step_id,
        reason="rail reported the effect definitively failed",
        command_id="cmd/ig002-reject-1/fail",
        requested_at=T_COMPLETE,
    )
    gate.stage_open_clearing_cycle(
        ids["cycle_id"],
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id="cmd/ig002-reject-1/cycle-open",
        requested_at=T_RECOGNIZE,
        description="IG-002 rejection recognition window",
    )
    obligations_before = set(_obligation_ids(gate))
    obligation_count = len(obligations_before)
    # Recognizing from the FAILED evidence must fail closed; the count
    # must not change.
    try:
        gate.stage_recognize_obligation(
            cycle_id=ids["cycle_id"],
            step_id=step_id,
            due_from=DUE_FROM,
            due_until=DUE_UNTIL,
            command_id="cmd/ig002-reject-1/recognize-probe",
            requested_at=T_RECOGNIZE,
        )
        recognized_failure = False
    except CoreValidationError:
        recognized_failure = True
    obligation_count_after = len(_obligation_ids(gate))
    return {
        "step_state": gate.execution.step(step_id).state.value,
        "plan_state": gate.execution.plan(ids["execution_plan_id"]).state.value,
        "obligation_count": obligation_count,
        "obligation_count_after": obligation_count_after,
        "failed_recognition_rejected": recognized_failure,
        "cycle_id": ids["cycle_id"],
        "step_id": step_id,
        "native_reference": native_reference,
    }


def netting_lifecycle(gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    """Two reciprocal payments whose obligations net before settlement."""
    rail = _rail_of(gate)
    first = run_fulfillment_lifecycle(
        gate,
        rail=rail,
        tag="net-1",
        payer=PAYER,
        payee=PAYEE,
        amount_minor=10000,
        stop_after="claimed",
    )
    second = run_fulfillment_lifecycle(
        gate,
        rail=rail,
        tag="net-2",
        payer=PAYEE,
        payee=PAYER,
        amount_minor=8000,
        stop_after="claimed",
    )
    cycle_id = "clearing/ig002/cycle-net"
    gate.stage_open_clearing_cycle(
        cycle_id,
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id="cmd/ig002-net/cycle-open",
        requested_at=T_RECOGNIZE,
        description="IG-002 netting recognition window",
    )
    obligations_before = set(_obligation_ids(gate))
    for tag, steps in (("net-1", first["step_ids"]), ("net-2", second["step_ids"])):
        gate.stage_recognize_obligation(
            cycle_id=cycle_id,
            step_id=steps[0],
            due_from=DUE_FROM,
            due_until=DUE_UNTIL,
            command_id=f"cmd/ig002-{tag}/recognize",
            requested_at=T_RECOGNIZE,
        )
    obligation_ids = [
        obligation_id
        for obligation_id in _obligation_ids(gate)
        if obligation_id not in obligations_before
    ]
    for index, obligation_id in enumerate(obligation_ids, start=1):
        gate.stage_validate_obligation(
            obligation_id,
            command_id=f"cmd/ig002-net/validate-{index}",
            requested_at=T_OBLIG_VALIDATE,
        )
    gate.stage_validate_cycle(
        cycle_id,
        command_id="cmd/ig002-net/cycle-validate",
        requested_at=T_CYCLE_VALIDATE,
    )
    gate.stage_finalize_cycle(
        cycle_id,
        command_id="cmd/ig002-net/cycle-finalize",
        requested_at=T_CYCLE_FINALIZE,
    )
    netting_id = "clearing/ig002/netting-1"
    gate.stage_net_obligations(
        netting_id,
        obligation_ids,
        mode="BILATERAL",
        due_from=DUE_FROM,
        due_until=DUE_UNTIL,
        command_prefix="cmd/ig002-net/net",
        requested_at=T_NETTING,
    )
    net_obligation_id = _issued_obligation_ids(gate, netting_id)[0]
    gate.stage_validate_obligation(
        net_obligation_id,
        command_id="cmd/ig002-net/validate-net",
        requested_at=T_NETTING,
    )
    gate.stage_mark_due_obligation(
        net_obligation_id,
        command_id="cmd/ig002-net/due-net",
        requested_at=T_MARK_DUE,
    )
    settlement_id = "settlement/ig002/batch-net"
    gate.stage_settle(
        settlement_id,
        [net_obligation_id],
        submit_by=SUBMIT_BY,
        settle_by=SETTLE_BY,
        command_prefix="cmd/ig002-net/settle",
        requested_at=T_SETTLEMENT,
    )
    legs = _leg_bindings(gate, settlement_id, {first["step_ids"][0]: net_obligation_id})
    gate.stage_fold_rail_evidence(
        settlement_id,
        legs,
        command_id="cmd/ig002-net/reconcile",
        requested_at=T_RECONCILE,
    )
    finality_id = "settlement/ig002/finality-net"
    gate.stage_validate_finality_certificate(
        finality_id,
        settlement_id,
        legs,
        command_prefix="cmd/ig002-net/claim-validate",
        requested_at=T_FINALITY_VALIDATE,
    )
    gate.stage_establish_finality(
        finality_id,
        command_id="cmd/ig002-net/finality",
        requested_at=T_FINALITY_ESTABLISH,
    )
    gate.stage_resolve_settled_obligations(
        settlement_id,
        command_prefix="cmd/ig002-net/resolve",
        requested_at=T_RESOLVE,
    )
    return {
        "obligation_ids": obligation_ids,
        "netting_id": netting_id,
        "net_obligation_id": net_obligation_id,
        "settlement_id": settlement_id,
        "finality_id": finality_id,
        "net_obligation_resolved": True,
        "invariant_checks": list(gate.last_invariant_checks),
        "stage_count": len(gate.stage_journal),
    }


def offline_lifecycle(gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    """Offline mode: the provider is absent, the effect is NOT ATTEMPTED."""
    rail = _rail_of(gate)
    outcome = run_fulfillment_lifecycle(
        gate, rail=rail, tag="offline-1", stop_after="submitted"
    )
    step_id = outcome["step_ids"][0]
    step = gate.execution.step(step_id)
    attempts = [
        record
        for record in gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
        and record.spec.step_id == step_id
    ]
    reason = attempts[-1].spec.reason if attempts else None
    # The unknown outcome enters the reconciliation-required state; the
    # query returns NOT_FOUND (the effect never arrived — the submission
    # was never attempted). The lifecycle must NOT progress further.
    reconciliation = gate.stage_reconcile_effect(
        step_id,
        command_id="cmd/ig002-offline-1/query",
        requested_at=T_QUERY,
    )
    query_outcome = gate.execution.observations()[-1].spec.content["outcome"]
    return {
        "submission_state": step.state.value,
        "submission_reason": reason,
        "plan_state": gate.execution.plan(outcome["execution_plan_id"]).state.value,
        "reconciliation_outcome": query_outcome,
        "reconciliation_entry": reconciliation,
        "any_settled_or_final": _any_settled_or_final(gate),
        "invariant_checks": list(gate.last_invariant_checks),
    }


def _any_settled_or_final(gate: FulfillmentLifecycleGate) -> bool:
    from src.settlement import Finality, Settlement

    for record in gate.settlement.records():
        if isinstance(record, Settlement) and record.state.value in (
            "COMPLETED",
            "FAILED",
        ):
            return True
    for record in gate.settlement.records():
        if isinstance(record, Finality):
            return True
    return False


def _obligation_ids(gate: FulfillmentLifecycleGate) -> list[str]:
    from src.clearing import Obligation

    return sorted(
        record.object_id
        for record in gate.clearing.records()
        if isinstance(record, Obligation)
    )


def _issued_obligation_ids(
    gate: FulfillmentLifecycleGate, netting_id: str
) -> list[str]:
    from src.clearing import Obligation

    netting = gate.clearing.netting(netting_id)
    issued = set()
    if netting.spec.statement is not None:
        for group in netting.spec.statement.groups:
            for pair in group.pairs:
                if pair.issued_obligation_id is not None:
                    issued.add(pair.issued_obligation_id)
    return sorted(
        record.object_id
        for record in gate.clearing.records()
        if isinstance(record, Obligation) and record.object_id in issued
    )


def _leg_bindings(
    gate: FulfillmentLifecycleGate,
    settlement_id: str,
    step_obligations: Mapping[str, str],
) -> dict[str, str]:
    """Bind each settlement leg to the step whose rail evidence folds it."""
    settlement = gate.settlement.settlement(settlement_id)
    instruction_by_obligation = {
        instruction.obligation_id: instruction.instruction_id
        for instruction in settlement.spec.instructions
    }
    legs: dict[str, str] = {}
    for step_id, obligation_id in step_obligations.items():
        instruction_id = instruction_by_obligation[obligation_id]
        legs[instruction_id] = step_id
    return legs


def rail_native_status(rail: Any, key: str) -> str:
    """The rail's own native status word for one processed key."""
    native = rail.native_status_for(key)
    if native is None:
        raise AssertionError(
            f"the rail reported no native status for key {key!r}; the status "
            "observation must record real rail vocabulary"
        )
    return native


def _rail_of(gate: FulfillmentLifecycleGate) -> Any:
    binding = next(iter(gate.bindings.values()))
    return binding.submission_port
