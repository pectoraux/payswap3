"""Deterministic parity scenario drivers for the IG-003 gate.

Every identifier, amount and instant is declared data; nothing reads a
clock or an entropy source, so two runs of the same scenario through
the same environment pair are byte-identical, and the two WORLDS of
one run differ only in their environment binding (identity, mode,
epistemic class, fidelity class, adapter identity, native-reference
prefix) — everything else must be semantically identical, which is
exactly what the parity verdict proves.

The drivers mirror the WORK-027 scenario discipline over the public
IG-002 stage API: the same declared stage sequence, the same declared
instants, the same command identities — driven once per world, in
lockstep. The required scenarios:

* ``A`` canonical success — the full chain to an ESTABLISHED finality
  certificate in both environments, with the idempotency convergence
  probes (the duplicate submit re-drive and the same-key re-request
  both converge without a second port call or economic effect);
* ``B`` rejection — a rail-definitive rejection in both environments:
  the step fails, no obligation is ever recognized (the recognition
  probe fails closed with no composed-state mutation), no economics;
* ``C`` idempotency — the canonical run whose probes prove the
  idempotency parity facts (same key set, one submission per key, one
  port call per world, converging re-drives);
* ``D`` recovery — an UNKNOWN submission reconciles NOT_FOUND
  (retry-safe), the same step re-arms under a fresh key and the chain
  completes to finality — identically in both environments;
* ``E`` finality discipline — at the payment-status checkpoint
  (the rail already reported STLD) NO finality exists in either
  environment; finality arrives only after the settlement chain, from
  the settlement authority, identically in both environments.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.integration.lifecycle import FulfillmentLifecycleGate
from src.settlement import Finality, Settlement

from .contracts import (
    PARITY_AMOUNT_MINOR,
    PARITY_PAYEE,
    PARITY_PAYER,
)
from .harness import ScenarioResult, SimulationParityGate
from .projection import semantic_projection, semantic_projection_digest
from .worlds import DeclaredRailScript, ParityWorld

#: Deterministic scenario instants (declared data; never a clock read).
T_COMPILE = "2026-09-04T00:31:00Z"
T_EXEC_CREATE = "2026-09-04T00:33:00Z"
T_EXEC_AUTHORIZE = "2026-09-04T00:34:00Z"
T_EXEC_START = "2026-09-04T00:35:00Z"
T_REQUEST = "2026-09-04T00:36:00Z"
T_SUBMIT = "2026-09-04T00:37:00Z"
T_ACK = "2026-09-04T00:38:00Z"
T_QUERY = "2026-09-04T00:38:30Z"
T_STATUS = "2026-09-04T00:39:00Z"
T_RESULT = "2026-09-04T00:40:00Z"
T_COMPLETE = "2026-09-04T00:41:00Z"
T_FINALITY_CLAIM = "2026-09-04T00:42:00Z"
T_CYCLE_OPEN = "2026-09-04T00:00:00Z"
T_CYCLE_CLOSE = "2026-09-04T06:00:00Z"
T_RECOGNIZE = "2026-09-04T00:50:00Z"
T_OBLIG_VALIDATE = "2026-09-04T01:20:00Z"
T_MARK_DUE = "2026-09-04T01:30:00Z"
T_CYCLE_VALIDATE = "2026-09-04T01:40:00Z"
T_CYCLE_FINALIZE = "2026-09-04T01:50:00Z"
T_SETTLEMENT = "2026-09-04T03:20:00Z"
T_RECONCILE = "2026-09-04T03:50:00Z"
T_FINALITY_VALIDATE = "2026-09-04T04:20:00Z"
T_FINALITY_ESTABLISH = "2026-09-04T04:50:00Z"
T_RESOLVE = "2026-09-04T05:20:00Z"

#: Recovery-path instants: reconcile before retry, fresh key after.
T_RECOVERY_QUERY = "2026-09-04T00:38:40Z"
T_RECOVERY_RETRY = "2026-09-04T00:39:30Z"
T_RECOVERY_REQUEST = "2026-09-04T00:39:35Z"
T_RECOVERY_SUBMIT = "2026-09-04T00:39:40Z"

#: Idempotency probe instants (after the resolved chain).
T_RE_DRIVE = "2026-09-04T05:30:00Z"
T_RE_REQUEST = "2026-09-04T05:31:00Z"

DUE_FROM = "2026-09-04T01:20:00Z"
DUE_UNTIL = "2026-09-05T06:00:00Z"
SUBMIT_BY = "2026-09-04T12:00:00Z"
SETTLE_BY = "2026-09-05T06:00:00Z"

_CHECKPOINTS = (
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
)


def _ids(tag: str) -> dict[str, str]:
    plan_id = f"plan/ig003-{tag}"
    execution_plan_id = f"execution/{plan_id}"
    return {
        "tag": tag,
        "plan_id": plan_id,
        "execution_plan_id": execution_plan_id,
        "step_id": f"{execution_plan_id}/step/1",
        "cycle_id": f"clearing/ig003/cycle-{tag}",
        "settlement_id": f"settlement/ig003/batch-{tag}",
        "finality_id": f"settlement/ig003/finality-{tag}",
        "idempotency_key": f"ig003-{tag}",
    }


def _shared_input_digest(
    *,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
    scripts: Sequence[DeclaredRailScript],
) -> str:
    return canonical_sha256(
        {
            "tag": tag,
            "payer": payer,
            "payee": payee,
            "amount_minor": amount_minor,
            "scripts": [
                {
                    "idempotency_key": script.idempotency_key,
                    "submission": script.submission,
                    "query": script.query,
                    "native_status": script.native_status,
                    "finality_claim": script.finality_claim,
                }
                for script in scripts
            ],
        }
    )


# ---------------------------------------------------------------------------
# the per-world stage driver (the public IG-002 stage API only)
# ---------------------------------------------------------------------------


def _drive_world(
    lifecycle_gate: FulfillmentLifecycleGate,
    world: ParityWorld,
    *,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
    stop_after: str = "resolved",
) -> dict[str, Any]:
    if stop_after not in _CHECKPOINTS:
        raise ValueError(f"unknown stop_after checkpoint {stop_after!r}")
    from src.integration.lifecycle import build_declared_world

    ids = _ids(tag)
    declared_world = build_declared_world(
        environment_id=lifecycle_gate.environment_id,
        domain_id=lifecycle_gate.domain_id,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
    )
    key = ids["idempotency_key"]
    outcome: dict[str, Any] = {
        "tag": tag,
        "ids": ids,
        "world": declared_world,
        "idempotency_keys": [key],
    }

    lifecycle_gate.stage_compile(
        declared_world,
        plan_id=ids["plan_id"],
        command_id=f"cmd/ig003-{tag}/compile",
        idempotency_key=f"key/ig003-{tag}/compile",
        nonce=f"nonce-ig003-{tag}-compile",
        requested_at=T_COMPILE,
    )
    if stop_after == "compiled":
        return outcome
    # The accept stage's declared instant is the world's own as_of (the
    # compiler handoff instant): the public IG-002 rebuild re-accepts at
    # exactly this declared instant, so the accepted plan record is
    # byte-stable across a journal-only rebuild (replay determinism).
    lifecycle_gate.stage_accept_plan(
        ids["plan_id"],
        command_id=f"cmd/ig003-{tag}/accept",
        idempotency_key=f"key/ig003-{tag}/accept",
        nonce=f"nonce-ig003-{tag}-accept",
        as_of=declared_world.as_of,
    )
    if stop_after == "accepted":
        return outcome
    lifecycle_gate.stage_create_execution_plan(
        ids["plan_id"],
        command_id=f"cmd/ig003-{tag}/exec-create",
        requested_at=T_EXEC_CREATE,
    )
    if stop_after == "created":
        return outcome
    lifecycle_gate.stage_authorize_execution_plan(
        ids["execution_plan_id"],
        command_id=f"cmd/ig003-{tag}/exec-authorize",
        requested_at=T_EXEC_AUTHORIZE,
    )
    if stop_after == "authorized":
        return outcome
    lifecycle_gate.stage_start_execution_plan(
        ids["execution_plan_id"],
        command_id=f"cmd/ig003-{tag}/exec-start",
        requested_at=T_EXEC_START,
    )
    if stop_after == "running":
        return outcome
    lifecycle_gate.stage_request_effect(
        ids["step_id"],
        idempotency_key=key,
        command_id=f"cmd/ig003-{tag}/request",
        requested_at=T_REQUEST,
        world=declared_world,
    )
    if stop_after == "requested":
        return outcome
    lifecycle_gate.stage_submit_effect(
        ids["step_id"],
        command_id=f"cmd/ig003-{tag}/submit",
        requested_at=T_SUBMIT,
    )
    step = lifecycle_gate.execution.step(ids["step_id"])
    outcome["submission_state"] = step.state.value
    outcome["submission_status"] = _attempt_status(lifecycle_gate, ids["step_id"])
    if step.state.value != "SUBMITTED":
        # A definitive rejection or an unknown outcome ends the main
        # chain here; the scenario-level probes take over.
        return outcome
    outcome["native_reference"] = _native_reference(lifecycle_gate, ids["step_id"])
    return _continue_accepted(
        lifecycle_gate,
        world,
        ids=ids,
        outcome=outcome,
        stop_after=stop_after,
    )


def _continue_accepted(
    lifecycle_gate: FulfillmentLifecycleGate,
    world: ParityWorld,
    *,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    stop_after: str,
    key: str | None = None,
) -> dict[str, Any]:
    """Continue the chain for an ACCEPTED submission, to ``stop_after``."""
    tag = ids["tag"]
    step_id = ids["step_id"]
    key = key if key is not None else ids["idempotency_key"]
    rail = world.rail
    native_reference = outcome["native_reference"]
    step = lifecycle_gate.execution.step(step_id)
    if step.state.value != "SUBMITTED":
        raise AssertionError(
            "the post-submission chain continues only an ACCEPTED submission; "
            f"step {step_id} is {step.state.value}"
        )
    lifecycle_gate.stage_acknowledge_effect(
        step_id,
        native_reference=native_reference,
        command_id=f"cmd/ig003-{tag}/ack",
        requested_at=T_ACK,
    )
    if stop_after == "acknowledged":
        return outcome
    lifecycle_gate.stage_reconcile_effect(
        step_id,
        command_id=f"cmd/ig003-{tag}/query",
        requested_at=T_QUERY,
    )
    if stop_after == "queried":
        return outcome
    lifecycle_gate.stage_record_payment_status(
        step_id,
        native_code=_native_status(rail, key),
        command_id=f"cmd/ig003-{tag}/status",
        requested_at=T_STATUS,
    )
    if stop_after == "status":
        return outcome
    lifecycle_gate.stage_observe_effect_result(
        step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id=f"cmd/ig003-{tag}/result",
    )
    if stop_after == "result":
        return outcome
    lifecycle_gate.stage_complete_step(
        step_id,
        command_id=f"cmd/ig003-{tag}/complete",
        requested_at=T_COMPLETE,
    )
    if stop_after == "completed":
        return outcome
    lifecycle_gate.stage_record_finality_claim(
        step_id,
        claim=_finality_claim(rail, key),
        native_reference=native_reference,
        command_id=f"cmd/ig003-{tag}/claim",
        requested_at=T_FINALITY_CLAIM,
    )
    if stop_after == "claimed":
        return outcome

    return _run_settlement_stretch(
        lifecycle_gate, ids=ids, outcome=outcome, stop_after=stop_after
    )


def _resume_after_status(
    lifecycle_gate: FulfillmentLifecycleGate,
    world: ParityWorld,
    *,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    key: str,
) -> dict[str, Any]:
    """Resume the chain after the recorded payment status, to resolved."""
    tag = ids["tag"]
    step_id = ids["step_id"]
    rail = world.rail
    native_reference = outcome["native_reference"]
    lifecycle_gate.stage_observe_effect_result(
        step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id=f"cmd/ig003-{tag}/result",
    )
    lifecycle_gate.stage_complete_step(
        step_id,
        command_id=f"cmd/ig003-{tag}/complete",
        requested_at=T_COMPLETE,
    )
    lifecycle_gate.stage_record_finality_claim(
        step_id,
        claim=_finality_claim(rail, key),
        native_reference=native_reference,
        command_id=f"cmd/ig003-{tag}/claim",
        requested_at=T_FINALITY_CLAIM,
    )
    # The remaining chain is the shared settlement stretch from the claim on.
    return _run_settlement_stretch(
        lifecycle_gate, ids=ids, outcome=outcome, stop_after="resolved"
    )


def _run_settlement_stretch(
    lifecycle_gate: FulfillmentLifecycleGate,
    *,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    stop_after: str = "resolved",
) -> dict[str, Any]:
    """The shared clearing + settlement stretch, from the claim on.

    Drives the canonical chain — clearing cycle, obligation
    recognition/validation/due, cycle validation/finalization,
    settlement batch, leg-bound rail-evidence folding, finality-claim
    validation, finality establishment and obligation resolution —
    through the public stage API, with the declared checkpoints.
    """
    tag = ids["tag"]
    step_id = ids["step_id"]
    lifecycle_gate.stage_open_clearing_cycle(
        ids["cycle_id"],
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id=f"cmd/ig003-{tag}/cycle-open",
        requested_at=T_RECOGNIZE,
        description=f"IG-003 parity recognition window for {tag}",
    )
    obligations_before = set(_obligation_ids(lifecycle_gate))
    lifecycle_gate.stage_recognize_obligation(
        cycle_id=ids["cycle_id"],
        step_id=step_id,
        due_from=DUE_FROM,
        due_until=DUE_UNTIL,
        command_id=f"cmd/ig003-{tag}/recognize",
        requested_at=T_RECOGNIZE,
    )
    obligation_ids = [
        obligation_id
        for obligation_id in _obligation_ids(lifecycle_gate)
        if obligation_id not in obligations_before
    ]
    outcome["obligation_ids"] = obligation_ids
    if stop_after == "recognized":
        return outcome
    for index, obligation_id in enumerate(obligation_ids, start=1):
        lifecycle_gate.stage_validate_obligation(
            obligation_id,
            command_id=f"cmd/ig003-{tag}/validate-{index}",
            requested_at=T_OBLIG_VALIDATE,
        )
    if stop_after == "validated":
        return outcome
    for index, obligation_id in enumerate(obligation_ids, start=1):
        lifecycle_gate.stage_mark_due_obligation(
            obligation_id,
            command_id=f"cmd/ig003-{tag}/due-{index}",
            requested_at=T_MARK_DUE,
        )
    if stop_after == "due":
        return outcome
    lifecycle_gate.stage_validate_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig003-{tag}/cycle-validate",
        requested_at=T_CYCLE_VALIDATE,
    )
    lifecycle_gate.stage_finalize_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig003-{tag}/cycle-finalize",
        requested_at=T_CYCLE_FINALIZE,
    )
    if stop_after == "closed":
        return outcome
    lifecycle_gate.stage_settle(
        ids["settlement_id"],
        obligation_ids,
        submit_by=SUBMIT_BY,
        settle_by=SETTLE_BY,
        command_prefix=f"cmd/ig003-{tag}/settle",
        requested_at=T_SETTLEMENT,
    )
    if stop_after == "settled":
        return outcome
    legs = _leg_bindings(lifecycle_gate, ids["settlement_id"], obligation_ids)
    lifecycle_gate.stage_fold_rail_evidence(
        ids["settlement_id"],
        legs,
        command_id=f"cmd/ig003-{tag}/reconcile",
        requested_at=T_RECONCILE,
    )
    if stop_after == "reconciled":
        return outcome
    lifecycle_gate.stage_validate_finality_certificate(
        ids["finality_id"],
        ids["settlement_id"],
        legs,
        command_prefix=f"cmd/ig003-{tag}/claim-validate",
        requested_at=T_FINALITY_VALIDATE,
    )
    if stop_after == "claims":
        return outcome
    lifecycle_gate.stage_establish_finality(
        ids["finality_id"],
        command_id=f"cmd/ig003-{tag}/finality",
        requested_at=T_FINALITY_ESTABLISH,
    )
    outcome["finality_established"] = True
    if stop_after == "finality":
        return outcome
    lifecycle_gate.stage_resolve_settled_obligations(
        ids["settlement_id"],
        command_prefix=f"cmd/ig003-{tag}/resolve",
        requested_at=T_RESOLVE,
    )
    outcome["obligation_resolved"] = True
    return outcome


# ---------------------------------------------------------------------------
# per-world facts
# ---------------------------------------------------------------------------


def _attempt_status(lifecycle_gate: FulfillmentLifecycleGate, step_id: str) -> str:
    attempts = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
        and record.spec.step_id == step_id
    ]
    if not attempts:
        raise AssertionError(
            f"step {step_id} carries no execution attempt; the submission "
            "must be attempted before its status can be projected"
        )
    return attempts[-1].spec.status.value


def _native_reference(lifecycle_gate: FulfillmentLifecycleGate, step_id: str) -> str:
    attempts = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
        and record.spec.step_id == step_id
    ]
    native_reference = attempts[-1].spec.native_reference
    if native_reference is None:
        raise AssertionError(
            "an ACCEPTED submission must carry the rail's native reference"
        )
    return native_reference


def _native_status(rail: Any, key: str) -> str:
    native = rail.native_status_for(key)
    if native is None:
        raise AssertionError(
            f"the rail reported no native status for key {key!r}; the status "
            "observation must record real rail vocabulary"
        )
    return native


def _finality_claim(rail: Any, key: str) -> str:
    claim = rail.finality_claim_for(key)
    if claim is None:
        raise AssertionError(
            f"the rail reported no finality claim for key {key!r}; the claim "
            "observation must record real rail vocabulary"
        )
    return claim


def _obligation_ids(lifecycle_gate: FulfillmentLifecycleGate) -> list[str]:
    from src.clearing import Obligation

    return sorted(
        record.object_id
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    )


def _obligation_states(lifecycle_gate: FulfillmentLifecycleGate) -> list[str]:
    from src.clearing import Obligation

    return sorted(
        record.state.value
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    )


def _leg_bindings(
    lifecycle_gate: FulfillmentLifecycleGate,
    settlement_id: str,
    obligation_ids: Sequence[str],
) -> dict[str, str]:
    settlement = lifecycle_gate.settlement.settlement(settlement_id)
    instruction_by_obligation = {
        instruction.obligation_id: instruction.instruction_id
        for instruction in settlement.spec.instructions
    }
    legs: dict[str, str] = {}
    step_id = _step_id_of(lifecycle_gate)
    for obligation_id in obligation_ids:
        legs[instruction_by_obligation[obligation_id]] = step_id
    return legs


def _step_id_of(lifecycle_gate: FulfillmentLifecycleGate) -> str:
    from src.execution import ExecutionStep

    steps = [
        record
        for record in lifecycle_gate.execution.objects()
        if isinstance(record, ExecutionStep)
    ]
    if not steps:
        raise AssertionError("the lifecycle gate carries no execution step")
    return steps[0].object_id


def _economics(lifecycle_gate: FulfillmentLifecycleGate) -> dict[str, Any]:
    from src.clearing import Obligation

    obligations = [
        record
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    ]
    obligation_total = sum(
        obligation.spec.amount.value for obligation in obligations
    )
    settled_legs = 0
    for settlement in lifecycle_gate.settlement.records():
        if not isinstance(settlement, Settlement):
            continue
        settled_legs += sum(
            1
            for outcome in settlement.spec.leg_outcomes
            if outcome.state == "SETTLED"
        )
    postings = lifecycle_gate.settlement.postings()
    return {
        "obligation_amount_minor": obligation_total,
        "settled_legs": settled_legs,
        "posting_count": len(postings),
    }


def _finality_state(lifecycle_gate: FulfillmentLifecycleGate) -> str | None:
    for record in lifecycle_gate.settlement.records():
        if isinstance(record, Finality):
            return record.state.value
    return None


def _world_facts(
    lifecycle_gate: FulfillmentLifecycleGate,
    outcome: Mapping[str, Any],
) -> dict[str, Any]:
    step_id = outcome["ids"]["step_id"]
    economics = _economics(lifecycle_gate)
    facts: dict[str, Any] = {
        "step_state": lifecycle_gate.execution.step(step_id).state.value,
        "plan_state": lifecycle_gate.execution.plan(
            outcome["ids"]["execution_plan_id"]
        ).state.value,
        "submission_status": outcome.get("submission_status"),
        "obligation_states": _obligation_states(lifecycle_gate),
        "economics": economics,
        "finality_state": _finality_state(lifecycle_gate),
        "finality_authority": "settlement",
        "stage_count": len(lifecycle_gate.stage_journal),
        "invariant_checks": list(lifecycle_gate.last_invariant_checks),
        "idempotency_keys": list(outcome.get("idempotency_keys", [])),
    }
    return facts


# ---------------------------------------------------------------------------
# the parity scenario runner
# ---------------------------------------------------------------------------


def run_parity_scenario(
    parity_gate: SimulationParityGate,
    *,
    tag: str,
    scripts: Sequence[DeclaredRailScript],
    payer: str = PARITY_PAYER,
    payee: str = PARITY_PAYEE,
    amount_minor: int = PARITY_AMOUNT_MINOR,
    stop_after: str = "resolved",
    scenario_id: str | None = None,
    mode: str = "canonical",
) -> ScenarioResult:
    """Drive one declared scenario through BOTH worlds and compare.

    ``mode`` selects the scenario discipline: ``canonical`` (the full
    chain plus the idempotency convergence probes — scenarios A and C),
    ``rejection`` (the rail-definitive rejection with fail-closed
    probes — scenario B) or ``recovery`` (the unknown/retry discipline
    — scenario D). Scenario E (finality discipline) has its dedicated
    runner below.
    """
    if mode not in ("canonical", "rejection", "recovery"):
        raise CoreValidationError(f"unknown parity scenario mode {mode!r}")
    shared_input_digest = _shared_input_digest(
        tag=tag, payer=payer, payee=payee, amount_minor=amount_minor, scripts=scripts
    )
    simulation = parity_gate.simulation_gate
    production = parity_gate.production_gate

    if mode == "canonical":
        sim_outcome = _drive_world(
            simulation,
            parity_gate.simulation_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
            stop_after=stop_after,
        )
        prod_outcome = _drive_world(
            production,
            parity_gate.production_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
            stop_after=stop_after,
        )
        idempotency = {
            "simulation": _idempotency_probes(simulation, parity_gate.simulation_world, sim_outcome),
            "production": _idempotency_probes(production, parity_gate.production_world, prod_outcome),
        }
        shared = {"economics": _economics(simulation), "idempotency": idempotency}
        shared["economics"]["intent_amount_minor"] = amount_minor
    elif mode == "rejection":
        sim_outcome = _drive_world(
            simulation,
            parity_gate.simulation_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
            stop_after="submitted",
        )
        prod_outcome = _drive_world(
            production,
            parity_gate.production_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
            stop_after="submitted",
        )
        sim_probe = _rejection_probes(simulation, sim_outcome)
        prod_probe = _rejection_probes(production, prod_outcome)
        shared = {
            "economics": _economics(simulation),
            "recognition_probe_rejected": (
                sim_probe["recognition_rejected"] and prod_probe["recognition_rejected"]
            ),
            "obligation_count": sim_probe["obligation_count"],
            "obligation_count_after_probe": sim_probe["obligation_count_after"],
        }
        shared["economics"]["intent_amount_minor"] = amount_minor
    else:  # recovery
        sim_outcome = _drive_recovery(
            simulation,
            parity_gate.simulation_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
        )
        prod_outcome = _drive_recovery(
            production,
            parity_gate.production_world,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
        )
        shared = {"economics": _economics(simulation)}
        shared["economics"]["intent_amount_minor"] = amount_minor

    simulation_facts = _world_facts(simulation, sim_outcome)
    production_facts = _world_facts(production, prod_outcome)
    if mode == "recovery":
        for facts, outcome in (
            (simulation_facts, sim_outcome),
            (production_facts, prod_outcome),
        ):
            facts["first_submission_state"] = outcome["first_submission_state"]
            facts["reconciliation_outcome"] = outcome["reconciliation_outcome"]
            facts["recovered"] = outcome["recovered"]

    verdict = parity_gate.parity_verdict(
        scenario_id=scenario_id or f"ig003-{tag}",
        shared_input_digest=shared_input_digest,
    )
    return ScenarioResult(
        scenario_id=scenario_id or f"ig003-{tag}",
        verdict=verdict,
        facts={
            "simulation": simulation_facts,
            "production": production_facts,
            "shared": shared,
        },
    )


def _idempotency_probes(
    lifecycle_gate: FulfillmentLifecycleGate,
    world: ParityWorld,
    outcome: Mapping[str, Any],
) -> dict[str, Any]:
    """The idempotency convergence probes on the completed chain."""
    tag = outcome["tag"]
    step_id = outcome["ids"]["step_id"]
    key = outcome["ids"]["idempotency_key"]
    before = world.rail.submit_call_count
    re_drive = lifecycle_gate.stage_submit_effect(
        step_id,
        command_id=f"cmd/ig003-{tag}/submit-replay",
        requested_at=T_RE_DRIVE,
    )
    after = world.rail.submit_call_count
    try:
        lifecycle_gate.stage_request_effect(
            step_id,
            idempotency_key=key,
            command_id=f"cmd/ig003-{tag}/request-replay",
            requested_at=T_RE_REQUEST,
            world=outcome["world"],
        )
        re_request_rejected = False
    except CoreValidationError:
        re_request_rejected = True
    ledger = lifecycle_gate.execution.submission_ledger().to_dict()
    return {
        "re_drive_outcome": re_drive["outcome"],
        "re_request_rejected": re_request_rejected,
        "port_calls_before": before,
        "port_calls_after": after,
        "ledger_keys": [entry["key"] for entry in ledger["entries"]],
    }


def _rejection_probes(
    lifecycle_gate: FulfillmentLifecycleGate,
    outcome: Mapping[str, Any],
) -> dict[str, Any]:
    """The fail-closed probes of the rejection scenario."""
    tag = outcome["tag"]
    ids = outcome["ids"]
    step_id = ids["step_id"]
    lifecycle_gate.stage_open_clearing_cycle(
        ids["cycle_id"],
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id=f"cmd/ig003-{tag}/cycle-open",
        requested_at=T_RECOGNIZE,
        description=f"IG-003 rejection recognition window for {tag}",
    )
    obligation_count = len(_obligation_ids(lifecycle_gate))
    try:
        lifecycle_gate.stage_recognize_obligation(
            cycle_id=ids["cycle_id"],
            step_id=step_id,
            due_from=DUE_FROM,
            due_until=DUE_UNTIL,
            command_id=f"cmd/ig003-{tag}/recognize-probe",
            requested_at=T_RECOGNIZE,
        )
        recognition_rejected = False
    except CoreValidationError:
        recognition_rejected = True
    obligation_count_after = len(_obligation_ids(lifecycle_gate))
    return {
        "recognition_rejected": recognition_rejected,
        "obligation_count": obligation_count,
        "obligation_count_after": obligation_count_after,
    }


def _drive_recovery(
    lifecycle_gate: FulfillmentLifecycleGate,
    world: ParityWorld,
    *,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
) -> dict[str, Any]:
    """UNKNOWN submission → reconciliation NOT_FOUND → safe retry → finality."""
    outcome = _drive_world(
        lifecycle_gate,
        world,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
        stop_after="submitted",
    )
    first_state = outcome["submission_state"]
    ids = outcome["ids"]
    step_id = ids["step_id"]
    retry_key = f"{ids['idempotency_key']}-retry"
    # The unknown outcome enters reconciliation BEFORE any retry.
    lifecycle_gate.stage_reconcile_effect(
        step_id,
        command_id=f"cmd/ig003-{tag}/query-1",
        requested_at=T_RECOVERY_QUERY,
    )
    observations = lifecycle_gate.execution.observations()
    query_outcome = observations[-1].spec.content["outcome"]
    lifecycle_gate.stage_retry_step(
        step_id,
        reason="rail reported NOT_FOUND; the effect never happened",
        command_id=f"cmd/ig003-{tag}/retry",
        requested_at=T_RECOVERY_RETRY,
    )
    lifecycle_gate.stage_request_effect(
        step_id,
        idempotency_key=retry_key,
        command_id=f"cmd/ig003-{tag}/request-retry",
        requested_at=T_RECOVERY_REQUEST,
        world=outcome["world"],
    )
    lifecycle_gate.stage_submit_effect(
        step_id,
        command_id=f"cmd/ig003-{tag}/submit-retry",
        requested_at=T_RECOVERY_SUBMIT,
    )
    outcome["idempotency_keys"] = [ids["idempotency_key"], retry_key]
    outcome["native_reference"] = _native_reference(lifecycle_gate, step_id)
    completed = _continue_accepted(
        lifecycle_gate,
        world,
        ids=ids,
        outcome=outcome,
        stop_after="resolved",
        key=retry_key,
    )
    completed["first_submission_state"] = first_state
    completed["reconciliation_outcome"] = query_outcome
    completed["recovered"] = True
    return completed


# ---------------------------------------------------------------------------
# scenario E — the finality discipline parity
# ---------------------------------------------------------------------------


def run_scenario_e_finality_discipline(
    parity_gate: SimulationParityGate,
    *,
    scripts: Sequence[DeclaredRailScript] | None = None,
    tag: str = "final-1",
    payer: str = PARITY_PAYER,
    payee: str = PARITY_PAYEE,
    amount_minor: int = PARITY_AMOUNT_MINOR,
) -> ScenarioResult:
    """Prove payment status ≠ settlement finality in BOTH environments.

    Phase 1 drives both worlds to the payment-status checkpoint (the
    rail already reported its settled payment status) and asserts NO
    finality exists yet in either world. Phase 2 continues both worlds
    through the full settlement chain — finality arrives only through
    the settlement authority over settled legs, identically.
    """
    if scripts is None:
        scripts = (
            DeclaredRailScript(
                idempotency_key=f"ig003-{tag}",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
    shared_input_digest = _shared_input_digest(
        tag=tag, payer=payer, payee=payee, amount_minor=amount_minor, scripts=scripts
    )
    simulation = parity_gate.simulation_gate
    production = parity_gate.production_gate

    sim_pre = _drive_world(
        simulation,
        parity_gate.simulation_world,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
        stop_after="status",
    )
    prod_pre = _drive_world(
        production,
        parity_gate.production_world,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
        stop_after="status",
    )
    pre_status = {}
    for name, lifecycle_gate, outcome in (
        ("simulation", simulation, sim_pre),
        ("production", production, prod_pre),
    ):
        finality_records = sum(
            1
            for record in lifecycle_gate.settlement.records()
            if isinstance(record, Finality)
        )
        settled_legs = sum(
            1
            for settlement in lifecycle_gate.settlement.records()
            if isinstance(settlement, Settlement)
            for leg in settlement.spec.leg_outcomes
            if leg.state == "SETTLED"
        )
        status_recorded = any(
            observation.spec.kind.value == "STATUS"
            for observation in lifecycle_gate.execution.observations()
        )
        if finality_records or settled_legs or not status_recorded:
            raise CoreValidationError(
                "IG-003 finality discipline violation: at the payment-status "
                "checkpoint the "
                f"{name} world carries finality_records={finality_records}, "
                f"settled_legs={settled_legs}, status_recorded={status_recorded} "
                "(a simulated or observed payment status must never establish "
                "settlement finality)"
            )
        world = getattr(parity_gate, f"{name}_world")
        pre_status[name] = {
            "status_recorded": status_recorded,
            "finality_records": finality_records,
            "settled_legs": settled_legs,
            "semantic_projection_digest": semantic_projection_digest(
                semantic_projection(lifecycle_gate, world)
            ),
        }

    sim_done = _resume_after_status(
        simulation,
        parity_gate.simulation_world,
        ids=sim_pre["ids"],
        outcome=sim_pre,
        key=sim_pre["ids"]["idempotency_key"],
    )
    prod_done = _resume_after_status(
        production,
        parity_gate.production_world,
        ids=prod_pre["ids"],
        outcome=prod_pre,
        key=prod_pre["ids"]["idempotency_key"],
    )
    simulation_facts = _world_facts(simulation, sim_done)
    production_facts = _world_facts(production, prod_done)
    shared = {
        "pre_status": pre_status,
        "economics": _economics(simulation),
    }
    shared["economics"]["intent_amount_minor"] = amount_minor
    verdict = parity_gate.parity_verdict(
        scenario_id=f"ig003-{tag}",
        shared_input_digest=shared_input_digest,
    )
    return ScenarioResult(
        scenario_id=f"ig003-{tag}",
        verdict=verdict,
        facts={
            "simulation": simulation_facts,
            "production": production_facts,
            "shared": shared,
        },
    )
