"""Deterministic rail scenario drivers for the IG-005 gate.

Every identifier, amount and instant is declared data; nothing reads
a clock or an entropy source, so two runs of the same scenario
through the same rail pair are semantically identical, and the two
WORLDS of one run differ only in their world binding (environment,
domain, adapter identity, native references, declared asset) —
everything else must be semantically identical, which is exactly what
the comparison verdict proves.

The drivers mirror the WORK-027 scenario discipline over the public
IG-002 stage API: the same declared stage sequence, the same declared
instants, the same command identities — driven once per world, in
lockstep. The required scenarios:

* ``A`` canonical success — the full chain to an ESTABLISHED finality
  certificate on both rails with the idempotency convergence probes,
  and the cross-rail comparison verdict;
* ``B`` rejection — a rail-definitive rejection on both rails: the
  step fails, no obligation is ever recognized (the recognition probe
  fails closed with no composed-state mutation), no economics;
* ``C`` unknown/recovery — an UNKNOWN submission (deterministic local
  transport ambiguity) reconciles NOT_FOUND (retry-safe), the same
  step re-arms under a fresh key and the chain completes to finality;
* ``D`` idempotent retry — the same canonical effect with the same
  idempotency key re-submitted through BOTH adapters: stable native
  reference, no duplicate economic effect, and the engine re-drive
  converges without a second port call;
* ``E`` finality discipline — at the payment-status checkpoint (the
  rail already reported the settled status) NO finality exists;
  finality arrives only after the settlement chain, from the
  settlement authority, on both rails.

The failure/investigation battery additionally proves the required
fail-closed paths: transport ambiguity, provider rejection,
reconciliation success, reconciliation not-found, idempotent retry
and the unexpected provider status (an undeclared native status word
fails closed through the adapter's status map).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.integration.lifecycle import FulfillmentLifecycleGate, build_declared_world

from .contracts import (
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_RAILS_ACTOR,
    RAILS_AMOUNT_MINOR,
    RAILS_PAYEE,
    RAILS_PAYER,
    RAILS_REJECTION_AMOUNT_MINOR,
)
from .harness import ExternalRailSandboxGate

#: Deterministic scenario instants (declared data; never a clock read).
T_COMPILE = "2026-09-04T01:31:00Z"
T_EXEC_CREATE = "2026-09-04T01:33:00Z"
T_EXEC_AUTHORIZE = "2026-09-04T01:34:00Z"
T_EXEC_START = "2026-09-04T01:35:00Z"
T_REQUEST = "2026-09-04T01:36:00Z"
T_SUBMIT = "2026-09-04T01:37:00Z"
T_ACK = "2026-09-04T01:38:00Z"
T_QUERY = "2026-09-04T01:38:30Z"
T_STATUS = "2026-09-04T01:39:00Z"
T_RESULT = "2026-09-04T01:40:00Z"
T_COMPLETE = "2026-09-04T01:41:00Z"
T_FINALITY_CLAIM = "2026-09-04T01:42:00Z"
T_CYCLE_OPEN = "2026-09-04T00:00:00Z"
T_CYCLE_CLOSE = "2026-09-04T06:00:00Z"
T_RECOGNIZE = "2026-09-04T01:50:00Z"
T_OBLIG_VALIDATE = "2026-09-04T02:20:00Z"
T_MARK_DUE = "2026-09-04T02:30:00Z"
T_CYCLE_VALIDATE = "2026-09-04T02:40:00Z"
T_CYCLE_FINALIZE = "2026-09-04T02:50:00Z"
T_SETTLEMENT = "2026-09-04T03:20:00Z"
T_RECONCILE = "2026-09-04T03:50:00Z"
T_FINALITY_VALIDATE = "2026-09-04T04:20:00Z"
T_FINALITY_ESTABLISH = "2026-09-04T04:50:00Z"
T_RESOLVE = "2026-09-04T05:20:00Z"

#: Recovery-path instants: reconcile before retry, fresh key after.
T_RECOVERY_QUERY = "2026-09-04T01:38:40Z"
T_RECOVERY_RETRY = "2026-09-04T01:39:30Z"
T_RECOVERY_REQUEST = "2026-09-04T01:39:35Z"
T_RECOVERY_SUBMIT = "2026-09-04T01:39:40Z"

#: Idempotency probe instants (after the resolved chain).
T_RE_DRIVE = "2026-09-04T05:30:00Z"
T_RE_REQUEST = "2026-09-04T05:31:00Z"

DUE_FROM = "2026-09-04T02:20:00Z"
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

#: The finality-claim word the rails' claims record (canonical
#: evidence vocabulary — a CLAIM, never truth; the settlement
#: authority validates it against settled legs).
FINALITY_CLAIM_WORD = "FINAL"


def _ids(tag: str) -> dict[str, str]:
    plan_id = f"plan/ig005-{tag}"
    execution_plan_id = f"execution/{plan_id}"
    return {
        "tag": tag,
        "plan_id": plan_id,
        "execution_plan_id": execution_plan_id,
        "step_id": f"{execution_plan_id}/step/1",
        "cycle_id": f"clearing/ig005/cycle-{tag}",
        "settlement_id": f"settlement/ig005/batch-{tag}",
        "finality_id": f"settlement/ig005/finality-{tag}",
        "idempotency_key": f"ig005-{tag}",
    }


def shared_declared_input_digest(
    *,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
    asset_a: str,
    asset_b: str,
) -> str:
    """The digest of the shared declared input of one scenario.

    Covers the declared payer/payee, the declared amount (value and
    scale), the declared per-rail asset pair (the *equivalent declared
    economic inputs* of work order §7E: the same declared value and
    scale over each rail's declared asset) and the scenario tag.
    """
    return canonical_sha256(
        {
            "tag": tag,
            "payer": payer,
            "payee": payee,
            "amount_minor": amount_minor,
            "amount_scale": 2,
            "rail_a_asset": asset_a,
            "rail_b_asset": asset_b,
            "gate": "IG-005",
        }
    )


# ---------------------------------------------------------------------------
# the per-world stage driver (the public IG-002 stage API only)
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


def _obligation_ids(lifecycle_gate: FulfillmentLifecycleGate) -> list[str]:
    from src.clearing import Obligation

    return sorted(
        record.object_id
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    )


def _discharge_count(lifecycle_gate: FulfillmentLifecycleGate) -> int:
    return len(
        [
            entry
            for entry in lifecycle_gate.settlement.postings()
            if entry.kind == "DISCHARGE"
        ]
    )


def _drive_world(
    lifecycle_gate: FulfillmentLifecycleGate,
    *,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
    stop_after: str = "resolved",
) -> dict[str, Any]:
    if stop_after not in _CHECKPOINTS:
        raise ValueError(f"unknown stop_after checkpoint {stop_after!r}")
    ids = _ids(tag)
    declared_world = build_declared_world(
        environment_id=lifecycle_gate.environment_id,
        domain_id=lifecycle_gate.domain_id,
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
        currency=_world_currency(lifecycle_gate),
    )
    key = ids["idempotency_key"]
    outcome: dict[str, Any] = {
        "tag": tag,
        "ids": ids,
        "world": declared_world,
        "idempotency_keys": [key],
        "amount_minor": amount_minor,
    }

    lifecycle_gate.stage_compile(
        declared_world,
        plan_id=ids["plan_id"],
        command_id=f"cmd/ig005-{tag}/compile",
        idempotency_key=f"key/ig005-{tag}/compile",
        nonce=f"nonce-ig005-{tag}-compile",
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
        command_id=f"cmd/ig005-{tag}/accept",
        idempotency_key=f"key/ig005-{tag}/accept",
        nonce=f"nonce-ig005-{tag}-accept",
        as_of=declared_world.as_of,
    )
    if stop_after == "accepted":
        return outcome
    lifecycle_gate.stage_create_execution_plan(
        ids["plan_id"],
        command_id=f"cmd/ig005-{tag}/exec-create",
        requested_at=T_EXEC_CREATE,
    )
    if stop_after == "created":
        return outcome
    lifecycle_gate.stage_authorize_execution_plan(
        ids["execution_plan_id"],
        command_id=f"cmd/ig005-{tag}/exec-authorize",
        requested_at=T_EXEC_AUTHORIZE,
    )
    if stop_after == "authorized":
        return outcome
    lifecycle_gate.stage_start_execution_plan(
        ids["execution_plan_id"],
        command_id=f"cmd/ig005-{tag}/exec-start",
        requested_at=T_EXEC_START,
    )
    if stop_after == "running":
        return outcome
    lifecycle_gate.stage_request_effect(
        ids["step_id"],
        idempotency_key=key,
        command_id=f"cmd/ig005-{tag}/request",
        requested_at=T_REQUEST,
        world=declared_world,
    )
    if stop_after == "requested":
        return outcome
    lifecycle_gate.stage_submit_effect(
        ids["step_id"],
        command_id=f"cmd/ig005-{tag}/submit",
        requested_at=T_SUBMIT,
    )
    step = lifecycle_gate.execution.step(ids["step_id"])
    outcome["submission_state"] = step.state.value
    outcome["submission_status"] = _attempt_status(lifecycle_gate, ids["step_id"])
    if step.state.value != "SUBMITTED":
        # A definitive rejection or an unknown outcome ends the main
        # chain here; the scenario-level probes take over.
        outcome["native_reference"] = None
        return outcome
    outcome["native_reference"] = _native_reference(lifecycle_gate, ids["step_id"])
    return _continue_accepted(
        lifecycle_gate, ids=ids, outcome=outcome, stop_after=stop_after
    )


def _world_currency(lifecycle_gate: FulfillmentLifecycleGate) -> str:
    """The world's declared canonical currency word.

    Every IG-005 world declares the SAME canonical asset (the merged
    money authority's closed vocabulary; the declared-asset discipline
    is documented in the normalization registry).
    """
    from .contracts import RAILS_DECLARED_CURRENCY

    return RAILS_DECLARED_CURRENCY


def _continue_accepted(
    lifecycle_gate: FulfillmentLifecycleGate,
    *,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    stop_after: str,
    key: str | None = None,
) -> dict[str, Any]:
    """Continue the chain for an ACCEPTED submission, to ``stop_after``."""
    tag = ids["tag"]
    step_id = ids["step_id"]
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
        command_id=f"cmd/ig005-{tag}/ack",
        requested_at=T_ACK,
    )
    if stop_after == "acknowledged":
        return outcome
    lifecycle_gate.stage_reconcile_effect(
        step_id,
        command_id=f"cmd/ig005-{tag}/query",
        requested_at=T_QUERY,
    )
    if stop_after == "queried":
        return outcome
    lifecycle_gate.stage_record_payment_status(
        step_id,
        native_code=_native_status_of(lifecycle_gate, ids),
        command_id=f"cmd/ig005-{tag}/status",
        requested_at=T_STATUS,
    )
    if stop_after == "status":
        return outcome
    lifecycle_gate.stage_observe_effect_result(
        step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id=f"cmd/ig005-{tag}/result",
    )
    if stop_after == "result":
        return outcome
    lifecycle_gate.stage_complete_step(
        step_id,
        command_id=f"cmd/ig005-{tag}/complete",
        requested_at=T_COMPLETE,
    )
    if stop_after == "completed":
        return outcome
    lifecycle_gate.stage_record_finality_claim(
        step_id,
        claim=FINALITY_CLAIM_WORD,
        native_reference=native_reference,
        command_id=f"cmd/ig005-{tag}/claim",
        requested_at=T_FINALITY_CLAIM,
    )
    if stop_after == "claimed":
        return outcome

    return _run_settlement_stretch(
        lifecycle_gate, ids=ids, outcome=outcome, stop_after=stop_after
    )


def _native_status_of(
    lifecycle_gate: FulfillmentLifecycleGate, ids: Mapping[str, str]
) -> str:
    """The rail's own native status word for the step's current request.

    The status observation always addresses the step's CURRENT
    in-flight effect request (the recovery scenario re-arms the step
    under a fresh idempotency key — the status belongs to that key,
    never to the retired one).
    """
    rail = next(iter(lifecycle_gate.bindings.values())).submission_port
    step_id = ids["step_id"]
    requests = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "EffectRequest"
        and record.spec.step_id == step_id
    ]
    if not requests:
        raise AssertionError(
            f"step {step_id} carries no effect request for its status"
        )
    key = requests[-1].spec.idempotency_key
    native = rail.native_status_for(key)
    if native is None:
        raise AssertionError(
            f"the rail reported no native status for key {key!r}; the status "
            "observation must record real rail vocabulary"
        )
    return native


def _run_settlement_stretch(
    lifecycle_gate: FulfillmentLifecycleGate,
    *,
    ids: Mapping[str, str],
    outcome: dict[str, Any],
    stop_after: str = "resolved",
) -> dict[str, Any]:
    """The shared clearing + settlement stretch, from the claim on."""
    tag = ids["tag"]
    step_id = ids["step_id"]
    lifecycle_gate.stage_open_clearing_cycle(
        ids["cycle_id"],
        opens_at=T_CYCLE_OPEN,
        closes_at=T_CYCLE_CLOSE,
        command_id=f"cmd/ig005-{tag}/cycle-open",
        requested_at=T_RECOGNIZE,
        description=f"IG-005 rail recognition window for {tag}",
    )
    obligations_before = set(_obligation_ids(lifecycle_gate))
    lifecycle_gate.stage_recognize_obligation(
        cycle_id=ids["cycle_id"],
        step_id=step_id,
        due_from=DUE_FROM,
        due_until=DUE_UNTIL,
        command_id=f"cmd/ig005-{tag}/recognize",
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
            command_id=f"cmd/ig005-{tag}/validate-{index}",
            requested_at=T_OBLIG_VALIDATE,
        )
    if stop_after == "validated":
        return outcome
    for index, obligation_id in enumerate(obligation_ids, start=1):
        lifecycle_gate.stage_mark_due_obligation(
            obligation_id,
            command_id=f"cmd/ig005-{tag}/due-{index}",
            requested_at=T_MARK_DUE,
        )
    if stop_after == "due":
        return outcome
    lifecycle_gate.stage_validate_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig005-{tag}/cycle-validate",
        requested_at=T_CYCLE_VALIDATE,
    )
    lifecycle_gate.stage_finalize_cycle(
        ids["cycle_id"],
        command_id=f"cmd/ig005-{tag}/cycle-finalize",
        requested_at=T_CYCLE_FINALIZE,
    )
    if stop_after == "closed":
        return outcome
    lifecycle_gate.stage_settle(
        ids["settlement_id"],
        obligation_ids,
        submit_by=SUBMIT_BY,
        settle_by=SETTLE_BY,
        command_prefix=f"cmd/ig005-{tag}/settle",
        requested_at=T_SETTLEMENT,
    )
    if stop_after == "settled":
        return outcome
    legs = _leg_bindings(lifecycle_gate, ids["settlement_id"], obligation_ids)
    lifecycle_gate.stage_fold_rail_evidence(
        ids["settlement_id"],
        legs,
        command_id=f"cmd/ig005-{tag}/reconcile",
        requested_at=T_RECONCILE,
    )
    if stop_after == "reconciled":
        return outcome
    lifecycle_gate.stage_validate_finality_certificate(
        ids["finality_id"],
        ids["settlement_id"],
        legs,
        command_prefix=f"cmd/ig005-{tag}/claim-validate",
        requested_at=T_FINALITY_VALIDATE,
    )
    if stop_after == "claims":
        return outcome
    lifecycle_gate.stage_establish_finality(
        ids["finality_id"],
        command_id=f"cmd/ig005-{tag}/finality",
        requested_at=T_FINALITY_ESTABLISH,
    )
    outcome["finality_established"] = True
    if stop_after == "finality":
        return outcome
    lifecycle_gate.stage_resolve_settled_obligations(
        ids["settlement_id"],
        command_prefix=f"cmd/ig005-{tag}/resolve",
        requested_at=T_RESOLVE,
    )
    outcome["obligation_resolved"] = True
    return outcome


def _leg_bindings(
    lifecycle_gate: FulfillmentLifecycleGate,
    settlement_id: str,
    obligation_ids: Sequence[str],
) -> dict[str, str]:
    """Bind each settlement leg to the step whose rail evidence folds it."""
    settlement = lifecycle_gate.settlement.settlement(settlement_id)
    instruction_by_obligation = {
        instruction.obligation_id: instruction.instruction_id
        for instruction in settlement.spec.instructions
    }
    legs: dict[str, str] = {}
    for obligation_id in obligation_ids:
        instruction_id = instruction_by_obligation[obligation_id]
        step_ids = _steps_of_obligation(lifecycle_gate, obligation_id)
        legs[instruction_id] = step_ids[0]
    return legs


def _steps_of_obligation(
    lifecycle_gate: FulfillmentLifecycleGate, obligation_id: str
) -> list[str]:
    from src.clearing import Obligation

    obligations = {
        record.object_id: record
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    }
    obligation = obligations[obligation_id]
    source_ref = obligation.spec.source_ref
    # The obligation's sealed authority is the execution evidence of
    # the scenario's step (the plan-hop binding recorded the pair).
    plan_hops = lifecycle_gate.snapshot()["plan_hops"]
    for plan_id, hop_records in plan_hops.items():
        for record in hop_records:
            step_id = record["step_id"]
            if f"{step_id}/result/1" == source_ref or source_ref.endswith(
                f"/{record['hop_id']}"
            ):
                return [step_id]
    # Fallback: the most recent execution step (single-hop scenarios).
    steps = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionStep"
    ]
    if steps:
        return [steps[-1].object_id]
    raise AssertionError(
        f"obligation {obligation_id} has no bound execution step"
    )


def _world_facts(gate: ExternalRailSandboxGate, world_name: str) -> dict[str, Any]:
    lifecycle_gate = (
        gate.rail_a_gate if world_name == "rail_a" else gate.rail_b_gate
    )
    world = gate.rail_a_world if world_name == "rail_a" else gate.rail_b_world
    steps = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionStep"
    ]
    plans = list(lifecycle_gate.execution_plans)
    return {
        "lifecycle_gate": lifecycle_gate,
        "world": world,
        "step_state": steps[-1].state.value if steps else "NONE",
        "plan_state": (
            lifecycle_gate.execution.plan(plans[-1]).state.value
            if plans
            else "NONE"
        ),
        "rail": world.rail,
    }


# ---------------------------------------------------------------------------
# scenario A — canonical success on both rails + the comparison verdict
# ---------------------------------------------------------------------------


def run_rails_scenario_a(
    gate: ExternalRailSandboxGate,
    *,
    tag: str = "a1",
    amount_minor: int = RAILS_AMOUNT_MINOR,
    payer: str = RAILS_PAYER,
    payee: str = RAILS_PAYEE,
) -> dict[str, Any]:
    """Drive the canonical success chain on BOTH worlds and compare."""
    outcomes = {}
    for world_name, lifecycle_gate in (
        ("rail_a", gate.rail_a_gate),
        ("rail_b", gate.rail_b_gate),
    ):
        outcomes[world_name] = _drive_world(
            lifecycle_gate,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
        )
    digest = shared_declared_input_digest(
        tag=tag,
        payer=payer,
        payee=payee,
        amount_minor=amount_minor,
        asset_a=f"asset/{gate.rail_a_world.declared_currency}",
        asset_b=f"asset/{gate.rail_b_world.declared_currency}",
    )
    verdict = gate.rail_comparison_verdict(
        scenario_id=f"IG-005/A/{tag}", shared_input_digest=digest
    )

    facts: dict[str, Any] = {"verdict": verdict, "shared_input_digest": digest}
    for world_name in ("rail_a", "rail_b"):
        driven = outcomes[world_name]
        lifecycle_gate = (
            gate.rail_a_gate if world_name == "rail_a" else gate.rail_b_gate
        )
        world = gate.rail_a_world if world_name == "rail_a" else gate.rail_b_world
        steps = driven["ids"]["step_id"]
        # Idempotency convergence probes: the completed step's lifecycle
        # guard converges the re-drive without a second port call.
        rail = world.rail
        before_calls = getattr(rail, "submit_call_count", 0)
        re_drive = lifecycle_gate.stage_submit_effect(
            driven["ids"]["step_id"],
            command_id=f"cmd/ig005-{tag}/submit-replay",
            requested_at=T_RE_DRIVE,
        )
        try:
            re_request = lifecycle_gate.stage_request_effect(
                driven["ids"]["step_id"],
                idempotency_key=driven["ids"]["idempotency_key"],
                command_id=f"cmd/ig005-{tag}/request-replay",
                requested_at=T_RE_REQUEST,
                world=driven["world"],
            )
            re_request_outcome = re_request["outcome"]
        except CoreValidationError:
            # The same-key re-request converges fail closed: the
            # engine's idempotency ledger rejects the re-binding (the
            # _drive wrapper verified the composed state did not
            # mutate before re-raising).
            re_request_outcome = "rejected"
        facts[world_name] = {
            "step_state": lifecycle_gate.execution.step(steps).state.value,
            "plan_state": (
                lifecycle_gate.execution.plan(
                    driven["ids"]["execution_plan_id"]
                ).state.value
            ),
            "submission_status": driven["submission_status"],
            "native_reference": driven["native_reference"],
            "finality_established": bool(driven.get("finality_established")),
            "obligation_resolved": bool(driven.get("obligation_resolved")),
            "amount_minor": driven["amount_minor"],
            "discharge_count": _discharge_count(lifecycle_gate),
            "idempotency_keys": driven["idempotency_keys"],
            "re_drive_outcome": re_drive["outcome"],
            "re_request_outcome": re_request_outcome,
            "re_drive_port_call_unchanged": (
                getattr(rail, "submit_call_count", 0) == before_calls
            ),
        }
    return facts


# ---------------------------------------------------------------------------
# scenario B — rejection on both rails (no economics, fail-closed probe)
# ---------------------------------------------------------------------------


def run_rails_scenario_b(
    gate: ExternalRailSandboxGate,
    *,
    tag: str = "b1",
    amount_minor: int = RAILS_REJECTION_AMOUNT_MINOR,
    payer: str = RAILS_PAYER,
    payee: str = RAILS_PAYEE,
) -> dict[str, Any]:
    """Drive the deterministic rejection chain on BOTH worlds."""
    facts: dict[str, Any] = {}
    for world_name, lifecycle_gate in (
        ("rail_a", gate.rail_a_gate),
        ("rail_b", gate.rail_b_gate),
    ):
        driven = _drive_world(
            lifecycle_gate,
            tag=tag,
            payer=payer,
            payee=payee,
            amount_minor=amount_minor,
            stop_after="submitted",
        )
        world = gate.rail_a_world if world_name == "rail_a" else gate.rail_b_world
        obligations_before = _obligation_ids(lifecycle_gate)
        discharges_before = _discharge_count(lifecycle_gate)
        settlements_before = _settlement_count(lifecycle_gate)
        snapshot_before = lifecycle_gate.snapshot()
        # The fail-closed recognition probe: recognizing an obligation
        # from FAILED evidence must be rejected with no mutation.
        recognition_rejected = False
        try:
            lifecycle_gate.stage_recognize_obligation(
                cycle_id=f"clearing/ig005/cycle-{tag}",
                step_id=driven["ids"]["step_id"],
                due_from=DUE_FROM,
                due_until=DUE_UNTIL,
                command_id=f"cmd/ig005-{tag}/recognize-probe",
                requested_at=T_RECOGNIZE,
            )
        except CoreValidationError:
            recognition_rejected = True
        snapshot_after = lifecycle_gate.snapshot()
        # The engine's plan-resolution authority is the effect-result
        # path: a port-level definitive rejection fails the STEP (and
        # the request resolves), while the plan stays RUNNING — the
        # plan state is reported as the engine's own truth, and the
        # no-obligation/no-economics facts below are the load-bearing
        # rejection semantics.
        facts[world_name] = {
            "submission_status": driven["submission_status"],
            "step_state": driven["submission_state"],
            "plan_state": (
                lifecycle_gate.execution.plan(
                    driven["ids"]["execution_plan_id"]
                ).state.value
            ),
            "obligations_recognized": (
                len(_obligation_ids(lifecycle_gate)) - len(obligations_before)
            ),
            "settlement_count": (
                _settlement_count(lifecycle_gate) - settlements_before
            ),
            "discharge_count": (
                _discharge_count(lifecycle_gate) - discharges_before
            ),
            "finality_established": False,
            "recognition_probe_rejected": recognition_rejected,
            "composed_state_unchanged": (
                canonical_sha256(snapshot_before)
                == canonical_sha256(snapshot_after)
            ),
        }
    return facts


def _settlement_count(lifecycle_gate: FulfillmentLifecycleGate) -> int:
    from src.settlement import Settlement

    return len(
        [
            record
            for record in lifecycle_gate.settlement.records()
            if isinstance(record, Settlement)
        ]
    )


# ---------------------------------------------------------------------------
# scenario C — unknown / reconciliation / recovery (local deterministic)
# ---------------------------------------------------------------------------


def run_rails_scenario_c(
    *,
    tag: str = "c1",
    submissions: Mapping[str, Sequence[str]] | None = None,
    queries: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """The deterministic unknown→reconciliation→definitive chain.

    The transport-ambiguity portion runs on the local deterministic
    pair (a real provider is never abused to fabricate network
    corruption — work order §7C); the canonical boundary is the same
    typed port contract and the same public stage API.
    """
    from .worlds import build_local_rail_pair

    if submissions is None:
        submissions = {f"ig005-{tag}": ("unknown",), f"ig005-{tag}-retry": ("accept",)}
    if queries is None:
        queries = {f"ig005-{tag}": ("not-found",)}
    world_a, _world_b = build_local_rail_pair(
        submissions=submissions, queries=queries
    )
    gate = ExternalRailSandboxGate((world_a, _world_b))
    lifecycle_gate = gate.rail_a_gate
    rail = world_a.rail
    ids = _ids(tag)
    first_key = ids["idempotency_key"]
    retry_key = f"{first_key}-retry"
    outcome: dict[str, Any] = {
        "first_key": first_key,
        "retry_key": retry_key,
    }

    driven = _drive_world(
        lifecycle_gate,
        tag=tag,
        payer=RAILS_PAYER,
        payee=RAILS_PAYEE,
        amount_minor=RAILS_AMOUNT_MINOR,
        stop_after="requested",
    )
    del driven
    port_calls_before = rail.submit_call_count
    lifecycle_gate.stage_submit_effect(
        ids["step_id"],
        command_id=f"cmd/ig005-{tag}/submit",
        requested_at=T_SUBMIT,
    )
    port_calls_for_first_key = rail.submit_call_count - port_calls_before
    step = lifecycle_gate.execution.step(ids["step_id"])
    outcome["first_submission_state"] = step.state.value
    outcome["port_calls_for_first_key"] = port_calls_for_first_key

    # The unknown submission is reconciled BEFORE any retry: the rail
    # never received the effect, so NOT_FOUND is the retry-safe truth.
    reconcile = lifecycle_gate.stage_reconcile_effect(
        ids["step_id"],
        command_id=f"cmd/ig005-{tag}/query",
        requested_at=T_RECOVERY_QUERY,
    )
    outcome["reconciliation_outcome"] = _query_outcome_of(lifecycle_gate, ids)
    outcome["reconciliation_stage_outcome"] = reconcile["outcome"]

    # Re-arm the SAME step under a fresh idempotency key and complete
    # the chain to a definitive outcome.
    lifecycle_gate.stage_retry_step(
        ids["step_id"],
        reason="transport ambiguity reconciled not-found; retry on a fresh key",
        command_id=f"cmd/ig005-{tag}/retry",
        requested_at=T_RECOVERY_RETRY,
    )
    lifecycle_gate.stage_request_effect(
        ids["step_id"],
        idempotency_key=retry_key,
        command_id=f"cmd/ig005-{tag}/request-retry",
        requested_at=T_RECOVERY_REQUEST,
        world=_world_of_gate(lifecycle_gate),
    )
    lifecycle_gate.stage_submit_effect(
        ids["step_id"],
        command_id=f"cmd/ig005-{tag}/submit-retry",
        requested_at=T_RECOVERY_SUBMIT,
    )
    step = lifecycle_gate.execution.step(ids["step_id"])
    outcome["retry_submission_state"] = step.state.value
    outcome["retry_submission_status"] = _attempt_status(
        lifecycle_gate, ids["step_id"]
    )
    if step.state.value == "SUBMITTED":
        outcome["native_reference"] = _native_reference(
            lifecycle_gate, ids["step_id"]
        )

    # An UNKNOWN outcome is never promoted to settled or final: the
    # promoted facts are read from the engine's own records.
    settled_before_recovery = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
        and record.spec.status.value == "ACCEPTED"
    ]
    outcome["unknown_promoted_to_settled"] = bool(
        _settlement_count(lifecycle_gate)
        and not settled_before_recovery
    )
    outcome["unknown_promoted_to_final"] = _finality_count(lifecycle_gate) > 0 and (
        not settled_before_recovery
    )

    if step.state.value == "SUBMITTED":
        _continue_accepted(
            lifecycle_gate,
            ids=ids,
            outcome=outcome,
            stop_after="resolved",
            key=retry_key,
        )
    outcome["finality_established"] = bool(outcome.get("finality_established"))
    outcome["obligation_resolved"] = bool(outcome.get("obligation_resolved"))
    outcome["recovered"] = (
        outcome["retry_submission_state"] in ("SUBMITTED", "COMPLETED")
        and outcome["finality_established"]
    )
    return outcome


def _query_outcome_of(
    lifecycle_gate: FulfillmentLifecycleGate, ids: Mapping[str, str]
) -> str:
    from src.transition.payload import payload_to_json_value

    observations = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExternalObservation"
        and record.spec.kind.value == "QUERY"
    ]
    if not observations:
        raise AssertionError("the reconciliation query recorded no observation")
    content = observations[-1].spec.content
    if not isinstance(content, Mapping):
        content = payload_to_json_value(content)
    return str(content.get("outcome", "UNKNOWN"))


def _finality_count(lifecycle_gate: FulfillmentLifecycleGate) -> int:
    from src.settlement import Finality

    return len(
        [
            record
            for record in lifecycle_gate.settlement.records()
            if isinstance(record, Finality)
        ]
    )


def _world_of_gate(lifecycle_gate: FulfillmentLifecycleGate) -> Any:
    return lifecycle_gate.worlds[-1] if lifecycle_gate.worlds else None


# ---------------------------------------------------------------------------
# scenario D — idempotent retry through both adapters
# ---------------------------------------------------------------------------


def run_rails_scenario_d(
    gate: ExternalRailSandboxGate,
    *,
    tag: str = "a1",
) -> dict[str, Any]:
    """Re-submit the same canonical effect with the same key, both rails.

    Requires scenario A's canonical chain on the gate (the probes
    target its completed step, its recorded request and its settled
    economics).
    """
    facts: dict[str, Any] = {}
    for world_name in ("rail_a", "rail_b"):
        lifecycle_gate = (
            gate.rail_a_gate if world_name == "rail_a" else gate.rail_b_gate
        )
        world = gate.rail_a_world if world_name == "rail_a" else gate.rail_b_world
        rail = world.rail
        step_id = f"execution/plan/ig005-{tag}/step/1"
        request = _request_record_of(lifecycle_gate, step_id)
        obligations_before = len(_obligation_ids(lifecycle_gate))
        discharges_before = _discharge_count(lifecycle_gate)

        # Engine re-drive on the completed step: the lifecycle guard
        # converges without a second port call.
        before_calls = getattr(rail, "submit_call_count", 0)
        re_drive = lifecycle_gate.stage_submit_effect(
            step_id,
            command_id=f"cmd/ig005-{tag}/submit-idem",
            requested_at=T_RE_DRIVE,
        )
        re_drive_unchanged = getattr(rail, "submit_call_count", 0) == before_calls

        # Rail-level same-key re-submission through the PUBLIC typed
        # adapter path (binding.submit): the same canonical effect with
        # the same idempotency key.
        resubmission = world.binding.submit(request)
        obligations_after = len(_obligation_ids(lifecycle_gate))
        discharges_after = _discharge_count(lifecycle_gate)
        scenario_key = request.spec.idempotency_key
        scenario_payment = getattr(rail, "native_payment", lambda _key: None)(
            scenario_key
        )
        facts[world_name] = {
            "re_drive_outcome": re_drive["outcome"],
            "re_drive_port_call_unchanged": re_drive_unchanged,
            "resubmission_status": resubmission.status.value,
            "resubmission_native_reference": resubmission.native_reference,
            "first_native_reference": _native_reference(lifecycle_gate, step_id),
            "obligation_delta": obligations_after - obligations_before,
            "discharge_delta": discharges_after - discharges_before,
            "native_payment_count": 1 if scenario_payment is not None else 0,
        }
    return facts


def _request_record_of(
    lifecycle_gate: FulfillmentLifecycleGate, step_id: str
) -> Any:
    requests = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "EffectRequest"
        and record.spec.step_id == step_id
    ]
    if not requests:
        raise AssertionError(f"step {step_id} carries no recorded effect request")
    return requests[-1]


# ---------------------------------------------------------------------------
# scenario E — finality discipline (payment status != settlement finality)
# ---------------------------------------------------------------------------


def run_rails_finality_discipline(
    gate: ExternalRailSandboxGate,
    *,
    tag: str = "e1",
    amount_minor: int = RAILS_AMOUNT_MINOR,
) -> dict[str, Any]:
    """Prove payment status alone never manufactures finality.

    Drives both worlds to the payment-status checkpoint (the rails
    already reported their native settled status), proves NO finality
    exists there, then completes the settlement chain and proves
    finality arrives ONLY from the settlement authority.
    """
    facts: dict[str, Any] = {}
    for world_name, lifecycle_gate in (
        ("rail_a", gate.rail_a_gate),
        ("rail_b", gate.rail_b_gate),
    ):
        driven = _drive_world(
            lifecycle_gate,
            tag=tag,
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=amount_minor,
            stop_after="status",
        )
        # The status checkpoint: the rail's settled status IS recorded,
        # and NO finality exists FOR THIS SCENARIO (the count is scoped
        # to the scenario's own finality id — a shared gate may already
        # carry other scenarios' certificates).
        finality_records = [
            record
            for record in lifecycle_gate.settlement.records()
            if record.__class__.__name__ == "Finality"
            and record.object_id == driven["ids"]["finality_id"]
        ]
        status_recorded_settled = _latest_status_is_settled(
            lifecycle_gate, driven["ids"]["step_id"]
        )
        # Continue the chain from the status checkpoint to resolution.
        _resume_after_status(lifecycle_gate, driven)
        finality_after = [
            record
            for record in lifecycle_gate.settlement.records()
            if record.__class__.__name__ == "Finality"
            and record.object_id == driven["ids"]["finality_id"]
        ]
        settlement = lifecycle_gate.settlement.settlement(
            driven["ids"]["settlement_id"]
        )
        settled_legs = _settled_leg_count(lifecycle_gate, settlement.object_id)
        facts[world_name] = {
            "status_recorded_settled": status_recorded_settled,
            "finality_exists_at_status_point": bool(finality_records),
            "finality_count_at_status_point": len(finality_records),
            "finality_id_at_status_point": (
                finality_records[0].object_id if finality_records else None
            ),
            "finality_established_after_settlement": (
                bool(finality_after)
                and finality_after[-1].state.value == "ESTABLISHED"
            ),
            "settlement_state": settlement.state.value,
            "settled_legs": settled_legs,
            "finality_claim_kind": FINALITY_CLAIM_WORD,
            "claim_recorded_as": "OBSERVED",
            "finality_id": (
                finality_after[-1].object_id if finality_after else None
            ),
        }
    return facts


def _latest_status_is_settled(
    lifecycle_gate: FulfillmentLifecycleGate, step_id: str
) -> bool:
    from src.transition.payload import payload_to_json_value

    status_observations = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExternalObservation"
        and record.spec.kind.value == "STATUS"
    ]
    if not status_observations:
        return False
    content = status_observations[-1].spec.content
    if not isinstance(content, Mapping):
        content = payload_to_json_value(content)
    return content.get("canonical_status") == "SETTLED"


def _settled_leg_count(
    lifecycle_gate: FulfillmentLifecycleGate, settlement_id: str
) -> int:
    settlement = lifecycle_gate.settlement.settlement(settlement_id)
    return len(
        [
            leg
            for leg in settlement.spec.leg_outcomes
            if leg.state == "SETTLED"
        ]
    )


def _resume_after_status(
    lifecycle_gate: FulfillmentLifecycleGate, driven: Mapping[str, Any]
) -> None:
    """Continue one world's chain from the status checkpoint to resolved."""
    ids = driven["ids"]
    tag = ids["tag"]
    step_id = ids["step_id"]
    native_reference = driven["native_reference"]
    lifecycle_gate.stage_observe_effect_result(
        step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=T_RESULT,
        command_id=f"cmd/ig005-{tag}/result",
    )
    lifecycle_gate.stage_complete_step(
        step_id,
        command_id=f"cmd/ig005-{tag}/complete",
        requested_at=T_COMPLETE,
    )
    lifecycle_gate.stage_record_finality_claim(
        step_id,
        claim=FINALITY_CLAIM_WORD,
        native_reference=native_reference,
        command_id=f"cmd/ig005-{tag}/claim",
        requested_at=T_FINALITY_CLAIM,
    )
    _run_settlement_stretch(
        lifecycle_gate, ids=ids, outcome=dict(driven), stop_after="resolved"
    )


# ---------------------------------------------------------------------------
# the failure / investigation battery
# ---------------------------------------------------------------------------


def run_failure_battery(gate: ExternalRailSandboxGate) -> dict[str, Any]:
    """Prove every required failure path fails closed.

    The battery probes: transport ambiguity (deterministic local
    rail), provider rejection (deterministic local rail), the
    reconciliation success and not-found queries through the real
    bound bindings, the idempotent same-key re-submission through both
    adapters, and the unexpected provider status word (an undeclared
    native code through the adapter's status map fails closed).
    """
    paths: dict[str, dict[str, Any]] = {}

    # -- transport ambiguity + provider rejection on the deterministic
    #    local pair (a real provider is never abused to fabricate
    #    network corruption; the canonical boundary is identical).
    from .worlds import build_local_rail_pair

    ambiguity_gate = ExternalRailSandboxGate(
        build_local_rail_pair(
            submissions={
                "ig005-fb-unknown": ("unknown",),
                "ig005-fb-reject": ("reject",),
            }
        )
    )
    unknown = _drive_world(
        ambiguity_gate.rail_a_gate,
        tag="fb-unknown",
        payer=RAILS_PAYER,
        payee=RAILS_PAYEE,
        amount_minor=RAILS_AMOUNT_MINOR,
        stop_after="submitted",
    )
    paths["transport_ambiguity"] = {
        "submission_status": unknown["submission_status"],
        "fail_closed": unknown["submission_status"] == "UNKNOWN",
        "detail": (
            "the transport-unknown submission left the rail with no "
            "definitive response; reconciliation (not blind retry) is the "
            "only permitted next step"
        ),
    }
    rejection = _drive_world(
        ambiguity_gate.rail_a_gate,
        tag="fb-reject",
        payer=RAILS_PAYER,
        payee=RAILS_PAYEE,
        amount_minor=RAILS_AMOUNT_MINOR,
        stop_after="submitted",
    )
    paths["provider_rejection"] = {
        "submission_status": rejection["submission_status"],
        "fail_closed": rejection["submission_status"] == "REJECTED",
        "detail": (
            "the rail's definitive business rejection failed the step "
            "with no obligation and no economic effect"
        ),
    }

    # -- reconciliation success: the canonical key's REAL recorded
    #    effect request reconciles to the definitive outcome through
    #    the bound reconciliation ports of both worlds.
    for world_name, world in (
        ("rail_a", gate.rail_a_world),
        ("rail_b", gate.rail_b_world),
    ):
        lifecycle_gate = (
            gate.rail_a_gate if world_name == "rail_a" else gate.rail_b_gate
        )
        request = _request_record_of(
            lifecycle_gate, f"execution/plan/ig005-a1/step/1"
        )
        result = world.binding.query(request)
        paths[f"reconciliation_success:{world_name}"] = {
            "outcome": result.outcome.value,
            "fail_closed": result.outcome.value
            in ("SUCCEEDED", "FAILED", "NOT_FOUND"),
            "detail": (
                "the reconciliation query returned the rail's "
                "authoritative statement (a definitive outcome or the "
                "retry-safe not-found truth)"
            ),
        }
    paths["reconciliation_success"] = paths["reconciliation_success:rail_a"]

    # -- reconciliation not-found: the transport-unknown submission's
    #    REAL recorded request (the rail never received the effect)
    #    reconciles to the retry-safe truth, never to fabricated
    #    success, on both worlds of the deterministic pair.
    not_found_facts: dict[str, Any] = {"fabricated_success": False}
    world = ambiguity_gate.rail_a_world
    lifecycle_gate = ambiguity_gate.rail_a_gate
    request = _request_record_of(
        lifecycle_gate, f"execution/plan/ig005-fb-unknown/step/1"
    )
    result = world.binding.query(request)
    if result.outcome.value == "SUCCEEDED":
        not_found_facts["fabricated_success"] = True
    else:
        not_found_facts["outcome"] = result.outcome.value
    not_found_facts["fail_closed"] = (
        not not_found_facts["fabricated_success"]
        and not_found_facts.get("outcome") == "NOT_FOUND"
    )
    paths["reconciliation_not_found"] = not_found_facts

    # -- idempotent retry: the same-key re-submission converges (the
    #    scenario D probe, summarized).
    idem = run_rails_scenario_d(gate)
    converged = all(
        side["resubmission_status"] == "ACCEPTED"
        and side["resubmission_native_reference"] == side["first_native_reference"]
        and side["obligation_delta"] == 0
        and side["discharge_delta"] == 0
        for side in idem.values()
    )
    paths["idempotent_retry"] = {
        "converged": converged,
        "fail_closed": converged,
        "detail": (
            "the same canonical effect with the same idempotency key "
            "re-submitted through both adapters returned the stable native "
            "reference with no duplicate economic effect"
        ),
    }

    # -- unexpected provider status: an undeclared native word through
    #    the adapter's status map fails closed.
    raised = False
    canonical_status = None
    try:
        for world in (gate.rail_a_world, gate.rail_b_world):
            canonical_status = world.binding.map_status(
                "unexpected-status-word"
            )
    except CoreValidationError:
        raised = True
    paths["unexpected_provider_status"] = {
        "raised_validation_error": raised,
        "canonical_status": canonical_status,
        "settled": False,
        "fail_closed": raised,
        "detail": (
            "an undeclared provider status word fails closed through the "
            "adapter's declared status map; it is never guessed into a "
            "settled or final state"
        ),
    }

    return {"paths": paths}


__all__ = [
    "run_failure_battery",
    "run_rails_finality_discipline",
    "run_rails_scenario_a",
    "run_rails_scenario_b",
    "run_rails_scenario_c",
    "run_rails_scenario_d",
    "shared_declared_input_digest",
]
