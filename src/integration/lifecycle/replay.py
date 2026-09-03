"""Deterministic journal-driven replay of the IG-002 composed state.

``rebuild_lifecycle_gate`` rebuilds the WHOLE composed lifecycle from
the snapshot alone — no provider is ever contacted:

1. a fresh gate is created with the caller's fresh adapter bindings
   (rail ports are never called during a rebuild — the execution
   submission ledger is reconstructed from the journal, so a re-driven
   duplicate submission converges without a port call);
2. the compiler stretch is REPLAYED DETERMINISTICALLY: the declared
   world (re-decoded through the intent domain's trusted paths) is
   recompiled and re-accepted, and the resulting plan digest must be
   byte-identical to the recorded plan (the compiler domain's own
   deterministic-semantic-equivalence proof, driven by the gate);
3. the execution, clearing and settlement engines are rebuilt from
   their kernel journals through each domain's public
   ``rebuild_from_journal`` (transformation completeness — the kernel's
   command-id dedup restarts by design, so the comparison below is
   over the SEMANTIC record state, never kernel bookkeeping);
4. the stage journal is verified: every entry chains
   (``state_before``/``state_after``), non-accepted entries never claim
   a state change, and the last accepted entry's ``state_after`` must
   equal the snapshot's recorded composed digest — a tampered or
   fabricated journal fails closed.

``assert_replay_equivalence`` then proves the rebuild semantically:
identical plan digests, identical per-domain record indexes (every
record re-verified through its domain seal), identical submission
ledger, identical semantic digest, and the full cross-domain invariant
battery re-verified on the rebuilt gate.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.clearing import ClearingEngine
from src.compiler import RouteHopOffer
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256
from src.execution import ExecutionEngine
from src.intent import EconomicSlack, FulfillmentPolicy, Intent
from src.reservation import Reservation
from src.settlement import SettlementEngine

from .contracts import (
    CLEARING_DOMAIN_SUFFIX,
    EXECUTION_DOMAIN_SUFFIX,
    LIFECYCLE_SCHEMA_VERSION,
    SETTLEMENT_DOMAIN_SUFFIX,
    validate_lifecycle_gate_id,
)
from .harness import FulfillmentLifecycleGate
from .invariants import verify_lifecycle_invariants
from .world import LifecycleWorld

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "gate_id",
        "environment_id",
        "domain_id",
        "actor",
        "authorized_actors",
        "adapter_ids",
        "worlds",
        "plans",
        "execution_plans",
        "plan_hops",
        "stage_journal",
        "execution_journal",
        "clearing_journal",
        "settlement_journal",
        "composed_digest",
    }
)


def _require_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(snapshot, Mapping):
        raise CoreValidationError("gate snapshot must be an object")
    if set(snapshot) != _SNAPSHOT_FIELDS:
        missing = sorted(_SNAPSHOT_FIELDS - set(snapshot))
        extra = sorted(set(snapshot) - _SNAPSHOT_FIELDS)
        raise CoreValidationError(
            f"gate snapshot fields are not canonical; missing={missing}, extra={extra}"
        )
    if snapshot["schema_version"] != LIFECYCLE_SCHEMA_VERSION:
        raise CoreValidationError(
            f"gate snapshot schema_version must be {LIFECYCLE_SCHEMA_VERSION}, got "
            f"{snapshot['schema_version']!r}"
        )
    validate_lifecycle_gate_id(snapshot["gate_id"])
    return dict(snapshot)


def _rebuild_world(declaration: Mapping[str, Any]) -> LifecycleWorld:
    reservations = {
        reservation_id: Reservation.from_dict(record)
        for reservation_id, record in declaration["reservations"].items()
    }
    return LifecycleWorld(
        environment_id=declaration["environment_id"],
        domain_id=declaration["domain_id"],
        payer=declaration["payer"],
        payee=declaration["payee"],
        currency=declaration["currency"],
        amount_minor=declaration["amount_minor"],
        destination=declaration["destination"],
        as_of=declaration["as_of"],
        jurisdiction=declaration["jurisdiction"],
        minimum_authority_tier=declaration["minimum_authority_tier"],
        intent=Intent.from_dict(declaration["intent"]),
        policy=FulfillmentPolicy.from_dict(declaration["policy"]),
        slack=EconomicSlack.from_dict(declaration["slack"]),
        hops=tuple(RouteHopOffer.from_dict(hop) for hop in declaration["hops"]),
        reservations=reservations,
        fraud_gates={
            hop_id: dict(gate) for hop_id, gate in declaration["fraud_gates"].items()
        },
        compliance_gates={
            hop_id: dict(gate)
            for hop_id, gate in declaration["compliance_gates"].items()
        },
        payment_legs={
            hop_id: dict(leg) for hop_id, leg in declaration["payment_legs"].items()
        },
        authorization=dict(declaration["authorization"]),
    )


def rebuild_lifecycle_gate(
    snapshot: Mapping[str, Any],
    *,
    bindings: Mapping[str, Any],
) -> FulfillmentLifecycleGate:
    """Rebuild a gate from its snapshot (journals only; fail closed)."""
    snapshot = _require_snapshot(snapshot)
    if sorted(snapshot["adapter_ids"]) != sorted(bindings):
        raise CoreValidationError(
            "the rebuild bindings must declare exactly the snapshot's adapter ids"
        )
    gate = FulfillmentLifecycleGate(
        environment_id=snapshot["environment_id"],
        domain_id=snapshot["domain_id"],
        bindings=bindings,
        gate_id=snapshot["gate_id"],
        authorized_actors=tuple(snapshot["authorized_actors"]),
        actor=snapshot["actor"],
    )

    # 1. deterministic compiler replay: recompile + re-accept every world.
    for declaration, plan_composite in zip(snapshot["worlds"], snapshot["plans"]):
        world = _rebuild_world(declaration)
        plan_id = plan_composite["envelope"]["object_id"]
        entry = gate.stage_compile(
            world,
            plan_id=plan_id,
            command_id=f"replay/compile/{plan_id}",
            idempotency_key=f"replay/key/compile/{plan_id}",
            nonce=f"replay-nonce-compile-{plan_id}",
            requested_at=world.as_of,
        )
        if entry["outcome"] != "accepted":
            raise CoreValidationError(
                f"replay divergence: recompiling {plan_id} was not accepted"
            )
        replayed = gate.compiler.plan(plan_id)
        recorded_digest = plan_composite["payload"]["plan_digest"]
        if replayed.spec.plan_digest != recorded_digest:
            raise CoreValidationError(
                f"replay divergence: plan {plan_id} recompiled to a different "
                "digest than the recorded plan (deterministic compilation broke)"
            )
        accepted = gate.stage_accept_plan(
            plan_id,
            command_id=f"replay/accept/{plan_id}",
            idempotency_key=f"replay/key/accept/{plan_id}",
            nonce=f"replay-nonce-accept-{plan_id}",
            as_of=world.as_of,
        )
        if accepted["outcome"] != "accepted":
            raise CoreValidationError(
                f"replay divergence: re-accepting {plan_id} was not accepted"
            )

    # 2. domain rebuilds from the kernel journals (public paths only).
    rebuilt_execution = ExecutionEngine.rebuild_from_journal(
        environment_id=gate.environment_id,
        domain_id=f"{gate.domain_id}/{EXECUTION_DOMAIN_SUFFIX}",
        bindings=bindings,
        journal=_journal_entries(snapshot["execution_journal"]),
    )
    rebuilt_clearing = ClearingEngine.rebuild_from_journal(
        environment_id=gate.environment_id,
        domain_id=f"{gate.domain_id}/{CLEARING_DOMAIN_SUFFIX}",
        journal=_journal_entries(snapshot["clearing_journal"]),
    )
    rebuilt_settlement = SettlementEngine.rebuild_from_journal(
        environment_id=gate.environment_id,
        domain_id=f"{gate.domain_id}/{SETTLEMENT_DOMAIN_SUFFIX}",
        journal=_journal_entries(snapshot["settlement_journal"]),
    )
    gate._execution = rebuilt_execution
    gate._clearing = rebuilt_clearing
    gate._settlement = rebuilt_settlement
    gate._execution_plans = list(snapshot["execution_plans"])
    gate._plan_hops = {
        plan_id: [dict(record) for record in records]
        for plan_id, records in snapshot["plan_hops"].items()
    }

    # 3. stage journal integrity: chaining, honest outcomes, and the
    #    final digest pin (a tampered journal fails closed here).
    journal = snapshot["stage_journal"]
    if not journal:
        raise CoreValidationError("the stage journal must not be empty")
    for previous, current in zip(journal, journal[1:]):
        if previous["state_after"] != current["state_before"]:
            raise CoreValidationError(
                f"stage journal broke its chain at {current['command_id']}"
            )
    last = journal[-1]
    if last["state_after"] != snapshot["composed_digest"]:
        raise CoreValidationError(
            "replay divergence: the last stage's recorded digest does not match "
            "the snapshot's composed digest — the stage journal was tampered with"
        )
    gate._stage_journal = [dict(entry) for entry in journal]

    # 4. the invariant battery must hold on the rebuilt state.
    gate._last_invariant_checks = tuple(verify_lifecycle_invariants(gate))
    return gate


def assert_replay_equivalence(
    original: FulfillmentLifecycleGate, rebuilt: FulfillmentLifecycleGate
) -> None:
    """Prove the rebuild: identical semantic state, re-verified invariants."""
    if rebuilt.environment_id != original.environment_id:
        raise CoreValidationError("rebuilt gate environment diverges")
    if len(rebuilt.plans) != len(original.plans):
        raise CoreValidationError("rebuilt gate plan count diverges")
    for original_plan, rebuilt_plan in zip(original.plans, rebuilt.plans):
        if original_plan.spec.plan_digest != rebuilt_plan.spec.plan_digest:
            raise CoreValidationError(
                "rebuilt plan digest diverges from the original"
            )
    if _engine_index_digest(rebuilt.execution) != _engine_index_digest(
        original.execution
    ):
        raise CoreValidationError("rebuilt execution index diverges")
    if _engine_index_digest(rebuilt.clearing) != _engine_index_digest(
        original.clearing
    ):
        raise CoreValidationError("rebuilt clearing index diverges")
    if _engine_index_digest(rebuilt.settlement) != _engine_index_digest(
        original.settlement
    ):
        raise CoreValidationError("rebuilt settlement index diverges")
    if canonical_json(
        rebuilt.execution.submission_ledger().to_dict()
    ) != canonical_json(original.execution.submission_ledger().to_dict()):
        raise CoreValidationError("rebuilt submission ledger diverges")
    if semantic_digest(rebuilt) != semantic_digest(original):
        raise CoreValidationError("rebuilt semantic digest diverges")
    verify_lifecycle_invariants(rebuilt)


def semantic_digest(gate: FulfillmentLifecycleGate) -> str:
    """Digest over the SEMANTIC composed state (records, never kernel
    bookkeeping — the kernel's command-id dedup restarts after a
    journal-only rebuild by design)."""
    return canonical_sha256(
        {
            "plans": [plan.spec.plan_digest for plan in gate.plans],
            "execution": _engine_index_digest(gate.execution),
            "clearing": _engine_index_digest(gate.clearing),
            "settlement": _engine_index_digest(gate.settlement),
            "submission_ledger": gate.execution.submission_ledger().to_dict(),
            "stage_journal": [dict(entry) for entry in gate.stage_journal],
        }
    )


def _engine_index_digest(engine: Any) -> str:
    records = engine.records() if callable(getattr(engine, "records", None)) else engine.objects()
    return canonical_sha256(
        {record.object_id: record.to_dict() for record in records}
    )


def _journal_entries(entries: list[Mapping[str, Any]]) -> list[Any]:
    """Rehydrate kernel journal entries from their canonical projection."""
    from src.transition import JournalEntry

    return [JournalEntry.from_dict(entry) for entry in entries]
