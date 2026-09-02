"""Deterministic journal-driven replay of the IG-001 composed state.

The kernel journal is the append-only record of every accepted command,
and every journal payload carries the full ledger ``effects`` (operation
inputs and outputs) of its step. ``replay_from_journal`` therefore
rebuilds the WHOLE composed state from a snapshot's journal alone:

1. a fresh gate is created and the deterministic environment is
   re-provisioned (same provisioning parameters, byte-identical result);
2. the kernel is rebuilt: the object store is re-derived from the
   idempotency records' resulting envelopes (latest version per object),
   and the engine state (clock, records, journal) is restored through the
   kernel's own canonical round trip;
3. the ledger is rebuilt: every journal effect is re-applied through the
   REAL domain APIs in journal order, and every re-applied output is
   compared canonically with the recorded output — any divergence fails
   closed (transformation completeness: no semantic loss across the
   state ↔ journal ↔ snapshot representation boundaries).

``assert_replay_equivalence`` then proves the rebuild: identical ledger,
kernel, journal and composed digests, identical kernel store, and the
full invariant battery re-verified on the rebuilt gate.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256
from src.transition import EngineState, MemoryStateStore
from src.transition.payload import payload_to_json_value

from .contracts import INTEGRATION_SCHEMA_VERSION, validate_gate_id
from .harness import IntegrationGate
from .invariants import verify_invariants

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "gate_id",
        "environment_id",
        "domain_id",
        "authorized_actors",
        "provisioning",
        "engine",
        "store",
        "ledger",
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
    if snapshot["schema_version"] != INTEGRATION_SCHEMA_VERSION:
        raise CoreValidationError(
            f"gate snapshot schema_version must be {INTEGRATION_SCHEMA_VERSION}, got "
            f"{snapshot['schema_version']!r}"
        )
    validate_gate_id(snapshot["gate_id"])
    return dict(snapshot)


def _latest_envelopes_from_records(engine_state: EngineState) -> dict[str, ObjectEnvelope]:
    latest: dict[str, ObjectEnvelope] = {}
    for record in engine_state.records:
        for envelope in record.result.resulting_envelopes:
            latest[envelope.object_id] = envelope
    return latest


def replay_from_journal(snapshot: Mapping[str, Any]) -> IntegrationGate:
    """Rebuild a gate from its snapshot's kernel journal (fail closed)."""
    snapshot = _require_snapshot(snapshot)
    engine_state = EngineState.from_dict(snapshot["engine"])

    # 1. fresh gate + deterministic re-provisioning.
    gate = IntegrationGate(
        environment_id=snapshot["environment_id"],
        domain_id=snapshot["domain_id"],
        gate_id=snapshot["gate_id"],
        authorized_actors=tuple(snapshot["authorized_actors"]),
    )
    gate.provision(
        initial_deposit_minor=snapshot["provisioning"]["initial_deposit_minor"],
        stamp=snapshot["provisioning"]["stamp"],
    )

    # 2. kernel rebuild: the store is re-derived from the journal records
    #    (latest envelope version per object) and must match the snapshot's
    #    recorded store exactly — otherwise the journal lost semantics.
    latest = _latest_envelopes_from_records(engine_state)
    rebuilt_store = MemoryStateStore(
        objects=tuple(latest[object_id] for object_id in sorted(latest))
    )
    recorded_store = [ObjectEnvelope.from_dict(item) for item in snapshot["store"]]
    if [envelope.to_dict() for envelope in rebuilt_store.snapshot()] != [
        envelope.to_dict() for envelope in recorded_store
    ]:
        raise CoreValidationError(
            "replay divergence: the kernel store rebuilt from journal records does "
            "not match the recorded store snapshot"
        )
    gate._rebind_kernel(rebuilt_store, engine_state)

    # 3. ledger rebuild: re-apply every journal effect through the REAL
    #    domain APIs and compare every output canonically.
    for entry in engine_state.journal:
        payload = payload_to_json_value(entry.payload)
        if not isinstance(payload, Mapping):
            raise CoreValidationError(
                f"journal entry {entry.event.event_id} payload is not an object"
            )
        effects = payload.get("effects", ())
        if not isinstance(effects, list):
            raise CoreValidationError(
                f"journal entry {entry.event.event_id} effects must be a list"
            )
        for effect in effects:
            if not isinstance(effect, Mapping):
                raise CoreValidationError(
                    f"journal entry {entry.event.event_id} carries a malformed effect"
                )
            kind = effect["kind"]
            inputs = effect["inputs"]
            outputs = effect["outputs"]
            actual = gate._apply_effect(kind, inputs)
            if canonical_json(actual) != canonical_json(outputs):
                raise CoreValidationError(
                    f"replay divergence at {entry.event.event_id}: re-applying the "
                    f"recorded {kind} effect produced a different canonical result "
                    "than the journal recorded"
                )
    return gate


def assert_replay_equivalence(
    original: IntegrationGate, rebuilt: IntegrationGate
) -> None:
    """Prove the rebuild: identical digests and re-verified invariants."""
    if rebuilt.ledger_digest() != original.ledger_digest():
        raise CoreValidationError(
            "replayed ledger digest diverges from the original composed state"
        )
    if rebuilt.kernel_digest() != original.kernel_digest():
        raise CoreValidationError(
            "replayed kernel digest diverges from the original composed state"
        )
    if rebuilt.journal_digest() != original.journal_digest():
        raise CoreValidationError(
            "replayed journal digest diverges from the original journal"
        )
    if rebuilt.composed_digest() != original.composed_digest():
        raise CoreValidationError(
            "replayed composed digest diverges from the original composed state"
        )
    if [
        envelope.to_dict() for envelope in rebuilt.store.snapshot()
    ] != [envelope.to_dict() for envelope in original.store.snapshot()]:
        raise CoreValidationError(
            "replayed kernel object store diverges from the original store"
        )
    verify_invariants(rebuilt)
