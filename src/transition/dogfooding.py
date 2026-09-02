"""DOGFOOD-003: command trace replay and duplicate command convergence.

Run in a clean process:

    python3 -m src.transition.dogfooding

The experiment drives the public kernel path (``TransitionEngine.process``)
with a representative intent lifecycle, replays the identical trace in
independent clean engines, restores persisted engine state into a fresh
kernel, and proves duplicate commands converge without new events or state
changes. Output is fully deterministic (no wall-clock time, no randomness).
"""

from __future__ import annotations

from src.core import ObjectEnvelope, Provenance, canonical_sha256

from .command import Command, ExpectedVersion
from .engine import (
    AuthorizationDecision,
    EngineState,
    TransitionApplication,
    TransitionEngine,
)
from .payload import payload_to_json_value
from .registry import PROTOCOL_VERSION
from .store import MemoryStateStore

ENVIRONMENT = "env/dogfood-003"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"

CREATE_TYPE = "transition/intent.create"
AUTHORIZE_TYPE = "transition/intent.authorize"


def _allow(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(granted=True, authority="A1", reason=None)


def _create_handler(command: Command, view) -> TransitionApplication:
    target = command.target_refs[0]
    envelope = ObjectEnvelope(
        object_id=target,
        object_type="payswap/intent/v1",
        object_version=1,
        environment_id=command.environment_id,
        domain_id=command.domain_id,
        schema_version=1,
        protocol_version="v0.1",
        state="CREATED",
        provenance=Provenance(
            issuer=command.actor,
            source="transition",
            recorded_at=command.requested_at,
        ),
        causation_id=command.command_id,
        correlation_id=command.correlation_id,
    ).with_integrity_hash()
    return TransitionApplication(
        resulting_envelopes=(envelope,),
        payload={"object_id": target, "created": True},
    )


def _authorize_handler(command: Command, view) -> TransitionApplication:
    resulting = tuple(
        view.get(object_ref).next_version(state="DISCOVERING").with_integrity_hash()
        for object_ref in command.target_refs
    )
    return TransitionApplication(resulting_envelopes=resulting, payload={"authorized": True})


def _engine(store: MemoryStateStore) -> TransitionEngine:
    engine = TransitionEngine(environment_id=ENVIRONMENT, authorization=_allow, store=store)
    engine.register(CREATE_TYPE, "intent/created", _create_handler)
    engine.register(AUTHORIZE_TYPE, "intent/authorized", _authorize_handler)
    return engine


def _create_command() -> Command:
    return Command.build(
        command_id="cmd/create/1",
        command_type=CREATE_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=("intent/1",),
        payload={"origin": "dogfood"},
        environment_id=ENVIRONMENT,
        domain_id=DOMAIN,
        expected_versions=(ExpectedVersion(object_ref="intent/1", object_version=0),),
        idempotency_key="key/create/1",
        nonce="1",
        requested_at=STAMP,
        correlation_id="corr/dogfood",
    )


def _authorize_command() -> Command:
    return Command.build(
        command_id="cmd/auth/1",
        command_type=AUTHORIZE_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=("intent/1",),
        payload={"authorized": True},
        environment_id=ENVIRONMENT,
        domain_id=DOMAIN,
        expected_versions=(ExpectedVersion(object_ref="intent/1", object_version=1),),
        idempotency_key="key/auth/1",
        nonce="1",
        requested_at=STAMP,
        correlation_id="corr/dogfood",
    )


def _trace_digest() -> tuple[str, list[str], list[str], int]:
    store = MemoryStateStore()
    engine = _engine(store)
    create = _create_command()
    authorize = _authorize_command()
    outcomes = [
        engine.process(create).outcome.value,
        engine.process(authorize).outcome.value,
    ]
    duplicate_outcomes = [
        engine.process(create).outcome.value,
        engine.process(authorize).outcome.value,
    ]
    journal_length = len(engine.journal)
    digest = canonical_sha256(
        {
            "outcomes": outcomes,
            "duplicate_outcomes": duplicate_outcomes,
            "events": [entry.event.to_json() for entry in engine.journal],
            "payloads": [payload_to_json_value(entry.payload) for entry in engine.journal],
            "state": [obj.to_dict() for obj in store.snapshot()],
        }
    )
    return digest, outcomes, duplicate_outcomes, journal_length


def _restored_replay() -> tuple[list[str], int]:
    store = MemoryStateStore()
    engine = _engine(store)
    create = _create_command()
    authorize = _authorize_command()
    engine.process(create)
    engine.process(authorize)
    state = EngineState.from_dict(engine.snapshot_state().to_dict())
    restarted = _engine(MemoryStateStore(objects=store.snapshot()))
    restarted.restore_state(state)
    outcomes = [
        restarted.process(create).outcome.value,
        restarted.process(authorize).outcome.value,
    ]
    return outcomes, len(restarted.journal)


def run_experiment() -> str:
    """Execute the DOGFOOD-003 experiment and return its evidence record."""
    lines = [
        "DOGFOOD-003: command trace replay and duplicate command convergence",
        "work order: WORK-003",
        f"architecture: {PROTOCOL_VERSION} (frozen protocol registry namespaces and authority classes)",
        "surface: src.transition public kernel API (TransitionEngine.process) in a clean process",
        f"environment: {ENVIRONMENT} (isolated in-memory store; no production state is reachable)",
        "task: replay an identical command trace in clean engines and prove duplicate command convergence",
        "starting state: empty isolated store; registered create/authorize transition handlers",
        "commands: 2 (create intent with expected absence; authorize with expected version 1)",
        "expected outcome: byte-identical events and state across clean runs; duplicate replays emit no new event and never re-apply state",
    ]
    try:
        first = _trace_digest()
        second = _trace_digest()
        restored_outcomes, restored_journal_length = _restored_replay()
        if first[0] != second[0]:
            raise AssertionError("clean-process trace digests differ")
        if first[1] != ["accepted", "accepted"]:
            raise AssertionError("initial trace was not fully accepted")
        if first[2] != ["duplicate", "duplicate"]:
            raise AssertionError("duplicate commands did not converge")
        if first[3] != 2:
            raise AssertionError("duplicate replays emitted new events")
        if restored_outcomes != ["duplicate", "duplicate"]:
            raise AssertionError("restored engine re-executed replayed commands")
        if restored_journal_length != 2:
            raise AssertionError("restored engine journal changed during replay")
        lines.extend(
            [
                f"trace digest (clean run 1): {first[0]}",
                f"trace digest (clean run 2): {second[0]}",
                f"initial outcomes: {', '.join(first[1])}",
                f"duplicate replay outcomes: {', '.join(first[2])}",
                f"journal length after duplicate replay: {first[3]} (unchanged)",
                f"restored-engine replay outcomes: {', '.join(restored_outcomes)}; journal {restored_journal_length} (unchanged)",
                "observed outcome: clean-process digests identical; duplicate convergence confirmed without new events or state changes",
                "classification: PASS",
            ]
        )
    except Exception as exc:  # dogfooding classification, not a kernel error path
        lines.extend(
            [
                f"observed outcome: experiment failed ({type(exc).__name__}: {exc})",
                "classification: CONTRACT_FAILURE",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    print(run_experiment(), end="")


if __name__ == "__main__":
    main()
