from __future__ import annotations

import unittest

from src.core import (
    CoreValidationError,
    ObjectEnvelope,
    Provenance,
    canonical_sha256,
)

from . import (
    AUTHORITY_CLASSES,
    DEFAULT_REJECTION_EVENT_TYPE,
    EVENT_NAMESPACES,
    PROTOCOL_VERSION,
    AuthorizationDecision,
    Command,
    EngineState,
    Event,
    ExpectedVersion,
    JournalEntry,
    MemoryStateStore,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    normalize_payload,
    payload_to_json_value,
)
from .dogfooding import run_experiment

STAMP = "2026-09-02T00:00:00Z"

CREATE_TYPE = "transition/intent.create"
AUTHORIZE_TYPE = "transition/intent.authorize"


def intent_envelope(
    object_id: str = "intent/1",
    state: str = "AUTHORIZED",
    version: int = 1,
    environment_id: str = "env/test",
    domain_id: str = "domain/demo",
) -> ObjectEnvelope:
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type="payswap/intent/v1",
        object_version=1,
        environment_id=environment_id,
        domain_id=domain_id,
        schema_version=1,
        protocol_version="v0.1",
        state=state,
        provenance=Provenance(
            issuer="principal/test",
            source="transition",
            recorded_at=STAMP,
        ),
        correlation_id="corr/1",
    ).with_integrity_hash()
    for _ in range(version - 1):
        envelope = envelope.next_version(state=state).with_integrity_hash()
    return envelope


def command(
    command_id: str,
    *,
    command_type: str = AUTHORIZE_TYPE,
    target_refs: tuple[str, ...] = ("intent/1",),
    expected: tuple[tuple[str, int], ...] = (("intent/1", 1),),
    payload: object = None,
    idempotency_key: str | None = None,
    nonce: str = "1",
    environment_id: str = "env/test",
    domain_id: str = "domain/demo",
    actor: str = "principal/test",
    requested_at: str = STAMP,
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=command_type,
        actor=actor,
        authority_refs=("authority/test",),
        target_refs=target_refs,
        payload=payload if payload is not None else {"note": "demo"},
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=tuple(
            ExpectedVersion(object_ref=ref, object_version=version)
            for ref, version in expected
        ),
        idempotency_key=idempotency_key or f"key/{command_id}",
        nonce=nonce,
        requested_at=requested_at,
        correlation_id="corr/1",
    )


def create_command(command_id: str = "cmd/create/1", object_id: str = "intent/1", **kwargs) -> Command:
    options: dict[str, object] = dict(
        command_type=CREATE_TYPE,
        target_refs=(object_id,),
        expected=((object_id, 0),),
        payload={"origin": "dogfood"},
    )
    options.update(kwargs)
    return command(command_id, **options)


def authorize_command(command_id: str = "cmd/auth/1", object_id: str = "intent/1", **kwargs) -> Command:
    options: dict[str, object] = dict(
        command_type=AUTHORIZE_TYPE,
        target_refs=(object_id,),
        expected=((object_id, 1),),
        payload={"authorized": True},
    )
    options.update(kwargs)
    return command(command_id, **options)


def create_handler(command: Command, view) -> TransitionApplication:
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


def authorize_handler(command: Command, view) -> TransitionApplication:
    resulting = tuple(
        view.get(object_ref).next_version(state="DISCOVERING").with_integrity_hash()
        for object_ref in command.target_refs
    )
    return TransitionApplication(
        resulting_envelopes=resulting,
        payload={"authorized": True, "targets": list(command.target_refs)},
    )


def allow_authorization(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(granted=True, authority="A1", reason=None)


def deny_authorization(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(granted=False, authority=None, reason="denied by test policy")


def build_engine(
    store: MemoryStateStore | None = None,
    *,
    authorization=allow_authorization,
    policy=None,
    invariants=(),
    emit_rejection_events: bool = False,
    rejection_authority: str | None = None,
    environment_id: str = "env/test",
) -> TransitionEngine:
    engine = TransitionEngine(
        environment_id=environment_id,
        authorization=authorization,
        policy=policy,
        invariants=invariants,
        store=store if store is not None else MemoryStateStore(),
        emit_rejection_events=emit_rejection_events,
        rejection_authority=rejection_authority,
    )
    engine.register(CREATE_TYPE, "intent/created", create_handler)
    engine.register(AUTHORIZE_TYPE, "intent/authorized", authorize_handler)
    return engine


def make_event(**overrides) -> Event:
    fields = dict(
        event_id="event/cmd/create/1",
        event_type="intent/created",
        object_refs=("intent/1",),
        environment_id="env/test",
        domain_id="domain/demo",
        actor="principal/test",
        authority="A1",
        previous_state=(None,),
        resulting_state=("CREATED",),
        object_versions=(1,),
        occurred_at=STAMP,
        logical_time=1,
        causation_id="cmd/create/1",
        correlation_id=None,
        payload_hash="0" * 64,
        protocol_version="v0.1",
    )
    fields.update(overrides)
    return Event(**fields)


class CommandContractTests(unittest.TestCase):
    """W003-1: the command envelope is typed, canonical and fail-closed."""

    def test_command_round_trip_is_lossless(self) -> None:
        value = command("cmd/1")
        self.assertEqual(Command.from_dict(value.to_dict()), value)
        self.assertEqual(Command.from_json(value.to_json()), value)
        self.assertEqual(Command.from_json(value.to_json()).to_json(), value.to_json())

    def test_unknown_and_missing_command_fields_fail_closed(self) -> None:
        value = command("cmd/1").to_dict()
        value["unknown"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            Command.from_dict(value)
        missing = command("cmd/1").to_dict()
        del missing["nonce"]
        with self.assertRaises(CoreValidationError):
            Command.from_dict(missing)

    def test_duplicate_command_json_keys_are_rejected(self) -> None:
        encoded = command("cmd/1").to_json()
        duplicated = encoded.replace('"actor":"principal/test"', '"actor":"principal/test","actor":"principal/attacker"')
        with self.assertRaises(CoreValidationError):
            Command.from_json(duplicated)

    def test_payload_must_use_the_canonical_value_domain(self) -> None:
        for bad in ({"ratio": 0.5}, {"amount": float("nan")}, {"value": object()}, {"value": {1: "v"}}):
            with self.assertRaises(CoreValidationError):
                Command.build(
                    command_id="cmd/1",
                    command_type=CREATE_TYPE,
                    actor="principal/test",
                    authority_refs=("authority/test",),
                    target_refs=("intent/1",),
                    payload=bad,
                    environment_id="env/test",
                    domain_id="domain/demo",
                    expected_versions=(ExpectedVersion("intent/1", 0),),
                    idempotency_key="key/cmd/1",
                    nonce="1",
                    requested_at=STAMP,
                )

    def test_payload_is_deeply_immutable_after_construction(self) -> None:
        source = {"amount": 100, "nested": {"x": 1}, "tags": ["a"]}
        value = command("cmd/1", payload=source)
        source["nested"]["x"] = 999
        source["tags"].append("mutated")
        self.assertEqual(
            payload_to_json_value(value.payload),
            {"amount": 100, "nested": {"x": 1}, "tags": ["a"]},
        )
        self.assertEqual(
            payload_to_json_value(normalize_payload("payload", {"b": 2, "a": [1, {"z": None}]})),
            {"a": [1, {"z": None}], "b": 2},
        )

    def test_direct_construction_rejects_mutable_payloads(self) -> None:
        with self.assertRaises(CoreValidationError):
            Command(
                command_id="cmd/1",
                command_type=CREATE_TYPE,
                actor="principal/test",
                authority_refs=("authority/test",),
                target_refs=("intent/1",),
                payload={"note": "mutable"},
                environment_id="env/test",
                domain_id="domain/demo",
                expected_versions=(ExpectedVersion("intent/1", 0),),
                idempotency_key="key/cmd/1",
                nonce="1",
                requested_at=STAMP,
            )

    def test_reference_lists_are_validated(self) -> None:
        with self.assertRaises(CoreValidationError):
            command("cmd/1", target_refs=("intent/1", "intent/1"))
        with self.assertRaises(CoreValidationError):
            command("cmd/1", target_refs=())
        with self.assertRaises(CoreValidationError):
            command("cmd/1", target_refs=("intent/1", " "))
        with self.assertRaises(CoreValidationError):
            Command.build(
                command_id="cmd/1",
                command_type=CREATE_TYPE,
                actor="principal/test",
                authority_refs=("authority/a", "authority/a"),
                target_refs=("intent/1",),
                payload=None,
                environment_id="env/test",
                domain_id="domain/demo",
                expected_versions=(ExpectedVersion("intent/1", 0),),
                idempotency_key="key/cmd/1",
                nonce="1",
                requested_at=STAMP,
            )

    def test_expected_versions_are_validated(self) -> None:
        for bad in (
            (ExpectedVersion("intent/1", 1), ExpectedVersion("intent/1", 2)),
            (("intent/1", 1),),
        ):
            with self.assertRaises(CoreValidationError):
                Command.build(
                    command_id="cmd/1",
                    command_type=CREATE_TYPE,
                    actor="principal/test",
                    authority_refs=("authority/test",),
                    target_refs=("intent/1",),
                    payload=None,
                    environment_id="env/test",
                    domain_id="domain/demo",
                    expected_versions=bad,
                    idempotency_key="key/cmd/1",
                    nonce="1",
                    requested_at=STAMP,
                )
        for bad_version in (-1, True, "1", 1.5):
            with self.assertRaises(CoreValidationError):
                ExpectedVersion("intent/1", bad_version)
        with self.assertRaises(CoreValidationError):
            ExpectedVersion(" ", 1)

    def test_requested_at_must_be_iso8601(self) -> None:
        with self.assertRaises(CoreValidationError):
            command("cmd/1", requested_at="not-a-timestamp")

    def test_command_digest_is_deterministic_and_content_sensitive(self) -> None:
        first = command("cmd/1")
        second = command("cmd/1")
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.to_json(), second.to_json())
        different = command("cmd/1", nonce="2")
        self.assertNotEqual(first.digest, different.digest)
        self.assertEqual(len(first.digest), 64)
        self.assertEqual(first.digest, canonical_sha256(first.to_dict()))


class EventContractTests(unittest.TestCase):
    """W003-2: event envelopes are immutable, canonical and registry-bound."""

    def test_event_round_trip_is_lossless(self) -> None:
        value = make_event()
        self.assertEqual(Event.from_dict(value.to_dict()), value)
        self.assertEqual(Event.from_json(value.to_json()), value)
        self.assertEqual(Event.from_json(value.to_json()).to_json(), value.to_json())

    def test_event_type_must_use_a_frozen_registry_namespace(self) -> None:
        for bad in ("billing/created", "intent", "intent/", "/created", "", 123, None):
            with self.assertRaises(CoreValidationError):
                make_event(event_type=bad)
        for namespace in EVENT_NAMESPACES:
            event_type = f"{namespace}/transitioned"
            self.assertEqual(make_event(event_type=event_type).event_type, event_type)

    def test_event_authority_must_use_a_frozen_registry_class(self) -> None:
        for bad in ("A9", "X1", "", None, "a0"):
            with self.assertRaises(CoreValidationError):
                make_event(authority=bad)
        self.assertIn(make_event(authority="A0").authority, AUTHORITY_CLASSES)
        self.assertIn(make_event(authority="R5").authority, AUTHORITY_CLASSES)

    def test_event_parallel_arrays_must_align(self) -> None:
        base = dict(object_refs=("intent/1", "intent/2"))
        for bad in (
            dict(previous_state=(None,)),
            dict(resulting_state=("CREATED",)),
            dict(object_versions=(1,)),
        ):
            with self.assertRaises(CoreValidationError):
                make_event(**base, **bad)

    def test_event_object_refs_must_be_unique_and_non_empty(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_event(object_refs=())
        with self.assertRaises(CoreValidationError):
            make_event(object_refs=("intent/1", "intent/1"))

    def test_version_zero_entries_require_absent_objects(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_event(
                previous_state=(None,),
                resulting_state=("CREATED",),
                object_versions=(0,),
            )
        with self.assertRaises(CoreValidationError):
            make_event(
                previous_state=("AUTHORIZED",),
                resulting_state=(None,),
                object_versions=(0,),
            )
        self.assertEqual(
            make_event(previous_state=(None,), resulting_state=(None,), object_versions=(0,)).object_versions,
            (0,),
        )

    def test_logical_time_and_timestamp_are_validated(self) -> None:
        for bad in (0, -1, True, "1"):
            with self.assertRaises(CoreValidationError):
                make_event(logical_time=bad)
        with self.assertRaises(CoreValidationError):
            make_event(occurred_at="yesterday")

    def test_event_is_immutable_and_caused(self) -> None:
        value = make_event()
        with self.assertRaises(AttributeError):
            value.actor = "principal/attacker"
        with self.assertRaises(CoreValidationError):
            make_event(causation_id=None)
        with self.assertRaises(CoreValidationError):
            make_event(event_id=" ")

    def test_unknown_event_fields_fail_closed(self) -> None:
        value = make_event().to_dict()
        value["unknown"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            Event.from_dict(value)


class KernelAcceptanceTests(unittest.TestCase):
    """W003-3: the transition pipeline is deterministic and explicit about failure."""

    def test_accepted_command_emits_canonical_event(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        cmd = authorize_command("cmd/auth/1")
        result = engine.process(cmd)

        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertIsNone(result.reason)
        event = result.event
        assert event is not None
        self.assertEqual(event.event_id, "event/cmd/auth/1")
        self.assertEqual(event.event_type, "intent/authorized")
        self.assertEqual(event.causation_id, "cmd/auth/1")
        self.assertEqual(event.correlation_id, "corr/1")
        self.assertEqual(event.object_refs, ("intent/1",))
        self.assertEqual(event.previous_state, ("AUTHORIZED",))
        self.assertEqual(event.resulting_state, ("DISCOVERING",))
        self.assertEqual(event.object_versions, (2,))
        self.assertEqual(event.occurred_at, cmd.requested_at)
        self.assertEqual(event.actor, "principal/test")
        self.assertEqual(event.authority, "A1")
        self.assertEqual(event.protocol_version, PROTOCOL_VERSION)
        self.assertEqual(event.logical_time, 1)
        self.assertEqual(event.payload_hash, canonical_sha256(payload_to_json_value(result.payload)))

        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.object_version, 2)
        self.assertEqual(stored.previous_version, 1)
        self.assertEqual(stored.state, "DISCOVERING")
        self.assertEqual(result.resulting_envelopes, (stored,))
        self.assertEqual(engine.journal[0].event, event)

    def test_creation_with_expected_absence_is_accepted(self) -> None:
        store = MemoryStateStore()
        engine = build_engine(store=store)
        result = engine.process(create_command())
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        assert result.event is not None
        self.assertEqual(result.event.previous_state, (None,))
        self.assertEqual(result.event.resulting_state, ("CREATED",))
        self.assertEqual(result.event.object_versions, (1,))
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.object_version, 1)

    def test_logical_time_is_monotonic_and_journal_is_append_only(self) -> None:
        store = MemoryStateStore()
        engine = build_engine(store=store)
        engine.process(create_command())
        engine.process(authorize_command())
        engine.process(create_command())
        journal = engine.journal
        self.assertEqual(len(journal), 2)
        self.assertEqual([entry.event.logical_time for entry in journal], [1, 2])
        self.assertEqual(
            [entry.event.event_id for entry in journal],
            ["event/cmd/create/1", "event/cmd/auth/1"],
        )

    def test_duplicate_command_converges_to_the_original_event(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        cmd = authorize_command("cmd/auth/1")
        first = engine.process(cmd)
        second = engine.process(cmd)

        self.assertEqual(first.outcome, Outcome.ACCEPTED)
        self.assertEqual(second.outcome, Outcome.DUPLICATE)
        self.assertIsNone(second.reason)
        assert first.event is not None and second.event is not None
        self.assertEqual(second.event.event_id, first.event.event_id)
        self.assertEqual(second.event, first.event)
        self.assertEqual(second.payload, first.payload)
        self.assertEqual(second.resulting_envelopes, first.resulting_envelopes)
        self.assertEqual(len(engine.journal), 1)
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.object_version, 2)

    def test_idempotency_key_conflict_fails_closed(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, emit_rejection_events=True, rejection_authority="A0")
        first = engine.process(authorize_command("cmd/auth/1"))
        conflicting = command("cmd/auth/2", idempotency_key="key/cmd/auth/1")
        rejected = engine.process(conflicting)
        replayed = engine.process(conflicting)

        self.assertEqual(first.outcome, Outcome.ACCEPTED)
        self.assertEqual(rejected.outcome, Outcome.REJECTED)
        self.assertEqual(rejected.reason, RejectionReason.IDEMPOTENCY_CONFLICT)
        self.assertIsNone(rejected.event)
        self.assertEqual(rejected.resulting_envelopes, ())
        self.assertEqual(len(engine.journal), 1)
        self.assertEqual(replayed.outcome, Outcome.REJECTED)
        self.assertEqual(replayed.reason, RejectionReason.IDEMPOTENCY_CONFLICT)
        self.assertEqual(len(engine.journal), 1)

    def test_command_id_reuse_fails_closed_without_history_rewrite(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, emit_rejection_events=True, rejection_authority="A0")
        engine.process(authorize_command("cmd/auth/1"))
        reused = command("cmd/auth/1", nonce="999", payload={"note": "different"})
        rejected = engine.process(reused)

        self.assertEqual(rejected.outcome, Outcome.REJECTED)
        self.assertEqual(rejected.reason, RejectionReason.COMMAND_ID_REUSED)
        self.assertIsNone(rejected.event)
        self.assertEqual(len(engine.journal), 1)
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.object_version, 2)

    def test_version_conflict_rejects_without_state_change(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        result = engine.process(authorize_command("cmd/auth/1", expected=(("intent/1", 5),)))

        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.VERSION_CONFLICT)
        self.assertIsNone(result.event)
        self.assertEqual(result.resulting_envelopes, ())
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.object_version, 1)
        self.assertEqual(stored.state, "AUTHORIZED")
        self.assertEqual(engine.journal, ())

    def test_missing_object_precondition_fails_closed(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        result = engine.process(
            command("cmd/auth/1", target_refs=("intent/missing",), expected=(("intent/missing", 3),))
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.OBJECT_NOT_FOUND)

    def test_creation_precondition_detects_existing_object(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        result = engine.process(create_command())
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.VERSION_CONFLICT)

    def test_unknown_command_type_fails_closed(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store)
        result = engine.process(command("cmd/auth/1", command_type="transition/unknown"))
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNKNOWN_COMMAND_TYPE)

    def test_default_authorization_policy_denies_all(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, authorization=None)
        result = engine.process(authorize_command())
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)
        self.assertIsNotNone(result.detail)

    def test_authorization_denial_is_recorded_with_reason(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, authorization=deny_authorization)
        result = engine.process(authorize_command())
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)
        self.assertEqual(result.detail, "denied by test policy")

    def test_environment_isolation_is_enforced(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, environment_id="env/test")
        production = engine.process(authorize_command(environment_id="env/production"))
        self.assertEqual(production.outcome, Outcome.REJECTED)
        self.assertEqual(production.reason, RejectionReason.ENVIRONMENT_MISMATCH)

        foreign_store = MemoryStateStore(objects=[intent_envelope(environment_id="env/other")])
        foreign_engine = build_engine(store=foreign_store)
        foreign = foreign_engine.process(authorize_command())
        self.assertEqual(foreign.outcome, Outcome.REJECTED)
        self.assertEqual(foreign.reason, RejectionReason.ENVIRONMENT_MISMATCH)

    def test_domain_mismatch_is_rejected(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope(domain_id="domain/other")])
        engine = build_engine(store=store)
        result = engine.process(authorize_command())
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.DOMAIN_MISMATCH)

    def test_policy_hook_can_reject_before_transition(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(store=store, policy=lambda command, view: "not allowed here")
        result = engine.process(authorize_command())
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.POLICY_REJECTED)
        self.assertEqual(result.detail, "not allowed here")
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.state, "AUTHORIZED")

    def test_invariant_violation_commits_nothing(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(
            store=store,
            invariants=(lambda command, resulting, view: "state must not become DISCOVERING",),
        )
        result = engine.process(authorize_command())
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.INVARIANT_VIOLATION)
        self.assertEqual(result.detail, "state must not become DISCOVERING")
        self.assertEqual(result.resulting_envelopes, ())
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.state, "AUTHORIZED")
        self.assertEqual(stored.object_version, 1)
        self.assertEqual(engine.journal, ())

    def test_rejection_events_are_emitted_only_when_policy_requires(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        silent = build_engine(store=store, authorization=deny_authorization)
        silent_result = silent.process(authorize_command())
        self.assertIsNone(silent_result.event)

        audited = build_engine(
            store=store,
            authorization=deny_authorization,
            emit_rejection_events=True,
            rejection_authority="A0",
        )
        result = audited.process(authorize_command("cmd/auth/9"))
        event = result.event
        assert event is not None
        self.assertEqual(event.event_id, "event/cmd/auth/9/rejection")
        self.assertEqual(event.event_type, DEFAULT_REJECTION_EVENT_TYPE)
        self.assertEqual(event.authority, "A0")
        self.assertEqual(event.object_refs, ("intent/1",))
        self.assertEqual(event.previous_state, ("AUTHORIZED",))
        self.assertEqual(event.resulting_state, ("AUTHORIZED",))
        self.assertEqual(event.object_versions, (1,))
        self.assertEqual(event.logical_time, 1)
        self.assertEqual(
            event.payload_hash,
            canonical_sha256(payload_to_json_value(result.payload)),
        )
        self.assertEqual(
            payload_to_json_value(result.payload),
            {"reason": "unauthorized", "detail": "denied by test policy"},
        )

    def test_rejection_event_for_absent_target_uses_version_zero(self) -> None:
        engine = build_engine(
            authorization=deny_authorization,
            emit_rejection_events=True,
            rejection_authority="A0",
        )
        result = engine.process(create_command())
        event = result.event
        assert event is not None
        self.assertEqual(event.previous_state, (None,))
        self.assertEqual(event.resulting_state, (None,))
        self.assertEqual(event.object_versions, (0,))

    def test_duplicate_rejected_command_echoes_original_rejection(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        engine = build_engine(
            store=store,
            authorization=deny_authorization,
            emit_rejection_events=True,
            rejection_authority="A0",
        )
        first = engine.process(authorize_command("cmd/auth/1"))
        second = engine.process(authorize_command("cmd/auth/1"))
        self.assertEqual(first.outcome, Outcome.REJECTED)
        self.assertEqual(second.outcome, Outcome.DUPLICATE)
        assert first.event is not None and second.event is not None
        self.assertEqual(second.event, first.event)
        self.assertEqual(len(engine.journal), 1)

    def test_process_rejects_non_command_input(self) -> None:
        engine = build_engine()
        with self.assertRaises(CoreValidationError):
            engine.process("not-a-command")


class HandlerContractTests(unittest.TestCase):
    """W003-4: handlers cannot bypass kernel guarantees."""

    def test_handler_must_touch_only_declared_targets(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])

        def rogue_handler(command: Command, view) -> TransitionApplication:
            undeclared = ObjectEnvelope(
                object_id="intent/2",
                object_type="payswap/intent/v1",
                object_version=1,
                environment_id=command.environment_id,
                domain_id=command.domain_id,
                schema_version=1,
                protocol_version="v0.1",
                state="HACKED",
                provenance=Provenance(issuer=command.actor, source="transition", recorded_at=command.requested_at),
            ).with_integrity_hash()
            return TransitionApplication(resulting_envelopes=(undeclared,), payload=None)

        engine = build_engine(store=store)
        engine.register("transition/intent.rogue", "intent/rogue", rogue_handler)
        with self.assertRaises(CoreValidationError):
            engine.process(command("cmd/rogue/1", command_type="transition/intent.rogue"))
        stored = store.get("intent/1")
        assert stored is not None
        self.assertEqual(stored.state, "AUTHORIZED")
        self.assertEqual(engine.journal, ())

    def test_handler_resulting_envelopes_must_be_sealed(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])

        def unsealed_handler(command: Command, view) -> TransitionApplication:
            current = view.get("intent/1")
            assert current is not None
            return TransitionApplication(
                resulting_envelopes=(current.next_version(state="DISCOVERING"),),
                payload=None,
            )

        engine = build_engine(store=store)
        engine.register("transition/intent.unsealed", "intent/unsealed", unsealed_handler)
        with self.assertRaises(CoreValidationError):
            engine.process(command("cmd/unsealed/1", command_type="transition/intent.unsealed"))

    def test_handler_resulting_envelopes_must_match_command_environment(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])

        def foreign_handler(command: Command, view) -> TransitionApplication:
            forged = ObjectEnvelope(
                object_id="intent/1",
                object_type="payswap/intent/v1",
                object_version=2,
                environment_id="env/other",
                domain_id="domain/demo",
                schema_version=1,
                protocol_version="v0.1",
                state="DISCOVERING",
                provenance=Provenance(
                    issuer="principal/test", source="transition", recorded_at=STAMP
                ),
                previous_version=1,
            ).with_integrity_hash()
            return TransitionApplication(resulting_envelopes=(forged,), payload=None)

        engine = build_engine(store=store)
        engine.register("transition/intent.foreign", "intent/foreign", foreign_handler)
        with self.assertRaises(CoreValidationError):
            engine.process(command("cmd/foreign/1", command_type="transition/intent.foreign"))

    def test_duplicate_registration_fails_closed(self) -> None:
        engine = build_engine()
        with self.assertRaises(CoreValidationError):
            engine.register(CREATE_TYPE, "intent/created-again", create_handler)

    def test_registration_requires_a_registry_event_type(self) -> None:
        engine = build_engine()
        with self.assertRaises(CoreValidationError):
            engine.register("transition/intent.billing", "billing/created", create_handler)
        with self.assertRaises(CoreValidationError):
            engine.register("transition/intent.billing", "intent", create_handler)

    def test_granted_authorization_must_state_a_registry_authority(self) -> None:
        def bad_hook(command: Command, view) -> AuthorizationDecision:
            return AuthorizationDecision(granted=True, authority="A9", reason=None)

        engine = build_engine(store=MemoryStateStore(objects=[intent_envelope()]), authorization=bad_hook)
        with self.assertRaises(CoreValidationError):
            engine.process(authorize_command())

    def test_rejection_events_require_a_configured_audit_authority(self) -> None:
        with self.assertRaises(CoreValidationError):
            TransitionEngine(environment_id="env/test", emit_rejection_events=True, rejection_authority=None)
        with self.assertRaises(CoreValidationError):
            TransitionEngine(environment_id="env/test", emit_rejection_events=True, rejection_authority="A9")


class StateStoreContractTests(unittest.TestCase):
    """W003-5: the store is the only writer of object state and enforces version chains."""

    def test_store_rejects_unsealed_objects(self) -> None:
        with self.assertRaises(CoreValidationError):
            MemoryStateStore(objects=[intent_envelope().next_version(state="DISCOVERING")])
        store = MemoryStateStore(objects=[intent_envelope()])
        with self.assertRaises(CoreValidationError):
            store.commit((intent_envelope().next_version(state="DISCOVERING"),))

    def test_store_rejects_version_jumps(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        jumped = intent_envelope(version=3)
        with self.assertRaises(CoreValidationError):
            store.commit((jumped,))

    def test_store_rejects_identity_changes(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        forged = ObjectEnvelope(
            object_id="intent/1",
            object_type="payswap/other/v1",
            object_version=2,
            environment_id="env/test",
            domain_id="domain/demo",
            schema_version=1,
            protocol_version="v0.1",
            state="DISCOVERING",
            provenance=Provenance(issuer="principal/test", source="transition", recorded_at=STAMP),
            previous_version=1,
        ).with_integrity_hash()
        with self.assertRaises(CoreValidationError):
            store.commit((forged,))

    def test_store_requires_version_one_for_new_objects(self) -> None:
        store = MemoryStateStore()
        with self.assertRaises(CoreValidationError):
            store.commit((intent_envelope(version=2),))

    def test_store_rejects_duplicate_ids_in_a_batch(self) -> None:
        store = MemoryStateStore(objects=[intent_envelope()])
        advanced = intent_envelope().next_version(state="DISCOVERING").with_integrity_hash()
        with self.assertRaises(CoreValidationError):
            store.commit((advanced, advanced))

    def test_store_snapshot_is_deterministic(self) -> None:
        first = MemoryStateStore(objects=[intent_envelope("intent/2"), intent_envelope("intent/1")])
        second = MemoryStateStore(objects=[intent_envelope("intent/1"), intent_envelope("intent/2")])
        self.assertEqual(
            [obj.object_id for obj in first.snapshot()],
            ["intent/1", "intent/2"],
        )
        self.assertEqual(first.snapshot(), second.snapshot())


class ReplayDeterminismTests(unittest.TestCase):
    """W003-6: identical command traces converge byte-for-byte in clean engines."""

    def trace_digest(self) -> str:
        store = MemoryStateStore()
        engine = build_engine(store=store)
        commands = (create_command(), authorize_command(), create_command())
        results = [engine.process(cmd) for cmd in commands]
        return canonical_sha256(
            {
                "outcomes": [result.outcome.value for result in results],
                "events": [
                    {"event": entry.event.to_json(), "payload": payload_to_json_value(entry.payload)}
                    for entry in engine.journal
                ],
                "state": [obj.to_dict() for obj in store.snapshot()],
            }
        )

    def test_replaying_identical_trace_in_clean_engines_is_byte_identical(self) -> None:
        self.assertEqual(self.trace_digest(), self.trace_digest())

    def test_engine_state_snapshot_round_trips_and_restores(self) -> None:
        store = MemoryStateStore()
        engine = build_engine(store=store)
        engine.process(create_command())
        engine.process(authorize_command())

        state = engine.snapshot_state()
        restored = EngineState.from_dict(state.to_dict())
        self.assertEqual(restored, state)

        restarted = build_engine(store=MemoryStateStore(objects=store.snapshot()))
        restarted.restore_state(restored)
        duplicate = restarted.process(create_command())
        self.assertEqual(duplicate.outcome, Outcome.DUPLICATE)
        assert duplicate.event is not None
        self.assertEqual(duplicate.event.event_id, "event/cmd/create/1")

        followup = restarted.process(authorize_command("cmd/auth/2", expected=(("intent/1", 2),)))
        self.assertEqual(followup.outcome, Outcome.ACCEPTED)
        assert followup.event is not None
        self.assertEqual(followup.event.logical_time, 3)
        self.assertEqual(len(restarted.journal), 3)

    def test_restored_state_rejects_history_rewrite(self) -> None:
        store = MemoryStateStore()
        engine = build_engine(store=store)
        engine.process(create_command())
        state = engine.snapshot_state().to_dict()
        rewritten = dict(state)
        rewritten["journal"] = [state["journal"][0], state["journal"][0]]
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict(rewritten)
        duplicate_record = dict(state)
        duplicate_record["records"] = [state["records"][0], state["records"][0]]
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict(duplicate_record)
        tampered_record = dict(state)
        tampered_record["records"] = [
            dict(state["records"][0],
                 result=dict(state["records"][0]["result"],
                             event=dict(state["records"][0]["result"]["event"],
                                        actor="principal/attacker")))
        ]
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict(tampered_record)

    def test_engine_state_fails_closed_on_unknown_fields_and_bad_clocks(self) -> None:
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict({})
        state = build_engine_with_history()
        tampered = state.to_dict()
        tampered["unknown"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict(tampered)
        non_monotonic = state.to_dict()
        non_monotonic["logical_time"] = 0
        with self.assertRaises(CoreValidationError):
            EngineState.from_dict(non_monotonic)


def build_engine_with_history() -> EngineState:
    engine = build_engine()
    engine.process(create_command())
    return engine.snapshot_state()


class TransitionDogfoodingTests(unittest.TestCase):
    """DOGFOOD-003: intent lifecycle, replay and duplicate convergence through the public path."""

    def test_intent_lifecycle_dogfooding(self) -> None:
        def run_trace() -> tuple[list[JournalEntry], tuple[ObjectEnvelope, ...]]:
            store = MemoryStateStore()
            engine = build_engine(store=store)
            engine.process(create_command())
            engine.process(authorize_command())
            engine.process(authorize_command())
            engine.process(
                authorize_command("cmd/auth/2", expected=(("intent/1", 2),), payload={"authorized": True})
            )
            return list(engine.journal), store.snapshot()

        first_journal, first_state = run_trace()
        second_journal, second_state = run_trace()
        self.assertEqual(
            [entry.event.to_json() for entry in first_journal],
            [entry.event.to_json() for entry in second_journal],
        )
        self.assertEqual(
            [obj.to_dict() for obj in first_state],
            [obj.to_dict() for obj in second_state],
        )
        self.assertEqual(len(first_journal), 3)
        self.assertEqual([obj.object_version for obj in first_state], [3])
        self.assertEqual([obj.state for obj in first_state], ["DISCOVERING"])

    def test_dogfooding_experiment_output_is_deterministic(self) -> None:
        first = run_experiment()
        second = run_experiment()
        self.assertEqual(first, second)
        self.assertIn("classification: PASS", first)


if __name__ == "__main__":
    unittest.main()
