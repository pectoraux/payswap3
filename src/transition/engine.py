from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .command import Command
from .event import Event
from .payload import PayloadObject, check_payload_value, normalize_payload, payload_to_json_value
from .registry import (
    DEFAULT_REJECTION_EVENT_TYPE,
    PROTOCOL_VERSION,
    validate_authority_class,
    validate_event_type,
)
from .store import MemoryStateStore, StateStore, StateStoreView
from .validation import exact_fields, require_digest, require_text


class Outcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class RejectionReason(StrEnum):
    UNKNOWN_COMMAND_TYPE = "unknown_command_type"
    UNAUTHORIZED = "unauthorized"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    DOMAIN_MISMATCH = "domain_mismatch"
    OBJECT_NOT_FOUND = "object_not_found"
    VERSION_CONFLICT = "version_conflict"
    POLICY_REJECTED = "policy_rejected"
    INVARIANT_VIOLATION = "invariant_violation"
    COMMAND_ID_REUSED = "command_id_reused"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"


DEFAULT_AUTHORIZATION_DENIED_REASON = "no authorization policy is configured; failing closed"

AuthorizationHook = Callable[[Command, StateStoreView], "AuthorizationDecision"]
PolicyHook = Callable[[Command, StateStoreView], "str | None"]
InvariantHook = Callable[[Command, tuple[ObjectEnvelope, ...], StateStoreView], "str | None"]
TransitionHandler = Callable[[Command, StateStoreView], "TransitionApplication"]


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Typed authorization verdict; granted decisions state the exercised
    registry authority class, denials state an explicit reason."""

    granted: bool
    authority: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.granted, bool):
            raise CoreValidationError("authorization decision granted must be a boolean")
        if self.granted:
            if self.authority is None:
                raise CoreValidationError(
                    "granted authorization must state the exercised authority class"
                )
            validate_authority_class("authorization decision authority", self.authority)
        else:
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise CoreValidationError("denied authorization must state a rejection reason")
            if self.authority is not None:
                validate_authority_class("authorization decision authority", self.authority)


@dataclass(frozen=True, slots=True)
class TransitionApplication:
    """Handler output: sealed resulting envelopes plus the transition payload.

    Payloads handed over in canonical JSON value form are normalized into the
    deeply immutable storage form on construction; floats and unsafe values
    fail closed.
    """

    resulting_envelopes: tuple[ObjectEnvelope, ...]
    payload: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.resulting_envelopes, tuple) or not self.resulting_envelopes:
            raise CoreValidationError("resulting_envelopes must be a non-empty tuple")
        for envelope in self.resulting_envelopes:
            if not isinstance(envelope, ObjectEnvelope):
                raise CoreValidationError(
                    "resulting envelopes must be ObjectEnvelope instances"
                )
        object.__setattr__(self, "payload", normalize_payload("payload", self.payload))


@dataclass(frozen=True, slots=True)
class TransitionResult:
    """Explicit decision record for one processed command.

    ACCEPTED results carry the emitted event, its payload and the resulting
    envelopes; REJECTED results carry a closed-vocabulary reason and never
    carry resulting envelopes; DUPLICATE results echo the original decision
    without emitting a new event or re-applying state.
    """

    command_id: str
    idempotency_key: str
    outcome: Outcome
    reason: RejectionReason | None
    detail: str | None
    event: Event | None
    payload: Any
    resulting_envelopes: tuple[ObjectEnvelope, ...]

    def __post_init__(self) -> None:
        require_text("result.command_id", self.command_id)
        require_text("result.idempotency_key", self.idempotency_key)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("result outcome must use the closed vocabulary")
        if self.detail is not None:
            require_text("result.detail", self.detail)
        if self.event is not None and not isinstance(self.event, Event):
            raise CoreValidationError("result event must be an Event")
        if not isinstance(self.resulting_envelopes, tuple):
            raise CoreValidationError("result resulting_envelopes must be a tuple")
        for envelope in self.resulting_envelopes:
            if not isinstance(envelope, ObjectEnvelope):
                raise CoreValidationError(
                    "result resulting_envelopes entries must be ObjectEnvelope instances"
                )
        check_payload_value("result payload", self.payload)
        if self.outcome is Outcome.ACCEPTED:
            if self.event is None:
                raise CoreValidationError("accepted transitions must emit an event")
            if self.reason is not None:
                raise CoreValidationError("accepted transitions carry no rejection reason")
            if not self.resulting_envelopes:
                raise CoreValidationError("accepted transitions must produce resulting envelopes")
        elif self.outcome is Outcome.REJECTED:
            if not isinstance(self.reason, RejectionReason):
                raise CoreValidationError(
                    "rejections must state a closed-vocabulary reason"
                )
            if self.resulting_envelopes:
                raise CoreValidationError("rejections must not produce resulting envelopes")
        elif self.reason is not None:
            raise CoreValidationError("duplicate replays echo the original decision reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "idempotency_key": self.idempotency_key,
            "outcome": self.outcome.value,
            "reason": self.reason.value if self.reason is not None else None,
            "detail": self.detail,
            "event": self.event.to_dict() if self.event is not None else None,
            "payload": payload_to_json_value(self.payload) if self.payload is not None else None,
            "resulting_envelopes": [
                envelope.to_dict() for envelope in self.resulting_envelopes
            ],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionResult":
        if not isinstance(value, Mapping):
            raise CoreValidationError("transition result must be an object")
        exact_fields(
            "transition result",
            value,
            {
                "command_id",
                "idempotency_key",
                "outcome",
                "reason",
                "detail",
                "event",
                "payload",
                "resulting_envelopes",
            },
        )
        try:
            outcome = Outcome(value["outcome"])
        except ValueError as exc:
            raise CoreValidationError("unknown transition outcome") from exc
        reason = None
        if value["reason"] is not None:
            try:
                reason = RejectionReason(value["reason"])
            except ValueError as exc:
                raise CoreValidationError("unknown transition rejection reason") from exc
        event = None
        if value["event"] is not None:
            event = Event.from_dict(value["event"])
        envelopes_raw = value["resulting_envelopes"]
        if not isinstance(envelopes_raw, list):
            raise CoreValidationError("transition result envelopes must deserialize from a list")
        envelopes = tuple(ObjectEnvelope.from_dict(item) for item in envelopes_raw)
        return cls(
            command_id=value["command_id"],
            idempotency_key=value["idempotency_key"],
            outcome=outcome,
            reason=reason,
            detail=value["detail"],
            event=event,
            payload=normalize_payload("payload", value["payload"]) if value["payload"] is not None else None,
            resulting_envelopes=envelopes,
        )


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Append-only journal record: the immutable event plus the payload its
    hash commits to."""

    event: Event
    payload: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.event, Event):
            raise CoreValidationError("journal entries must carry an Event")
        check_payload_value("journal payload", self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "payload": payload_to_json_value(self.payload) if self.payload is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "JournalEntry":
        if not isinstance(value, Mapping):
            raise CoreValidationError("journal entry must be an object")
        exact_fields("journal entry", value, {"event", "payload"})
        return cls(
            event=Event.from_dict(value["event"]),
            payload=normalize_payload("payload", value["payload"]) if value["payload"] is not None else None,
        )


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """Processed-command record used for duplicate convergence and
    idempotency-conflict detection."""

    idempotency_key: str
    command_id: str
    command_digest: str
    result: TransitionResult

    def __post_init__(self) -> None:
        require_text("record.idempotency_key", self.idempotency_key)
        require_text("record.command_id", self.command_id)
        require_digest("record.command_digest", self.command_digest)
        if not isinstance(self.result, TransitionResult):
            raise CoreValidationError("record result must be a TransitionResult")

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "command_id": self.command_id,
            "command_digest": self.command_digest,
            "result": self.result.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IdempotencyRecord":
        if not isinstance(value, Mapping):
            raise CoreValidationError("idempotency record must be an object")
        exact_fields(
            "idempotency record",
            value,
            {"idempotency_key", "command_id", "command_digest", "result"},
        )
        return cls(
            idempotency_key=value["idempotency_key"],
            command_id=value["command_id"],
            command_digest=value["command_digest"],
            result=TransitionResult.from_dict(value["result"]),
        )


@dataclass(frozen=True, slots=True)
class EngineState:
    """Snapshottable kernel state: logical clock, processed-command records
    and the append-only event journal. Round-trips canonically so a restarted
    kernel keeps deduplicating instead of re-executing."""

    logical_time: int
    records: tuple[IdempotencyRecord, ...] = ()
    journal: tuple[JournalEntry, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.logical_time, int)
            or isinstance(self.logical_time, bool)
            or self.logical_time < 0
        ):
            raise CoreValidationError("engine state logical_time must be a non-negative integer")
        if not isinstance(self.records, tuple) or not isinstance(self.journal, tuple):
            raise CoreValidationError("engine state collections must be tuples")
        command_ids = [record.command_id for record in self.records]
        if len(set(command_ids)) != len(command_ids):
            raise CoreValidationError("engine state contains duplicate command_id records")
        idempotency_keys = [record.idempotency_key for record in self.records]
        if len(set(idempotency_keys)) != len(idempotency_keys):
            raise CoreValidationError("engine state contains duplicate idempotency keys")
        event_ids = [entry.event.event_id for entry in self.journal]
        if len(set(event_ids)) != len(event_ids):
            raise CoreValidationError("engine state journal would rewrite event history")
        journal_events = {entry.event.event_id: entry.event for entry in self.journal}
        for record in self.records:
            recorded_event = record.result.event
            if recorded_event is None:
                continue
            journal_event = journal_events.get(recorded_event.event_id)
            if journal_event is None or journal_event != recorded_event:
                raise CoreValidationError(
                    "engine state records must echo journal events exactly"
                )
        last_logical_time = 0
        for entry in self.journal:
            if (
                entry.event.logical_time <= last_logical_time
                or entry.event.logical_time > self.logical_time
            ):
                raise CoreValidationError(
                    "engine state journal logical times must strictly increase up to the clock"
                )
            last_logical_time = entry.event.logical_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_time": self.logical_time,
            "records": [record.to_dict() for record in self.records],
            "journal": [entry.to_dict() for entry in self.journal],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EngineState":
        if not isinstance(value, Mapping):
            raise CoreValidationError("engine state must be an object")
        exact_fields("engine state", value, {"logical_time", "records", "journal"})
        records_raw = value["records"]
        journal_raw = value["journal"]
        if not isinstance(records_raw, list) or not isinstance(journal_raw, list):
            raise CoreValidationError("engine state collections must deserialize from lists")
        return cls(
            logical_time=value["logical_time"],
            records=tuple(IdempotencyRecord.from_dict(item) for item in records_raw),
            journal=tuple(JournalEntry.from_dict(item) for item in journal_raw),
        )


class TransitionEngine:
    """Deterministic command/event transition kernel for one environment.

    Implements the frozen pipeline
    ``input → authorization → preconditions → policy → invariant check →
    transition → immutable event`` with explicit failure paths:

    * input-level idempotency and command-id integrity (duplicate commands
      converge to the original decision; conflicts fail closed);
    * hard environment isolation (a kernel bound to one environment never
      accepts commands or objects of another environment — simulation
      cannot mutate production state);
    * optimistic-concurrency preconditions via ``expected_versions``;
    * policy and invariant hooks that gate the commit;
    * handler registration per command type (unknown command types fail
      closed) with kernel-owned canonical event envelopes, logical clock and
      append-only journal;
    * store-side version-chain and identity enforcement.

    The kernel is deterministic: no wall-clock time, no randomness, no
    floats; event ids are derived from command ids, logical times from a
    monotonic counter, timestamps from the command's ``requested_at``.
    """

    def __init__(
        self,
        environment_id: str,
        *,
        authorization: AuthorizationHook | None = None,
        policy: PolicyHook | None = None,
        invariants: Iterable[InvariantHook] = (),
        store: StateStore | None = None,
        emit_rejection_events: bool = False,
        rejection_event_type: str = DEFAULT_REJECTION_EVENT_TYPE,
        rejection_authority: str | None = None,
    ) -> None:
        require_text("environment_id", environment_id)
        validate_event_type("rejection_event_type", rejection_event_type)
        if emit_rejection_events:
            if rejection_authority is None:
                raise CoreValidationError(
                    "rejection events require a configured audit authority class"
                )
            validate_authority_class("rejection_authority", rejection_authority)
        self._environment_id = environment_id
        self._authorization = authorization
        self._policy = policy
        self._invariants = tuple(invariants)
        self._store: StateStore = store if store is not None else MemoryStateStore()
        self._view = StateStoreView(self._store)
        self._emit_rejection_events = emit_rejection_events
        self._rejection_event_type = rejection_event_type
        self._rejection_authority = rejection_authority
        self._handlers: dict[str, tuple[str, TransitionHandler]] = {}
        self._clock = 0
        self._records: dict[str, IdempotencyRecord] = {}
        self._records_by_key: dict[str, IdempotencyRecord] = {}
        self._journal: list[JournalEntry] = []

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def journal(self) -> tuple[JournalEntry, ...]:
        return tuple(self._journal)

    def register(self, command_type: str, event_type: str, handler: TransitionHandler) -> None:
        """Register the transition handler for a command type.

        The emitted event type must be registry-valid; re-registering a
        command type fails closed (one authority per command type).
        """
        require_text("command_type", command_type)
        validate_event_type("event_type", event_type)
        if not callable(handler):
            raise CoreValidationError("transition handler must be callable")
        if command_type in self._handlers:
            raise CoreValidationError(f"command type {command_type} is already registered")
        self._handlers[command_type] = (event_type, handler)

    def snapshot_state(self) -> EngineState:
        return EngineState(
            logical_time=self._clock,
            records=tuple(self._records.values()),
            journal=tuple(self._journal),
        )

    def restore_state(self, state: EngineState) -> None:
        if not isinstance(state, EngineState):
            raise CoreValidationError("engine state must be an EngineState")
        self._clock = state.logical_time
        self._records = {record.command_id: record for record in state.records}
        self._records_by_key = {record.idempotency_key: record for record in state.records}
        self._journal = list(state.journal)

    def process(self, command: Command) -> TransitionResult:
        if not isinstance(command, Command):
            raise CoreValidationError("process expects a Command envelope")
        digest = command.digest

        # Stage 1 — input-level idempotency and command-id integrity.
        seen_by_id = self._records.get(command.command_id)
        if seen_by_id is not None:
            if seen_by_id.command_digest == digest:
                return self._duplicate(command, seen_by_id)
            return self._input_integrity_rejection(
                command,
                RejectionReason.COMMAND_ID_REUSED,
                f"command_id {command.command_id} was already used for different command content",
            )
        seen_by_key = self._records_by_key.get(command.idempotency_key)
        if seen_by_key is not None:
            if seen_by_key.command_digest == digest:
                return self._duplicate(command, seen_by_key)
            return self._input_integrity_rejection(
                command,
                RejectionReason.IDEMPOTENCY_CONFLICT,
                f"idempotency_key {command.idempotency_key} was already used for different command content",
            )

        # Stage 2 — hard environment binding.
        if command.environment_id != self._environment_id:
            return self._reject(
                command,
                RejectionReason.ENVIRONMENT_MISMATCH,
                f"command environment {command.environment_id} does not match kernel "
                f"environment {self._environment_id}",
                digest,
            )

        # Stage 3 — known command type (fail closed on unknown input).
        registration = self._handlers.get(command.command_type)
        if registration is None:
            return self._reject(
                command,
                RejectionReason.UNKNOWN_COMMAND_TYPE,
                f"command type {command.command_type} is not registered with the kernel",
                digest,
            )

        # Stage 4 — authorization.
        if self._authorization is None:
            decision = AuthorizationDecision(
                granted=False,
                authority=None,
                reason=DEFAULT_AUTHORIZATION_DENIED_REASON,
            )
        else:
            decision = self._authorization(command, self._view)
            if not isinstance(decision, AuthorizationDecision):
                raise CoreValidationError(
                    "authorization hook must return an AuthorizationDecision"
                )
        if not decision.granted:
            return self._reject(
                command,
                RejectionReason.UNAUTHORIZED,
                decision.reason or "unauthorized",
                digest,
            )

        # Stage 5 — preconditions on declared references.
        declared_refs: list[str] = []
        for object_ref in command.target_refs:
            if object_ref not in declared_refs:
                declared_refs.append(object_ref)
        for expected in command.expected_versions:
            if expected.object_ref not in declared_refs:
                declared_refs.append(expected.object_ref)
        current_state: dict[str, ObjectEnvelope | None] = {}
        for object_ref in declared_refs:
            current = self._store.get(object_ref)
            current_state[object_ref] = current
            if current is not None:
                if current.environment_id != command.environment_id:
                    return self._reject(
                        command,
                        RejectionReason.ENVIRONMENT_MISMATCH,
                        f"object {object_ref} belongs to environment "
                        f"{current.environment_id}, not {command.environment_id}",
                        digest,
                    )
                if current.domain_id != command.domain_id:
                    return self._reject(
                        command,
                        RejectionReason.DOMAIN_MISMATCH,
                        f"object {object_ref} belongs to domain "
                        f"{current.domain_id}, not {command.domain_id}",
                        digest,
                    )
        for expected in command.expected_versions:
            current = current_state[expected.object_ref]
            if current is None:
                if expected.object_version != 0:
                    return self._reject(
                        command,
                        RejectionReason.OBJECT_NOT_FOUND,
                        f"expected object {expected.object_ref} at version "
                        f"{expected.object_version} but it does not exist",
                        digest,
                    )
            elif expected.object_version == 0:
                return self._reject(
                    command,
                    RejectionReason.VERSION_CONFLICT,
                    f"object {expected.object_ref} exists at version "
                    f"{current.object_version} but the command required its absence",
                    digest,
                )
            elif current.object_version != expected.object_version:
                return self._reject(
                    command,
                    RejectionReason.VERSION_CONFLICT,
                    f"object {expected.object_ref} is at version "
                    f"{current.object_version}, command expected {expected.object_version}",
                    digest,
                )

        # Stage 6 — policy gate.
        if self._policy is not None:
            verdict = self._policy(command, self._view)
            if verdict is not None:
                if not isinstance(verdict, str) or not verdict.strip():
                    raise CoreValidationError("policy verdicts must be non-empty strings")
                return self._reject(command, RejectionReason.POLICY_REJECTED, verdict, digest)

        # Stage 7 — deterministic transition.
        event_type, handler = registration
        application = handler(command, self._view)
        if not isinstance(application, TransitionApplication):
            raise CoreValidationError(
                "transition handler must return a TransitionApplication"
            )
        resulting = application.resulting_envelopes
        declared_targets = set(command.target_refs)
        for envelope in resulting:
            envelope.verify_integrity()
            if envelope.object_id not in declared_targets:
                raise CoreValidationError(
                    f"handler produced object {envelope.object_id} which the command "
                    "did not declare in target_refs"
                )
            if envelope.environment_id != command.environment_id:
                raise CoreValidationError(
                    f"resulting object {envelope.object_id} does not match command "
                    f"environment {command.environment_id}"
                )
            if envelope.domain_id != command.domain_id:
                raise CoreValidationError(
                    f"resulting object {envelope.object_id} does not match command "
                    f"domain {command.domain_id}"
                )

        # Stage 8 — invariant hooks gate the commit.
        for invariant in self._invariants:
            violation = invariant(command, resulting, self._view)
            if violation is not None:
                if not isinstance(violation, str) or not violation.strip():
                    raise CoreValidationError("invariant verdicts must be non-empty strings")
                return self._reject(command, RejectionReason.INVARIANT_VIOLATION, violation, digest)

        # Stage 9 — immutable event, commit, journal, idempotency record.
        object_refs = tuple(sorted(envelope.object_id for envelope in resulting))
        resulting_by_id = {envelope.object_id: envelope for envelope in resulting}
        event = Event(
            event_id=f"event/{command.command_id}",
            event_type=event_type,
            object_refs=object_refs,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            actor=command.actor,
            authority=decision.authority,
            previous_state=tuple(
                current_state[object_ref].state
                if current_state[object_ref] is not None
                else None
                for object_ref in object_refs
            ),
            resulting_state=tuple(
                resulting_by_id[object_ref].state for object_ref in object_refs
            ),
            object_versions=tuple(
                resulting_by_id[object_ref].object_version for object_ref in object_refs
            ),
            occurred_at=command.requested_at,
            logical_time=self._clock + 1,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            payload_hash=canonical_sha256(payload_to_json_value(application.payload)),
            protocol_version=PROTOCOL_VERSION,
        )
        self._store.commit(resulting)
        self._clock += 1
        self._journal.append(JournalEntry(event=event, payload=application.payload))
        result = TransitionResult(
            command_id=command.command_id,
            idempotency_key=command.idempotency_key,
            outcome=Outcome.ACCEPTED,
            reason=None,
            detail=None,
            event=event,
            payload=application.payload,
            resulting_envelopes=resulting,
        )
        self._record(command, digest, result)
        return result

    def _reject(
        self,
        command: Command,
        reason: RejectionReason,
        detail: str,
        digest: str,
    ) -> TransitionResult:
        event: Event | None = None
        payload: Any = None
        if self._emit_rejection_events:
            if self._rejection_authority is None:
                raise CoreValidationError(
                    "rejection events require a configured audit authority class"
                )
            payload = PayloadObject(
                pairs=(("detail", detail), ("reason", reason.value))
            )
            object_refs = tuple(sorted(command.target_refs))
            previous_state: list[str | None] = []
            resulting_state: list[str | None] = []
            object_versions: list[int] = []
            for object_ref in object_refs:
                current = self._store.get(object_ref)
                if current is None:
                    previous_state.append(None)
                    resulting_state.append(None)
                    object_versions.append(0)
                else:
                    previous_state.append(current.state)
                    resulting_state.append(current.state)
                    object_versions.append(current.object_version)
            event = Event(
                event_id=f"event/{command.command_id}/rejection",
                event_type=self._rejection_event_type,
                object_refs=object_refs,
                environment_id=command.environment_id,
                domain_id=command.domain_id,
                actor=command.actor,
                authority=self._rejection_authority,
                previous_state=tuple(previous_state),
                resulting_state=tuple(resulting_state),
                object_versions=tuple(object_versions),
                occurred_at=command.requested_at,
                logical_time=self._clock + 1,
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
                payload_hash=canonical_sha256(payload_to_json_value(payload)),
                protocol_version=PROTOCOL_VERSION,
            )
            self._clock += 1
            self._journal.append(JournalEntry(event=event, payload=payload))
        result = TransitionResult(
            command_id=command.command_id,
            idempotency_key=command.idempotency_key,
            outcome=Outcome.REJECTED,
            reason=reason,
            detail=detail,
            event=event,
            payload=payload,
            resulting_envelopes=(),
        )
        self._record(command, digest, result)
        return result

    def _duplicate(self, command: Command, record: IdempotencyRecord) -> TransitionResult:
        original = record.result
        return TransitionResult(
            command_id=command.command_id,
            idempotency_key=command.idempotency_key,
            outcome=Outcome.DUPLICATE,
            reason=None,
            detail=f"duplicate replay of command {command.command_id}",
            event=original.event,
            payload=original.payload,
            resulting_envelopes=original.resulting_envelopes,
        )

    def _input_integrity_rejection(
        self,
        command: Command,
        reason: RejectionReason,
        detail: str,
    ) -> TransitionResult:
        # Input-level integrity failures emit no event and are not recorded:
        # an event derived from an unprocessable input could collide with
        # already-emitted history (events never rewrite history).
        return TransitionResult(
            command_id=command.command_id,
            idempotency_key=command.idempotency_key,
            outcome=Outcome.REJECTED,
            reason=reason,
            detail=detail,
            event=None,
            payload=None,
            resulting_envelopes=(),
        )

    def _record(self, command: Command, digest: str, result: TransitionResult) -> None:
        record = IdempotencyRecord(
            idempotency_key=command.idempotency_key,
            command_id=command.command_id,
            command_digest=digest,
            result=result,
        )
        self._records[command.command_id] = record
        self._records_by_key[command.idempotency_key] = record
