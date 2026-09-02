"""The environment runtime over the real transition kernel (WORK-019).

One executable protocol machine, many worlds. The
:class:`EnvironmentRuntime` wraps ONE :class:`~src.transition.TransitionEngine`
(the real command/event kernel — never a second state machine) and owns:

* the frozen environment mode and identity;
* the deterministic world adapter and its :class:`~src.simulation.world.WorldView`
  handed to protocol handlers (the environment supplies world
  observations, clocks and models);
* the five separated state namespaces with fail-closed classification;
* the effect policy — the only environment-dependent component;
* snapshots, sealed checkpoints and deterministic restore;
* the debugger operations: step, pause/resume, checkpoint, fault
  injection, branch and replay (the frozen ``Simulation`` command family).

The parity invariant is the heart of this module: given the same
protocol version, policy, extension versions, initial state, inputs and
world observations, protocol transitions are identical across
environments — :func:`parity_projection` strips environment and
command identity and :func:`canonical_journal_diff` proves the raw
journals differ ONLY in environment identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256

from src.transition import (
    Command,
    EngineState,
    JournalEntry,
    MemoryStateStore,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
    payload_to_json_value,
    validate_event_type,
)

from ._validation import (
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    SIMULATION_COMMANDS,
    SIMULATION_OBJECT_TYPE,
    SIMULATION_PROTOCOL_VERSION,
    SIMULATION_SCHEMA_VERSION,
    SIMULATION_TERMINAL_STATES,
    EnvironmentMode,
    FaultKind,
    SimulationRunState,
    StateNamespace,
    mode_epistemic_type,
    validate_operation,
)
from .effects import EffectIntent, EffectPolicy, EffectRecord, record_effects
from .snapshots import EnvironmentSnapshot, SimulationCheckpoint, SimulationResult
from .state import (
    DEFAULT_NAMESPACE_RULES,
    NamespaceRules,
    NamespacedStateStore,
    provision_namespaced_state,
)
from .world import (
    EnvironmentClock,
    WorldAdapter,
    WorldObservation,
    WorldView,
)

#: A protocol transition handler as declared by a shared binding. The
#: runtime adapts each handler into a kernel handler closure and injects
#: its own environment's world view — the binding (business semantics) is
#: identical across environments; the world differs.
WorldAwareHandler = Callable[[Command, Any, WorldView], TransitionApplication]

_OPERATION_FIELDS = frozenset({"sequence", "operation", "at", "detail"})
_FAULT_FIELDS = frozenset({"kind", "target", "reason", "at"})
_TRANSITION_LOG_FIELDS = frozenset(
    {"index", "command_id", "command_digest", "outcome", "transition_digest"}
)


@dataclass(frozen=True, slots=True)
class CommandRegistration:
    """One command type of the shared protocol binding."""

    command_type: str
    event_type: str
    handler: WorldAwareHandler

    def __post_init__(self) -> None:
        require_text("command registration command_type", self.command_type)
        validate_event_type("command registration event_type", self.event_type)
        if not callable(self.handler):
            raise CoreValidationError("command registration handler must be callable")


@dataclass(frozen=True, slots=True)
class ProtocolBinding:
    """The protocol machine shared by every environment.

    A binding declares the kernel command registrations (with their
    registry event types), the authorization/policy/invariant hooks and
    the protocol version. The SAME binding instance runs in simulation,
    shadow and production — that is what makes parity meaningful: only
    the environment identity, the world and the effect policy differ.
    """

    binding_id: str
    protocol_version: str
    registrations: tuple[CommandRegistration, ...]
    authorization: Callable | None = None
    policy: Callable | None = None
    invariants: tuple[Callable, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("binding_id", self.binding_id)
        require_text("protocol_version", self.protocol_version)
        if self.protocol_version != SIMULATION_PROTOCOL_VERSION:
            raise CoreValidationError(
                "protocol binding must use the kernel protocol version "
                f"{SIMULATION_PROTOCOL_VERSION}; a second protocol semantics "
                "is forbidden"
            )
        if not isinstance(self.registrations, tuple) or not self.registrations:
            raise CoreValidationError(
                "protocol binding registrations must be a non-empty tuple"
            )
        command_types: list[str] = []
        for registration in self.registrations:
            if not isinstance(registration, CommandRegistration):
                raise CoreValidationError(
                    "protocol binding registrations must be CommandRegistration records"
                )
            command_types.append(registration.command_type)
        if len(set(command_types)) != len(command_types):
            raise CoreValidationError(
                "protocol binding registers a command type twice"
            )
        if self.authorization is not None and not callable(self.authorization):
            raise CoreValidationError("protocol binding authorization must be callable")
        if self.policy is not None and not callable(self.policy):
            raise CoreValidationError("protocol binding policy must be callable")
        if not isinstance(self.invariants, tuple):
            raise CoreValidationError("protocol binding invariants must be a tuple")
        for invariant in self.invariants:
            if not callable(invariant):
                raise CoreValidationError("protocol binding invariants must be callable")

    @property
    def fingerprint(self) -> str:
        """Deterministic digest of the binding declarations."""
        return canonical_sha256(
            {
                "binding_id": self.binding_id,
                "protocol_version": self.protocol_version,
                "registrations": sorted(
                    [registration.command_type, registration.event_type]
                    for registration in self.registrations
                ),
            }
        )


@dataclass(frozen=True, slots=True)
class EnvironmentSpec:
    """Identity and mode of one environment."""

    environment_id: str
    mode: EnvironmentMode
    domain_id: str
    as_of: str
    label: str = ""

    def __post_init__(self) -> None:
        require_identifier("spec environment_id", self.environment_id)
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError(
                "spec mode must be an EnvironmentMode member of the frozen "
                "six-mode vocabulary"
            )
        require_identifier("spec domain_id", self.domain_id)
        require_utc_timestamp("spec as_of", self.as_of)
        if not isinstance(self.label, str):
            raise CoreValidationError("spec label must be a string")


@dataclass(frozen=True, slots=True)
class SimulationOperation:
    """One sealed debugger/lifecycle operation record."""

    sequence: int
    operation: str
    at: str
    detail: str

    def __post_init__(self) -> None:
        require_int("operation sequence", self.sequence, minimum=1)
        validate_operation(self.operation)
        require_utc_timestamp("operation at", self.at)
        require_text("operation detail", self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "operation": self.operation,
            "at": self.at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SimulationOperation":
        if not isinstance(value, Mapping):
            raise CoreValidationError("simulation operation must be an object")
        strict_fields("simulation operation", value, _OPERATION_FIELDS)
        return cls(
            sequence=value["sequence"],
            operation=value["operation"],
            at=value["at"],
            detail=value["detail"],
        )


@dataclass(frozen=True, slots=True)
class FaultInjection:
    """One injected fault over the real protocol machine's inputs."""

    kind: FaultKind
    target: str
    reason: str
    at: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, FaultKind):
            raise CoreValidationError("fault kind must be a FaultKind")
        require_identifier("fault target", self.target)
        require_text("fault reason", self.reason)
        require_utc_timestamp("fault at", self.at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "reason": self.reason,
            "at": self.at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FaultInjection":
        if not isinstance(value, Mapping):
            raise CoreValidationError("fault injection must be an object")
        strict_fields("fault injection", value, _FAULT_FIELDS)
        return cls(
            kind=FaultKind(value["kind"]),
            target=value["target"],
            reason=value["reason"],
            at=value["at"],
        )


@dataclass(frozen=True, slots=True)
class TransitionLog:
    """Compact journal record of one submitted command."""

    index: int
    command_id: str
    command_digest: str
    outcome: Outcome
    transition_digest: str

    def __post_init__(self) -> None:
        require_int("transition log index", self.index, minimum=1)
        require_identifier("transition log command_id", self.command_id)
        require_text("transition log command_digest", self.command_digest)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("transition log outcome must be an Outcome")
        require_text("transition log transition_digest", self.transition_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "command_id": self.command_id,
            "command_digest": self.command_digest,
            "outcome": self.outcome.value,
            "transition_digest": self.transition_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionLog":
        if not isinstance(value, Mapping):
            raise CoreValidationError("transition log must be an object")
        strict_fields("transition log", value, _TRANSITION_LOG_FIELDS)
        return cls(
            index=value["index"],
            command_id=value["command_id"],
            command_digest=value["command_digest"],
            outcome=Outcome(value["outcome"]),
            transition_digest=value["transition_digest"],
        )


@dataclass(frozen=True, slots=True)
class EnvironmentTransition:
    """The full record of one submitted command in one environment."""

    transition_index: int
    command: Command
    command_digest: str
    outcome: Outcome
    reason: RejectionReason | None
    detail: str | None
    event: Any
    payload: Any
    resulting_envelopes: tuple[ObjectEnvelope, ...]
    result: TransitionResult
    transition_digest: str
    effect_intents: tuple[EffectIntent, ...]
    effects: tuple[EffectRecord, ...]
    observations: tuple[WorldObservation, ...]

    def __post_init__(self) -> None:
        require_int("transition index", self.transition_index, minimum=1)
        if not isinstance(self.command, Command):
            raise CoreValidationError("transition command must be a Command")
        require_text("transition command_digest", self.command_digest)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("transition outcome must be an Outcome")
        if not isinstance(self.result, TransitionResult):
            raise CoreValidationError("transition result must be a TransitionResult")
        if not isinstance(self.resulting_envelopes, tuple):
            raise CoreValidationError("transition resulting_envelopes must be a tuple")
        require_text("transition transition_digest", self.transition_digest)
        if not isinstance(self.effect_intents, tuple) or not isinstance(
            self.effects, tuple
        ):
            raise CoreValidationError("transition effect records must be tuples")
        if not isinstance(self.observations, tuple):
            raise CoreValidationError("transition observations must be a tuple")


def _journal_value(entry: JournalEntry) -> dict[str, Any]:
    return {
        "event": entry.event.to_dict(),
        "payload": payload_to_json_value(entry.payload),
    }


#: Journal identity fields stripped by the parity projection: the
#: environment identity (``environment_id``) and the command-derived
#: identity (``event_id`` and ``causation_id``, both derived from the
#: submitting command's id). Comparing the same scenario across
#: environments — or a parent run against a branch that repeats the same
#: semantics under new command identity — must never depend on who or
#: where a transition was executed, only on what the machine did.
_PARITY_IDENTITY_FIELDS = ("environment_id", "event_id", "causation_id")


def parity_projection(journal: Iterable[JournalEntry]) -> list[str]:
    """Canonical transition projection with environment identity removed.

    Given the same inputs and world observations, this projection is
    byte-identical across environments (and across branches that repeat
    the same semantics under new command identity) — the parity
    invariant. Only the identity fields of each canonical event are
    normalized (``environment_id``, and the command-derived ``event_id``
    and ``causation_id``); every business-semantic field (states,
    versions, payloads, logical times, actors, authorities, correlation
    and protocol version) stays exactly as the real kernel produced it.
    """
    projected: list[str] = []
    for entry in journal:
        value = _journal_value(entry)
        for field in _PARITY_IDENTITY_FIELDS:
            value["event"][field] = None
        projected.append(canonical_json(value))
    return projected


def parity_digest(journal: Iterable[JournalEntry]) -> str:
    """Deterministic digest of the parity projection of a journal."""
    entries = list(journal)
    return canonical_sha256(parity_projection(entries))


def _diff_values(left: Any, right: Any, path: str, paths: list[str]) -> None:
    if left == right:
        return
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        for key in sorted(set(left) | set(right)):
            _diff_values(
                left.get(key),
                right.get(key),
                f"{path}.{key}" if path else key,
                paths,
            )
        return
    if isinstance(left, list) and isinstance(right, list):
        for index in range(min(len(left), len(right))):
            _diff_values(left[index], right[index], f"{path}[{index}]", paths)
        if len(left) != len(right):
            paths.append(f"{path}[length]")
        return
    paths.append(path)


def canonical_journal_diff(
    journal_a: Iterable[JournalEntry],
    journal_b: Iterable[JournalEntry],
) -> tuple[str, ...]:
    """Deterministic paths at which two raw canonical journals differ.

    Parity proof helper: the difference set between the same scenario's
    journals in two environments must be exactly the environment identity
    fields — anything else is a business-semantics divergence.
    """
    left = [_journal_value(entry) for entry in journal_a]
    right = [_journal_value(entry) for entry in journal_b]
    paths: list[str] = []
    _diff_values(left, right, "entry", paths)
    return tuple(paths)


def raw_journal_digest(journal: Iterable[JournalEntry]) -> str:
    """Deterministic digest of the raw canonical journal (identity kept)."""
    entries = list(journal)
    return canonical_sha256([_journal_value(entry) for entry in entries])


class EnvironmentRuntime:
    """One environment of the protocol machine.

    The runtime is environment orchestration — never a second
    business-logic implementation: every transition is processed by the
    real kernel through the shared binding, every world observation
    comes through the deterministic adapter boundary, every effect is a
    typed policy record, and every snapshot/checkpoint is sealed with the
    single canonical hash authority.
    """

    def __init__(
        self,
        *,
        spec: EnvironmentSpec,
        binding: ProtocolBinding,
        world: WorldAdapter,
        namespace_rules: NamespaceRules = DEFAULT_NAMESPACE_RULES,
        initial_state: Mapping[StateNamespace, Iterable[ObjectEnvelope]] | None = None,
        effect_policy: EffectPolicy | None = None,
        simulation_id: str = "simulation/run-1",
        provenance_issuer: str = "principal/simulation-operator",
        first_operation: str = "simulation/create",
        branched_from: str | None = None,
    ) -> None:
        if not isinstance(spec, EnvironmentSpec):
            raise CoreValidationError("runtime requires an EnvironmentSpec")
        if not isinstance(binding, ProtocolBinding):
            raise CoreValidationError("runtime requires a ProtocolBinding")
        if not isinstance(world, WorldAdapter):
            raise CoreValidationError("runtime requires a WorldAdapter")
        required_epistemic = mode_epistemic_type(spec.mode)
        if world.epistemic_type is not required_epistemic:
            raise CoreValidationError(
                f"mode/epistemic confusion: environment mode {spec.mode.value} "
                f"requires {required_epistemic.value} world observations but the "
                f"adapter declares {world.epistemic_type.value}"
            )
        if not isinstance(namespace_rules, NamespaceRules):
            raise CoreValidationError("runtime requires NamespaceRules")
        if effect_policy is None:
            effect_policy = EffectPolicy.for_mode(spec.mode)
        elif not isinstance(effect_policy, EffectPolicy):
            raise CoreValidationError("runtime effect policy must be an EffectPolicy")
        elif effect_policy.mode is not spec.mode:
            raise CoreValidationError(
                "runtime effect policy mode must match the environment mode"
            )
        require_identifier("simulation_id", simulation_id)
        require_identifier("provenance issuer", provenance_issuer)
        validate_operation(first_operation)
        if branched_from is not None:
            require_text("branched_from", branched_from)

        self._spec = spec
        self._binding = binding
        self._world = world
        self._rules = namespace_rules
        self._policy = effect_policy
        self._provenance_issuer = provenance_issuer
        store, _inventory = provision_namespaced_state(
            namespace_rules, initial_state if initial_state is not None else {}
        )
        self._initial_state: tuple[ObjectEnvelope, ...] = store.snapshot()
        self._namespaced = NamespacedStateStore(namespace_rules, store)
        self._store = store
        self._engine = self._build_engine()
        self._clock = EnvironmentClock(logical_time=0, as_of=spec.as_of)
        self._observations: list[WorldObservation] = []
        self._effects: list[EffectRecord] = []
        self._operations: list[SimulationOperation] = []
        self._transition_log: list[TransitionLog] = []
        self._submitted: list[tuple[Command, tuple[EffectIntent, ...]]] = []
        self._intents_by_command: dict[str, str] = {}
        self._effects_by_command: dict[str, tuple[EffectRecord, ...]] = {}
        self._active_world_faults: dict[str, str] = {}
        self._active_effect_faults: dict[str, str] = {}
        self._fault_journal: list[FaultInjection] = []
        self._world_view = WorldView(
            world,
            mode=spec.mode,
            journal=self._observations,
            clock=self._clock,
            world_faults=self._active_world_faults,
        )
        self._run_state = SimulationRunState.RUNNING
        self._simulation_envelope = ObjectEnvelope(
            object_id=simulation_id,
            object_type=SIMULATION_OBJECT_TYPE,
            object_version=1,
            environment_id=spec.environment_id,
            domain_id=spec.domain_id,
            schema_version=SIMULATION_SCHEMA_VERSION,
            protocol_version=SIMULATION_PROTOCOL_VERSION,
            state=SimulationRunState.RUNNING.value,
            provenance=Provenance(
                issuer=provenance_issuer,
                source=f"simulation/{spec.mode.value}",
                recorded_at=spec.as_of,
            ),
            causation_id=branched_from,
            correlation_id=None,
            previous_version=None,
        ).with_integrity_hash()
        self._checkpoint_sequence = 0
        self._last_checkpoint_digest: str | None = None
        self._record_operation(
            first_operation,
            spec.as_of,
            f"environment {spec.environment_id} mode {spec.mode.value}"
            + (f" branched from {branched_from}" if branched_from else ""),
        )

    # -- construction helpers ------------------------------------------------

    def _build_engine(self) -> TransitionEngine:
        engine = TransitionEngine(
            environment_id=self._spec.environment_id,
            authorization=self._binding.authorization,
            policy=self._binding.policy,
            invariants=self._binding.invariants,
            store=self._namespaced,
        )
        for registration in self._binding.registrations:
            engine.register(
                registration.command_type,
                registration.event_type,
                self._adapt_handler(registration),
            )
        return engine

    def _adapt_handler(self, registration: CommandRegistration) -> Callable:
        def kernel_handler(command: Command, view: Any) -> TransitionApplication:
            return registration.handler(command, view, self._world_view)

        return kernel_handler

    # -- read-only surface ---------------------------------------------------

    @property
    def spec(self) -> EnvironmentSpec:
        return self._spec

    @property
    def mode(self) -> EnvironmentMode:
        return self._spec.mode

    @property
    def environment_id(self) -> str:
        return self._spec.environment_id

    @property
    def domain_id(self) -> str:
        return self._spec.domain_id

    @property
    def binding(self) -> ProtocolBinding:
        return self._binding

    @property
    def world(self) -> WorldAdapter:
        return self._world

    @property
    def effect_policy(self) -> EffectPolicy:
        return self._policy

    @property
    def run_state(self) -> SimulationRunState:
        return self._run_state

    @property
    def simulation_envelope(self) -> ObjectEnvelope:
        return self._simulation_envelope

    @property
    def journal(self) -> tuple[JournalEntry, ...]:
        return self._engine.journal

    @property
    def transitions(self) -> tuple[TransitionLog, ...]:
        return tuple(self._transition_log)

    @property
    def observations(self) -> tuple[WorldObservation, ...]:
        return tuple(self._observations)

    @property
    def effects(self) -> tuple[EffectRecord, ...]:
        return tuple(self._effects)

    @property
    def operations(self) -> tuple[SimulationOperation, ...]:
        return tuple(self._operations)

    @property
    def faults(self) -> tuple[FaultInjection, ...]:
        return tuple(self._fault_journal)

    @property
    def submitted_commands(self) -> tuple[tuple[Command, tuple[EffectIntent, ...]], ...]:
        return tuple(self._submitted)

    @property
    def initial_state(self) -> tuple[ObjectEnvelope, ...]:
        return self._initial_state

    @property
    def state_digest(self) -> str:
        return canonical_sha256(
            [envelope.to_dict() for envelope in self._store.snapshot()]
        )

    def namespace_state(self, namespace: StateNamespace) -> tuple[ObjectEnvelope, ...]:
        if not isinstance(namespace, StateNamespace):
            raise CoreValidationError("namespace must be a StateNamespace")
        return self._namespaced.namespace_state(namespace)

    def namespace_digest(self, namespace: StateNamespace) -> str:
        if not isinstance(namespace, StateNamespace):
            raise CoreValidationError("namespace must be a StateNamespace")
        return self._namespaced.namespace_digest(namespace)

    def namespace_digests(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (namespace.value, self.namespace_digest(namespace))
            for namespace in sorted(StateNamespace, key=lambda item: item.value)
        )

    @property
    def namespace_rules(self) -> NamespaceRules:
        """The namespace classification this environment runs under."""
        return self._rules

    # -- submission (Run / Step) ---------------------------------------------

    def submit(
        self,
        command: Command,
        *,
        effect_intents: Sequence[EffectIntent] = (),
    ) -> EnvironmentTransition:
        """Process one command through the real kernel in this environment."""
        self._require_active("submissions")
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        intents = tuple(effect_intents)
        for intent in intents:
            if not isinstance(intent, EffectIntent):
                raise CoreValidationError(
                    "effect_intents entries must be EffectIntent records"
                )
        # Namespace pre-gate: declared references must classify.
        for object_ref in command.target_refs:
            self._rules.classify(object_ref)
        for expected in command.expected_versions:
            self._rules.classify(expected.object_ref)

        self._clock.as_of = command.requested_at
        self._clock.logical_time = len(self._engine.journal)
        observation_start = len(self._observations)
        result = self._engine.process(command)
        consumed = tuple(self._observations[observation_start:])

        effects: tuple[EffectRecord, ...] = ()
        if result.outcome is Outcome.ACCEPTED:
            if intents:
                effects = record_effects(
                    self._policy,
                    intents,
                    environment_id=self._spec.environment_id,
                    command_id=command.command_id,
                    faults=dict(self._active_effect_faults),
                )
                self._effects.extend(effects)
                self._intents_by_command[command.command_id] = canonical_sha256(
                    [intent.to_dict() for intent in intents]
                )
                self._effects_by_command[command.command_id] = effects
        elif result.outcome is Outcome.DUPLICATE:
            if intents:
                intents_digest = canonical_sha256(
                    [intent.to_dict() for intent in intents]
                )
                recorded = self._intents_by_command.get(command.command_id)
                if recorded is None:
                    raise CoreValidationError(
                        "duplicate command carries effect intents but the "
                        "original submission recorded none; idempotent effects "
                        "fail closed on unknown originals"
                    )
                if recorded != intents_digest:
                    raise CoreValidationError(
                        "duplicate command carries effect intents that conflict "
                        "with the original submission; external effects are "
                        "idempotent and never re-decided"
                    )
                effects = self._effects_by_command.get(command.command_id, ())
        else:
            if intents:
                raise CoreValidationError(
                    "effects cannot be authorized by a rejected transition: "
                    f"{result.reason.value if result.reason else 'rejected'}"
                )

        transition_digest = canonical_sha256(
            {
                "event": result.event.to_dict() if result.event is not None else None,
                "payload": payload_to_json_value(result.payload),
            }
        )
        transition = EnvironmentTransition(
            transition_index=len(self._transition_log) + 1,
            command=command,
            command_digest=command.digest,
            outcome=result.outcome,
            reason=result.reason,
            detail=result.detail,
            event=result.event,
            payload=result.payload,
            resulting_envelopes=result.resulting_envelopes,
            result=result,
            transition_digest=transition_digest,
            effect_intents=intents,
            effects=effects,
            observations=consumed,
        )
        self._transition_log.append(
            TransitionLog(
                index=transition.transition_index,
                command_id=command.command_id,
                command_digest=command.digest,
                outcome=result.outcome,
                transition_digest=transition_digest,
            )
        )
        self._submitted.append((command, intents))
        self._record_operation(
            "simulation/step",
            command.requested_at,
            f"command {command.command_id} -> {result.outcome.value}",
        )
        self._clock.logical_time = len(self._engine.journal)
        return transition

    def step(
        self,
        command: Command,
        *,
        effect_intents: Sequence[EffectIntent] = (),
    ) -> EnvironmentTransition:
        """Single-command debugger primitive (alias of :meth:`submit`)."""
        return self.submit(command, effect_intents=effect_intents)

    def run(
        self, commands: Iterable[Command]
    ) -> tuple[EnvironmentTransition, ...]:
        """Process a batch of commands in order (frozen ``Run`` verb)."""
        results = []
        for command in commands:
            results.append(self.submit(command))
        return tuple(results)

    # -- lifecycle (Pause/Resume/Complete/Fail/Cancel) -----------------------

    def _require_active(self, action: str) -> None:
        if self._run_state in SIMULATION_TERMINAL_STATES:
            raise CoreValidationError(
                f"environment run is terminal ({self._run_state.value}); "
                f"{action} fail closed"
            )
        if self._run_state is SimulationRunState.PAUSED:
            raise CoreValidationError(
                f"environment run is paused; {action} require an explicit resume"
            )

    def _advance_run_envelope(self, state: SimulationRunState, at: str) -> None:
        self._simulation_envelope = self._simulation_envelope.next_version(
            state=state.value,
            provenance=Provenance(
                issuer=self._provenance_issuer,
                source=f"simulation/{state.value.lower()}",
                recorded_at=at,
            ),
        ).with_integrity_hash()
        self._run_state = state

    def pause(self, at: str) -> None:
        require_utc_timestamp("pause at", at)
        self._require_active("pause")
        self._advance_run_envelope(SimulationRunState.PAUSED, at)
        self._record_operation("simulation/pause", at, "run paused")

    def resume(self, at: str) -> None:
        require_utc_timestamp("resume at", at)
        if self._run_state in SIMULATION_TERMINAL_STATES:
            raise CoreValidationError(
                "terminal runs never resume; history is immutable"
            )
        if self._run_state is not SimulationRunState.PAUSED:
            raise CoreValidationError("only paused runs can resume")
        self._advance_run_envelope(SimulationRunState.RUNNING, at)
        self._record_operation("simulation/resume", at, "run resumed")

    def _seal_result(
        self, state: SimulationRunState, at: str, note: str
    ) -> SimulationResult:
        return SimulationResult.seal(
            environment_id=self._spec.environment_id,
            domain_id=self._spec.domain_id,
            mode=self._spec.mode,
            run_state=state,
            at=at,
            provenance=Provenance(
                issuer=self._provenance_issuer,
                source=f"simulation/{state.value.lower()}",
                recorded_at=at,
            ),
            result_id=f"simulation/result/{self._simulation_envelope.object_id}",
            journal_digest=raw_journal_digest(self._engine.journal),
            state_digest=self.state_digest,
            parity_digest=parity_digest(self._engine.journal),
            namespace_digests=self.namespace_digests(),
            transition_count=len(self._transition_log),
            observation_count=len(self._observations),
            effect_count=len(self._effects),
            note=note,
        )

    def complete(self, at: str, *, note: str = "run completed") -> SimulationResult:
        require_utc_timestamp("complete at", at)
        self._require_active("complete")
        self._advance_run_envelope(SimulationRunState.COMPLETED, at)
        result = self._seal_result(SimulationRunState.COMPLETED, at, note)
        self._record_operation("simulation/complete", at, note)
        return result

    def fail(self, at: str, *, reason: str) -> SimulationResult:
        require_utc_timestamp("fail at", at)
        require_text("fail reason", reason)
        self._require_active("fail")
        self._advance_run_envelope(SimulationRunState.FAILED, at)
        result = self._seal_result(SimulationRunState.FAILED, at, reason)
        self._record_operation("simulation/fail", at, reason)
        return result

    def cancel(self, at: str, *, reason: str) -> SimulationResult:
        require_utc_timestamp("cancel at", at)
        require_text("cancel reason", reason)
        self._require_active("cancel")
        self._advance_run_envelope(SimulationRunState.CANCELLED, at)
        result = self._seal_result(SimulationRunState.CANCELLED, at, reason)
        self._record_operation("simulation/cancel", at, reason)
        return result

    # -- fault injection (InjectFault) ---------------------------------------

    def inject_fault(
        self,
        *,
        kind: FaultKind,
        reason: str,
        at: str,
        observation_key: str | None = None,
        effect_type: str | None = None,
    ) -> None:
        require_text("fault reason", reason)
        require_utc_timestamp("fault at", at)
        if not isinstance(kind, FaultKind):
            raise CoreValidationError("fault kind must be a FaultKind")
        if kind is FaultKind.WORLD_OBSERVATION_UNAVAILABLE:
            if observation_key is None or effect_type is not None:
                raise CoreValidationError(
                    "world observation faults target an observation key"
                )
            target = observation_key
            self._active_world_faults[target] = reason
        else:
            if effect_type is None or observation_key is not None:
                raise CoreValidationError(
                    "effect faults target an effect type"
                )
            target = effect_type
            self._active_effect_faults[target] = reason
        fault = FaultInjection(kind=kind, target=target, reason=reason, at=at)
        self._fault_journal.append(fault)
        self._record_operation(
            "simulation/inject-fault", at, f"fault {kind.value} on {target}"
        )

    def clear_fault(self, *, kind: FaultKind, target: str, at: str) -> None:
        require_utc_timestamp("clear fault at", at)
        if not isinstance(kind, FaultKind):
            raise CoreValidationError("fault kind must be a FaultKind")
        require_identifier("fault target", target)
        if kind is FaultKind.WORLD_OBSERVATION_UNAVAILABLE:
            if target not in self._active_world_faults:
                raise CoreValidationError(
                    f"no active world observation fault on {target!r}"
                )
            del self._active_world_faults[target]
        else:
            if target not in self._active_effect_faults:
                raise CoreValidationError(f"no active effect fault on {target!r}")
            del self._active_effect_faults[target]
        self._record_operation(
            "simulation/inject-fault", at, f"cleared fault {kind.value} on {target}"
        )

    # -- snapshots and checkpoints (Checkpoint) ------------------------------

    def snapshot(self, *, label: str = "", at: str = "") -> EnvironmentSnapshot:
        self._require_active("snapshots")
        require_text("snapshot label", label)
        require_utc_timestamp("snapshot at", at)
        engine_state = self._engine.snapshot_state()
        return EnvironmentSnapshot(
            environment_id=self._spec.environment_id,
            mode=self._spec.mode,
            domain_id=self._spec.domain_id,
            as_of=self._clock.as_of,
            clock=engine_state.logical_time,
            label=label,
            recorded_at=at,
            binding_fingerprint=self._binding.fingerprint,
            namespace_rules_digest=self._rules.digest,
            engine_state=engine_state.to_dict(),
            objects=tuple(
                envelope.to_dict() for envelope in self._store.snapshot()
            ),
            namespace_digests=self.namespace_digests(),
            observation_journal=tuple(
                observation.to_dict() for observation in self._observations
            ),
            effect_journal=tuple(record.to_dict() for record in self._effects),
            operation_journal=tuple(
                operation.to_dict() for operation in self._operations
            ),
            transition_log=tuple(log.to_dict() for log in self._transition_log),
            active_faults=tuple(
                (kind, target, reason)
                for kind, target, reason in self._fault_inventory()
            ),
            simulation_envelope=self._simulation_envelope.to_dict(),
        )

    def _fault_inventory(self) -> list[tuple[str, str, str]]:
        inventory = [
            ("world.observation-unavailable", target, reason)
            for target, reason in sorted(self._active_world_faults.items())
        ]
        inventory.extend(
            ("effect.failure", target, reason)
            for target, reason in sorted(self._active_effect_faults.items())
        )
        return sorted(inventory)

    def checkpoint(self, *, label: str = "", at: str = "") -> SimulationCheckpoint:
        self._require_active("checkpoints")
        require_text("checkpoint label", label)
        require_utc_timestamp("checkpoint at", at)
        snapshot = self.snapshot(label=label, at=at)
        self._checkpoint_sequence += 1
        checkpoint = SimulationCheckpoint.seal(
            snapshot=snapshot,
            sequence=self._checkpoint_sequence,
            parent_checkpoint_digest=self._last_checkpoint_digest,
            provenance=Provenance(
                issuer=self._provenance_issuer,
                source="simulation/checkpoint",
                recorded_at=at,
            ),
            checkpoint_id=f"simulation/checkpoint/{self._checkpoint_sequence}",
        )
        self._last_checkpoint_digest = checkpoint.checkpoint_digest
        self._record_operation(
            "simulation/checkpoint", at, f"checkpoint {self._checkpoint_sequence}"
        )
        return checkpoint

    def restore(self, checkpoint: SimulationCheckpoint) -> None:
        """Restore a sealed checkpoint into this environment, failing closed.

        Restore is the single in-place state-reconstruction path and it
        refuses every cross-boundary restore: wrong environment identity,
        wrong mode (simulation state is never copied into production
        financial state), wrong domain, mismatched binding fingerprint or
        mismatched namespace rules all fail closed. Terminal runs never
        resume. The restored snapshot content digest and checkpoint seal
        are verified first.
        """
        if not isinstance(checkpoint, SimulationCheckpoint):
            raise CoreValidationError("restore requires a SimulationCheckpoint")
        if self._run_state in SIMULATION_TERMINAL_STATES:
            raise CoreValidationError("terminal runs never resume")
        checkpoint.snapshot.verify()
        snapshot = checkpoint.snapshot
        if snapshot.environment_id != self._spec.environment_id:
            raise CoreValidationError(
                f"cross-environment restore fails closed: snapshot belongs to "
                f"environment {snapshot.environment_id}, not "
                f"{self._spec.environment_id}"
            )
        if snapshot.mode is not self._spec.mode:
            raise CoreValidationError(
                "cross-mode restore fails closed: simulation state is never "
                f"copied into production financial state (snapshot mode "
                f"{snapshot.mode.value}, runtime mode {self._spec.mode.value})"
            )
        if snapshot.domain_id != self._spec.domain_id:
            raise CoreValidationError(
                f"cross-domain restore fails closed: snapshot domain "
                f"{snapshot.domain_id} does not match {self._spec.domain_id}"
            )
        if snapshot.binding_fingerprint != self._binding.fingerprint:
            raise CoreValidationError(
                "restore fails closed: binding fingerprint mismatch (the same "
                "protocol machine must reconstruct the state)"
            )
        if snapshot.namespace_rules_digest != self._rules.digest:
            raise CoreValidationError(
                "restore fails closed: namespace rules digest mismatch"
            )
        envelopes = tuple(
            ObjectEnvelope.from_dict(item) for item in snapshot.objects
        )
        store = MemoryStateStore(envelopes)
        self._store = store
        self._initial_state = store.snapshot()
        self._namespaced = NamespacedStateStore(self._rules, store)
        self._engine = self._build_engine()
        self._engine.restore_state(EngineState.from_dict(snapshot.engine_state))
        self._clock = EnvironmentClock(
            logical_time=snapshot.clock, as_of=snapshot.as_of
        )
        self._observations = [
            WorldObservation.from_dict(item)
            for item in snapshot.observation_journal
        ]
        self._effects = [
            EffectRecord.from_dict(item) for item in snapshot.effect_journal
        ]
        self._operations = [
            SimulationOperation.from_dict(item)
            for item in snapshot.operation_journal
        ]
        self._transition_log = [
            TransitionLog.from_dict(item) for item in snapshot.transition_log
        ]
        self._submitted = []
        # Intent bookkeeping is reconstructed lazily: restored runs keep
        # duplicate-convergence through the kernel's engine state, and a
        # duplicate submission carrying external effect intents fails
        # closed on unknown originals rather than re-deciding effects.
        self._intents_by_command = {}
        self._effects_by_command = {}
        self._active_world_faults = {}
        self._active_effect_faults = {}
        for kind, target, reason in snapshot.active_faults:
            if kind == FaultKind.WORLD_OBSERVATION_UNAVAILABLE.value:
                self._active_world_faults[target] = reason
            else:
                self._active_effect_faults[target] = reason
        self._fault_journal = []
        self._world_view = WorldView(
            self._world,
            mode=self._spec.mode,
            journal=self._observations,
            clock=self._clock,
            world_faults=self._active_world_faults,
        )
        self._simulation_envelope = ObjectEnvelope.from_dict(
            snapshot.simulation_envelope
        )
        self._run_state = SimulationRunState(self._simulation_envelope.state)
        self._checkpoint_sequence = checkpoint.sequence
        self._last_checkpoint_digest = checkpoint.checkpoint_digest
        self._record_operation(
            "simulation/checkpoint",
            snapshot.recorded_at,
            f"restored checkpoint {checkpoint.sequence}",
        )

    def _record_operation(self, operation: str, at: str, detail: str) -> None:
        self._operations.append(
            SimulationOperation(
                sequence=len(self._operations) + 1,
                operation=operation,
                at=at,
                detail=detail,
            )
        )

    def _adopt_engine_state(self, engine_state: EngineState, *, as_of: str) -> None:
        """Package-internal: adopt a sealed engine history (branching).

        Branching is the one governed path along which protocol history
        crosses environment identities: the branch inherits the parent's
        engine clock, processed-command records and append-only journal
        (so duplicates of parent commands converge instead of
        re-executing), while the branched object state is re-bound to the
        new environment identity by the caller.
        """
        if not isinstance(engine_state, EngineState):
            raise CoreValidationError("adopted engine state must be an EngineState")
        require_utc_timestamp("adopted as_of", as_of)
        self._engine.restore_state(engine_state)
        self._clock.logical_time = engine_state.logical_time
        self._clock.as_of = as_of
