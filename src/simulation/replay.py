"""Deterministic replay over the recorded environment journal (WORK-019).

``REPLAY`` is historical observation/state reconstruction: the same
protocol commands, the same recorded world observations and the same
binding are re-driven through a fresh :class:`EnvironmentRuntime` over
the REAL transition kernel — never a second state machine. A
:class:`ReplayJournal` is the sealed durable record of one run (the
submitted commands in order, their recorded transition digests, the
consumed world observations, the initial state and the final digests),
and :func:`replay` proves determinism end to end: every replayed entry
must reproduce its recorded outcome and per-entry transition digest, and
the final journal, state and namespace digests must match exactly.
Divergence fails closed with the exact entry at which history stopped
matching.

Determinism discipline: the journal is addressed by declared data only —
explicit ``as_of`` instants, recorded observations, no clock reads, no
entropy sources.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import Command, Outcome

from ._validation import (
    require_digest,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import EnvironmentMode, StateNamespace, mode_epistemic_type
from .effects import EffectIntent, EffectPolicy
from .runtime import (
    EnvironmentRuntime,
    EnvironmentSpec,
    ProtocolBinding,
    raw_journal_digest,
)
from .state import DEFAULT_NAMESPACE_RULES
from .world import ScriptedWorld, WorldObservation

_ENTRY_FIELDS = frozenset(
    {
        "index",
        "command",
        "command_id",
        "command_digest",
        "outcome",
        "transition_digest",
        "effect_intents",
    }
)
_JOURNAL_FIELDS = frozenset({"content", "integrity_hash"})
_CONTENT_FIELDS = frozenset(
    {
        "environment_id",
        "mode",
        "domain_id",
        "as_of",
        "label",
        "binding_fingerprint",
        "namespace_rules_digest",
        "simulation_id",
        "initial_objects",
        "entries",
        "observations",
        "final_journal_digest",
        "final_state_digest",
        "namespace_digests",
    }
)


@dataclass(frozen=True, slots=True)
class ReplayEntry:
    """One recorded submission: the exact command, its outcome, its sealed
    transition digest and the external effect intents it carried."""

    index: int
    command: Command
    command_id: str
    command_digest: str
    outcome: Outcome
    transition_digest: str
    effect_intents: tuple[EffectIntent, ...]

    def __post_init__(self) -> None:
        require_int("replay entry index", self.index, minimum=1)
        if not isinstance(self.command, Command):
            raise CoreValidationError("replay entry command must be a Command")
        if self.command.command_id != self.command_id:
            raise CoreValidationError(
                "replay entry command_id must match the recorded command"
            )
        require_digest("replay entry command_digest", self.command_digest)
        if self.command.digest != self.command_digest:
            raise CoreValidationError(
                "replay entry command_digest must match the recorded command"
            )
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("replay entry outcome must be an Outcome")
        require_digest("replay entry transition_digest", self.transition_digest)
        if not isinstance(self.effect_intents, tuple):
            raise CoreValidationError("replay entry effect_intents must be a tuple")
        for intent in self.effect_intents:
            if not isinstance(intent, EffectIntent):
                raise CoreValidationError(
                    "replay entry effect_intents entries must be EffectIntent records"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "command": self.command.to_dict(),
            "command_id": self.command_id,
            "command_digest": self.command_digest,
            "outcome": self.outcome.value,
            "transition_digest": self.transition_digest,
            "effect_intents": [intent.to_dict() for intent in self.effect_intents],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReplayEntry":
        if not isinstance(value, Mapping):
            raise CoreValidationError("replay entry must be an object")
        strict_fields("replay entry", value, _ENTRY_FIELDS)
        intents_raw = value["effect_intents"]
        if not isinstance(intents_raw, list):
            raise CoreValidationError(
                "replay entry effect_intents must deserialize from a list"
            )
        return cls(
            index=value["index"],
            command=Command.from_dict(value["command"]),
            command_id=value["command_id"],
            command_digest=value["command_digest"],
            outcome=Outcome(value["outcome"]),
            transition_digest=value["transition_digest"],
            effect_intents=tuple(
                EffectIntent.from_dict(item) for item in intents_raw
            ),
        )


@dataclass(frozen=True, slots=True)
class ReplayJournal:
    """The sealed durable record of one environment run.

    The durable form is ``{"content": {...}, "integrity_hash": ...}``:
    the content carries the run identity, the binding fingerprint, the
    namespace-rules digest, the initial object state, the ordered
    entries, the consumed world observations and the final digests; the
    seal is computed with the single canonical hash authority, so
    tampered or spliced journals fail closed on the trusted
    deserialization path.
    """

    environment_id: str
    mode: EnvironmentMode
    domain_id: str
    as_of: str
    label: str
    binding_fingerprint: str
    namespace_rules_digest: str
    simulation_id: str
    initial_objects: tuple[dict[str, Any], ...]
    entries: tuple[ReplayEntry, ...]
    observations: tuple[dict[str, Any], ...]
    final_journal_digest: str
    final_state_digest: str
    namespace_digests: tuple[tuple[str, str], ...]
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        require_identifier("replay journal environment_id", self.environment_id)
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError("replay journal mode must be an EnvironmentMode")
        require_identifier("replay journal domain_id", self.domain_id)
        require_utc_timestamp("replay journal as_of", self.as_of)
        require_text("replay journal label", self.label)
        require_digest("replay journal binding_fingerprint", self.binding_fingerprint)
        require_digest(
            "replay journal namespace_rules_digest", self.namespace_rules_digest
        )
        require_identifier("replay journal simulation_id", self.simulation_id)
        if not isinstance(self.initial_objects, tuple) or not isinstance(
            self.entries, tuple
        ) or not isinstance(self.observations, tuple):
            raise CoreValidationError("replay journal collections must be tuples")
        for item in self.initial_objects:
            if not isinstance(item, Mapping):
                raise CoreValidationError(
                    "replay journal initial objects must be objects"
                )
        for entry in self.entries:
            if not isinstance(entry, ReplayEntry):
                raise CoreValidationError(
                    "replay journal entries must be ReplayEntry records"
                )
        for item in self.observations:
            if not isinstance(item, Mapping):
                raise CoreValidationError(
                    "replay journal observations must be objects"
                )
        require_digest("replay journal final_journal_digest", self.final_journal_digest)
        require_digest("replay journal final_state_digest", self.final_state_digest)
        for pair in self.namespace_digests:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise CoreValidationError(
                    "replay journal namespace_digests entries must be "
                    "(namespace, digest) tuples"
                )
        expected = canonical_sha256(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                "replay journal integrity hash mismatch; tampered journals fail closed"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "mode": self.mode.value,
            "domain_id": self.domain_id,
            "as_of": self.as_of,
            "label": self.label,
            "binding_fingerprint": self.binding_fingerprint,
            "namespace_rules_digest": self.namespace_rules_digest,
            "simulation_id": self.simulation_id,
            "initial_objects": list(self.initial_objects),
            "entries": [entry.to_dict() for entry in self.entries],
            "observations": list(self.observations),
            "final_journal_digest": self.final_journal_digest,
            "final_state_digest": self.final_state_digest,
            "namespace_digests": [list(pair) for pair in self.namespace_digests],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self._content(),
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReplayJournal":
        if not isinstance(value, Mapping):
            raise CoreValidationError("replay journal must be an object")
        strict_fields("replay journal", value, _JOURNAL_FIELDS)
        content = value["content"]
        if not isinstance(content, Mapping):
            raise CoreValidationError("replay journal content must be an object")
        strict_fields("replay journal content", content, _CONTENT_FIELDS)
        entries_raw = content["entries"]
        objects_raw = content["initial_objects"]
        observations_raw = content["observations"]
        digests_raw = content["namespace_digests"]
        for name, raw in (
            ("entries", entries_raw),
            ("initial_objects", objects_raw),
            ("observations", observations_raw),
            ("namespace_digests", digests_raw),
        ):
            if not isinstance(raw, list):
                raise CoreValidationError(
                    f"replay journal {name} must deserialize from a list"
                )
        return cls(
            environment_id=content["environment_id"],
            mode=EnvironmentMode.parse(content["mode"]),
            domain_id=content["domain_id"],
            as_of=content["as_of"],
            label=content["label"],
            binding_fingerprint=content["binding_fingerprint"],
            namespace_rules_digest=content["namespace_rules_digest"],
            simulation_id=content["simulation_id"],
            initial_objects=tuple(objects_raw),
            entries=tuple(ReplayEntry.from_dict(item) for item in entries_raw),
            observations=tuple(observations_raw),
            final_journal_digest=content["final_journal_digest"],
            final_state_digest=content["final_state_digest"],
            namespace_digests=tuple(
                (pair[0], pair[1]) for pair in digests_raw
            ),
            integrity_hash=value["integrity_hash"],
        )

    def verify(self) -> None:
        """Fail closed unless the recorded seal matches the content."""
        expected = canonical_sha256(self._content())
        if self.integrity_hash != expected:
            raise CoreValidationError(
                "replay journal integrity hash mismatch; tampered journals fail closed"
            )

    @classmethod
    def from_runtime(
        cls, runtime: EnvironmentRuntime, *, label: str
    ) -> "ReplayJournal":
        """Record the sealed journal of one live run."""
        if not isinstance(runtime, EnvironmentRuntime):
            raise CoreValidationError(
                "replay journals are recorded from EnvironmentRuntime runs"
            )
        require_text("replay journal label", label)
        entries: list[ReplayEntry] = []
        for log, (command, intents) in zip(
            runtime.transitions, runtime.submitted_commands
        ):
            if log.command_id != command.command_id:
                raise CoreValidationError(
                    "runtime transition log and submitted commands disagree"
                )
            entries.append(
                ReplayEntry(
                    index=log.index,
                    command=command,
                    command_id=log.command_id,
                    command_digest=log.command_digest,
                    outcome=log.outcome,
                    transition_digest=log.transition_digest,
                    effect_intents=intents,
                )
            )
        return cls(
            environment_id=runtime.environment_id,
            mode=runtime.mode,
            domain_id=runtime.domain_id,
            as_of=runtime.spec.as_of,
            label=label,
            binding_fingerprint=runtime.binding.fingerprint,
            namespace_rules_digest=runtime.namespace_rules.digest,
            simulation_id=runtime.simulation_envelope.object_id,
            initial_objects=tuple(
                envelope.to_dict() for envelope in runtime.initial_state
            ),
            entries=tuple(entries),
            observations=tuple(
                observation.to_dict() for observation in runtime.observations
            ),
            final_journal_digest=raw_journal_digest(runtime.journal),
            final_state_digest=runtime.state_digest,
            namespace_digests=runtime.namespace_digests(),
        )


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """The outcome of one deterministic replay.

    The report carries the replayed counts and digests (which equal the
    journal's recorded final digests — divergence failed closed
    otherwise) plus the live replayed runtime for inspection. The
    durable form of a replay is the journal itself; the runtime is the
    live artifact and is therefore not serialized here.
    """

    environment_id: str
    mode: EnvironmentMode
    entries_replayed: int
    journal_digest: str
    state_digest: str
    namespace_digests: tuple[tuple[str, str], ...]
    runtime: EnvironmentRuntime

    def __post_init__(self) -> None:
        require_identifier("replay report environment_id", self.environment_id)
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError("replay report mode must be an EnvironmentMode")
        require_int(
            "replay report entries_replayed", self.entries_replayed, minimum=0
        )
        require_digest("replay report journal_digest", self.journal_digest)
        require_digest("replay report state_digest", self.state_digest)
        if not isinstance(self.runtime, EnvironmentRuntime):
            raise CoreValidationError(
                "replay report runtime must be an EnvironmentRuntime"
            )
        for pair in self.namespace_digests:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise CoreValidationError(
                    "replay report namespace_digests entries must be "
                    "(namespace, digest) tuples"
                )


def replay(
    journal: ReplayJournal,
    *,
    binding: ProtocolBinding,
    effect_policy: EffectPolicy | None = None,
) -> ReplayReport:
    """Re-drive one sealed journal through a fresh environment runtime.

    The replayed runtime is rebuilt from declared data only: the same
    environment identity and mode (so the epistemic gating of the world
    view is exercised again), the same binding (the same protocol
    machine — a fingerprint mismatch fails closed), the same initial
    object state and a scripted world serving exactly the recorded
    observations. Every entry must reproduce its recorded outcome and
    per-entry transition digest; the final journal, state and namespace
    digests must match the recorded ones. Any divergence fails closed
    with the exact entry at which it happened.
    """
    if not isinstance(journal, ReplayJournal):
        raise CoreValidationError("replay requires a ReplayJournal")
    if not isinstance(binding, ProtocolBinding):
        raise CoreValidationError("replay requires a ProtocolBinding")
    journal.verify()
    if journal.binding_fingerprint != binding.fingerprint:
        raise CoreValidationError(
            "replay fails closed: the binding fingerprint does not match the "
            "recorded journal (the same protocol machine must replay the history)"
        )
    if journal.namespace_rules_digest != DEFAULT_NAMESPACE_RULES.digest:
        raise CoreValidationError(
            "replay fails closed: the namespace rules digest does not match "
            "the default classification of this domain"
        )
    observations = tuple(
        WorldObservation.from_dict(item) for item in journal.observations
    )
    world = ScriptedWorld(
        observations, epistemic_type=mode_epistemic_type(journal.mode)
    )
    envelopes = tuple(
        ObjectEnvelope.from_dict(item) for item in journal.initial_objects
    )
    grouped: dict[StateNamespace, list[ObjectEnvelope]] = {}
    for envelope in envelopes:
        grouped.setdefault(
            DEFAULT_NAMESPACE_RULES.classify(envelope.object_id), []
        ).append(envelope)
    runtime = EnvironmentRuntime(
        spec=EnvironmentSpec(
            environment_id=journal.environment_id,
            mode=journal.mode,
            domain_id=journal.domain_id,
            as_of=journal.as_of,
        ),
        binding=binding,
        world=world,
        initial_state=grouped,
        effect_policy=effect_policy,
        simulation_id=journal.simulation_id,
        first_operation="simulation/replay",
    )
    for entry in journal.entries:
        transition = runtime.submit(
            entry.command, effect_intents=entry.effect_intents
        )
        if transition.outcome is not entry.outcome:
            raise CoreValidationError(
                f"replay divergence at entry {entry.index}: outcome "
                f"{transition.outcome.value} does not match the recorded "
                f"{entry.outcome.value}"
            )
        if transition.transition_digest != entry.transition_digest:
            raise CoreValidationError(
                f"replay divergence at entry {entry.index}: the replayed "
                "transition digest does not match the recorded journal entry"
            )
    journal_digest = raw_journal_digest(runtime.journal)
    state_digest = runtime.state_digest
    namespace_digests = runtime.namespace_digests()
    if journal_digest != journal.final_journal_digest:
        raise CoreValidationError(
            "replay divergence: the final journal digest does not match the "
            "recorded journal"
        )
    if state_digest != journal.final_state_digest:
        raise CoreValidationError(
            "replay divergence: the final state digest does not match the "
            "recorded journal"
        )
    if namespace_digests != journal.namespace_digests:
        raise CoreValidationError(
            "replay divergence: the final namespace digests do not match the "
            "recorded journal"
        )
    return ReplayReport(
        environment_id=journal.environment_id,
        mode=journal.mode,
        entries_replayed=len(journal.entries),
        journal_digest=journal_digest,
        state_digest=state_digest,
        namespace_digests=namespace_digests,
        runtime=runtime,
    )
