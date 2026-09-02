"""The deterministic world adapter boundary (WORK-019).

The environment supplies world observations; the protocol machine never
reads the outside world directly. Every observation carries the frozen
epistemic type (vocabulary owned by ``src.evidence``), the explicit
``as_of`` instant the world was observed at and a canonical value.

Determinism discipline: adapters are addressed by
``(observation_key, as_of)`` pairs with explicit instants — the domain
contains no wall-clock reads, no entropy sources and no identifier
generation. Missing observations fail closed (implementation principle
6: fail closed on unknown evidence).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition.payload import normalize_payload, payload_to_json_value

from ._validation import (
    require_identifier,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import EpistemicType, mode_epistemic_type, EnvironmentMode

_OBSERVATION_FIELDS = frozenset(
    {
        "observation_key",
        "epistemic_type",
        "as_of",
        "value",
        "source",
    }
)


@dataclass(frozen=True, slots=True)
class WorldObservation:
    """One immutable world observation record.

    The value is normalized into the deeply immutable payload form owned
    by the transition kernel's public payload utilities (floats and unsafe
    values fail closed). The record carries no seal of its own: world
    observations are environment-local evidence; integrity is covered
    transitively by the environment snapshot content digest.
    """

    observation_key: str
    epistemic_type: EpistemicType
    as_of: str
    value: Any
    source: str

    def __post_init__(self) -> None:
        require_identifier("world observation key", self.observation_key)
        if not isinstance(self.epistemic_type, EpistemicType):
            raise CoreValidationError(
                "world observation epistemic_type must be the frozen EpistemicType"
            )
        require_utc_timestamp("world observation as_of", self.as_of)
        require_text("world observation source", self.source)
        object.__setattr__(
            self, "value", normalize_payload("world observation value", self.value)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_key": self.observation_key,
            "epistemic_type": self.epistemic_type.value,
            "as_of": self.as_of,
            "value": payload_to_json_value(self.value),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "WorldObservation":
        if not isinstance(value, Mapping):
            raise CoreValidationError("world observation must be an object")
        strict_fields("world observation", value, _OBSERVATION_FIELDS)
        try:
            epistemic_type = EpistemicType(value["epistemic_type"])
        except ValueError as exc:
            raise CoreValidationError(
                "world observation epistemic_type must be the frozen EpistemicType"
            ) from exc
        return cls(
            observation_key=value["observation_key"],
            epistemic_type=epistemic_type,
            as_of=value["as_of"],
            value=value["value"],
            source=value["source"],
        )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


class WorldAdapter(abc.ABC):
    """The deterministic boundary through which an environment observes the world.

    Implementations must be pure functions of
    ``(observation_key, as_of)``: no clock reads, no entropy, no hidden
    state transitions. Unknown observations fail closed.
    """

    @property
    @abc.abstractmethod
    def epistemic_type(self) -> EpistemicType:
        """The declared epistemic type every served observation carries."""

    @abc.abstractmethod
    def observe(self, observation_key: str, as_of: str) -> WorldObservation:
        """Return the world observation for one key at one explicit instant."""


@dataclass
class EnvironmentClock:
    """Mutable holder of the environment's explicit clock state.

    The runtime advances the logical time and the environment ``as_of``
    deterministically from submitted commands; the world view exposes
    both to protocol handlers so handlers never read a clock.
    """

    logical_time: int = 0
    as_of: str = ""


class WorldView:
    """Read-only deterministic world boundary handed to protocol handlers.

    The view is the ONLY path through which world observations reach
    protocol transitions. It enforces the mode/epistemic gating at every
    observation (a lying adapter that serves a record of the wrong
    epistemic type fails closed) and journals every consumed observation
    into the owning environment.
    """

    def __init__(
        self,
        adapter: WorldAdapter,
        *,
        mode: EnvironmentMode,
        journal: list[WorldObservation],
        clock: EnvironmentClock,
        world_faults: Mapping[str, str],
    ) -> None:
        if not isinstance(adapter, WorldAdapter):
            raise CoreValidationError("world view requires a WorldAdapter")
        self._adapter = adapter
        self._required = mode_epistemic_type(mode)
        self._journal = journal
        self._clock = clock
        self._world_faults = world_faults

    @property
    def clock(self) -> int:
        return self._clock.logical_time

    @property
    def as_of(self) -> str:
        return self._clock.as_of

    def observe(self, observation_key: str, as_of: str) -> WorldObservation:
        fault = self._world_faults.get(observation_key)
        if fault is not None:
            raise CoreValidationError(
                f"injected fault on world observation {observation_key!r}: {fault}"
            )
        record = self._adapter.observe(observation_key, as_of)
        if not isinstance(record, WorldObservation):
            raise CoreValidationError(
                "world adapter must return a WorldObservation record"
            )
        if record.epistemic_type is not self._required:
            raise CoreValidationError(
                f"epistemic-type confusion: environment mode requires "
                f"{self._required.value} observations but {observation_key!r} "
                f"carries {record.epistemic_type.value}"
            )
        if record.epistemic_type is not self._adapter.epistemic_type:
            raise CoreValidationError(
                f"world adapter served an observation of {record.epistemic_type.value} "
                f"while declaring {self._adapter.epistemic_type.value}"
            )
        if record.as_of != as_of:
            raise CoreValidationError(
                f"world observation {observation_key!r} was requested at {as_of} "
                f"but served at {record.as_of}"
            )
        self._journal.append(record)
        return record


class ScriptedWorld(WorldAdapter):
    """A fully deterministic scripted world.

    Serves the exact recorded observations by
    ``(observation_key, as_of)``. Conflicting duplicates fail closed at
    construction; exact duplicates are tolerated (the same world value
    may be observed by several commands). Unknown keys and unknown
    instants fail closed at observe time.
    """

    def __init__(
        self,
        observations: Iterable[WorldObservation],
        *,
        epistemic_type: EpistemicType,
    ) -> None:
        if not isinstance(epistemic_type, EpistemicType):
            raise CoreValidationError(
                "scripted world requires the frozen EpistemicType"
            )
        self._epistemic_type = epistemic_type
        self._records: dict[tuple[str, str], WorldObservation] = {}
        for observation in observations:
            if not isinstance(observation, WorldObservation):
                raise CoreValidationError(
                    "scripted world observations must be WorldObservation records"
                )
            if observation.epistemic_type is not epistemic_type:
                raise CoreValidationError(
                    "scripted world mixes epistemic types: declared "
                    f"{epistemic_type.value}, got {observation.epistemic_type.value}"
                )
            key = (observation.observation_key, observation.as_of)
            existing = self._records.get(key)
            if existing is not None and existing != observation:
                raise CoreValidationError(
                    f"scripted world contains conflicting observations for "
                    f"{observation.observation_key!r} at {observation.as_of}"
                )
            self._records[key] = observation

    @property
    def epistemic_type(self) -> EpistemicType:
        return self._epistemic_type

    def observe(self, observation_key: str, as_of: str) -> WorldObservation:
        record = self._records.get((observation_key, as_of))
        if record is None:
            raise CoreValidationError(
                f"world observation {observation_key!r} at {as_of} is not scripted; "
                "the environment fails closed on unknown observations"
            )
        return record
