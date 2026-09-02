from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .registry import validate_authority_class, validate_event_type
from .validation import exact_fields, require_digest, require_text, validate_timestamp

EVENT_FIELDS = {
    "event_id",
    "event_type",
    "object_refs",
    "environment_id",
    "domain_id",
    "actor",
    "authority",
    "previous_state",
    "resulting_state",
    "object_versions",
    "occurred_at",
    "logical_time",
    "causation_id",
    "correlation_id",
    "payload_hash",
    "protocol_version",
}


def _require_state_array(name: str, value: tuple[str | None, ...], width: int) -> None:
    if not isinstance(value, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    if len(value) != width:
        raise CoreValidationError(f"{name} must align with object_refs")
    for entry in value:
        if entry is not None:
            require_text(f"{name} entry", entry)


@dataclass(frozen=True, slots=True)
class Event:
    """Immutable canonical event envelope (frozen v0.1 command-event model).

    Every event is caused (``causation_id`` names the command that produced
    it), registry-bound (``event_type`` namespace and ``authority`` class come
    from the frozen protocol registry) and never rewrites history: event ids
    are unique per emitted journal. ``object_versions`` entries are the
    resulting versions of the referenced objects; 0 encodes "object absent"
    and requires both state entries to be ``None``.
    """

    event_id: str
    event_type: str
    object_refs: tuple[str, ...]
    environment_id: str
    domain_id: str
    actor: str
    authority: str
    previous_state: tuple[str | None, ...]
    resulting_state: tuple[str | None, ...]
    object_versions: tuple[int, ...]
    occurred_at: str
    logical_time: int
    causation_id: str
    correlation_id: str | None = None
    payload_hash: str = "0" * 64
    protocol_version: str = "v0.1"

    def __post_init__(self) -> None:
        require_text("event_id", self.event_id)
        validate_event_type("event_type", self.event_type)
        for name in ("environment_id", "domain_id", "actor"):
            require_text(name, getattr(self, name))
        validate_authority_class("authority", self.authority)
        require_text("causation_id", self.causation_id)
        if self.correlation_id is not None:
            require_text("correlation_id", self.correlation_id)
        require_digest("payload_hash", self.payload_hash)
        require_text("protocol_version", self.protocol_version)
        validate_timestamp("occurred_at", self.occurred_at)
        if (
            not isinstance(self.logical_time, int)
            or isinstance(self.logical_time, bool)
            or self.logical_time < 1
        ):
            raise CoreValidationError("logical_time must be a positive integer")
        if not isinstance(self.object_refs, tuple) or not self.object_refs:
            raise CoreValidationError("object_refs must be a non-empty tuple")
        for ref in self.object_refs:
            require_text("object_refs entry", ref)
        if len(set(self.object_refs)) != len(self.object_refs):
            raise CoreValidationError("object_refs contains duplicate references")
        width = len(self.object_refs)
        _require_state_array("previous_state", self.previous_state, width)
        _require_state_array("resulting_state", self.resulting_state, width)
        if not isinstance(self.object_versions, tuple):
            raise CoreValidationError("object_versions must be a tuple")
        if len(self.object_versions) != width:
            raise CoreValidationError("object_versions must align with object_refs")
        for version in self.object_versions:
            if not isinstance(version, int) or isinstance(version, bool) or version < 0:
                raise CoreValidationError("object_versions entries must be non-negative integers")
        for previous, resulting, version in zip(
            self.previous_state, self.resulting_state, self.object_versions
        ):
            if version == 0:
                if previous is not None or resulting is not None:
                    raise CoreValidationError(
                        "object_versions 0 encodes an absent object and requires both state entries to be None"
                    )
            elif resulting is None:
                raise CoreValidationError(
                    "existing objects must record their resulting state"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "object_refs": list(self.object_refs),
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "actor": self.actor,
            "authority": self.authority,
            "previous_state": list(self.previous_state),
            "resulting_state": list(self.resulting_state),
            "object_versions": list(self.object_versions),
            "occurred_at": self.occurred_at,
            "logical_time": self.logical_time,
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "payload_hash": self.payload_hash,
            "protocol_version": self.protocol_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Event":
        if not isinstance(value, Mapping):
            raise CoreValidationError("event must be an object")
        exact_fields("event", value, EVENT_FIELDS)
        return cls(
            event_id=value["event_id"],
            event_type=value["event_type"],
            object_refs=tuple(value["object_refs"]),
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            actor=value["actor"],
            authority=value["authority"],
            previous_state=tuple(value["previous_state"]),
            resulting_state=tuple(value["resulting_state"]),
            object_versions=tuple(value["object_versions"]),
            occurred_at=value["occurred_at"],
            logical_time=value["logical_time"],
            causation_id=value["causation_id"],
            correlation_id=value["correlation_id"],
            payload_hash=value["payload_hash"],
            protocol_version=value["protocol_version"],
        )

    @classmethod
    def from_json(cls, value: str) -> "Event":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("canonical event JSON must decode to an object")
        return cls.from_dict(decoded)
