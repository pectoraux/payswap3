from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from .payload import check_payload_value, normalize_payload, payload_to_json_value
from .validation import exact_fields, require_text, validate_timestamp

COMMAND_FIELDS = {
    "command_id",
    "command_type",
    "actor",
    "authority_refs",
    "target_refs",
    "payload",
    "environment_id",
    "domain_id",
    "expected_versions",
    "idempotency_key",
    "nonce",
    "requested_at",
    "causation_id",
    "correlation_id",
}


def _require_refs(name: str, value: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    for ref in value:
        require_text(f"{name} entry", ref)
    if len(set(value)) != len(value):
        raise CoreValidationError(f"{name} contains duplicate references")
    return value


@dataclass(frozen=True, slots=True)
class ExpectedVersion:
    """Optimistic-concurrency precondition on one declared object reference.

    ``object_version`` 0 means the object must not exist yet (creation
    precondition); a positive value means the object must be exactly at that
    version when the command executes.
    """

    object_ref: str
    object_version: int

    def __post_init__(self) -> None:
        require_text("expected_version.object_ref", self.object_ref)
        if (
            not isinstance(self.object_version, int)
            or isinstance(self.object_version, bool)
            or self.object_version < 0
        ):
            raise CoreValidationError(
                "expected_version.object_version must be a non-negative integer"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_ref": self.object_ref,
            "object_version": self.object_version,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExpectedVersion":
        if not isinstance(value, Mapping):
            raise CoreValidationError("expected version must be an object")
        exact_fields("expected version", value, {"object_ref", "object_version"})
        return cls(
            object_ref=value["object_ref"],
            object_version=value["object_version"],
        )


@dataclass(frozen=True, slots=True)
class Command:
    """Immutable command envelope (frozen v0.1 command-event model).

    Direct construction requires payloads already in the deeply immutable
    storage form; use :meth:`build` to normalize canonical JSON values
    (mirroring the core ``Relationship.build`` discipline).
    """

    command_id: str
    command_type: str
    actor: str
    authority_refs: tuple[str, ...]
    target_refs: tuple[str, ...]
    payload: Any
    environment_id: str
    domain_id: str
    expected_versions: tuple[ExpectedVersion, ...]
    idempotency_key: str
    nonce: str
    requested_at: str
    causation_id: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "command_id",
            "command_type",
            "actor",
            "environment_id",
            "domain_id",
            "idempotency_key",
            "nonce",
        ):
            require_text(name, getattr(self, name))
        validate_timestamp("requested_at", self.requested_at)
        _require_refs("authority_refs", self.authority_refs)
        target_refs = _require_refs("target_refs", self.target_refs)
        if not target_refs:
            raise CoreValidationError("target_refs must declare at least one target object")
        if not isinstance(self.expected_versions, tuple):
            raise CoreValidationError("expected_versions must be a tuple")
        declared: list[str] = []
        for expected in self.expected_versions:
            if not isinstance(expected, ExpectedVersion):
                raise CoreValidationError("expected_versions entries must be ExpectedVersion")
            declared.append(expected.object_ref)
        if len(set(declared)) != len(declared):
            raise CoreValidationError("expected_versions contains duplicate object references")
        check_payload_value("payload", self.payload)
        for name in ("causation_id", "correlation_id"):
            if getattr(self, name) is not None:
                require_text(name, getattr(self, name))

    @classmethod
    def build(
        cls,
        *,
        command_id: str,
        command_type: str,
        actor: str,
        target_refs: tuple[str, ...],
        payload: Any,
        environment_id: str,
        domain_id: str,
        idempotency_key: str,
        nonce: str,
        requested_at: str,
        authority_refs: tuple[str, ...] = (),
        expected_versions: tuple[ExpectedVersion, ...] = (),
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Command":
        return cls(
            command_id=command_id,
            command_type=command_type,
            actor=actor,
            authority_refs=tuple(authority_refs),
            target_refs=tuple(target_refs),
            payload=normalize_payload("payload", payload),
            environment_id=environment_id,
            domain_id=domain_id,
            expected_versions=tuple(expected_versions),
            idempotency_key=idempotency_key,
            nonce=nonce,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command_type": self.command_type,
            "actor": self.actor,
            "authority_refs": list(self.authority_refs),
            "target_refs": list(self.target_refs),
            "payload": payload_to_json_value(self.payload),
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "expected_versions": [expected.to_dict() for expected in self.expected_versions],
            "idempotency_key": self.idempotency_key,
            "nonce": self.nonce,
            "requested_at": self.requested_at,
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Command":
        if not isinstance(value, Mapping):
            raise CoreValidationError("command must be an object")
        exact_fields("command", value, COMMAND_FIELDS)
        expected_raw = value["expected_versions"]
        if not isinstance(expected_raw, list):
            raise CoreValidationError("command.expected_versions must deserialize from a list")
        expected = tuple(ExpectedVersion.from_dict(item) for item in expected_raw)
        return cls(
            command_id=value["command_id"],
            command_type=value["command_type"],
            actor=value["actor"],
            authority_refs=tuple(value["authority_refs"]),
            target_refs=tuple(value["target_refs"]),
            payload=normalize_payload("payload", value["payload"]),
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            expected_versions=expected,
            idempotency_key=value["idempotency_key"],
            nonce=value["nonce"],
            requested_at=value["requested_at"],
            causation_id=value["causation_id"],
            correlation_id=value["correlation_id"],
        )

    @classmethod
    def from_json(cls, value: str) -> "Command":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("canonical command JSON must decode to an object")
        return cls.from_dict(decoded)
