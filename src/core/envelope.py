from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Mapping

from .errors import CoreValidationError
from .serialization import canonical_sha256, normalize_immutable_value

# Identity fields may never change across an ordinary version transition.
# Changing any of them requires an explicitly governed migration mechanism,
# which does not exist in the frozen v0.1 architecture.
IDENTITY_FIELDS = (
    "object_id",
    "object_type",
    "environment_id",
    "domain_id",
    "schema_version",
    "protocol_version",
)


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def _require_positive(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CoreValidationError(f"{name} must be a positive integer")
    return value


def _normalize_pairs(name: str, value: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be a mapping")
    keys = list(value)
    for key in keys:
        _require_text(f"{name} key", key)
    if len(set(keys)) != len(keys):
        raise CoreValidationError(f"{name} contains duplicate keys")
    return tuple(
        (key, normalize_immutable_value(f"{name}.{key}", value[key]))
        for key in sorted(keys)
    )


def _validate_timestamp(name: str, value: str) -> None:
    _require_text(name, value)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc


@dataclass(frozen=True, slots=True)
class Provenance:
    issuer: str
    source: str
    recorded_at: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("provenance.issuer", self.issuer)
        _require_text("provenance.source", self.source)
        _validate_timestamp("provenance.recorded_at", self.recorded_at)
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("provenance.evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            _require_text("provenance.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "source": self.source,
            "recorded_at": self.recorded_at,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Provenance":
        if not isinstance(value, Mapping):
            raise CoreValidationError("provenance must be an object")
        if set(value) != {"issuer", "source", "recorded_at", "evidence_refs"}:
            raise CoreValidationError("provenance fields are not canonical")
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError("provenance.evidence_refs must deserialize from a list")
        return cls(
            issuer=value["issuer"],
            source=value["source"],
            recorded_at=value["recorded_at"],
            evidence_refs=tuple(refs),
        )


@dataclass(frozen=True, slots=True)
class ObjectEnvelope:
    """Immutable common envelope for every durable protocol object."""

    object_id: str
    object_type: str
    object_version: int
    environment_id: str
    domain_id: str
    schema_version: int
    protocol_version: str
    state: str
    provenance: Provenance
    causation_id: str | None = None
    correlation_id: str | None = None
    previous_version: int | None = None
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "object_id",
            "object_type",
            "environment_id",
            "domain_id",
            "protocol_version",
            "state",
        ):
            _require_text(name, getattr(self, name))
        _require_positive("object_version", self.object_version)
        _require_positive("schema_version", self.schema_version)
        if not isinstance(self.provenance, Provenance):
            raise CoreValidationError("provenance must be Provenance")
        for name in ("causation_id", "correlation_id", "integrity_hash"):
            value = getattr(self, name)
            if value is not None:
                _require_text(name, value)
        if self.previous_version is not None:
            _require_positive("previous_version", self.previous_version)
            if self.previous_version >= self.object_version:
                raise CoreValidationError("previous_version must be less than object_version")
        if self.object_version == 1 and self.previous_version is not None:
            raise CoreValidationError("version 1 cannot have previous_version")

    def canonical_dict(self, *, include_integrity_hash: bool = True) -> dict[str, Any]:
        value = {
            "object_id": self.object_id,
            "object_type": self.object_type,
            "object_version": self.object_version,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "state": self.state,
            "provenance": self.provenance.to_dict(),
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "previous_version": self.previous_version,
        }
        if include_integrity_hash:
            value["integrity_hash"] = self.integrity_hash
        return value

    def with_integrity_hash(self) -> "ObjectEnvelope":
        digest = canonical_sha256(self.canonical_dict(include_integrity_hash=False))
        return replace(self, integrity_hash=digest)

    def verify_integrity(self) -> None:
        """Recompute and verify the integrity hash on a trusted path.

        Envelopes without an integrity hash cannot be verified and are
        rejected; envelopes whose recorded hash does not match the
        recomputed canonical digest are rejected as tampered.
        """
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"integrity_hash is required for trusted deserialization of {self.object_id}"
            )
        expected = canonical_sha256(self.canonical_dict(include_integrity_hash=False))
        if self.integrity_hash != expected:
            raise CoreValidationError(f"integrity hash mismatch for object {self.object_id}")

    def next_version(self, **changes: Any) -> "ObjectEnvelope":
        """Create the next immutable version without mutating this object."""
        for field in IDENTITY_FIELDS:
            if field in changes and changes[field] != getattr(self, field):
                raise CoreValidationError(
                    f"identity field {field} cannot change across object versions"
                )
        if "object_version" in changes or "previous_version" in changes or "integrity_hash" in changes:
            raise CoreValidationError("version chain and integrity hash are controlled by next_version")
        return replace(
            self,
            object_version=self.object_version + 1,
            previous_version=self.object_version,
            integrity_hash=None,
            **changes,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.canonical_dict(include_integrity_hash=True)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObjectEnvelope":
        if not isinstance(value, Mapping):
            raise CoreValidationError("envelope must be an object")
        required = {
            "object_id", "object_type", "object_version", "environment_id",
            "domain_id", "schema_version", "protocol_version", "state",
            "provenance", "causation_id", "correlation_id", "previous_version",
            "integrity_hash",
        }
        if set(value) != required:
            missing = sorted(required - set(value))
            extra = sorted(set(value) - required)
            raise CoreValidationError(f"non-canonical envelope fields; missing={missing}, extra={extra}")
        envelope = cls(
            object_id=value["object_id"],
            object_type=value["object_type"],
            object_version=value["object_version"],
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            schema_version=value["schema_version"],
            protocol_version=value["protocol_version"],
            state=value["state"],
            provenance=Provenance.from_dict(value["provenance"]),
            causation_id=value["causation_id"],
            correlation_id=value["correlation_id"],
            previous_version=value["previous_version"],
            integrity_hash=value["integrity_hash"],
        )
        envelope.verify_integrity()
        return envelope
