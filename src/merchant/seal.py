from __future__ import annotations

from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from ._validation import fields
from .contracts import PROTOCOL, SCHEMA_VERSION

COMPOSITE_FIELDS = {"envelope", "payload", "integrity_hash"}


def build_envelope(*, object_id: str, object_type: str, state: str, environment_id: str,
                   domain_id: str, provenance: Provenance, causation_id: str | None = None,
                   correlation_id: str | None = None) -> ObjectEnvelope:
    envelope = ObjectEnvelope(
        object_id=object_id, object_type=object_type, object_version=1,
        environment_id=environment_id, domain_id=domain_id,
        schema_version=SCHEMA_VERSION, protocol_version=PROTOCOL,
        state=state, provenance=provenance, causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return envelope.with_integrity_hash()


def seal(envelope: ObjectEnvelope, payload: Any) -> str:
    return canonical_sha256({"envelope": envelope.to_dict(), "payload": payload.to_dict()})


def verify(envelope: ObjectEnvelope, payload: Any, integrity_hash: object) -> None:
    if not isinstance(integrity_hash, str) or not integrity_hash:
        raise CoreValidationError(f"integrity_hash is required for {envelope.object_id}")
    if integrity_hash != seal(envelope, payload):
        raise CoreValidationError(f"integrity hash mismatch for object {envelope.object_id}")


def to_dict(envelope: ObjectEnvelope, payload: Any, integrity_hash: str) -> dict[str, Any]:
    return {"envelope": envelope.to_dict(), "payload": payload.to_dict(), "integrity_hash": integrity_hash}


def to_json(envelope: ObjectEnvelope, payload: Any, integrity_hash: str) -> str:
    return canonical_json(to_dict(envelope, payload, integrity_hash))


def decode(value: Mapping[str, Any], *, object_type: str, state_type: type[StrEnum]) -> tuple[ObjectEnvelope, Mapping[str, Any], str]:
    fields(object_type, value, COMPOSITE_FIELDS)
    envelope = ObjectEnvelope.from_dict(value["envelope"])
    if envelope.object_type != object_type:
        raise CoreValidationError(f"object_type mismatch: expected {object_type}, got {envelope.object_type}")
    if envelope.schema_version != SCHEMA_VERSION or envelope.protocol_version != PROTOCOL:
        raise CoreValidationError(f"{object_type} version binding mismatch")
    try:
        state_type(envelope.state)
    except ValueError as exc:
        raise CoreValidationError(f"unknown {object_type} state: {envelope.state!r}") from exc
    payload = value["payload"]
    if not isinstance(payload, Mapping):
        raise CoreValidationError(f"{object_type} payload must be an object")
    return envelope, payload, value["integrity_hash"]


def decode_json(value: str, *, object_type: str, state_type: type[StrEnum]) -> tuple[ObjectEnvelope, Mapping[str, Any], str]:
    decoded = loads_canonical(value)
    if not isinstance(decoded, dict):
        raise CoreValidationError(f"{object_type} JSON must decode to an object")
    return decode(decoded, object_type=object_type, state_type=state_type)
