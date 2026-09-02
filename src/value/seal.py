"""Composite sealing for value domain durable objects.

Every value domain durable object is ``ObjectEnvelope + payload`` and
carries a domain seal: a SHA-256 digest computed with the single
canonical hash authority (``src.core.serialization.canonical_sha256``)
over the sealed envelope plus the canonical payload. This mirrors the
remediated core pattern (W032: ``from_dict``/``from_json`` verify
integrity and reject unsealed or tampered envelopes) at the composite
layer, so tampered or spliced composite objects fail closed on the
trusted deserialization path. No second hash or error authority is
introduced.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from .contracts import VALUE_PROTOCOL_VERSION, VALUE_SCHEMA_VERSION
from .validation import strict_fields

COMPOSITE_FIELDS = frozenset({"envelope", "payload", "integrity_hash"})


def build_domain_envelope(
    *,
    object_id: str,
    object_type: str,
    state: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ObjectEnvelope:
    """Build and seal a version-1 domain envelope bound to the frozen contracts."""
    if not isinstance(provenance, Provenance):
        raise CoreValidationError("provenance must be a Provenance")
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=1,
        environment_id=environment_id,
        domain_id=domain_id,
        schema_version=VALUE_SCHEMA_VERSION,
        protocol_version=VALUE_PROTOCOL_VERSION,
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return envelope.with_integrity_hash()


def advance_domain_envelope(
    envelope: ObjectEnvelope,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ObjectEnvelope:
    """Produce the next sealed envelope version (identity fields frozen)."""
    if not isinstance(provenance, Provenance):
        raise CoreValidationError("provenance must be a Provenance")
    return envelope.next_version(
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    ).with_integrity_hash()


def seal_composite(envelope: ObjectEnvelope, payload: Any) -> str:
    """Domain seal over the sealed envelope plus the canonical payload."""
    return canonical_sha256({"envelope": envelope.to_dict(), "payload": payload.to_dict()})


def verify_composite(
    envelope: ObjectEnvelope,
    payload: Any,
    integrity_hash: Any,
    object_id: str,
) -> None:
    """Fail closed on missing, forged or mismatched domain seals."""
    if not isinstance(integrity_hash, str) or not integrity_hash:
        raise CoreValidationError(
            f"integrity_hash is required for trusted deserialization of {object_id}"
        )
    expected = seal_composite(envelope, payload)
    if integrity_hash != expected:
        raise CoreValidationError(f"integrity hash mismatch for object {object_id}")


def composite_to_dict(envelope: ObjectEnvelope, payload: Any, integrity_hash: str) -> dict[str, Any]:
    return {
        "envelope": envelope.to_dict(),
        "payload": payload.to_dict(),
        "integrity_hash": integrity_hash,
    }


def composite_to_json(envelope: ObjectEnvelope, payload: Any, integrity_hash: str) -> str:
    return canonical_json(composite_to_dict(envelope, payload, integrity_hash))


def decode_composite(value: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any], Any]:
    """Validate the composite field set and return (envelope, payload, hash)."""
    strict_fields("value domain composite", value, COMPOSITE_FIELDS)
    envelope_value = value["envelope"]
    payload_value = value["payload"]
    if not isinstance(envelope_value, Mapping):
        raise CoreValidationError("composite envelope must be an object")
    if not isinstance(payload_value, Mapping):
        raise CoreValidationError("composite payload must be an object")
    return envelope_value, payload_value, value["integrity_hash"]


def decode_composite_json(value: str) -> dict[str, Any]:
    """Decode canonical JSON into a composite dict, rejecting duplicates."""
    decoded = loads_canonical(value)
    if not isinstance(decoded, dict):
        raise CoreValidationError("value domain composite JSON must decode to an object")
    return decoded
