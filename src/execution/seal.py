"""Composite sealing for execution-domain durable objects.

Every execution-domain durable object is ``ObjectEnvelope + payload`` and
carries a domain seal: a SHA-256 digest computed with the single
canonical hash authority (``src.core.serialization.canonical_sha256``)
over the sealed envelope plus the canonical payload. This mirrors the
core and sibling pattern at the composite layer, so tampered or spliced
composite objects fail closed on the trusted deserialization path. No
second hash or error authority is introduced.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from ._validation import strict_fields
from .contracts import (
    EXECUTION_PROTOCOL_VERSION,
    EXECUTION_SCHEMA_VERSION,
)

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
        schema_version=EXECUTION_SCHEMA_VERSION,
        protocol_version=EXECUTION_PROTOCOL_VERSION,
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
        previous_version=None,
    )
    return envelope.with_integrity_hash()


def advance_envelope(
    envelope: ObjectEnvelope,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ObjectEnvelope:
    """Produce the next sealed envelope version (identity fields frozen).

    Omitted ``causation_id``/``correlation_id`` values are preserved from
    the previous version (monotone provenance): only an explicit new value
    replaces the recorded one.
    """
    if not isinstance(provenance, Provenance):
        raise CoreValidationError("provenance must be a Provenance")
    changes: dict[str, Any] = {"state": state, "provenance": provenance}
    if causation_id is not None:
        changes["causation_id"] = causation_id
    if correlation_id is not None:
        changes["correlation_id"] = correlation_id
    return envelope.next_version(**changes).with_integrity_hash()


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


def composite_to_dict(
    envelope: ObjectEnvelope,
    payload: Any,
    integrity_hash: str,
) -> dict[str, Any]:
    return {
        "envelope": envelope.to_dict(),
        "payload": payload.to_dict(),
        "integrity_hash": integrity_hash,
    }


def composite_to_json(
    envelope: ObjectEnvelope,
    payload: Any,
    integrity_hash: str,
) -> str:
    return canonical_json(composite_to_dict(envelope, payload, integrity_hash))


def decode_composite(
    value: Mapping[str, Any],
    *,
    object_type: str,
    state_type: type[StrEnum],
) -> tuple[ObjectEnvelope, Mapping[str, Any]]:
    """Decode and pre-validate a composite object on the trusted path.

    Order of checks: canonical field set, envelope integrity (core, which
    rejects unsealed and tampered envelopes), object type (the one
    registry-listed plan type or an internal ``execution/...`` type;
    claiming another ``payswap/`` registry type fails closed with a
    dedicated message), protocol and schema versions, closed state
    vocabulary, payload container type.
    """
    strict_fields(object_type, value, COMPOSITE_FIELDS)
    envelope = ObjectEnvelope.from_dict(value["envelope"])
    if envelope.object_type != object_type:
        if str(envelope.object_type).startswith("payswap/") and not object_type.startswith(
            "payswap/"
        ):
            raise CoreValidationError(
                "execution object_type must not claim a registry-governed "
                f"protocol-visible type; this record kind uses the internal type "
                f"{object_type}"
            )
        raise CoreValidationError(
            f"object_type mismatch: expected {object_type}, got {envelope.object_type}"
        )
    if envelope.protocol_version != EXECUTION_PROTOCOL_VERSION:
        raise CoreValidationError(
            f"{object_type} requires protocol version "
            f"{EXECUTION_PROTOCOL_VERSION}, got {envelope.protocol_version!r}"
        )
    if envelope.schema_version != EXECUTION_SCHEMA_VERSION:
        raise CoreValidationError(
            f"{object_type} requires schema version "
            f"{EXECUTION_SCHEMA_VERSION}, got {envelope.schema_version}"
        )
    try:
        state_type(envelope.state)
    except ValueError as exc:
        raise CoreValidationError(
            f"unknown {object_type} state: {envelope.state!r}"
        ) from exc
    payload = value["payload"]
    if not isinstance(payload, Mapping):
        raise CoreValidationError(f"{object_type} payload must be an object")
    return envelope, payload


def decode_composite_json(
    value: str,
    *,
    object_type: str,
    state_type: type[StrEnum],
) -> tuple[ObjectEnvelope, Mapping[str, Any], str]:
    """Decode composite JSON with the duplicate-key-safe canonical decoder."""
    decoded = loads_canonical(value)
    if not isinstance(decoded, dict):
        raise CoreValidationError(f"{object_type} JSON must decode to an object")
    envelope, payload = decode_composite(decoded, object_type=object_type, state_type=state_type)
    return envelope, payload, decoded["integrity_hash"]
