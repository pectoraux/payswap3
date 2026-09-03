"""Composite sealing for operations-domain durable objects.

Every operations-domain durable object is ``ObjectEnvelope + payload`` and
carries a domain seal: a SHA-256 digest computed with the single canonical
hash authority (``src.core.serialization.canonical_sha256``) over the
sealed envelope plus the canonical payload. This mirrors the core and
sibling pattern at the composite layer, so tampered or spliced composite
objects fail closed on the trusted deserialization path. No second hash or
error authority is introduced.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from ._validation import strict_fields
from .contracts import (
    OPERATIONS_PROTOCOL_VERSION,
    OPERATIONS_SCHEMA_VERSION,
)

COMPOSITE_FIELDS = frozenset({"envelope", "payload", "integrity_hash"})

#: Composite field set of sealed domain records (the record's spec is the
#: payload; the serialized key names the record's own vocabulary).
RECORD_FIELDS = frozenset({"envelope", "spec", "integrity_hash"})


def _payload_value(payload: Any) -> Any:
    """Canonical payload value: record specs serialize through ``to_dict``.

    A plain mapping payload is used as-is (already canonical); a record
    spec serializes through its own ``to_dict``; anything else fails
    closed (the sealed composite payload must be canonicalizable).
    """
    if isinstance(payload, Mapping):
        return payload
    to_dict = getattr(payload, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise CoreValidationError(
        "composite payload must be a canonical mapping or a record with "
        "to_dict() (fail closed)"
    )


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
        schema_version=OPERATIONS_SCHEMA_VERSION,
        protocol_version=OPERATIONS_PROTOCOL_VERSION,
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


def seal_composite(envelope: ObjectEnvelope, payload: Any, *, payload_key: str = "payload") -> str:
    """Domain seal over the sealed envelope plus the canonical payload.

    ``payload_key`` names the payload inside the sealed composite
    (``"payload"`` for generic composites, ``"spec"`` for domain
    records) — the digest always covers the envelope plus the exact
    canonical payload value.
    """
    if payload_key not in ("payload", "spec"):
        raise CoreValidationError("payload_key must be 'payload' or 'spec'")
    return canonical_sha256(
        {"envelope": envelope.to_dict(), payload_key: _payload_value(payload)}
    )


def seal_record(envelope: ObjectEnvelope, spec: Any) -> str:
    """Domain seal over a sealed record composite (``envelope + spec``)."""
    return seal_composite(envelope, spec, payload_key="spec")


def verify_composite(
    envelope: ObjectEnvelope,
    payload: Any,
    integrity_hash: Any,
    object_id: str,
    *,
    payload_key: str = "payload",
) -> None:
    """Fail closed on missing, forged or mismatched domain seals."""
    if not isinstance(integrity_hash, str) or not integrity_hash:
        raise CoreValidationError(
            f"integrity_hash is required for trusted deserialization of {object_id}"
        )
    expected = seal_composite(envelope, payload, payload_key=payload_key)
    if integrity_hash != expected:
        raise CoreValidationError(f"integrity hash mismatch for object {object_id}")


def composite_to_dict(
    envelope: ObjectEnvelope,
    payload: Any,
    integrity_hash: str,
    *,
    payload_key: str = "payload",
) -> dict[str, Any]:
    return {
        "envelope": envelope.to_dict(),
        payload_key: _payload_value(payload),
        "integrity_hash": integrity_hash,
    }


def record_to_dict(
    envelope: ObjectEnvelope,
    spec: Any,
    integrity_hash: str,
) -> dict[str, Any]:
    """Serialize one sealed record composite (``envelope + spec + seal``)."""
    return composite_to_dict(envelope, spec, integrity_hash, payload_key="spec")


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
    payload_key: str = "payload",
) -> tuple[ObjectEnvelope, Mapping[str, Any]]:
    """Decode and pre-validate a composite object on the trusted path.

    Order of checks: canonical field set, envelope integrity (core, which
    rejects unsealed and tampered envelopes), object type (internal
    ``operations/...`` types; claiming a registry-governed type foreign to
    this record kind fails closed with a dedicated message), protocol and
    schema versions, closed state vocabulary, payload container type.
    """
    fields = COMPOSITE_FIELDS if payload_key == "payload" else RECORD_FIELDS
    strict_fields(object_type, value, fields)
    if payload_key not in ("payload", "spec"):
        raise CoreValidationError("payload_key must be 'payload' or 'spec'")
    envelope = ObjectEnvelope.from_dict(value["envelope"])
    if envelope.object_type != object_type:
        if str(envelope.object_type).startswith("payswap/") and not object_type.startswith(
            "payswap/"
        ):
            raise CoreValidationError(
                "operations object_type must not claim a registry-governed "
                f"protocol-visible type; this record kind uses the internal type "
                f"{object_type}"
            )
        raise CoreValidationError(
            f"object_type mismatch: expected {object_type}, got {envelope.object_type}"
        )
    if envelope.protocol_version != OPERATIONS_PROTOCOL_VERSION:
        raise CoreValidationError(
            f"{object_type} requires protocol version "
            f"{OPERATIONS_PROTOCOL_VERSION}, got {envelope.protocol_version!r}"
        )
    if envelope.schema_version != OPERATIONS_SCHEMA_VERSION:
        raise CoreValidationError(
            f"{object_type} requires schema version "
            f"{OPERATIONS_SCHEMA_VERSION}, got {envelope.schema_version}"
        )
    try:
        state_type(envelope.state)
    except ValueError as exc:
        raise CoreValidationError(
            f"unknown {object_type} state: {envelope.state!r}"
        ) from exc
    payload = value[payload_key]
    if not isinstance(payload, Mapping):
        raise CoreValidationError(f"{object_type} payload must be an object")
    return envelope, payload


def decode_record(
    value: Mapping[str, Any],
    *,
    object_type: str,
    state_type: type[StrEnum],
) -> tuple[ObjectEnvelope, Mapping[str, Any], str]:
    """Decode and pre-validate one sealed record composite.

    Same validation cascade as :func:`decode_composite` over the
    ``envelope + spec + integrity_hash`` field set; returns the envelope,
    the record's spec mapping and the domain seal.
    """
    envelope, spec = decode_composite(
        value, object_type=object_type, state_type=state_type, payload_key="spec"
    )
    return envelope, spec, value["integrity_hash"]


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
