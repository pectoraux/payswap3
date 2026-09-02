from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

# Canonical validation helpers are reused from the single owning authority
# (src.core.envelope) so this domain never re-implements their semantics.
from src.core.envelope import (
    _require_positive,
    _require_text,
    _validate_timestamp,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for annotations only
    from src.core import ObjectEnvelope

# Internal (non-registry) object identity formats for the interoperability
# domain. The frozen protocol registry lists exactly eight protocol-visible
# object types; endpoint, endpoint-resolution and payment-message records are
# internal domain objects and deliberately use non-registry identifier formats.
OBJECT_TYPE_ENDPOINT = "interoperability/endpoint"
OBJECT_TYPE_ENDPOINT_RESOLUTION = "interoperability/endpoint-resolution"
OBJECT_TYPE_PAYMENT_MESSAGE = "interoperability/payment-message"

ADAPTER_ID_PREFIX = "interoperability/adapter/"
RESOLUTION_STATE = "RESOLVED"
DOMAIN_PROTOCOL_VERSION = "v0.1"
DOMAIN_SCHEMA_VERSION = 1

RECORD_KEYS = frozenset({"envelope", "payload", "payload_hash"})


def require_object_identity(envelope: "ObjectEnvelope", object_type: str) -> None:
    """Bind a domain record to its declared internal object identity."""
    if envelope.object_type != object_type:
        raise CoreValidationError(
            f"object_type must be {object_type!r} for object {envelope.object_id}, "
            f"got {envelope.object_type!r}"
        )
    expected_prefix = object_type + "/"
    if not envelope.object_id.startswith(expected_prefix):
        raise CoreValidationError(
            f"object_id must be prefixed by {expected_prefix!r}, got {envelope.object_id!r}"
        )


def require_adapter_id(name: str, value: str) -> None:
    """Require the internal adapter identifier format for world adapter contracts."""
    _require_text(name, value)
    if not value.startswith(ADAPTER_ID_PREFIX) or len(value) <= len(ADAPTER_ID_PREFIX):
        raise CoreValidationError(
            f"{name} must use the internal adapter identifier format "
            f"{ADAPTER_ID_PREFIX!r}+local_id, got {value!r}"
        )


def payload_binding_hash(envelope: "ObjectEnvelope", payload: Mapping[str, Any]) -> str:
    """Bind a domain payload to one exact sealed envelope version.

    The binding input includes the envelope integrity hash so a payload can
    never be spliced onto a different envelope (or envelope version) without
    detection, mirroring the payload_hash discipline of the frozen event model.
    """
    if envelope.integrity_hash is None:
        raise CoreValidationError(
            f"record {envelope.object_id} requires a sealed envelope before payload binding"
        )
    return canonical_sha256({"envelope_hash": envelope.integrity_hash, "payload": payload})


def verify_payload_binding(envelope: "ObjectEnvelope", payload: Mapping[str, Any],
                           payload_hash: str) -> None:
    """Recompute and verify the payload binding of a domain record."""
    _require_text("payload_hash", payload_hash)
    expected = payload_binding_hash(envelope, payload)
    if payload_hash != expected:
        raise CoreValidationError(
            f"payload hash mismatch for object {envelope.object_id}"
        )


def decode_record(value: Mapping[str, Any]) -> tuple["ObjectEnvelope", dict[str, Any], str]:
    """Strictly decode a serialized domain record.

    Envelope integrity is verified by the core trusted path, which rejects
    unsealed and tampered envelopes before any payload interpretation.
    """
    from src.core import ObjectEnvelope

    if not isinstance(value, Mapping):
        raise CoreValidationError("domain record must be an object")
    if set(value) != RECORD_KEYS:
        missing = sorted(RECORD_KEYS - set(value))
        extra = sorted(set(value) - RECORD_KEYS)
        raise CoreValidationError(
            f"non-canonical record fields; missing={missing}, extra={extra}"
        )
    payload = value["payload"]
    if not isinstance(payload, Mapping):
        raise CoreValidationError("record payload must be an object")
    payload_hash = value["payload_hash"]
    if not isinstance(payload_hash, str) or not payload_hash.strip():
        raise CoreValidationError("record payload_hash must be a non-empty string")
    envelope = ObjectEnvelope.from_dict(value["envelope"])
    return envelope, dict(payload), payload_hash


def require_payload_keys(payload: Mapping[str, Any], expected: frozenset[str]) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        raise CoreValidationError(
            f"non-canonical payload fields; missing={missing}, extra={extra}"
        )


def coerce_enum(name: str, enum_cls: type[StrEnum], value: Any) -> StrEnum:
    """Coerce a value into a closed vocabulary with a descriptive failure."""
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            pass
    vocabulary = sorted(member.value for member in enum_cls)
    raise CoreValidationError(
        f"{name} must be one of the closed vocabulary {vocabulary}, got {value!r}"
    )


def require_identifier_tuple(
    name: str, values: Any
) -> tuple[Any, ...]:
    from .identifiers import EndpointIdentifier

    if not isinstance(values, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    for index, item in enumerate(values):
        if not isinstance(item, EndpointIdentifier):
            raise CoreValidationError(f"{name}[{index}] must be an EndpointIdentifier")
    return values


def validate_timestamp(name: str, value: str) -> None:
    _validate_timestamp(name, value)


__all__ = [
    "ADAPTER_ID_PREFIX",
    "DOMAIN_PROTOCOL_VERSION",
    "DOMAIN_SCHEMA_VERSION",
    "OBJECT_TYPE_ENDPOINT",
    "OBJECT_TYPE_ENDPOINT_RESOLUTION",
    "OBJECT_TYPE_PAYMENT_MESSAGE",
    "RESOLUTION_STATE",
    "coerce_enum",
    "decode_record",
    "payload_binding_hash",
    "require_adapter_id",
    "require_identifier_tuple",
    "require_object_identity",
    "require_payload_keys",
    "validate_timestamp",
    "verify_payload_binding",
]
