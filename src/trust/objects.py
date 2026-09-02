"""Shared infrastructure for trust-domain durable records.

Every durable trust object is an immutable ``ObjectEnvelope`` (the frozen
canonical object model) plus a typed payload, bound together by a domain seal:
``canonical_sha256(["trust/seal/v1", sealed envelope, canonical payload])``.
Deserialization verifies the core envelope integrity hash first (rejecting
unsealed or tampered envelopes) and then verifies the domain seal (rejecting
tampered payloads). The seal reuses the core hash and error authorities; it
does not create a second authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from ._validation import (
    require_non_negative_int,
    require_text,
    require_timestamp,
)
from .registry import PROTOCOL_VERSION, require_internal_object_type

TRUST_SEAL_VERSION = "trust/seal/v1"
TRUST_SCHEMA_VERSION = 1

#: Version of the trust-domain public API surface (``src.trust``).
TRUST_API_VERSION = 1

RECORD_KEYS = frozenset({"envelope", "payload", "domain_seal"})


def domain_seal(envelope: ObjectEnvelope, payload: Mapping[str, Any]) -> str:
    return canonical_sha256([TRUST_SEAL_VERSION, envelope.to_dict(), dict(payload)])


class TrustObject:
    """Mixin shared by every durable trust record (envelope + payload + seal)."""

    envelope: ObjectEnvelope

    def payload_dict(self) -> dict[str, Any]:  # pragma: no cover - abstract contract
        raise NotImplementedError

    def domain_seal(self) -> str:
        return domain_seal(self.envelope, self.payload_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.payload_dict(),
            "domain_seal": self.domain_seal(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str):
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("trust record JSON must decode to an object")
        return cls.from_dict(decoded)


def validate_record_envelope(
    envelope: object,
    *,
    object_id: str,
    object_type: str,
    state_vocab: type[StrEnum],
) -> ObjectEnvelope:
    """Fail-closed envelope contract shared by all trust records."""
    if not isinstance(envelope, ObjectEnvelope):
        raise CoreValidationError("trust record envelope must be an ObjectEnvelope")
    require_internal_object_type(object_type)
    if envelope.object_type != object_type:
        raise CoreValidationError(
            f"trust record object_type must be '{object_type}', found '{envelope.object_type}'"
        )
    envelope.verify_integrity()
    if envelope.object_id != object_id:
        raise CoreValidationError(
            f"trust record envelope object_id must equal the record id '{object_id}'"
        )
    if envelope.schema_version != TRUST_SCHEMA_VERSION:
        raise CoreValidationError("trust record schema_version must be 1")
    if envelope.protocol_version != PROTOCOL_VERSION:
        raise CoreValidationError(f"trust record protocol_version must be '{PROTOCOL_VERSION}'")
    if envelope.state not in tuple(item.value for item in state_vocab):
        raise CoreValidationError(
            f"trust record state '{envelope.state}' is outside the {state_vocab.__name__} vocabulary"
        )
    return envelope


def record_from_dict(cls, value: object, build_payload):
    """Shared from_dict: strict keys, envelope verification, seal verification."""
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{cls.__name__} must decode from an object")
    if set(value) != RECORD_KEYS:
        missing = sorted(RECORD_KEYS - set(value))
        extra = sorted(set(value) - RECORD_KEYS)
        raise CoreValidationError(
            f"{cls.__name__} fields are not canonical; missing={missing}, extra={extra}"
        )
    envelope = ObjectEnvelope.from_dict(value["envelope"])
    record = build_payload(envelope, value["payload"])
    if value["domain_seal"] != record.domain_seal():
        raise CoreValidationError(
            f"domain seal mismatch for {cls.__name__} {record.envelope.object_id}"
        )
    return record


def build_envelope(
    *,
    object_id: str,
    object_type: str,
    state: str,
    environment_id: str,
    domain_id: str,
    issuer: str,
    source: str,
    recorded_at: str,
    evidence_refs: tuple[str, ...] = (),
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ObjectEnvelope:
    """Build the sealed version-1 envelope for a new trust record."""
    require_text("environment_id", environment_id)
    require_text("domain_id", domain_id)
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=1,
        environment_id=environment_id,
        domain_id=domain_id,
        schema_version=TRUST_SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        state=state,
        provenance=Provenance(
            issuer=issuer,
            source=source,
            recorded_at=require_timestamp("recorded_at", recorded_at),
            evidence_refs=evidence_refs,
        ),
        causation_id=causation_id,
        correlation_id=correlation_id,
        previous_version=None,
        integrity_hash=None,
    )
    return envelope.with_integrity_hash()


def advance_envelope(
    envelope: ObjectEnvelope,
    *,
    state: str | None = None,
    issuer: str | None = None,
    source: str | None = None,
    recorded_at: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ObjectEnvelope:
    """Create the next sealed envelope version, preserving identity fields."""
    provenance = envelope.provenance
    if issuer is not None or source is not None or recorded_at is not None:
        provenance = Provenance(
            issuer=issuer if issuer is not None else provenance.issuer,
            source=source if source is not None else provenance.source,
            recorded_at=recorded_at if recorded_at is not None else provenance.recorded_at,
            evidence_refs=provenance.evidence_refs,
        )
    changes: dict[str, Any] = {"provenance": provenance}
    if state is not None:
        changes["state"] = state
    if causation_id is not None:
        changes["causation_id"] = causation_id
    if correlation_id is not None:
        changes["correlation_id"] = correlation_id
    return envelope.next_version(**changes).with_integrity_hash()


@dataclass(frozen=True, slots=True)
class AmountBound:
    """Generic scaled-integer amount bound (no floats, no money-domain arithmetic).

    Used as an authorization bound (grant/mandate limit) and as the request
    amount checked against those bounds. Comparison is exact integer
    cross-multiplication; amounts are non-negative minor units at a scale.
    """

    asset: str
    amount_minor: int
    scale: int

    def __post_init__(self) -> None:
        require_text("amount.asset", self.asset)
        require_non_negative_int("amount.amount_minor", self.amount_minor)
        require_non_negative_int("amount.scale", self.scale)

    def to_dict(self) -> dict[str, Any]:
        return {"asset": self.asset, "amount_minor": self.amount_minor, "scale": self.scale}

    @classmethod
    def from_dict(cls, value: object) -> "AmountBound":
        if not isinstance(value, Mapping):
            raise CoreValidationError("amount bound must be an object")
        if set(value) != {"asset", "amount_minor", "scale"}:
            raise CoreValidationError("amount bound fields are not canonical")
        return cls(
            asset=value["asset"],
            amount_minor=value["amount_minor"],
            scale=value["scale"],
        )

    def within(self, other: "AmountBound") -> bool:
        """True when this bound does not exceed ``other`` (same asset required)."""
        if self.asset != other.asset:
            raise CoreValidationError(
                f"amount bounds for different assets cannot be compared: "
                f"{self.asset} vs {other.asset}"
            )
        left = self.amount_minor * 10**other.scale
        right = other.amount_minor * 10**self.scale
        return left <= right

    def covers(self, other: "AmountBound") -> bool:
        """True when ``other`` is within this bound."""
        return other.within(self)


def amount_limits_to_dict(limits: tuple[AmountBound, ...]) -> list[dict[str, Any]]:
    return [item.to_dict() for item in limits]


def amount_limits_from_dict(name: str, value: object) -> tuple[AmountBound, ...]:
    if not isinstance(value, list):
        raise CoreValidationError(f"{name} must deserialize from a list")
    limits = tuple(AmountBound.from_dict(item) for item in value)
    assets = [item.asset for item in limits]
    if len(set(assets)) != len(assets):
        raise CoreValidationError(f"{name} contains duplicate asset bounds")
    return limits


def amount_limits_bounded_by(
    name: str, child: tuple[AmountBound, ...], parent: tuple[AmountBound, ...]
) -> None:
    """Fail closed unless every parent-capped asset is capped no looser in the child.

    A child may introduce caps for assets the parent leaves uncapped (narrowing
    an unbounded grant), but may never drop or loosen a parent cap.
    """
    parent_by_asset = {item.asset: item for item in parent}
    child_by_asset = {item.asset: item for item in child}
    for asset, parent_bound in parent_by_asset.items():
        child_bound = child_by_asset.get(asset)
        if child_bound is None:
            raise CoreValidationError(
                f"{name} drops the amount limit for asset {asset} present in the parent grant"
            )
        if not child_bound.within(parent_bound):
            raise CoreValidationError(
                f"{name} widens the amount limit for asset {asset} beyond the parent grant"
            )


def scope_subset(
    child_objects: tuple[str, ...],
    child_domains: tuple[str, ...],
    parent_objects: tuple[str, ...],
    parent_domains: tuple[str, ...],
) -> bool:
    return set(child_objects).issubset(parent_objects) and set(child_domains).issubset(
        parent_domains
    )


def jurisdictions_subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    """A child may only narrow jurisdictions; unconstrained parents allow any subset."""
    if not parent:
        return True
    return bool(child) and set(child).issubset(parent)
