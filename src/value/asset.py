"""Assets: the registrable units of value the ledger denominates.

An asset declares the canonical minor-unit ``scale`` amounts must use
and a closed ``AssetKind`` classification. The lifecycle follows the
frozen value command family ``Register/Activate/Suspend/RetireAsset``:

```text
REGISTERED → ACTIVE → SUSPENDED → RETIRED
                 ↑___________|
```

Activation is legal from ``REGISTERED`` and from ``SUSPENDED`` (the
family has no separate resume command, so re-activation is the explicit
unsuspend path). Retirement requires a prior suspension so an asset
never disappears while active accounts depend on it. Object type
``value/asset/v1`` is an internal (non-registry) identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .contracts import ASSET_OBJECT_TYPE, MAX_SCALE
from .seal import (
    advance_domain_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)
from .validation import require_identifier, require_int, require_text, strict_fields

ASSET_PAYLOAD_FIELDS = frozenset({"code", "scale", "kind", "issuer_id", "name"})


class AssetKind(StrEnum):
    """Closed classification of registrable assets (declared data only)."""

    FIAT = "FIAT"
    STABLECOIN = "STABLECOIN"
    TOKENIZED = "TOKENIZED"
    LOYALTY = "LOYALTY"
    PREPAID = "PREPAID"
    COMMODITY = "COMMODITY"


class AssetState(StrEnum):
    REGISTERED = "REGISTERED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"


_ASSET_TRANSITIONS: dict[str, str] = {
    "activate": AssetState.ACTIVE.value,
    "suspend": AssetState.SUSPENDED.value,
    "retire": AssetState.RETIRED.value,
}

_ALLOWED_SOURCES: dict[str, frozenset[str]] = {
    "activate": frozenset({AssetState.REGISTERED.value, AssetState.SUSPENDED.value}),
    "suspend": frozenset({AssetState.ACTIVE.value}),
    "retire": frozenset({AssetState.SUSPENDED.value}),
}


@dataclass(frozen=True, slots=True)
class AssetPayload:
    """Immutable asset data: unique code, minor-unit scale, kind, issuer."""

    code: str
    scale: int
    kind: AssetKind
    issuer_id: str
    name: str | None = None

    def __post_init__(self) -> None:
        require_identifier("asset.code", self.code)
        require_int("asset.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        if not isinstance(self.kind, AssetKind):
            raise CoreValidationError("asset.kind must use the closed AssetKind vocabulary")
        require_identifier("asset.issuer_id", self.issuer_id)
        if self.name is not None:
            require_text("asset.name", self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "scale": self.scale,
            "kind": self.kind.value,
            "issuer_id": self.issuer_id,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetPayload":
        strict_fields("asset payload", value, ASSET_PAYLOAD_FIELDS)
        try:
            kind = AssetKind(value["kind"])
        except ValueError as exc:
            raise CoreValidationError(
                f"asset.kind must use the closed vocabulary, got {value['kind']!r}"
            ) from exc
        return cls(
            code=value["code"],
            scale=value["scale"],
            kind=kind,
            issuer_id=value["issuer_id"],
            name=value["name"],
        )


@dataclass(frozen=True, slots=True)
class Asset:
    """Durable, integrity-sealed asset record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: AssetPayload
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"asset envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != ASSET_OBJECT_TYPE:
            raise CoreValidationError(
                f"asset object_type must be {ASSET_OBJECT_TYPE!r}, got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != 1:
            raise CoreValidationError(
                f"asset schema_version must be 1, got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != "v0.1":
            raise CoreValidationError(
                f"asset rejects unknown protocol version {self.envelope.protocol_version!r}; "
                "expected 'v0.1'"
            )
        try:
            AssetState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"asset state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.payload, AssetPayload):
            raise CoreValidationError(
                f"asset payload must be an AssetPayload, got {type(self.payload).__name__}"
            )
        if self.integrity_hash is not None and (
            not isinstance(self.integrity_hash, str) or not self.integrity_hash.strip()
        ):
            raise CoreValidationError("asset integrity hash must be a non-empty string or null")

    @classmethod
    def register(
        cls,
        *,
        object_id: str,
        code: str,
        scale: int,
        kind: AssetKind,
        issuer_id: str,
        name: str | None = None,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "Asset":
        payload = AssetPayload(code=code, scale=scale, kind=kind, issuer_id=issuer_id, name=name)
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=ASSET_OBJECT_TYPE,
            state=AssetState.REGISTERED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(envelope=envelope, payload=payload).with_integrity_hash()

    def _transition(
        self,
        operation: str,
        *,
        provenance: Provenance,
        causation_id: str | None,
        correlation_id: str | None,
    ) -> "Asset":
        target = _ASSET_TRANSITIONS[operation]
        allowed = _ALLOWED_SOURCES[operation]
        if self.envelope.state not in allowed:
            raise CoreValidationError(
                f"asset {self.envelope.object_id} cannot {operation} from state "
                f"{self.envelope.state}; allowed source states are {sorted(allowed)}"
            )
        envelope = advance_domain_envelope(
            self.envelope,
            state=target,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return Asset(envelope=envelope, payload=self.payload).with_integrity_hash()

    def activate(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Asset":
        return self._transition(
            "activate", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def suspend(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Asset":
        return self._transition(
            "suspend", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def retire(
        self, *, provenance: Provenance, causation_id: str | None = None, correlation_id: str | None = None
    ) -> "Asset":
        return self._transition(
            "retire", provenance=provenance, causation_id=causation_id, correlation_id=correlation_id
        )

    def with_integrity_hash(self) -> "Asset":
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"asset envelope must be sealed before the payload hash of {self.envelope.object_id}"
            )
        return Asset(
            envelope=self.envelope,
            payload=self.payload,
            integrity_hash=seal_composite(self.envelope, self.payload),
        )

    def verify_integrity(self) -> None:
        verify_composite(self.envelope, self.payload, self.integrity_hash, self.envelope.object_id)

    def to_dict(self) -> dict[str, Any]:
        if self.integrity_hash is None:
            raise CoreValidationError(
                f"asset {self.envelope.object_id} must be sealed before serialization"
            )
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Asset":
        envelope_value, payload_value, integrity_hash = decode_composite(value)
        envelope = ObjectEnvelope.from_dict(envelope_value)
        payload = AssetPayload.from_dict(payload_value)
        asset = cls(envelope=envelope, payload=payload, integrity_hash=integrity_hash)
        asset.verify_integrity()
        return asset

    @classmethod
    def from_json(cls, value: str) -> "Asset":
        return cls.from_dict(decode_composite_json(value))
