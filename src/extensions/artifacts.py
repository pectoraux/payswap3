"""Typed composition artifacts exchanged by extensions (extensions.md).

Extensions exchange typed artifacts such as ``DemandSignal``,
``RouteProposal``, ``QuoteSet``, ``RiskAssessment``,
``ComplianceProof``, ``Attestation``, ``ExecutionAdapter`` and
``SettlementInstruction``. Artifacts carry schema version, producer,
provenance, expiry, confidence, dependencies and risk.

Artifacts are sealed values: the payload is restricted to the canonical
immutable domain (sorted ``(key, value)`` pair tuples — no floats, no
mappings), the producer identifies the emitting extension, the expiry is
declared data compared only against declared ``as_of`` instants, the
confidence is a basis-point integer, the dependencies are producer
artifact references, and the risk band is the frozen safety vocabulary
(owned by ``src.safety``). This module transports and validates
artifacts only; the owning domains keep their deep semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.safety.contracts import RiskBand

from .contracts import ExtensionArtifactKind, require_confidence_bps
from ._validation import (
    exact_fields,
    normalize_canonical_pairs,
    pairs_to_dict,
    pairs_to_json_value,
    parse_enum,
    require_digest,
    require_int,
    require_text,
    unique_entries,
    validate_timestamp,
)

_ARTIFACT_FIELDS = (
    "artifact_id",
    "kind",
    "schema_version",
    "producer",
    "payload",
    "provenance",
    "expires_at",
    "confidence_bps",
    "dependencies",
    "risk_band",
)


@dataclass(frozen=True, slots=True)
class ExtensionArtifact:
    """One immutable, sealed composition artifact.

    ``payload`` is stored as sorted canonical ``(key, value)`` pair
    tuples so the artifact is deeply immutable and byte-stable under
    canonical JSON encoding; :meth:`payload_value` exposes a read-only
    plain-dict view for sandbox consumers.
    """

    artifact_id: str
    kind: ExtensionArtifactKind
    schema_version: int
    producer: str
    payload: tuple[tuple[str, Any], ...]
    provenance: Provenance
    expires_at: str
    confidence_bps: int
    dependencies: tuple[str, ...]
    risk_band: RiskBand

    def __post_init__(self) -> None:
        require_text("artifact.artifact_id", self.artifact_id)
        if not isinstance(self.kind, ExtensionArtifactKind):
            object.__setattr__(self, "kind", ExtensionArtifactKind.parse(self.kind))
        require_int("artifact.schema_version", self.schema_version, minimum=1)
        require_text("artifact.producer", self.producer)
        # The payload is ALWAYS normalized (even when already a tuple of
        # pairs): normalization sorts the pairs and rejects every value
        # outside the canonical immutable domain (floats fail closed).
        object.__setattr__(
            self, "payload", normalize_canonical_pairs("artifact.payload", self.payload)
        )
        if not isinstance(self.risk_band, RiskBand):
            object.__setattr__(
                self, "risk_band", parse_enum("artifact.risk_band", RiskBand, self.risk_band)
            )
        if not isinstance(self.provenance, Provenance):
            raise CoreValidationError("artifact.provenance must be a Provenance")
        validate_timestamp("artifact.expires_at", self.expires_at)
        require_confidence_bps("artifact.confidence_bps", self.confidence_bps)
        if not isinstance(self.dependencies, tuple):
            raise CoreValidationError("artifact.dependencies must be a tuple")
        for ref in self.dependencies:
            require_text("artifact.dependency", ref)
        unique_entries("artifact.dependencies", self.dependencies)

    def payload_value(self) -> dict[str, Any]:
        """Read-only plain-dict view of the canonical payload pairs."""
        return pairs_to_dict("artifact.payload", self.payload)

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "schema_version": self.schema_version,
            "producer": self.producer,
            "payload": pairs_to_json_value("artifact.payload", self.payload),
            "provenance": self.provenance.to_dict(),
            "expires_at": self.expires_at,
            "confidence_bps": self.confidence_bps,
            "dependencies": list(self.dependencies),
            "risk_band": self.risk_band.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionArtifact":
        if not isinstance(value, Mapping):
            raise CoreValidationError("artifact must be an object")
        exact_fields("artifact", value, set(_ARTIFACT_FIELDS))
        dependencies = value["dependencies"]
        if not isinstance(dependencies, list):
            raise CoreValidationError("artifact.dependencies must deserialize from a list")
        return cls(
            artifact_id=value["artifact_id"],
            kind=value["kind"],
            schema_version=value["schema_version"],
            producer=value["producer"],
            payload=normalize_canonical_pairs("artifact.payload", value["payload"]),
            provenance=Provenance.from_dict(value["provenance"]),
            expires_at=value["expires_at"],
            confidence_bps=value["confidence_bps"],
            dependencies=tuple(dependencies),
            risk_band=value["risk_band"],
        )
