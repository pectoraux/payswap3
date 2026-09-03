"""The state commitment record with finality binding.

A :class:`StateCommitment` (canonical-object-model Federation family)
is the domain's signed commitment over its own committed state: a
canonical digest of the engine's journal history plus digest-bound
finality evidence (governance.md "Federated state" — a domain "publishes
state commitments/finality evidence"). The commitment is immutable and
append-only (ownership-lifecycle IMMUTABLE class): it is created
``PUBLISHED`` and never transitions; a superseding commitment is a new
record at the next sequence (constitution invariant 17).

Finality binding discipline (WORK-016 consumed, never reimplemented):
each :class:`FinalityBinding` is derived from a sealed settlement-domain
finality certificate decoded through its own trusted path, and only
from an ``ESTABLISHED`` certificate — a pending or withdrawn claim can
never be bound, and a payment status is never finality evidence
(constitution §4 and invariant 11). The binding pins the certificate's
identity, its settlement, the settlement digest and the certificate's
composite digest, so a binding cannot be spliced onto another
certificate.

The signature is the deterministic purpose-bound scheme from
:mod:`.authority` over :func:`commitment_payload_digest` — the canonical
digest of the commitment's identity, domain, sequence, state digest and
finality bindings (domain included: a commitment cannot be replayed as
another domain's).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.settlement.contracts import FinalityState
from src.settlement.finality import Finality

from ._validation import (
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_text,
    strict_fields,
)
from .contracts import COMMITMENT_OBJECT_TYPE, CommitmentState
from .seal import (
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_FINALITY_BINDING_FIELDS = frozenset(
    {
        "finality_id",
        "settlement_id",
        "settlement_digest",
        "certificate_digest",
    }
)

_SPEC_FIELDS = frozenset(
    {
        "commitment_id",
        "sequence",
        "state_digest",
        "finality_bindings",
        "key_id",
        "public_material",
        "signature",
    }
)

_PUBLISH_PAYLOAD_FIELDS = frozenset(
    {
        "commitment_id",
        "sequence",
        "state_digest",
        "finality_bindings",
        "key_id",
        "public_material",
        "signature",
        "destination_domain_id",
        "message_id",
        "message_nonce",
    }
)


@dataclass(frozen=True, slots=True)
class FinalityBinding:
    """One digest-bound finality certificate reference.

    All facts are derived from the decoded sealed certificate — never
    trusted from a raw payload.
    """

    finality_id: str
    settlement_id: str
    settlement_digest: str
    certificate_digest: str

    def __post_init__(self) -> None:
        require_identifier("binding.finality_id", self.finality_id)
        require_identifier("binding.settlement_id", self.settlement_id)
        require_digest("binding.settlement_digest", self.settlement_digest)
        require_digest("binding.certificate_digest", self.certificate_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finality_id": self.finality_id,
            "settlement_id": self.settlement_id,
            "settlement_digest": self.settlement_digest,
            "certificate_digest": self.certificate_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FinalityBinding":
        require_mapping("finality binding", value)
        strict_fields("finality binding", value, _FINALITY_BINDING_FIELDS)
        return cls(
            finality_id=value["finality_id"],
            settlement_id=value["settlement_id"],
            settlement_digest=value["settlement_digest"],
            certificate_digest=value["certificate_digest"],
        )


def finality_binding_from_certificate(certificate: Finality) -> FinalityBinding:
    """Derive one binding from a decoded sealed finality certificate.

    Only ``ESTABLISHED`` certificates bind (WORK-016's trusted decode
    path verified the seal; the state gate here keeps pending or
    withdrawn claims out of domain state commitments — no false
    finality).
    """
    if certificate.state is not FinalityState.ESTABLISHED:
        raise CoreValidationError(
            "a state commitment binds ESTABLISHED finality certificates only; "
            f"certificate {certificate.object_id} is {certificate.state.value}"
        )
    return FinalityBinding(
        finality_id=certificate.object_id,
        settlement_id=certificate.spec.settlement_id,
        settlement_digest=certificate.spec.settlement_digest,
        certificate_digest=certificate.integrity_hash,
    )


def decode_finality_certificate(composite: Any) -> Finality:
    """Decode a finality certificate through the settlement trusted path."""
    if not isinstance(composite, Mapping):
        raise CoreValidationError(
            "state commitment publication requires settlement Finality composites"
        )
    return Finality.from_dict(composite)


def commitment_payload_digest(
    *,
    commitment_id: str,
    domain_id: str,
    sequence: int,
    state_digest: str,
    finality_bindings: tuple[FinalityBinding, ...] | list[Mapping[str, Any]],
) -> str:
    """Canonical digest of the commitment facts the signature covers.

    Includes the publishing domain: a commitment cannot be spliced and
    replayed as another domain's commitment.
    """
    require_identifier("commitment.commitment_id", commitment_id)
    require_identifier("commitment.domain_id", domain_id)
    require_int("commitment.sequence", sequence, minimum=1)
    require_digest("commitment.state_digest", state_digest)
    bindings = list(finality_bindings)
    return canonical_sha256(
        {
            "commitment_id": commitment_id,
            "domain_id": domain_id,
            "sequence": sequence,
            "state_digest": state_digest,
            "finality_bindings": [
                binding.to_dict() if isinstance(binding, FinalityBinding) else dict(binding)
                for binding in bindings
            ],
        }
    )


@dataclass(frozen=True, slots=True)
class CommitmentSpec:
    """Commitment identity, state digest, finality bindings and signature."""

    commitment_id: str
    sequence: int
    state_digest: str
    finality_bindings: tuple[FinalityBinding, ...]
    key_id: str
    public_material: str
    signature: str

    def __post_init__(self) -> None:
        require_identifier("commitment.commitment_id", self.commitment_id)
        require_int("commitment.sequence", self.sequence, minimum=1)
        require_digest("commitment.state_digest", self.state_digest)
        if not isinstance(self.finality_bindings, tuple):
            raise CoreValidationError("commitment.finality_bindings must be a tuple")
        seen: set[str] = set()
        for binding in self.finality_bindings:
            if not isinstance(binding, FinalityBinding):
                raise CoreValidationError(
                    "commitment.finality_bindings entries must be FinalityBinding records"
                )
            if binding.finality_id in seen:
                raise CoreValidationError(
                    f"duplicate finality binding for certificate {binding.finality_id}"
                )
            seen.add(binding.finality_id)
        require_identifier("commitment.key_id", self.key_id)
        require_text("commitment.public_material", self.public_material)
        require_digest("commitment.signature", self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "sequence": self.sequence,
            "state_digest": self.state_digest,
            "finality_bindings": [
                binding.to_dict() for binding in self.finality_bindings
            ],
            "key_id": self.key_id,
            "public_material": self.public_material,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CommitmentSpec":
        require_mapping("commitment spec", value)
        strict_fields("commitment spec", value, _SPEC_FIELDS)
        bindings = value["finality_bindings"]
        if not isinstance(bindings, list):
            raise CoreValidationError(
                "commitment finality_bindings must deserialize from a list"
            )
        return cls(
            commitment_id=value["commitment_id"],
            sequence=value["sequence"],
            state_digest=value["state_digest"],
            finality_bindings=tuple(
                FinalityBinding.from_dict(item) for item in bindings
            ),
            key_id=value["key_id"],
            public_material=value["public_material"],
            signature=value["signature"],
        )


@dataclass(frozen=True, slots=True)
class StateCommitment:
    """The sealed internal ``federation/state-commitment/v1`` object."""

    envelope: ObjectEnvelope
    spec: CommitmentSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = COMMITMENT_OBJECT_TYPE
    STATE_TYPE = CommitmentState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("commitment envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, CommitmentSpec):
            raise CoreValidationError("commitment spec must be a CommitmentSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.commitment_id:
            raise CoreValidationError(
                "commitment envelope and spec must agree on the commitment id"
            )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> CommitmentState:
        return CommitmentState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        from src.core.serialization import canonical_json

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StateCommitment":
        envelope, payload = decode_composite(
            value,
            object_type=COMMITMENT_OBJECT_TYPE,
            state_type=CommitmentState,
        )
        return cls(
            envelope=envelope,
            spec=CommitmentSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "StateCommitment":
        decoded = decode_composite_json(
            value,
            object_type=COMMITMENT_OBJECT_TYPE,
            state_type=CommitmentState,
        )
        return cls.from_dict(decoded)


def make_commitment_record(
    *,
    commitment_id: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    sequence: int,
    state_digest: str,
    finality_bindings: tuple[FinalityBinding, ...],
    key_id: str,
    public_material: str,
    signature: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> StateCommitment:
    """Build the sealed immutable commitment record (PUBLISHED)."""
    spec = CommitmentSpec(
        commitment_id=commitment_id,
        sequence=sequence,
        state_digest=state_digest,
        finality_bindings=finality_bindings,
        key_id=key_id,
        public_material=public_material,
        signature=signature,
    )
    envelope = build_domain_envelope(
        object_id=commitment_id,
        object_type=COMMITMENT_OBJECT_TYPE,
        state=CommitmentState.PUBLISHED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return StateCommitment(
        envelope=envelope,
        spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


# -- command payload parsing (handler-side, strict) ---------------------------


def parse_publish_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation publish payload", payload)
    strict_fields("federation publish payload", payload, _PUBLISH_PAYLOAD_FIELDS)
    require_identifier("publish payload commitment_id", payload["commitment_id"])
    require_int("publish payload sequence", payload["sequence"], minimum=1)
    require_digest("publish payload state_digest", payload["state_digest"])
    require_identifier("publish payload key_id", payload["key_id"])
    require_text("publish payload public_material", payload["public_material"])
    require_digest("publish payload signature", payload["signature"])
    bindings_raw = payload["finality_bindings"]
    if not isinstance(bindings_raw, list):
        raise CoreValidationError("publish payload finality_bindings must be a list")
    bindings = tuple(
        FinalityBinding.from_dict(item) for item in bindings_raw
    )
    destination = payload["destination_domain_id"]
    if destination is not None:
        require_identifier("publish payload destination_domain_id", destination)
        require_identifier("publish payload message_id", payload["message_id"])
        require_text("publish payload message_nonce", payload["message_nonce"])
    else:
        if payload["message_id"] is not None or payload["message_nonce"] is not None:
            raise CoreValidationError(
                "a destinationless commitment must not declare a message"
            )
    return {
        "commitment_id": payload["commitment_id"],
        "sequence": payload["sequence"],
        "state_digest": payload["state_digest"],
        "finality_bindings": bindings,
        "key_id": payload["key_id"],
        "public_material": payload["public_material"],
        "signature": payload["signature"],
        "destination_domain_id": destination,
        "message_id": payload["message_id"],
        "message_nonce": payload["message_nonce"],
    }
