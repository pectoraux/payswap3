"""Inter-domain messages and commitment acceptances.

An :class:`InterDomainMessage` (canonical-object-model Federation
family) is the immutable cross-domain vehicle for one published state
commitment: it is created — atomically, in the same kernel transition —
by ``publish-commitment`` in the ORIGIN domain's engine (an object of
the origin domain, sealed by the origin domain's engine), carrying the
destination domain, a per-origin nonce and the commitment's composite
digest. The destination domain never mutates the message; it decodes
it read-only through the trusted seal-verification path, exactly like
the settlement domain consumes clearing obligations.

A :class:`CommitmentAcceptance` is the immutable record the
DESTINATION domain creates when it accepts a foreign commitment: the
verified message identity, the commitment identity and digest, the
origin domain, the anchor key the signature was verified against, and
the acceptance instant. Replaying a message that was already accepted
is rejected by the accepting engine's replay gate (the accepted
message identities are derived from the acceptance records —
rebuild-safe, journal-only reconstructible).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from ._validation import (
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import ACCEPTANCE_OBJECT_TYPE, AcceptanceState, MessageKind, MessageState, MESSAGE_OBJECT_TYPE
from .seal import (
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_MESSAGE_SPEC_FIELDS = frozenset(
    {
        "message_id",
        "origin_domain",
        "destination_domain",
        "kind",
        "nonce",
        "commitment_id",
        "commitment_digest",
        "issued_at",
    }
)

_ACCEPTANCE_SPEC_FIELDS = frozenset(
    {
        "acceptance_id",
        "origin_domain",
        "message_id",
        "message_digest",
        "commitment_id",
        "commitment_digest",
        "sequence",
        "anchor_key_id",
        "accepted_at",
    }
)

_ACCEPT_PAYLOAD_FIELDS = frozenset({"acceptance_id", "message", "commitment"})


@dataclass(frozen=True, slots=True)
class MessageSpec:
    """Message identity, routing and commitment binding facts."""

    message_id: str
    origin_domain: str
    destination_domain: str
    kind: MessageKind
    nonce: str
    commitment_id: str
    commitment_digest: str
    issued_at: str

    def __post_init__(self) -> None:
        require_identifier("message.message_id", self.message_id)
        require_identifier("message.origin_domain", self.origin_domain)
        require_identifier("message.destination_domain", self.destination_domain)
        if self.origin_domain == self.destination_domain:
            raise CoreValidationError(
                "an inter-domain message must cross two distinct domains"
            )
        if not isinstance(self.kind, MessageKind):
            if isinstance(self.kind, str):
                self_kind = MessageKind.parse(self.kind)
            else:
                raise CoreValidationError(
                    "message.kind must be a MessageKind (or its canonical string value)"
                )
        else:
            self_kind = self.kind
        require_text("message.nonce", self.nonce)
        require_identifier("message.commitment_id", self.commitment_id)
        require_digest("message.commitment_digest", self.commitment_digest)
        require_utc_timestamp("message.issued_at", self.issued_at)

    def to_dict(self) -> dict[str, Any]:
        kind = self.kind.value if isinstance(self.kind, MessageKind) else str(self.kind)
        return {
            "message_id": self.message_id,
            "origin_domain": self.origin_domain,
            "destination_domain": self.destination_domain,
            "kind": kind,
            "nonce": self.nonce,
            "commitment_id": self.commitment_id,
            "commitment_digest": self.commitment_digest,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MessageSpec":
        require_mapping("message spec", value)
        strict_fields("message spec", value, _MESSAGE_SPEC_FIELDS)
        return cls(
            message_id=value["message_id"],
            origin_domain=value["origin_domain"],
            destination_domain=value["destination_domain"],
            kind=MessageKind.parse(value["kind"]),
            nonce=value["nonce"],
            commitment_id=value["commitment_id"],
            commitment_digest=value["commitment_digest"],
            issued_at=value["issued_at"],
        )


@dataclass(frozen=True, slots=True)
class InterDomainMessage:
    """The sealed internal ``federation/inter-domain-message/v1`` object.

    The message is an object of the ORIGIN domain (envelope domain id
    equals the spec's origin domain): the kernel's domain binding makes
    unilateral mutation by any other domain structurally impossible.
    """

    envelope: ObjectEnvelope
    spec: MessageSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = MESSAGE_OBJECT_TYPE
    STATE_TYPE = MessageState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("message envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, MessageSpec):
            raise CoreValidationError("message spec must be a MessageSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.message_id:
            raise CoreValidationError(
                "message envelope and spec must agree on the message id"
            )
        if self.envelope.domain_id != self.spec.origin_domain:
            raise CoreValidationError(
                "an inter-domain message is an object of its origin domain"
            )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> MessageState:
        return MessageState(self.envelope.state)

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
    def from_dict(cls, value: Mapping[str, Any]) -> "InterDomainMessage":
        envelope, payload = decode_composite(
            value,
            object_type=MESSAGE_OBJECT_TYPE,
            state_type=MessageState,
        )
        return cls(
            envelope=envelope,
            spec=MessageSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "InterDomainMessage":
        decoded = decode_composite_json(
            value,
            object_type=MESSAGE_OBJECT_TYPE,
            state_type=MessageState,
        )
        return cls.from_dict(decoded)


def make_message_record(
    *,
    message_id: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    origin_domain: str,
    destination_domain: str,
    kind: MessageKind,
    nonce: str,
    commitment_id: str,
    commitment_digest: str,
    issued_at: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> InterDomainMessage:
    """Build the sealed immutable message record (ISSUED)."""
    spec = MessageSpec(
        message_id=message_id,
        origin_domain=origin_domain,
        destination_domain=destination_domain,
        kind=kind,
        nonce=nonce,
        commitment_id=commitment_id,
        commitment_digest=commitment_digest,
        issued_at=issued_at,
    )
    envelope = build_domain_envelope(
        object_id=message_id,
        object_type=MESSAGE_OBJECT_TYPE,
        state=MessageState.ISSUED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return InterDomainMessage(
        envelope=envelope,
        spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


@dataclass(frozen=True, slots=True)
class AcceptanceSpec:
    """Acceptance identity and the verified cross-domain facts."""

    acceptance_id: str
    origin_domain: str
    message_id: str
    message_digest: str
    commitment_id: str
    commitment_digest: str
    sequence: int
    anchor_key_id: str
    accepted_at: str

    def __post_init__(self) -> None:
        require_identifier("acceptance.acceptance_id", self.acceptance_id)
        require_identifier("acceptance.origin_domain", self.origin_domain)
        require_identifier("acceptance.message_id", self.message_id)
        require_digest("acceptance.message_digest", self.message_digest)
        require_identifier("acceptance.commitment_id", self.commitment_id)
        require_digest("acceptance.commitment_digest", self.commitment_digest)
        require_int("acceptance.sequence", self.sequence, minimum=1)
        require_identifier("acceptance.anchor_key_id", self.anchor_key_id)
        require_utc_timestamp("acceptance.accepted_at", self.accepted_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_id": self.acceptance_id,
            "origin_domain": self.origin_domain,
            "message_id": self.message_id,
            "message_digest": self.message_digest,
            "commitment_id": self.commitment_id,
            "commitment_digest": self.commitment_digest,
            "sequence": self.sequence,
            "anchor_key_id": self.anchor_key_id,
            "accepted_at": self.accepted_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AcceptanceSpec":
        require_mapping("acceptance spec", value)
        strict_fields("acceptance spec", value, _ACCEPTANCE_SPEC_FIELDS)
        return cls(
            acceptance_id=value["acceptance_id"],
            origin_domain=value["origin_domain"],
            message_id=value["message_id"],
            message_digest=value["message_digest"],
            commitment_id=value["commitment_id"],
            commitment_digest=value["commitment_digest"],
            sequence=value["sequence"],
            anchor_key_id=value["anchor_key_id"],
            accepted_at=value["accepted_at"],
        )


@dataclass(frozen=True, slots=True)
class CommitmentAcceptance:
    """The sealed internal ``federation/commitment-acceptance/v1`` object.

    An object of the ACCEPTING domain; the origin domain must be
    foreign (an acceptance records trusting a peer, never oneself).
    """

    envelope: ObjectEnvelope
    spec: AcceptanceSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = ACCEPTANCE_OBJECT_TYPE
    STATE_TYPE = AcceptanceState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("acceptance envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, AcceptanceSpec):
            raise CoreValidationError("acceptance spec must be an AcceptanceSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.acceptance_id:
            raise CoreValidationError(
                "acceptance envelope and spec must agree on the acceptance id"
            )
        if self.envelope.domain_id == self.spec.origin_domain:
            raise CoreValidationError(
                "an acceptance records a FOREIGN domain commitment; the origin "
                "domain must differ from the accepting domain"
            )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> AcceptanceState:
        return AcceptanceState(self.envelope.state)

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
    def from_dict(cls, value: Mapping[str, Any]) -> "CommitmentAcceptance":
        envelope, payload = decode_composite(
            value,
            object_type=ACCEPTANCE_OBJECT_TYPE,
            state_type=AcceptanceState,
        )
        return cls(
            envelope=envelope,
            spec=AcceptanceSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "CommitmentAcceptance":
        decoded = decode_composite_json(
            value,
            object_type=ACCEPTANCE_OBJECT_TYPE,
            state_type=AcceptanceState,
        )
        return cls.from_dict(decoded)


def make_acceptance_record(
    *,
    acceptance_id: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    origin_domain: str,
    message_id: str,
    message_digest: str,
    commitment_id: str,
    commitment_digest: str,
    sequence: int,
    anchor_key_id: str,
    accepted_at: str,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> CommitmentAcceptance:
    """Build the sealed immutable acceptance record (ACCEPTED)."""
    spec = AcceptanceSpec(
        acceptance_id=acceptance_id,
        origin_domain=origin_domain,
        message_id=message_id,
        message_digest=message_digest,
        commitment_id=commitment_id,
        commitment_digest=commitment_digest,
        sequence=sequence,
        anchor_key_id=anchor_key_id,
        accepted_at=accepted_at,
    )
    envelope = build_domain_envelope(
        object_id=acceptance_id,
        object_type=ACCEPTANCE_OBJECT_TYPE,
        state=AcceptanceState.ACCEPTED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return CommitmentAcceptance(
        envelope=envelope,
        spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


# -- command payload parsing (handler-side, strict) ---------------------------


def parse_accept_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation accept payload", payload)
    strict_fields("federation accept payload", payload, _ACCEPT_PAYLOAD_FIELDS)
    require_identifier("accept payload acceptance_id", payload["acceptance_id"])
    require_mapping("accept payload message", payload["message"])
    require_mapping("accept payload commitment", payload["commitment"])
    return {
        "acceptance_id": payload["acceptance_id"],
        "message": payload["message"],
        "commitment": payload["commitment"],
    }
