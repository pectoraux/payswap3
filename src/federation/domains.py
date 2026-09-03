"""The network domain record: domains, anchors, rotations and transfers.

A :class:`NetworkDomain` is the authoritative record of ONE domain in
its own federation engine (canonical-object-model Federation family
``NetworkDomain`` / ``StateAuthority``). The record carries the
governed state authority, the federation anchor recorded at join time
(the peer domain whose commitment key this domain trusts —
governance.md "Federated state"), the append-only commitment-key
rotation history, and the append-only governed authority-transfer
history (ownership-lifecycle: "domain transfer is explicit and leaves
no dual-authority interval" — a transfer replaces the authority in ONE
atomic version bump, dual-consent proven by knowledge of both keys'
secret material at the engine boundary).

The record's identity discipline: the object id, the spec's domain id
and the envelope's domain id must all agree — a domain record is an
object of the very domain it describes, which is what makes the
kernel's domain binding structurally enforce the Work Order's
forbidden surface "no unilateral foreign-domain mutation".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from ._validation import (
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .authority import StateAuthority
from .contracts import DOMAIN_OBJECT_TYPE, DomainState
from .seal import (
    advance_envelope,
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_JOIN_FACT_FIELDS = frozenset(
    {
        "anchor_domain_id",
        "anchor_key_id",
        "anchor_public_material",
        "anchor_verification_digest",
        "joined_at",
    }
)

_AUTHORITY_UPDATE_FIELDS = frozenset(
    {
        "prior_key_id",
        "new_key_id",
        "new_public_material",
        "new_verification_digest",
        "updated_at",
    }
)

_TRANSFER_FACT_FIELDS = frozenset(
    {
        "prior_principal_id",
        "prior_key_id",
        "new_principal_id",
        "new_key_id",
        "new_public_material",
        "new_verification_digest",
        "transferred_at",
    }
)

_SPEC_FIELDS = frozenset(
    {
        "domain_id",
        "authority",
        "registered_at",
        "join",
        "left_at",
        "authority_updates",
        "transfers",
    }
)

_REGISTER_PAYLOAD_FIELDS = frozenset({"domain_id", "authority_key"})
_JOIN_PAYLOAD_FIELDS = frozenset({"anchor_domain_id", "anchor_key"})
_LEAVE_PAYLOAD_FIELDS = frozenset({"reason"})
_UPDATE_AUTHORITY_PAYLOAD_FIELDS = frozenset({"new_key"})
_TRANSFER_PAYLOAD_FIELDS = frozenset({"new_principal_id", "new_key"})


@dataclass(frozen=True, slots=True)
class JoinFact:
    """The federation anchor recorded when a domain joins a peer.

    The anchor facts (peer domain id and its commitment key) are the
    trust root for every foreign state commitment this domain accepts
    from that peer: acceptance verifies signatures against exactly
    these facts.
    """

    anchor_domain_id: str
    anchor_key_id: str
    anchor_public_material: str
    anchor_verification_digest: str
    joined_at: str

    def __post_init__(self) -> None:
        require_identifier("join.anchor_domain_id", self.anchor_domain_id)
        require_identifier("join.anchor_key_id", self.anchor_key_id)
        require_text("join.anchor_public_material", self.anchor_public_material)
        if (
            len(self.anchor_verification_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.anchor_verification_digest)
        ):
            raise CoreValidationError(
                "join.anchor_verification_digest must be a canonical SHA-256 digest"
            )
        require_utc_timestamp("join.joined_at", self.joined_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_domain_id": self.anchor_domain_id,
            "anchor_key_id": self.anchor_key_id,
            "anchor_public_material": self.anchor_public_material,
            "anchor_verification_digest": self.anchor_verification_digest,
            "joined_at": self.joined_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "JoinFact":
        require_mapping("join fact", value)
        strict_fields("join fact", value, _JOIN_FACT_FIELDS)
        return cls(
            anchor_domain_id=value["anchor_domain_id"],
            anchor_key_id=value["anchor_key_id"],
            anchor_public_material=value["anchor_public_material"],
            anchor_verification_digest=value["anchor_verification_digest"],
            joined_at=value["joined_at"],
        )


@dataclass(frozen=True, slots=True)
class AuthorityUpdate:
    """One append-only commitment-key rotation (UpdateAuthority)."""

    prior_key_id: str
    new_key_id: str
    new_public_material: str
    new_verification_digest: str
    updated_at: str

    def __post_init__(self) -> None:
        require_identifier("authority_update.prior_key_id", self.prior_key_id)
        require_identifier("authority_update.new_key_id", self.new_key_id)
        require_text("authority_update.new_public_material", self.new_public_material)
        if (
            len(self.new_verification_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.new_verification_digest)
        ):
            raise CoreValidationError(
                "authority_update.new_verification_digest must be a canonical SHA-256 digest"
            )
        require_utc_timestamp("authority_update.updated_at", self.updated_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prior_key_id": self.prior_key_id,
            "new_key_id": self.new_key_id,
            "new_public_material": self.new_public_material,
            "new_verification_digest": self.new_verification_digest,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityUpdate":
        require_mapping("authority update", value)
        strict_fields("authority update", value, _AUTHORITY_UPDATE_FIELDS)
        return cls(
            prior_key_id=value["prior_key_id"],
            new_key_id=value["new_key_id"],
            new_public_material=value["new_public_material"],
            new_verification_digest=value["new_verification_digest"],
            updated_at=value["updated_at"],
        )


@dataclass(frozen=True, slots=True)
class TransferFact:
    """One append-only governed authority transfer (TransferDomain).

    Dual consent: the outgoing authority's secret (proven at the engine
    boundary against the prior key's verification digest) and the
    incoming authority's secret (proven against the new key's
    verification digest). The atomic version bump that replaces the
    authority leaves no dual-authority interval.
    """

    prior_principal_id: str
    prior_key_id: str
    new_principal_id: str
    new_key_id: str
    new_public_material: str
    new_verification_digest: str
    transferred_at: str

    def __post_init__(self) -> None:
        require_identifier("transfer.prior_principal_id", self.prior_principal_id)
        require_identifier("transfer.prior_key_id", self.prior_key_id)
        require_identifier("transfer.new_principal_id", self.new_principal_id)
        require_identifier("transfer.new_key_id", self.new_key_id)
        require_text("transfer.new_public_material", self.new_public_material)
        if (
            len(self.new_verification_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.new_verification_digest)
        ):
            raise CoreValidationError(
                "transfer.new_verification_digest must be a canonical SHA-256 digest"
            )
        require_utc_timestamp("transfer.transferred_at", self.transferred_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prior_principal_id": self.prior_principal_id,
            "prior_key_id": self.prior_key_id,
            "new_principal_id": self.new_principal_id,
            "new_key_id": self.new_key_id,
            "new_public_material": self.new_public_material,
            "new_verification_digest": self.new_verification_digest,
            "transferred_at": self.transferred_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransferFact":
        require_mapping("transfer fact", value)
        strict_fields("transfer fact", value, _TRANSFER_FACT_FIELDS)
        return cls(
            prior_principal_id=value["prior_principal_id"],
            prior_key_id=value["prior_key_id"],
            new_principal_id=value["new_principal_id"],
            new_key_id=value["new_key_id"],
            new_public_material=value["new_public_material"],
            new_verification_digest=value["new_verification_digest"],
            transferred_at=value["transferred_at"],
        )


@dataclass(frozen=True, slots=True)
class DomainSpec:
    """Domain identity, governed authority and lifecycle facts."""

    domain_id: str
    authority: StateAuthority
    registered_at: str
    join: JoinFact | None = None
    left_at: str | None = None
    authority_updates: tuple[AuthorityUpdate, ...] = ()
    transfers: tuple[TransferFact, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("domain.domain_id", self.domain_id)
        if not isinstance(self.authority, StateAuthority):
            raise CoreValidationError("domain.authority must be a StateAuthority")
        require_utc_timestamp("domain.registered_at", self.registered_at)
        if self.join is not None and not isinstance(self.join, JoinFact):
            raise CoreValidationError("domain.join must be a JoinFact")
        if self.left_at is not None:
            require_utc_timestamp("domain.left_at", self.left_at)
        if not isinstance(self.authority_updates, tuple) or not isinstance(
            self.transfers, tuple
        ):
            raise CoreValidationError("domain history collections must be tuples")
        for update in self.authority_updates:
            if not isinstance(update, AuthorityUpdate):
                raise CoreValidationError(
                    "domain.authority_updates entries must be AuthorityUpdate records"
                )
        for transfer in self.transfers:
            if not isinstance(transfer, TransferFact):
                raise CoreValidationError(
                    "domain.transfers entries must be TransferFact records"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "authority": self.authority.to_dict(),
            "registered_at": self.registered_at,
            "join": self.join.to_dict() if self.join is not None else None,
            "left_at": self.left_at,
            "authority_updates": [update.to_dict() for update in self.authority_updates],
            "transfers": [transfer.to_dict() for transfer in self.transfers],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DomainSpec":
        require_mapping("domain spec", value)
        strict_fields("domain spec", value, _SPEC_FIELDS)
        updates = value["authority_updates"]
        transfers = value["transfers"]
        if not isinstance(updates, list) or not isinstance(transfers, list):
            raise CoreValidationError("domain history collections deserialize from lists")
        return cls(
            domain_id=value["domain_id"],
            authority=StateAuthority.from_dict(value["authority"]),
            registered_at=value["registered_at"],
            join=(
                JoinFact.from_dict(value["join"])
                if value["join"] is not None
                else None
            ),
            left_at=value["left_at"],
            authority_updates=tuple(
                AuthorityUpdate.from_dict(item) for item in updates
            ),
            transfers=tuple(TransferFact.from_dict(item) for item in transfers),
        )


@dataclass(frozen=True, slots=True)
class NetworkDomain:
    """The sealed internal ``federation/network-domain/v1`` object."""

    envelope: ObjectEnvelope
    spec: DomainSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = DOMAIN_OBJECT_TYPE
    STATE_TYPE = DomainState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("domain envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, DomainSpec):
            raise CoreValidationError("domain spec must be a DomainSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.domain_id:
            raise CoreValidationError(
                "domain envelope and spec must agree on the domain id"
            )
        if self.envelope.domain_id != self.spec.domain_id:
            raise CoreValidationError(
                "a domain record is an object of the very domain it describes"
            )
        _validate_state_facts(DomainState(self.envelope.state), self.spec)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> DomainState:
        return DomainState(self.envelope.state)

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
    def from_dict(cls, value: Mapping[str, Any]) -> "NetworkDomain":
        envelope, payload = decode_composite(
            value,
            object_type=DOMAIN_OBJECT_TYPE,
            state_type=DomainState,
        )
        return cls(
            envelope=envelope,
            spec=DomainSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "NetworkDomain":
        decoded = decode_composite_json(
            value,
            object_type=DOMAIN_OBJECT_TYPE,
            state_type=DomainState,
        )
        return cls.from_dict(decoded)


def _validate_state_facts(state: DomainState, spec: DomainSpec) -> None:
    """State-specific coherence of the domain facts (fail closed)."""
    if state is DomainState.REGISTERED:
        if spec.join is not None:
            raise CoreValidationError("a REGISTERED domain must carry no join fact")
        if spec.left_at is not None:
            raise CoreValidationError("a REGISTERED domain must carry no left_at")
    if state is DomainState.JOINED:
        if spec.join is None:
            raise CoreValidationError("a JOINED domain must carry its anchor join fact")
        if spec.left_at is not None:
            raise CoreValidationError("a JOINED domain must carry no left_at")
    if state is DomainState.LEFT:
        if spec.join is None:
            raise CoreValidationError("a LEFT domain must have joined before leaving")
        if spec.left_at is None:
            raise CoreValidationError("a LEFT domain must carry left_at")


def make_domain_record(
    *,
    domain_id: str,
    environment_id: str,
    provenance: Provenance,
    authority: StateAuthority,
    registered_at: str,
    join: JoinFact | None = None,
    left_at: str | None = None,
    authority_updates: tuple[AuthorityUpdate, ...] = (),
    transfers: tuple[TransferFact, ...] = (),
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> NetworkDomain:
    """Build the sealed version-1 domain record (REGISTERED facts)."""
    spec = DomainSpec(
        domain_id=domain_id,
        authority=authority,
        registered_at=registered_at,
        join=join,
        left_at=left_at,
        authority_updates=authority_updates,
        transfers=transfers,
    )
    envelope = build_domain_envelope(
        object_id=domain_id,
        object_type=DOMAIN_OBJECT_TYPE,
        state=DomainState.REGISTERED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return NetworkDomain(
        envelope=envelope,
        spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


def advance_domain(
    record: NetworkDomain,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
    spec: DomainSpec | None = None,
) -> NetworkDomain:
    """Produce the next sealed domain version with new state and facts."""
    new_spec = spec if spec is not None else record.spec
    envelope = advance_envelope(
        record.envelope,
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return NetworkDomain(
        envelope=envelope,
        spec=new_spec,
        integrity_hash=seal_composite(envelope, new_spec),
    )


# -- command payload parsing (handler-side, strict) ---------------------------


def parse_register_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation register payload", payload)
    strict_fields("federation register payload", payload, _REGISTER_PAYLOAD_FIELDS)
    require_identifier(
        "register payload domain_id", payload["domain_id"]
    )
    require_mapping("register payload authority_key", payload["authority_key"])
    return {
        "domain_id": payload["domain_id"],
        "authority_key": payload["authority_key"],
    }


def parse_join_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation join payload", payload)
    strict_fields("federation join payload", payload, _JOIN_PAYLOAD_FIELDS)
    require_identifier("join payload anchor_domain_id", payload["anchor_domain_id"])
    require_mapping("join payload anchor_key", payload["anchor_key"])
    return {
        "anchor_domain_id": payload["anchor_domain_id"],
        "anchor_key": payload["anchor_key"],
    }


def parse_leave_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation leave payload", payload)
    strict_fields("federation leave payload", payload, _LEAVE_PAYLOAD_FIELDS)
    require_text("leave payload reason", payload["reason"])
    return {"reason": payload["reason"]}


def parse_update_authority_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation update-authority payload", payload)
    strict_fields(
        "federation update-authority payload", payload, _UPDATE_AUTHORITY_PAYLOAD_FIELDS
    )
    require_mapping("update-authority payload new_key", payload["new_key"])
    return {"new_key": payload["new_key"]}


def parse_transfer_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    require_mapping("federation transfer-domain payload", payload)
    strict_fields(
        "federation transfer-domain payload", payload, _TRANSFER_PAYLOAD_FIELDS
    )
    require_identifier(
        "transfer-domain payload new_principal_id", payload["new_principal_id"]
    )
    require_mapping("transfer-domain payload new_key", payload["new_key"])
    return {
        "new_principal_id": payload["new_principal_id"],
        "new_key": payload["new_key"],
    }
