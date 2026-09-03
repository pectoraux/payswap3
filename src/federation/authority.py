"""State authorities and the deterministic commitment signature scheme.

A :class:`StateAuthority` is the governed authority of a network domain
(governance.md "Federated state"): an authoritative principal plus the
purpose-bound commitment key whose facts are derived from the trust
domain's sealed :class:`~src.trust.keys.KeyRecord` (WORK-004 — the
``DOMAIN_STATE_COMMITMENT`` key purpose is frozen in the trust
contract). The signature scheme is deterministic and purpose-bound,
mirroring the trust domain's key discipline: no randomness, no
wall-clock, no third-party cryptography — the canonical hash authority
alone, over the signature version, key identity, purpose, public
material, payload digest and the caller-supplied secret material.

Secret material discipline: secrets are caller-supplied parameters at
signature/verification time and NEVER stored in any command payload,
event payload, journal entry or durable record. The authenticity of a
supplied secret is pinned by the key's recorded ``verification_digest``
(the trust domain's deterministic binding of id+purpose+public+secret),
which is a public, journaled fact — so a verifier can prove a supplied
secret matches the registered key without ever persisting it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.trust.keys import KeyPurpose, KeyRecord, KeyState

from ._validation import (
    require_digest,
    require_identifier,
    require_mapping,
    require_text,
    strict_fields,
)

#: Canonical version string binding the commitment signature scheme.
COMMITMENT_SIGNATURE_VERSION = "federation/commitment-signature/v1"

_AUTHORITY_FIELDS = frozenset(
    {
        "principal_id",
        "key_id",
        "public_material",
        "verification_digest",
    }
)


@dataclass(frozen=True, slots=True)
class StateAuthority:
    """The governed authority of one network domain.

    ``principal_id`` is the authoritative principal (trust domain
    identity); ``key_id``/``public_material``/``verification_digest``
    are the commitment key facts derived from the sealed trust key
    record (purpose ``DOMAIN_STATE_COMMITMENT``), never trusted from a
    raw payload.
    """

    principal_id: str
    key_id: str
    public_material: str
    verification_digest: str

    def __post_init__(self) -> None:
        require_identifier("authority.principal_id", self.principal_id)
        require_identifier("authority.key_id", self.key_id)
        require_text("authority.public_material", self.public_material)
        require_digest("authority.verification_digest", self.verification_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "public_material": self.public_material,
            "verification_digest": self.verification_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StateAuthority":
        require_mapping("state authority", value)
        strict_fields("state authority", value, _AUTHORITY_FIELDS)
        return cls(
            principal_id=value["principal_id"],
            key_id=value["key_id"],
            public_material=value["public_material"],
            verification_digest=value["verification_digest"],
        )


def state_authority_from_key(key: KeyRecord) -> StateAuthority:
    """Derive the authority facts from a decoded commitment key record.

    The facts (owner principal, key id, public material, verification
    digest) are re-derived from the sealed trust record — payload text
    is never trusted.
    """
    if key.purpose is not KeyPurpose.DOMAIN_STATE_COMMITMENT:
        raise CoreValidationError(
            "a domain state authority must be backed by a "
            f"DOMAIN_STATE_COMMITMENT purpose key; key {key.key_id} has purpose "
            f"{key.purpose.value}"
        )
    if key.state != KeyState.ACTIVE.value:
        raise CoreValidationError(
            f"commitment key {key.key_id} is {key.state}, not ACTIVE"
        )
    return StateAuthority(
        principal_id=key.owner_principal_id,
        key_id=key.key_id,
        public_material=key.public_material,
        verification_digest=key.verification_digest,
    )


def decode_authority_key(composite: Any) -> KeyRecord:
    """Decode a commitment key through the trust domain's trusted path.

    The composite seal is verified by the trust domain's decode path
    (a tampered or spliced key fails closed here), and the key must be
    an ACTIVE ``DOMAIN_STATE_COMMITMENT`` purpose key.
    """
    if not isinstance(composite, Mapping):
        raise CoreValidationError("federation commands require trust key composites")
    key = KeyRecord.from_dict(composite)
    if key.purpose is not KeyPurpose.DOMAIN_STATE_COMMITMENT:
        raise CoreValidationError(
            "the federation commitment key must have purpose DOMAIN_STATE_COMMITMENT; "
            f"key {key.key_id} has purpose {key.purpose.value}"
        )
    if key.state != KeyState.ACTIVE.value:
        raise CoreValidationError(
            f"the federation commitment key {key.key_id} is {key.state}, not ACTIVE"
        )
    return key


def sign_commitment(
    *,
    key_id: str,
    public_material: str,
    secret_material: str,
    payload_digest: str,
) -> str:
    """Deterministic purpose-bound signature over a commitment payload digest."""
    require_identifier("signature.key_id", key_id)
    require_text("signature.public_material", public_material)
    require_text("signature.secret_material", secret_material)
    require_digest("signature.payload_digest", payload_digest)
    return canonical_sha256(
        [
            COMMITMENT_SIGNATURE_VERSION,
            key_id,
            KeyPurpose.DOMAIN_STATE_COMMITMENT.value,
            public_material,
            payload_digest,
            secret_material,
        ]
    )


def verify_commitment_signature(
    signature: str,
    *,
    key_id: str,
    public_material: str,
    secret_material: str,
    payload_digest: str,
) -> None:
    """Fail closed unless the signature verifies for this exact key and payload."""
    require_digest("signature", signature)
    expected = sign_commitment(
        key_id=key_id,
        public_material=public_material,
        secret_material=secret_material,
        payload_digest=payload_digest,
    )
    if signature != expected:
        raise CoreValidationError(
            "state commitment signature verification failed: the signature does "
            "not verify for the registered commitment key and payload digest"
        )


def require_secret_matches_key(
    *,
    key_id: str,
    public_material: str,
    verification_digest: str,
    secret_material: str,
    role: str,
) -> None:
    """Prove a caller-supplied secret matches a registered key.

    Recomputes the trust domain's deterministic verification digest
    (id + purpose + public + secret) and fails closed on mismatch: the
    caller must hold the registered key's secret material to drive the
    authority-bound federation operations. The secret itself is never
    stored.
    """
    from src.trust.keys import derive_key_verification_digest

    derived = derive_key_verification_digest(
        key_id, KeyPurpose.DOMAIN_STATE_COMMITMENT, public_material, secret_material
    )
    if derived != verification_digest:
        raise CoreValidationError(
            f"the supplied {role} secret material does not match the registered "
            f"commitment key {key_id}"
        )
