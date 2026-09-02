"""Credential records: purpose-bound authentication instruments.

Lifecycle follows the frozen identity command family
``Issue/Rotate/RevokeCredential``. Two closed credential kinds exist:

``SECRET_DIGEST``
    A symmetric proof-of-control credential: the stored value is a deterministic
    SHA-256 verifier digest derived from the caller-supplied secret; the secret
    itself is never stored, logged or serialized. Authentication presents the
    secret; the digest is recomputed and compared in constant time.

``KEY_PROOF``
    A credential bound to a purpose-bound :class:`src.trust.keys.KeyRecord`
    whose purpose must be ``AUTHENTICATION``; authentication presents the key's
    secret material and the key's verification digest is checked.

Validity windows are half-open ``[not_before, not_after)`` checked against the
caller-supplied ``as_of`` logical instant (no wall-clock, no randomness).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    require_identifier,
    require_optional_text,
    require_str_enum,
    require_text,
    require_timestamp,
    require_window,
)
from .objects import TrustObject, record_from_dict, validate_record_envelope

CREDENTIAL_OBJECT_TYPE = "trust/credential/v1"
CREDENTIAL_ID_PREFIX = "trust/credential/"
CREDENTIAL_VERIFIER_VERSION = "trust/credential-verifier/v1"
_CREDENTIAL_PAYLOAD_KEYS = frozenset(
    {
        "credential_id",
        "principal_id",
        "kind",
        "key_id",
        "verifier_digest",
        "not_before",
        "not_after",
        "successor_credential_id",
        "predecessor_credential_id",
    }
)


class CredentialState(StrEnum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"


class CredentialKind(StrEnum):
    SECRET_DIGEST = "SECRET_DIGEST"
    KEY_PROOF = "KEY_PROOF"


def derive_credential_verifier(credential_id: str, secret: str) -> str:
    """Deterministic verifier digest for a SECRET_DIGEST credential.

    The secret never persists; only this digest does. No randomness and no
    wall-clock are involved, so identical inputs always yield identical
    verifiers.
    """
    require_identifier("credential_id", credential_id, CREDENTIAL_ID_PREFIX)
    require_text("secret", secret)
    return canonical_sha256([CREDENTIAL_VERIFIER_VERSION, credential_id, secret])


@dataclass(frozen=True, slots=True)
class CredentialRecord(TrustObject):
    """Immutable durable credential record (envelope + typed payload + seal)."""

    envelope: ObjectEnvelope
    credential_id: str
    principal_id: str
    kind: CredentialKind
    key_id: str | None = None
    verifier_digest: str | None = None
    not_before: str = ""
    not_after: str = ""
    successor_credential_id: str | None = None
    predecessor_credential_id: str | None = None

    def __post_init__(self) -> None:
        require_identifier("credential.credential_id", self.credential_id, CREDENTIAL_ID_PREFIX)
        require_identifier("credential.principal_id", self.principal_id, "trust/principal/")
        kind = require_str_enum("credential.kind", self.kind, CredentialKind)
        if kind is CredentialKind.SECRET_DIGEST:
            if self.key_id is not None:
                raise CoreValidationError("SECRET_DIGEST credentials must not reference a key")
            if not isinstance(self.verifier_digest, str):
                raise CoreValidationError(
                    "SECRET_DIGEST credentials require a verifier digest"
                )
        else:
            require_identifier("credential.key_id", self.key_id, "trust/key/")
            if self.verifier_digest is not None:
                raise CoreValidationError("KEY_PROOF credentials must not store a verifier digest")
        for name in ("successor_credential_id", "predecessor_credential_id"):
            value = getattr(self, name)
            if value is not None:
                require_identifier(f"credential.{name}", value, CREDENTIAL_ID_PREFIX)
        if self.verifier_digest is not None:
            from ._validation import require_hex_digest

            require_hex_digest("credential.verifier_digest", self.verifier_digest)
        require_timestamp("credential.not_before", self.not_before)
        require_timestamp("credential.not_after", self.not_after)
        require_window("credential window", self.not_before, self.not_after)
        validate_record_envelope(
            self.envelope,
            object_id=self.credential_id,
            object_type=CREDENTIAL_OBJECT_TYPE,
            state_vocab=CredentialState,
        )

    @property
    def state(self) -> str:
        return self.envelope.state

    def payload_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "principal_id": self.principal_id,
            "kind": self.kind.value,
            "key_id": self.key_id,
            "verifier_digest": self.verifier_digest,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "successor_credential_id": self.successor_credential_id,
            "predecessor_credential_id": self.predecessor_credential_id,
        }

    @classmethod
    def from_dict(cls, value: object) -> "CredentialRecord":
        def build_payload(envelope: ObjectEnvelope, payload: object) -> CredentialRecord:
            if not isinstance(payload, Mapping) or set(payload) != _CREDENTIAL_PAYLOAD_KEYS:
                raise CoreValidationError("credential payload fields are not canonical")
            return cls(
                envelope=envelope,
                credential_id=payload["credential_id"],
                principal_id=payload["principal_id"],
                kind=require_str_enum("credential.kind", payload["kind"], CredentialKind),
                key_id=require_optional_text("credential.key_id", payload["key_id"]),
                verifier_digest=payload["verifier_digest"],
                not_before=payload["not_before"],
                not_after=payload["not_after"],
                successor_credential_id=payload["successor_credential_id"],
                predecessor_credential_id=payload["predecessor_credential_id"],
            )

        return record_from_dict(cls, value, build_payload)
