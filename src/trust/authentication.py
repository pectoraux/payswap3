"""Authentication events: immutable records of authentication attempts.

Authentication proves identity/control (the frozen security contract). An
authentication event records the outcome of one authentication attempt by a
principal with a credential at an explicit logical instant: ``SUCCESS`` or
``FAILURE`` with a closed failure-reason vocabulary (wrong verifier, suspended
principal, revoked/rotated/expired/not-yet-valid credential or key).

Events are IMMUTABLE lifecycle objects (single sealed version, never amended).
The deterministic event id is derived from
``["trust/authentication-id/v1", principal, credential, nonce, as_of]`` with an
explicit caller-supplied nonce, so replays of the identical attempt are
idempotent while a conflicting retry under the same nonce fails closed.
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
)
from .credentials import CredentialKind
from .objects import TrustObject, record_from_dict, validate_record_envelope

AUTHENTICATION_OBJECT_TYPE = "trust/authentication/v1"
AUTHENTICATION_ID_PREFIX = "trust/authentication/"
AUTHENTICATION_ID_VERSION = "trust/authentication-id/v1"
_AUTHENTICATION_PAYLOAD_KEYS = frozenset(
    {
        "authentication_id",
        "principal_id",
        "credential_id",
        "credential_kind",
        "nonce",
        "outcome",
        "failure_reason",
        "occurred_at",
    }
)


class AuthenticationOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuthenticationFailureReason(StrEnum):
    VERIFIER_MISMATCH = "VERIFIER_MISMATCH"
    PRINCIPAL_SUSPENDED = "PRINCIPAL_SUSPENDED"
    CREDENTIAL_NOT_YET_VALID = "CREDENTIAL_NOT_YET_VALID"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_ROTATED = "CREDENTIAL_ROTATED"
    KEY_NOT_YET_VALID = "KEY_NOT_YET_VALID"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_ROTATED = "KEY_ROTATED"


def derive_authentication_id(
    principal_id: str, credential_id: str, nonce: str, as_of: str
) -> str:
    """Deterministic authentication event id from the explicit attempt inputs."""
    require_identifier("principal_id", principal_id, "trust/principal/")
    require_identifier("credential_id", credential_id, "trust/credential/")
    require_text("nonce", nonce)
    require_timestamp("as_of", as_of)
    digest = canonical_sha256(
        [AUTHENTICATION_ID_VERSION, principal_id, credential_id, nonce, as_of]
    )
    return AUTHENTICATION_ID_PREFIX + digest


@dataclass(frozen=True, slots=True)
class AuthenticationEventRecord(TrustObject):
    """Immutable durable authentication event (envelope + typed payload + seal)."""

    envelope: ObjectEnvelope
    authentication_id: str
    principal_id: str
    credential_id: str
    credential_kind: CredentialKind
    nonce: str
    outcome: AuthenticationOutcome
    failure_reason: AuthenticationFailureReason | None = None
    occurred_at: str = ""

    def __post_init__(self) -> None:
        require_identifier(
            "authentication.authentication_id", self.authentication_id, AUTHENTICATION_ID_PREFIX
        )
        require_identifier("authentication.principal_id", self.principal_id, "trust/principal/")
        require_identifier("authentication.credential_id", self.credential_id, "trust/credential/")
        kind = require_str_enum("authentication.credential_kind", self.credential_kind, CredentialKind)
        object.__setattr__(self, "credential_kind", kind)
        require_text("authentication.nonce", self.nonce)
        outcome = require_str_enum("authentication.outcome", self.outcome, AuthenticationOutcome)
        object.__setattr__(self, "outcome", outcome)
        require_timestamp("authentication.occurred_at", self.occurred_at)
        if outcome is AuthenticationOutcome.SUCCESS:
            if self.failure_reason is not None:
                raise CoreValidationError(
                    "successful authentication events must not carry a failure reason"
                )
        else:
            reason = require_str_enum(
                "authentication.failure_reason", self.failure_reason, AuthenticationFailureReason
            )
            object.__setattr__(self, "failure_reason", reason)
        validate_record_envelope(
            self.envelope,
            object_id=self.authentication_id,
            object_type=AUTHENTICATION_OBJECT_TYPE,
            state_vocab=AuthenticationOutcome,
        )
        if self.envelope.state != outcome.value:
            raise CoreValidationError(
                "authentication envelope state must equal the authentication outcome"
            )

    def payload_dict(self) -> dict[str, Any]:
        return {
            "authentication_id": self.authentication_id,
            "principal_id": self.principal_id,
            "credential_id": self.credential_id,
            "credential_kind": self.credential_kind.value,
            "nonce": self.nonce,
            "outcome": self.outcome.value,
            "failure_reason": None if self.failure_reason is None else self.failure_reason.value,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> "AuthenticationEventRecord":
        def build_payload(
            envelope: ObjectEnvelope, payload: object
        ) -> AuthenticationEventRecord:
            if not isinstance(payload, Mapping) or set(payload) != _AUTHENTICATION_PAYLOAD_KEYS:
                raise CoreValidationError("authentication payload fields are not canonical")
            failure_reason = require_optional_text(
                "authentication.failure_reason", payload["failure_reason"]
            )
            return cls(
                envelope=envelope,
                authentication_id=payload["authentication_id"],
                principal_id=payload["principal_id"],
                credential_id=payload["credential_id"],
                credential_kind=require_str_enum(
                    "authentication.credential_kind", payload["credential_kind"], CredentialKind
                ),
                nonce=payload["nonce"],
                outcome=require_str_enum(
                    "authentication.outcome", payload["outcome"], AuthenticationOutcome
                ),
                failure_reason=failure_reason,
                occurred_at=payload["occurred_at"],
            )

        return record_from_dict(cls, value, build_payload)
