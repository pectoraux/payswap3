"""Purpose-bound keys, rotation, revocation, recovery and threshold approval.

Keys are purpose-bound per the frozen security architecture: ``AUTHENTICATION``,
``SIGNING``, ``EXTENSION_SIGNING``, ``PARTICIPANT_AUTHORIZATION``,
``DOMAIN_STATE_COMMITMENT``, ``FINALITY_EVIDENCE`` and ``RECOVERY``. Keys
support rotation (old key ``ROTATED`` with an explicit successor link),
revocation (``REVOKED`` terminal) and recovery (a bound ``RECOVERY``-purpose
key can re-authorize rotation of a guarded key).

Privileged key rotation is guarded by a threshold approval interface:
``ThresholdPolicy`` (M-of-N approver principals), ``Approval`` (an
authenticated approver decision bound to a proposal digest) and
``ThresholdApproval`` (the aggregated approval set). Approval is only valid
when it is ``APPROVED`` (>= threshold distinct approvals, no rejections), its
policy equals the guarded key's policy, every approval's proposal digest
equals the canonical digest of the actual rotation proposal, and every
approver authenticated at or before the operation instant.

Determinism: key material is caller-supplied; the stored verification digest
is a deterministic SHA-256 over the key id, purpose, public material and
secret material. No randomness, no wall-clock, no third-party cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    require_hex_digest,
    require_identifier,
    require_positive_int,
    require_str_enum,
    require_str_tuple,
    require_text,
    require_timestamp,
    require_window,
)
from .authentication import AuthenticationEventRecord
from .objects import TrustObject, record_from_dict, validate_record_envelope

KEY_OBJECT_TYPE = "trust/key/v1"
KEY_ID_PREFIX = "trust/key/"
KEY_VERIFICATION_VERSION = "trust/key-verification/v1"
KEY_ROTATION_PROPOSAL_VERSION = "trust/key-rotation-proposal/v1"
_KEY_PAYLOAD_KEYS = frozenset(
    {
        "key_id",
        "owner_principal_id",
        "purpose",
        "public_material",
        "verification_digest",
        "not_before",
        "not_after",
        "successor_key_id",
        "predecessor_key_id",
        "threshold_policy",
        "recovery_key_id",
    }
)


class KeyState(StrEnum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"


class KeyPurpose(StrEnum):
    """Purpose-bound key vocabulary derived from the frozen security contract."""

    AUTHENTICATION = "AUTHENTICATION"
    SIGNING = "SIGNING"
    EXTENSION_SIGNING = "EXTENSION_SIGNING"
    PARTICIPANT_AUTHORIZATION = "PARTICIPANT_AUTHORIZATION"
    DOMAIN_STATE_COMMITMENT = "DOMAIN_STATE_COMMITMENT"
    FINALITY_EVIDENCE = "FINALITY_EVIDENCE"
    RECOVERY = "RECOVERY"


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class ThresholdApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


def derive_key_verification_digest(
    key_id: str, purpose: KeyPurpose, public_material: str, secret_material: str
) -> str:
    """Deterministic verification digest binding id+purpose+public+secret material."""
    require_identifier("key_id", key_id, KEY_ID_PREFIX)
    purpose_value = require_str_enum("purpose", purpose, KeyPurpose)
    require_text("public_material", public_material)
    require_text("secret_material", secret_material)
    return canonical_sha256(
        [KEY_VERIFICATION_VERSION, key_id, purpose_value.value, public_material, secret_material]
    )


def key_rotation_proposal_digest(
    *,
    key_id: str,
    successor_key_id: str,
    successor_public_material: str,
    as_of: str,
) -> str:
    """Canonical digest of a key rotation proposal used to bind threshold approvals."""
    require_identifier("key_id", key_id, KEY_ID_PREFIX)
    require_identifier("successor_key_id", successor_key_id, KEY_ID_PREFIX)
    require_text("successor_public_material", successor_public_material)
    require_timestamp("as_of", as_of)
    return canonical_sha256(
        [
            KEY_ROTATION_PROPOSAL_VERSION,
            key_id,
            successor_key_id,
            successor_public_material,
            as_of,
        ]
    )


@dataclass(frozen=True, slots=True)
class ThresholdPolicy:
    """M-of-N approval policy over an explicit set of approver principals."""

    threshold: int
    approvers: tuple[str, ...]

    def __post_init__(self) -> None:
        require_positive_int("threshold_policy.threshold", self.threshold)
        approvers = require_str_tuple("threshold_policy.approvers", self.approvers, distinct=True)
        if not approvers:
            raise CoreValidationError("threshold_policy.approvers must not be empty")
        for approver in approvers:
            require_identifier("threshold_policy.approver", approver, "trust/principal/")
        if self.threshold > len(approvers):
            raise CoreValidationError(
                "threshold_policy.threshold must not exceed the number of approvers"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"threshold": self.threshold, "approvers": list(self.approvers)}

    @classmethod
    def from_dict(cls, value: object) -> "ThresholdPolicy":
        if not isinstance(value, Mapping):
            raise CoreValidationError("threshold policy must be an object")
        if set(value) != {"threshold", "approvers"}:
            raise CoreValidationError("threshold policy fields are not canonical")
        approvers = require_str_tuple("threshold_policy.approvers", value["approvers"])
        return cls(threshold=value["threshold"], approvers=approvers)


@dataclass(frozen=True, slots=True)
class Approval:
    """A single authenticated approver decision bound to a proposal digest."""

    approver_principal_id: str
    decision: ApprovalDecision
    proposal_digest: str
    authentication: AuthenticationEventRecord

    def __post_init__(self) -> None:
        require_identifier("approval.approver", self.approver_principal_id, "trust/principal/")
        require_str_enum("approval.decision", self.decision, ApprovalDecision)
        require_hex_digest("approval.proposal_digest", self.proposal_digest)
        if not isinstance(self.authentication, AuthenticationEventRecord):
            raise CoreValidationError("approval.authentication must be an AuthenticationEventRecord")
        if self.authentication.outcome != "SUCCESS":
            raise CoreValidationError("approval.authentication must be a SUCCESS authentication event")
        if self.authentication.principal_id != self.approver_principal_id:
            raise CoreValidationError(
                "approval.authentication must authenticate the approving principal"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "approver_principal_id": self.approver_principal_id,
            "decision": self.decision.value,
            "proposal_digest": self.proposal_digest,
            "authentication": self.authentication.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> "Approval":
        if not isinstance(value, Mapping):
            raise CoreValidationError("approval must be an object")
        if set(value) != {
            "approver_principal_id",
            "decision",
            "proposal_digest",
            "authentication",
        }:
            raise CoreValidationError("approval fields are not canonical")
        return cls(
            approver_principal_id=value["approver_principal_id"],
            decision=require_str_enum("approval.decision", value["decision"], ApprovalDecision),
            proposal_digest=value["proposal_digest"],
            authentication=AuthenticationEventRecord.from_dict(value["authentication"]),
        )


@dataclass(frozen=True, slots=True)
class ThresholdApproval:
    """Aggregated approval set evaluated deterministically against its policy."""

    policy: ThresholdPolicy
    approvals: tuple[Approval, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ThresholdPolicy):
            raise CoreValidationError("threshold approval policy must be a ThresholdPolicy")
        if not isinstance(self.approvals, tuple) or not self.approvals:
            raise CoreValidationError("threshold approvals must be a non-empty tuple")
        seen: set[str] = set()
        for approval in self.approvals:
            if not isinstance(approval, Approval):
                raise CoreValidationError("threshold approvals must contain Approval records")
            if approval.approver_principal_id in seen:
                raise CoreValidationError(
                    f"threshold approvals contain a duplicate approver: {approval.approver_principal_id}"
                )
            seen.add(approval.approver_principal_id)
            if approval.approver_principal_id not in self.policy.approvers:
                raise CoreValidationError(
                    f"threshold approver {approval.approver_principal_id} is not in the policy approver set"
                )

    @property
    def state(self) -> ThresholdApprovalState:
        for approval in self.approvals:
            if approval.decision is ApprovalDecision.REJECT:
                return ThresholdApprovalState.REJECTED
        approvals_count = sum(
            1 for approval in self.approvals if approval.decision is ApprovalDecision.APPROVE
        )
        if approvals_count >= self.policy.threshold:
            return ThresholdApprovalState.APPROVED
        return ThresholdApprovalState.PENDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "approvals": [approval.to_dict() for approval in self.approvals],
        }

    @classmethod
    def from_dict(cls, value: object) -> "ThresholdApproval":
        if not isinstance(value, Mapping):
            raise CoreValidationError("threshold approval must be an object")
        if set(value) != {"policy", "approvals"}:
            raise CoreValidationError("threshold approval fields are not canonical")
        approvals_value = value["approvals"]
        if not isinstance(approvals_value, list):
            raise CoreValidationError("threshold approval approvals must deserialize from a list")
        return cls(
            policy=ThresholdPolicy.from_dict(value["policy"]),
            approvals=tuple(Approval.from_dict(item) for item in approvals_value),
        )


@dataclass(frozen=True, slots=True)
class KeyRecord(TrustObject):
    """Immutable durable purpose-bound key record (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    key_id: str
    owner_principal_id: str
    purpose: KeyPurpose
    public_material: str
    verification_digest: str
    not_before: str = ""
    not_after: str = ""
    successor_key_id: str | None = None
    predecessor_key_id: str | None = None
    threshold_policy: ThresholdPolicy | None = None
    recovery_key_id: str | None = None

    def __post_init__(self) -> None:
        require_identifier("key.key_id", self.key_id, KEY_ID_PREFIX)
        require_identifier("key.owner_principal_id", self.owner_principal_id, "trust/principal/")
        require_str_enum("key.purpose", self.purpose, KeyPurpose)
        require_text("key.public_material", self.public_material)
        require_hex_digest("key.verification_digest", self.verification_digest)
        require_timestamp("key.not_before", self.not_before)
        require_timestamp("key.not_after", self.not_after)
        require_window("key window", self.not_before, self.not_after)
        if self.successor_key_id is not None:
            require_identifier("key.successor_key_id", self.successor_key_id, KEY_ID_PREFIX)
        if self.predecessor_key_id is not None:
            require_identifier("key.predecessor_key_id", self.predecessor_key_id, KEY_ID_PREFIX)
        if self.recovery_key_id is not None:
            require_identifier("key.recovery_key_id", self.recovery_key_id, KEY_ID_PREFIX)
        if self.threshold_policy is not None and not isinstance(self.threshold_policy, ThresholdPolicy):
            raise CoreValidationError("key.threshold_policy must be a ThresholdPolicy or None")
        validate_record_envelope(
            self.envelope,
            object_id=self.key_id,
            object_type=KEY_OBJECT_TYPE,
            state_vocab=KeyState,
        )

    @property
    def state(self) -> str:
        return self.envelope.state

    def payload_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_principal_id": self.owner_principal_id,
            "purpose": self.purpose.value,
            "public_material": self.public_material,
            "verification_digest": self.verification_digest,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "successor_key_id": self.successor_key_id,
            "predecessor_key_id": self.predecessor_key_id,
            "threshold_policy": (
                self.threshold_policy.to_dict() if self.threshold_policy is not None else None
            ),
            "recovery_key_id": self.recovery_key_id,
        }

    @classmethod
    def from_dict(cls, value: object) -> "KeyRecord":
        def build_payload(envelope: ObjectEnvelope, payload: object) -> KeyRecord:
            if not isinstance(payload, Mapping) or set(payload) != _KEY_PAYLOAD_KEYS:
                raise CoreValidationError("key payload fields are not canonical")
            threshold_value = payload["threshold_policy"]
            return cls(
                envelope=envelope,
                key_id=payload["key_id"],
                owner_principal_id=payload["owner_principal_id"],
                purpose=require_str_enum("key.purpose", payload["purpose"], KeyPurpose),
                public_material=payload["public_material"],
                verification_digest=payload["verification_digest"],
                not_before=payload["not_before"],
                not_after=payload["not_after"],
                successor_key_id=payload["successor_key_id"],
                predecessor_key_id=payload["predecessor_key_id"],
                threshold_policy=(
                    ThresholdPolicy.from_dict(threshold_value)
                    if threshold_value is not None
                    else None
                ),
                recovery_key_id=payload["recovery_key_id"],
            )

        return record_from_dict(cls, value, build_payload)
