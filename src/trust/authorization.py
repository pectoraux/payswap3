"""Authorization requests and decisions: the deterministic decision contract.

Authorization is a separate deterministic decision over principal,
delegation, object, domain, amount, jurisdiction and policy (frozen security
contract). :class:`AuthorizationRequest` carries those inputs plus the
required authority classes and the authentication evidence;
:class:`AuthorizationDecision` carries the outcome (``ALLOW``/``DENY``), a
closed denial-reason vocabulary, the matched delegation chains and mandate,
and deterministic request/decision digests for provenance.

The decision itself is evaluated by :class:`src.trust.service.TrustRegistry`
against live registry state: default deny, fail-closed on every unknown or
inactive input, and full re-validation of each delegation chain link
(state, window, environment, scope, amount limits, jurisdictions) from the
acting principal's grant up to its ROOT grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    require_identifier,
    require_optional_text,
    require_str_tuple,
    require_text,
    require_timestamp,
)
from .authentication import AuthenticationEventRecord
from .objects import AmountBound
from .registry import validate_authority_class

AUTHORIZATION_REQUEST_VERSION = "trust/authorization-request/v1"
AUTHORIZATION_DECISION_VERSION = "trust/authorization-decision/v1"


class AuthorizationOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationDenialReason(StrEnum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    AUTHENTICATION_INVALID = "AUTHENTICATION_INVALID"
    UNKNOWN_PRINCIPAL = "UNKNOWN_PRINCIPAL"
    PRINCIPAL_INACTIVE = "PRINCIPAL_INACTIVE"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    AUTHORITY_CLASS_NOT_GRANTED = "AUTHORITY_CLASS_NOT_GRANTED"
    GRANT_INACTIVE = "GRANT_INACTIVE"
    GRANT_WINDOW_INVALID = "GRANT_WINDOW_INVALID"
    SCOPE_NOT_COVERED = "SCOPE_NOT_COVERED"
    AMOUNT_EXCEEDS_LIMIT = "AMOUNT_EXCEEDS_LIMIT"
    JURISDICTION_NOT_COVERED = "JURISDICTION_NOT_COVERED"
    DELEGATION_CHAIN_INVALID = "DELEGATION_CHAIN_INVALID"
    MANDATE_REQUIRED = "MANDATE_REQUIRED"
    MANDATE_INACTIVE = "MANDATE_INACTIVE"
    MANDATE_WINDOW_INVALID = "MANDATE_WINDOW_INVALID"
    MANDATE_SCOPE_NOT_COVERED = "MANDATE_SCOPE_NOT_COVERED"
    MANDATE_AMOUNT_EXCEEDS_LIMIT = "MANDATE_AMOUNT_EXCEEDS_LIMIT"
    MANDATE_JURISDICTION_NOT_COVERED = "MANDATE_JURISDICTION_NOT_COVERED"
    MANDATE_ENVIRONMENT_MISMATCH = "MANDATE_ENVIRONMENT_MISMATCH"


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Inputs of the deterministic authorization decision (typed, versioned)."""

    principal_id: str
    authority_classes: tuple
    domain_id: str
    environment_id: str
    as_of: str
    authentication: AuthenticationEventRecord | None = None
    object_ref: str | None = None
    amount: AmountBound | None = None
    jurisdiction: str | None = None
    on_behalf_of: str | None = None
    action: str | None = None
    policy_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("request.principal_id", self.principal_id, "trust/principal/")
        require_text("request.domain_id", self.domain_id)
        require_text("request.environment_id", self.environment_id)
        require_timestamp("request.as_of", self.as_of)
        if not isinstance(self.authority_classes, tuple) or not self.authority_classes:
            raise CoreValidationError(
                "request.authority_classes must be a non-empty tuple of registry authority classes"
            )
        classes = tuple(validate_authority_class(item) for item in self.authority_classes)
        if len({item.value for item in classes}) != len(classes):
            raise CoreValidationError("request.authority_classes contains duplicate classes")
        object.__setattr__(self, "authority_classes", classes)
        if self.authentication is not None and not isinstance(
            self.authentication, AuthenticationEventRecord
        ):
            raise CoreValidationError(
                "request.authentication must be an AuthenticationEventRecord or None"
            )
        require_optional_text("request.object_ref", self.object_ref)
        if self.amount is not None and not isinstance(self.amount, AmountBound):
            raise CoreValidationError("request.amount must be an AmountBound or None")
        require_optional_text("request.jurisdiction", self.jurisdiction)
        if self.on_behalf_of is not None:
            require_identifier("request.on_behalf_of", self.on_behalf_of, "trust/principal/")
        require_optional_text("request.action", self.action)
        object.__setattr__(
            self, "policy_refs", require_str_tuple("request.policy_refs", self.policy_refs)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "authority_classes": [item.value for item in self.authority_classes],
            "object_ref": self.object_ref,
            "domain_id": self.domain_id,
            "environment_id": self.environment_id,
            "as_of": self.as_of,
            "amount": None if self.amount is None else self.amount.to_dict(),
            "jurisdiction": self.jurisdiction,
            "on_behalf_of": self.on_behalf_of,
            "action": self.action,
            "policy_refs": list(self.policy_refs),
            "authentication_id": (
                None if self.authentication is None else self.authentication.authentication_id
            ),
        }

    @property
    def request_digest(self) -> str:
        return canonical_sha256([AUTHORIZATION_REQUEST_VERSION, self.to_dict()])


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Deterministic outcome of an authorization decision, with provenance."""

    decision: AuthorizationOutcome
    reasons: tuple
    principal_id: str
    as_of: str
    environment_id: str
    authentication_id: str | None
    matched_grant_chains: tuple
    matched_mandate_id: str | None
    request_digest: str

    def __post_init__(self) -> None:
        from ._validation import require_hex_digest

        outcome = self._require_enum("decision.decision", self.decision, AuthorizationOutcome)
        object.__setattr__(self, "decision", outcome)
        if not isinstance(self.reasons, tuple):
            raise CoreValidationError("decision.reasons must be a tuple of denial reasons")
        reasons = tuple(
            self._require_enum("decision.reason", item, AuthorizationDenialReason)
            for item in self.reasons
        )
        if len({item.value for item in reasons}) != len(reasons):
            raise CoreValidationError("decision.reasons contains duplicate values")
        object.__setattr__(self, "reasons", tuple(sorted(reasons, key=lambda item: item.value)))
        if outcome is AuthorizationOutcome.ALLOW and reasons:
            raise CoreValidationError("an ALLOW decision cannot carry denial reasons")
        if outcome is AuthorizationOutcome.DENY and not reasons:
            raise CoreValidationError("a DENY decision must carry at least one denial reason")
        require_identifier("decision.principal_id", self.principal_id, "trust/principal/")
        require_timestamp("decision.as_of", self.as_of)
        require_text("decision.environment_id", self.environment_id)
        require_optional_text("decision.authentication_id", self.authentication_id)
        if not isinstance(self.matched_grant_chains, tuple):
            raise CoreValidationError("decision.matched_grant_chains must be a tuple of chains")
        for chain in self.matched_grant_chains:
            if not isinstance(chain, tuple) or not chain:
                raise CoreValidationError("each matched grant chain must be a non-empty tuple")
            for grant_id in chain:
                require_identifier("decision.chain grant", grant_id, "trust/grant/")
        object.__setattr__(
            self, "matched_grant_chains", tuple(sorted(self.matched_grant_chains))
        )
        require_optional_text("decision.matched_mandate_id", self.matched_mandate_id)
        if self.matched_mandate_id is not None:
            require_identifier(
                "decision.matched_mandate_id", self.matched_mandate_id, "trust/mandate/"
            )
        require_hex_digest("decision.request_digest", self.request_digest)
        if outcome is AuthorizationOutcome.DENY and self.matched_grant_chains:
            raise CoreValidationError("a DENY decision cannot carry matched grant chains")

    @staticmethod
    def _require_enum(name: str, value: object, enum_cls: type[StrEnum]) -> StrEnum:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            for member in enum_cls:
                if member.value == value:
                    return member
        raise CoreValidationError(
            f"{name} must be one of {[item.value for item in enum_cls]}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": [item.value for item in self.reasons],
            "principal_id": self.principal_id,
            "as_of": self.as_of,
            "environment_id": self.environment_id,
            "authentication_id": self.authentication_id,
            "matched_grant_chains": [list(chain) for chain in self.matched_grant_chains],
            "matched_mandate_id": self.matched_mandate_id,
            "request_digest": self.request_digest,
        }

    @property
    def decision_digest(self) -> str:
        return canonical_sha256([AUTHORIZATION_DECISION_VERSION, self.to_dict()])


def decision_from_dict(value: object) -> AuthorizationDecision:
    """Decode a decision record (fail closed on non-canonical fields)."""
    if not isinstance(value, Mapping):
        raise CoreValidationError("authorization decision must be an object")
    expected = {
        "decision", "reasons", "principal_id", "as_of", "environment_id",
        "authentication_id", "matched_grant_chains", "matched_mandate_id", "request_digest",
    }
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise CoreValidationError(
            f"authorization decision fields are not canonical; missing={missing}, extra={extra}"
        )
    chains_value = value["matched_grant_chains"]
    if not isinstance(chains_value, list):
        raise CoreValidationError("matched grant chains must deserialize from a list")
    return AuthorizationDecision(
        decision=value["decision"],
        reasons=tuple(value["reasons"]),
        principal_id=value["principal_id"],
        as_of=value["as_of"],
        environment_id=value["environment_id"],
        authentication_id=value["authentication_id"],
        matched_grant_chains=tuple(tuple(chain) for chain in chains_value),
        matched_mandate_id=value["matched_mandate_id"],
        request_digest=value["request_digest"],
    )
