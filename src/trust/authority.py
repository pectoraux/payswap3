"""Authorization grants: bounded, revocable delegation of authority classes.

An :class:`AuthorizationGrantRecord` binds an authority class from the frozen
registry vocabulary, an explicit scope (object refs and/or domains), a half-open
validity window, a delegation depth budget, optional per-asset amount limits
and optional jurisdictions, from a grantor principal to a grantee principal.

``ROOT`` grants are the explicit bootstrap of authority (issued by an active
authority principal through the trust registry's genesis operation). Every
``DELEGATED`` grant must be created from a currently valid covering parent
grant held by the grantor, and may only narrow it: scope, window, depth,
amount limits and jurisdictions are all tighten-only. Delegation depth
strictly decreases, so chains are finite and cycle-free by construction.

Revocation is effective immediately for descendants without mutating them:
authorization decisions walk the live chain from the acting principal's grant
to its root, and any revoked or suspended link denies the request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope
from src.core.errors import CoreValidationError

from ._validation import (
    require_identifier,
    require_non_negative_int,
    require_optional_text,
    require_str_enum,
    require_str_tuple,
    require_timestamp,
    require_window,
)
from .objects import (
    AmountBound,
    TrustObject,
    amount_limits_from_dict,
    amount_limits_to_dict,
    record_from_dict,
    validate_record_envelope,
)
from .registry import validate_authority_class

GRANT_OBJECT_TYPE = "trust/grant/v1"
GRANT_ID_PREFIX = "trust/grant/"
_GRANT_PAYLOAD_KEYS = frozenset(
    {
        "grant_id",
        "grant_kind",
        "authority_class",
        "grantor_principal_id",
        "grantee_principal_id",
        "scope_objects",
        "scope_domains",
        "not_before",
        "not_after",
        "delegation_depth",
        "amount_limits",
        "jurisdictions",
        "parent_grant_id",
    }
)


class GrantState(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class GrantKind(StrEnum):
    ROOT = "ROOT"
    DELEGATED = "DELEGATED"


@dataclass(frozen=True, slots=True)
class AuthorizationGrantRecord(TrustObject):
    """Immutable durable authorization grant (envelope + typed payload + seal)."""

    envelope: ObjectEnvelope
    grant_id: str
    grant_kind: GrantKind
    authority_class: AuthorityClass
    grantor_principal_id: str
    grantee_principal_id: str
    scope_objects: tuple[str, ...] = ()
    scope_domains: tuple[str, ...] = ()
    not_before: str = ""
    not_after: str = ""
    delegation_depth: int = 0
    amount_limits: tuple = ()
    jurisdictions: tuple[str, ...] = ()
    parent_grant_id: str | None = None

    def __post_init__(self) -> None:
        require_identifier("grant.grant_id", self.grant_id, GRANT_ID_PREFIX)
        kind = require_str_enum("grant.grant_kind", self.grant_kind, GrantKind)
        object.__setattr__(self, "authority_class", validate_authority_class(self.authority_class))
        object.__setattr__(self, "grant_kind", kind)
        require_identifier("grant.grantor_principal_id", self.grantor_principal_id, "trust/principal/")
        require_identifier("grant.grantee_principal_id", self.grantee_principal_id, "trust/principal/")
        object.__setattr__(
            self, "scope_objects", require_str_tuple("grant.scope_objects", self.scope_objects, distinct=True)
        )
        object.__setattr__(
            self, "scope_domains", require_str_tuple("grant.scope_domains", self.scope_domains, distinct=True)
        )
        require_timestamp("grant.not_before", self.not_before)
        require_timestamp("grant.not_after", self.not_after)
        require_window("grant window", self.not_before, self.not_after)
        require_non_negative_int("grant.delegation_depth", self.delegation_depth)
        if not isinstance(self.amount_limits, tuple):
            raise CoreValidationError("grant.amount_limits must be a tuple of amount bounds")
        for limit in self.amount_limits:
            if not isinstance(limit, AmountBound):
                raise CoreValidationError("grant.amount_limits must contain AmountBound values")
        if len({limit.asset for limit in self.amount_limits}) != len(self.amount_limits):
            raise CoreValidationError("grant.amount_limits contains duplicate asset bounds")
        object.__setattr__(
            self, "jurisdictions", require_str_tuple("grant.jurisdictions", self.jurisdictions, distinct=True)
        )
        if kind is GrantKind.ROOT:
            if self.parent_grant_id is not None:
                raise CoreValidationError("ROOT grants must not reference a parent grant")
        else:
            require_identifier("grant.parent_grant_id", self.parent_grant_id, GRANT_ID_PREFIX)
        validate_record_envelope(
            self.envelope,
            object_id=self.grant_id,
            object_type=GRANT_OBJECT_TYPE,
            state_vocab=GrantState,
        )

    @property
    def state(self) -> str:
        return self.envelope.state

    def payload_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "grant_kind": self.grant_kind.value,
            "authority_class": self.authority_class.value,
            "grantor_principal_id": self.grantor_principal_id,
            "grantee_principal_id": self.grantee_principal_id,
            "scope_objects": list(self.scope_objects),
            "scope_domains": list(self.scope_domains),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "delegation_depth": self.delegation_depth,
            "amount_limits": amount_limits_to_dict(self.amount_limits),
            "jurisdictions": list(self.jurisdictions),
            "parent_grant_id": self.parent_grant_id,
        }

    @classmethod
    def from_dict(cls, value: object) -> "AuthorizationGrantRecord":
        def build_payload(envelope: ObjectEnvelope, payload: object) -> AuthorizationGrantRecord:
            if not isinstance(payload, Mapping) or set(payload) != _GRANT_PAYLOAD_KEYS:
                raise CoreValidationError("grant payload fields are not canonical")
            return cls(
                envelope=envelope,
                grant_id=payload["grant_id"],
                grant_kind=require_str_enum("grant.grant_kind", payload["grant_kind"], GrantKind),
                authority_class=validate_authority_class(payload["authority_class"]),
                grantor_principal_id=payload["grantor_principal_id"],
                grantee_principal_id=payload["grantee_principal_id"],
                scope_objects=require_str_tuple("grant.scope_objects", payload["scope_objects"]),
                scope_domains=require_str_tuple("grant.scope_domains", payload["scope_domains"]),
                not_before=payload["not_before"],
                not_after=payload["not_after"],
                delegation_depth=payload["delegation_depth"],
                amount_limits=amount_limits_from_dict("grant.amount_limits", payload["amount_limits"]),
                jurisdictions=require_str_tuple("grant.jurisdictions", payload["jurisdictions"]),
                parent_grant_id=require_optional_text("grant.parent_grant_id", payload["parent_grant_id"]),
            )

        return record_from_dict(cls, value, build_payload)
