"""Mandates: explicit representation authority of one principal for another.

A mandate records that ``mandator_principal_id`` empowers
``mandatary_principal_id`` to act on the mandator's behalf for a stated
purpose within an explicit scope, half-open validity window, optional amount
limits and jurisdictions. The lifecycle follows the frozen command family
``Create/Activate/Suspend/Resume/Amend/RevokeMandate``: creation lands in
``CREATED`` and becomes usable only after explicit activation; amendment is
tighten-only; revocation is terminal.

Mandates are consulted by the authorization decision whenever an action is
requested ``on_behalf_of`` another principal; a missing, inactive, expired,
out-of-scope, over-limit or wrong-environment mandate denies the action.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope
from src.core.errors import CoreValidationError

from ._validation import (
    require_identifier,
    require_str_tuple,
    require_text,
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

MANDATE_OBJECT_TYPE = "trust/mandate/v1"
MANDATE_ID_PREFIX = "trust/mandate/"
_MANDATE_PAYLOAD_KEYS = frozenset(
    {
        "mandate_id",
        "mandator_principal_id",
        "mandatary_principal_id",
        "purpose",
        "scope_objects",
        "scope_domains",
        "not_before",
        "not_after",
        "amount_limits",
        "jurisdictions",
    }
)


class MandateState(StrEnum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True)
class MandateRecord(TrustObject):
    """Immutable durable mandate record (envelope + typed payload + seal)."""

    envelope: ObjectEnvelope
    mandate_id: str
    mandator_principal_id: str
    mandatary_principal_id: str
    purpose: str
    scope_objects: tuple[str, ...] = ()
    scope_domains: tuple[str, ...] = ()
    not_before: str = ""
    not_after: str = ""
    amount_limits: tuple = ()
    jurisdictions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("mandate.mandate_id", self.mandate_id, MANDATE_ID_PREFIX)
        require_identifier(
            "mandate.mandator_principal_id", self.mandator_principal_id, "trust/principal/"
        )
        require_identifier(
            "mandate.mandatary_principal_id", self.mandatary_principal_id, "trust/principal/"
        )
        require_text("mandate.purpose", self.purpose)
        if self.mandator_principal_id == self.mandatary_principal_id:
            raise CoreValidationError("mandate mandator and mandatary must be distinct principals")
        object.__setattr__(
            self,
            "scope_objects",
            require_str_tuple("mandate.scope_objects", self.scope_objects, distinct=True),
        )
        object.__setattr__(
            self,
            "scope_domains",
            require_str_tuple("mandate.scope_domains", self.scope_domains, distinct=True),
        )
        require_timestamp("mandate.not_before", self.not_before)
        require_timestamp("mandate.not_after", self.not_after)
        require_window("mandate window", self.not_before, self.not_after)
        if not isinstance(self.amount_limits, tuple):
            raise CoreValidationError("mandate.amount_limits must be a tuple of amount bounds")
        for limit in self.amount_limits:
            if not isinstance(limit, AmountBound):
                raise CoreValidationError("mandate.amount_limits must contain AmountBound values")
        if len({limit.asset for limit in self.amount_limits}) != len(self.amount_limits):
            raise CoreValidationError("mandate.amount_limits contains duplicate asset bounds")
        object.__setattr__(
            self,
            "jurisdictions",
            require_str_tuple("mandate.jurisdictions", self.jurisdictions, distinct=True),
        )
        validate_record_envelope(
            self.envelope,
            object_id=self.mandate_id,
            object_type=MANDATE_OBJECT_TYPE,
            state_vocab=MandateState,
        )

    @property
    def state(self) -> str:
        return self.envelope.state

    def payload_dict(self) -> dict[str, Any]:
        return {
            "mandate_id": self.mandate_id,
            "mandator_principal_id": self.mandator_principal_id,
            "mandatary_principal_id": self.mandatary_principal_id,
            "purpose": self.purpose,
            "scope_objects": list(self.scope_objects),
            "scope_domains": list(self.scope_domains),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "amount_limits": amount_limits_to_dict(self.amount_limits),
            "jurisdictions": list(self.jurisdictions),
        }

    @classmethod
    def from_dict(cls, value: object) -> "MandateRecord":
        def build_payload(envelope: ObjectEnvelope, payload: object) -> MandateRecord:
            if not isinstance(payload, Mapping) or set(payload) != _MANDATE_PAYLOAD_KEYS:
                raise CoreValidationError("mandate payload fields are not canonical")
            return cls(
                envelope=envelope,
                mandate_id=payload["mandate_id"],
                mandator_principal_id=payload["mandator_principal_id"],
                mandatary_principal_id=payload["mandatary_principal_id"],
                purpose=payload["purpose"],
                scope_objects=require_str_tuple("mandate.scope_objects", payload["scope_objects"]),
                scope_domains=require_str_tuple("mandate.scope_domains", payload["scope_domains"]),
                not_before=payload["not_before"],
                not_after=payload["not_after"],
                amount_limits=amount_limits_from_dict(
                    "mandate.amount_limits", payload["amount_limits"]
                ),
                jurisdictions=require_str_tuple("mandate.jurisdictions", payload["jurisdictions"]),
            )

        return record_from_dict(cls, value, build_payload)
