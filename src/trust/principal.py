"""Principal records: the identity objects of the trust domain.

Lifecycle follows the frozen identity command family
``Create/Update/Suspend/Reinstate/RetirePrincipal``: creation lands in
``ACTIVE``; suspend/reinstate toggle ``ACTIVE``/``SUSPENDED``; retirement is
terminal. State transitions are performed by :class:`src.trust.service.TrustRegistry`
which enforces cross-object guards (no active dependents on retirement).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core import ObjectEnvelope
from src.core.errors import CoreValidationError

from ._validation import check_attribute_pairs, require_attributes, require_identifier, require_text
from .objects import TrustObject, validate_record_envelope, record_from_dict

PRINCIPAL_OBJECT_TYPE = "trust/principal/v1"
PRINCIPAL_ID_PREFIX = "trust/principal/"
_PRINCIPAL_PAYLOAD_KEYS = frozenset({"principal_id", "display_name", "attributes"})


class PrincipalState(StrEnum):
    """Object-specific machine for principals (CREATED collapses into ACTIVE)."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"


@dataclass(frozen=True, slots=True)
class PrincipalRecord(TrustObject):
    """Immutable durable principal record (envelope + typed payload + seal)."""

    envelope: ObjectEnvelope
    principal_id: str
    display_name: str
    attributes: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        require_identifier("principal.principal_id", self.principal_id, PRINCIPAL_ID_PREFIX)
        require_text("principal.display_name", self.display_name)
        check_attribute_pairs("principal.attributes", self.attributes)
        validate_record_envelope(
            self.envelope,
            object_id=self.principal_id,
            object_type=PRINCIPAL_OBJECT_TYPE,
            state_vocab=PrincipalState,
        )

    @property
    def state(self) -> str:
        return self.envelope.state

    def payload_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "display_name": self.display_name,
            "attributes": {key: value for key, value in self.attributes},
        }

    @classmethod
    def from_dict(cls, value: object) -> "PrincipalRecord":
        def build_payload(envelope: ObjectEnvelope, payload: object) -> PrincipalRecord:
            if not isinstance(payload, Mapping) or set(payload) != _PRINCIPAL_PAYLOAD_KEYS:
                raise CoreValidationError("principal payload fields are not canonical")
            return cls(
                envelope=envelope,
                principal_id=payload["principal_id"],
                display_name=payload["display_name"],
                attributes=require_attributes("principal.attributes", payload["attributes"]),
            )

        return record_from_dict(cls, value, build_payload)
