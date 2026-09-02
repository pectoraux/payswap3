"""Frozen v0.1 protocol-registry projection for the trust domain.

The registry file ``spec/registry/protocol-registry.json`` is the frozen
authority for protocol-visible names. This module is a hard-coded projection
of that authority for runtime use; the test suite cross-checks the projection
against the registry file so drift fails closed. Registry-listed object types
are the only protocol-visible object types; trust domain objects use internal
non-registry ``trust/<kind>/v1`` formats deliberately.
"""

from __future__ import annotations

from enum import StrEnum

from src.core.errors import CoreValidationError
from ._validation import require_text

PROTOCOL_VERSION = "v0.1"

#: Registry-listed (protocol-visible) object types, frozen at v0.1.
REGISTRY_OBJECT_TYPES: tuple[str, ...] = (
    "payswap/execution-plan/v1",
    "payswap/extension-manifest/v1",
    "payswap/finality/v1",
    "payswap/fulfillment-plan/v1",
    "payswap/intent/v1",
    "payswap/obligation/v1",
    "payswap/settlement/v1",
    "payswap/simulation/v1",
)


class AuthorityClass(StrEnum):
    """Closed authority-class vocabulary frozen in the protocol registry."""

    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"
    A5 = "A5"
    A6 = "A6"
    A7 = "A7"
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


AUTHORITY_CLASSES: tuple[AuthorityClass, ...] = tuple(AuthorityClass)

#: Internal (non protocol-visible) object types used by trust domain records.
TRUST_OBJECT_TYPES: dict[str, str] = {
    "principal": "trust/principal/v1",
    "credential": "trust/credential/v1",
    "key": "trust/key/v1",
    "grant": "trust/grant/v1",
    "mandate": "trust/mandate/v1",
    "authentication": "trust/authentication/v1",
}


def validate_authority_class(value: object) -> AuthorityClass:
    """Validate an authority class against the frozen registry vocabulary."""
    if isinstance(value, AuthorityClass):
        return value
    if isinstance(value, str):
        for member in AUTHORITY_CLASSES:
            if member.value == value:
                return member
    raise CoreValidationError(
        "authority_class must be one of the frozen registry authority classes "
        f"{sorted(item.value for item in AUTHORITY_CLASSES)}"
    )


def require_internal_object_type(object_type: object) -> str:
    """Fail closed unless object_type is an internal non-registry trust format.

    Protocol-visible object types come only from the frozen registry; the trust
    domain must never introduce a protocol-visible name that the registry does
    not list (that would require an ACR or a registry Work Order).
    """
    text = require_text("object_type", object_type)
    if text in REGISTRY_OBJECT_TYPES:
        raise CoreValidationError(
            f"object_type {text} is registry-listed and not available to the trust domain"
        )
    if not text.startswith("trust/") or not text.endswith("/v1"):
        raise CoreValidationError(
            f"object_type {text} must use the internal 'trust/<kind>/v1' format"
        )
    kind = text[len("trust/") : -len("/v1")]
    if not kind or not all(char.islower() or char.isdigit() or char == "-" for char in kind):
        raise CoreValidationError(
            f"object_type {text} must use the internal 'trust/<kind>/v1' format"
        )
    return text
