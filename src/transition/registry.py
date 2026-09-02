from __future__ import annotations

from src.core.errors import CoreValidationError

PROTOCOL_VERSION = "v0.1"

# Frozen protocol-registry projection (spec/registry/protocol-registry.json,
# status "frozen"). Consumed, never redefined: only these namespaces/classes
# are protocol-visible in the v0.1 transition kernel.
EVENT_NAMESPACES = frozenset(
    {
        "intent",
        "market",
        "reservation",
        "execution",
        "clearing",
        "settlement",
        "risk",
        "extension",
        "simulation",
        "governance",
    }
)

AUTHORITY_CLASSES = frozenset(
    {
        "A0",
        "A1",
        "A2",
        "A3",
        "A4",
        "A5",
        "A6",
        "A7",
        "R0",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
    }
)

DEFAULT_REJECTION_EVENT_TYPE = "governance/command-rejected"


def validate_event_type(name: str, event_type: str) -> str:
    """Fail closed unless event_type is '<namespace>/<name>' with a registry namespace."""
    if not isinstance(event_type, str) or not event_type.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    namespace, separator, event_name = event_type.partition("/")
    if not separator:
        raise CoreValidationError(f"{name} must use the '<namespace>/<name>' format")
    if namespace not in EVENT_NAMESPACES:
        raise CoreValidationError(
            f"{name} namespace '{namespace}' is not listed in the frozen protocol registry"
        )
    if not event_name.strip():
        raise CoreValidationError(f"{name} must carry a non-empty event name after the namespace")
    return event_type


def validate_authority_class(name: str, authority: str) -> str:
    """Fail closed unless authority is one of the frozen registry authority classes."""
    if not isinstance(authority, str) or authority not in AUTHORITY_CLASSES:
        raise CoreValidationError(
            f"{name} must be one of the frozen-registry authority classes "
            f"{sorted(AUTHORITY_CLASSES)}"
        )
    return authority
