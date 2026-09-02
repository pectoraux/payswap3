"""PaySwap deterministic command/event transition kernel (WORK-003).

Owned surface: ``src/transition/`` only. The kernel consumes the remediated
canonical core (``src.core``) and never redefines it: canonical JSON and
SHA-256, object envelopes with integrity verification and frozen version
identity, and the single ``CoreValidationError`` error authority.
"""

from src.core.errors import CoreValidationError

from .command import Command, ExpectedVersion
from .engine import (
    AuthorizationDecision,
    EngineState,
    IdempotencyRecord,
    JournalEntry,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)
from .event import Event
from .payload import PayloadObject, normalize_payload, payload_to_json_value
from .registry import (
    AUTHORITY_CLASSES,
    DEFAULT_REJECTION_EVENT_TYPE,
    EVENT_NAMESPACES,
    PROTOCOL_VERSION,
    validate_authority_class,
    validate_event_type,
)
from .store import MemoryStateStore, StateStore, StateStoreView

__all__ = [
    "AUTHORITY_CLASSES",
    "DEFAULT_REJECTION_EVENT_TYPE",
    "EVENT_NAMESPACES",
    "PROTOCOL_VERSION",
    "AuthorizationDecision",
    "Command",
    "CoreValidationError",
    "EngineState",
    "Event",
    "ExpectedVersion",
    "IdempotencyRecord",
    "JournalEntry",
    "MemoryStateStore",
    "Outcome",
    "PayloadObject",
    "RejectionReason",
    "StateStore",
    "StateStoreView",
    "TransitionApplication",
    "TransitionEngine",
    "TransitionResult",
    "normalize_payload",
    "payload_to_json_value",
    "validate_authority_class",
    "validate_event_type",
]
