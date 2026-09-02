"""WORK-007 interoperability domain: endpoint resolution and canonical adapter contracts.

This package implements the frozen v0.1 interoperability contract above
heterogeneous rails: endpoint identifier schemes, sealed endpoint and
endpoint-resolution records, the canonical payment message, the canonical
payment lifecycle vocabulary with fail-closed native status mapping, and the
canonical world adapter contracts (observation/effect interfaces, fidelity
classes, directories, status maps and pure domestic translations).

All durable records consume the remediated canonical core (ObjectEnvelope,
canonical JSON/SHA-256, CoreValidationError) and use internal, non-registry
object identity formats: the frozen protocol registry lists exactly eight
protocol-visible object types, none of which belong to this domain, so no
protocol-visible names are introduced here.
"""

from src.core import CoreValidationError, Provenance

from .adapter import (
    AdapterStatusMap,
    DomesticInstruction,
    EFFECT_CAPABLE_FIDELITY_CLASSES,
    EffectInterface,
    EffectOperation,
    FidelityClass,
    ObservationInterface,
    ObservationOperation,
    StatusMapEntry,
    WorldAdapter,
    apply_status_observation,
    translate_to_domestic,
)
from .endpoint import (
    Destination,
    Endpoint,
    EndpointDirectory,
    EndpointResolution,
    EndpointState,
    IdentifierTranslation,
    ResolutionMethod,
    resolve_endpoint,
)
from .identifiers import EndpointIdentifier, IdentifierScheme
from .message import (
    CanonicalPaymentMessage,
    InstructedAmount,
    ensure_safe_for_resubmission,
)
from .status import (
    BRANCH_PAYMENT_STATUSES,
    CANONICAL_PAYMENT_STATUS_CHAIN,
    RECONCILIATION_REQUIRED_STATUSES,
    RETRY_SAFE_PAYMENT_STATUSES,
    TERMINAL_PAYMENT_STATUSES,
    CanonicalPaymentStatus,
    is_retry_safe_payment_status,
    is_terminal_payment_status,
    requires_reconciliation,
)

__all__ = [
    "AdapterStatusMap",
    "BRANCH_PAYMENT_STATUSES",
    "CANONICAL_PAYMENT_STATUS_CHAIN",
    "CanonicalPaymentMessage",
    "CanonicalPaymentStatus",
    "CoreValidationError",
    "Destination",
    "DomesticInstruction",
    "EffectInterface",
    "EffectOperation",
    "Endpoint",
    "EndpointDirectory",
    "EndpointIdentifier",
    "EndpointResolution",
    "EndpointState",
    "FidelityClass",
    "IdentifierScheme",
    "IdentifierTranslation",
    "InstructedAmount",
    "ObservationInterface",
    "ObservationOperation",
    "Provenance",
    "ResolutionMethod",
    "StatusMapEntry",
    "WorldAdapter",
    "apply_status_observation",
    "ensure_safe_for_resubmission",
    "is_retry_safe_payment_status",
    "is_terminal_payment_status",
    "requires_reconciliation",
    "resolve_endpoint",
    "translate_to_domestic",
]
