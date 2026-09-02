"""Public boundary of the capability domain (WORK-009).

Capabilities, capability commitments, operating windows and verification
metadata are declarative records and verifiable metadata only: this package
performs no execution and causes no direct provider side effects.

The package consumes the canonical core (:mod:`src.core`) for envelopes,
integrity sealing, relationships, canonical JSON and the single validation
error authority ``CoreValidationError``. Object identity and integrity are
owned by the core; the lifecycle state machines below are object-specific
expressions of the frozen v0.1 architecture.

Protocol-visible names are governed by the frozen protocol registry; this
domain deliberately uses internal non-registry identifier formats such as
"capability/provider/..." and internal object types
"capability/capability/v1" / "capability/commitment/v1".
"""

from ..core import (
    CoreValidationError,
    ObjectEnvelope,
    ObjectGraph,
    Provenance,
    Relationship,
    RelationshipType,
    canonical_json,
    relationship_from_json,
    relationship_to_json,
)
from ..core.serialization import loads_canonical
from .commitments import (
    COMMITMENT_OBJECT_TYPE,
    BreachReason,
    BreachRecord,
    CapabilityCommitment,
    CommitmentState,
    CommitmentTerms,
    ServiceLevel,
    amend_commitment,
    build_dependency_relationship,
    cancel_commitment,
    create_commitment,
    expire_commitment,
    record_commitment_breach,
)
from .records import (
    CAPABILITY_OBJECT_TYPE,
    GOVERNING_PROTOCOL_VERSION,
    AuthorityTier,
    CapabilityKind,
    CapabilityRecord,
    CapabilityState,
    STRONGER_VERIFICATION_TIERS,
    activate_capability,
    apply_verification,
    build_attests_relationship,
    build_authorizes_relationship,
    build_services_relationship,
    classify_environment,
    register_capability,
    resume_capability,
    retire_capability,
    suspend_capability,
    update_capability,
)
from .verification import (
    VerificationMethod,
    VerificationMetadata,
    VerificationResult,
)
from .windows import OperatingWindow

__all__ = [
    "CAPABILITY_OBJECT_TYPE",
    "COMMITMENT_OBJECT_TYPE",
    "GOVERNING_PROTOCOL_VERSION",
    "STRONGER_VERIFICATION_TIERS",
    "AuthorityTier",
    "BreachReason",
    "BreachRecord",
    "CapabilityCommitment",
    "CapabilityKind",
    "CapabilityRecord",
    "CapabilityState",
    "CommitmentState",
    "CommitmentTerms",
    "CoreValidationError",
    "ObjectEnvelope",
    "ObjectGraph",
    "OperatingWindow",
    "Provenance",
    "Relationship",
    "RelationshipType",
    "ServiceLevel",
    "VerificationMethod",
    "VerificationMetadata",
    "VerificationResult",
    "activate_capability",
    "amend_commitment",
    "apply_verification",
    "build_attests_relationship",
    "build_authorizes_relationship",
    "build_dependency_relationship",
    "build_services_relationship",
    "cancel_commitment",
    "canonical_json",
    "classify_environment",
    "create_commitment",
    "expire_commitment",
    "loads_canonical",
    "record_commitment_breach",
    "register_capability",
    "relationship_from_json",
    "relationship_to_json",
    "resume_capability",
    "retire_capability",
    "suspend_capability",
    "update_capability",
]
