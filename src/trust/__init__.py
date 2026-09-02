"""WORK-004 trust domain: identity, authentication, authority and key primitives.

Public API surface (version 1) re-exported from the implementation modules.
The contract is defined by ``src/trust/test_trust.py`` (written red-first);
internal implementation modules follow. The domain consumes the remediated
canonical core (``src.core``) and never introduces a second authority.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .objects import (
    TRUST_API_VERSION,
    AmountBound,
)
from .keys import (
    Approval,
    ApprovalDecision,
    KeyRecord,
    ThresholdApproval,
    ThresholdPolicy,
    key_rotation_proposal_digest,
)
from .mandates import MandateRecord
from .principal import PrincipalRecord
from .registry import (
    AUTHORITY_CLASSES,
    PROTOCOL_VERSION,
    REGISTRY_OBJECT_TYPES,
    AuthorityClass,
    require_internal_object_type,
    validate_authority_class,
)
from .service import TRUST_DOMAIN_ID, TrustRegistry
from .authorization import (
    AuthorizationOutcome,
    AuthorizationRequest,
)
from .authentication import AuthenticationEventRecord
from .authority import (
    AuthorizationGrantRecord,
    GrantKind,
    GrantState,
)

__all__ = [
    "TRUST_API_VERSION",
    "TRUST_DOMAIN_ID",
    "AUTHORITY_CLASSES",
    "PROTOCOL_VERSION",
    "REGISTRY_OBJECT_TYPES",
    "AuthorityClass",
    "AmountBound",
    "Approval",
    "ApprovalDecision",
    "AuthorizationGrantRecord",
    "AuthorizationOutcome",
    "AuthorizationRequest",
    "AuthenticationEventRecord",
    "CoreValidationError",
    "GrantKind",
    "GrantState",
    "KeyRecord",
    "MandateRecord",
    "PrincipalRecord",
    "ThresholdApproval",
    "ThresholdPolicy",
    "TrustRegistry",
    "key_rotation_proposal_digest",
    "require_internal_object_type",
    "validate_authority_class",
]
