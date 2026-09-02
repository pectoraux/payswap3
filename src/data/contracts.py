"""Frozen public-boundary contracts for the data domain (WORK-022).

The data domain owns data governance, privacy and recourse: declared data
policies (typed references to governance-declared policy identifiers),
disclosure and selective disclosure over isolated datasets, retention
bookkeeping, and the case/claim/recourse lifecycle.

No data-domain object type is listed in the frozen protocol registry (the
registry lists protocol-visible ``payswap/...`` object types only), so —
following the sibling convention of ``src/evidence``, ``src/safety`` and
``src/integration`` — every data object type below uses an internal
non-registry ``data/...`` format. No new protocol-visible name is
invented here.

Registry discipline (frozen ``spec/registry/protocol-registry.json``):
there is no ``data``/``privacy``/``recourse`` event namespace. The
data-governance lifecycle events emitted through the transition kernel
therefore use the existing frozen ``governance`` namespace (data policy
activation, disclosure and case/recourse lifecycle records are
governance-family state transitions; the kernel's own default rejection
event ``governance/command-rejected`` sets the precedent). This choice is
recorded here so it is auditable; ``spec/registry`` is never edited.
"""

from __future__ import annotations

from enum import StrEnum

# -- typed, versioned public boundary --------------------------------------

#: Version of the data-domain public boundary API.
DATA_API_VERSION = "v0.1"

#: Governing protocol version (frozen architecture v0.1).
DATA_PROTOCOL_VERSION = "v0.1"

#: Canonical schema version of every data-domain durable object.
DATA_SCHEMA_VERSION = 1

#: Domain identifier used by the kernel-bound engine.
DATA_DOMAIN_ID = "domain/data"

#: Internal operational authority class exercised by the data-governance
#: operator for kernel command authorization (registry-listed class).
DATA_AUTHORITY_CLASS = "A2"

# Internal (non-registry) object types of the data domain.
DATA_POLICY_OBJECT_TYPE = "data/policy/v1"
PRIVACY_ASSESSMENT_OBJECT_TYPE = "data/privacy-assessment/v1"
DISCLOSURE_OBJECT_TYPE = "data/disclosure/v1"
RETENTION_OBJECT_TYPE = "data/retention/v1"
CASE_OBJECT_TYPE = "data/case/v1"
SELECTIVE_PROOF_OBJECT_TYPE = "data/selective-proof/v1"

# Identifier prefixes (internal formats; trust principals are owned by
# ``src.trust`` and referenced opaquely).
POLICY_ID_PREFIX = "data-policy/"
ASSESSMENT_ID_PREFIX = "data-assessment/"
DISCLOSURE_ID_PREFIX = "data-disclosure/"
RETENTION_ID_PREFIX = "data-retention/"
CASE_ID_PREFIX = "data-case/"
PROOF_ID_PREFIX = "data-proof/"
HOLD_ID_PREFIX = "legal-hold/"
PRINCIPAL_PREFIX = "trust/principal/"
LEGAL_BASIS_PREFIX = "legal-basis/"

#: Provenance source tag used by the kernel-bound engine.
DATA_GOVERNANCE_SOURCE = "data-governance"


# -- closed vocabularies ----------------------------------------------------


class DataClass(StrEnum):
    """Closed per-field data classification vocabulary.

    The classification of a field is DECLARED policy content recorded in
    a :class:`~src.data.policy.DataPolicySpec`; the data domain enforces
    the declared classification mechanically and never invents
    classifications of its own.
    """

    PUBLIC = "PUBLIC"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"


class DisclosurePurpose(StrEnum):
    """Closed vocabulary of disclosure purposes.

    Purposes are mechanism labels: which declared purpose a disclosure
    request serves. The mapping purpose -> allowed data classes is
    declared policy content; absence of a purpose grant denies that
    purpose (fail closed).
    """

    DISPUTE = "DISPUTE"
    SUPPORT = "SUPPORT"
    COMPLIANCE = "COMPLIANCE"
    FRAUD_ANALYSIS = "FRAUD_ANALYSIS"
    OPERATIONS = "OPERATIONS"


class PolicyState(StrEnum):
    """Closed lifecycle of a declared data policy."""

    DECLARED = "DECLARED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class DisclosureState(StrEnum):
    """Closed lifecycle of a disclosure record."""

    REQUESTED = "REQUESTED"
    DISCLOSED = "DISCLOSED"
    REJECTED = "REJECTED"


class AssessmentVerdict(StrEnum):
    """Closed verdict vocabulary of a privacy assessment."""

    PERMITTED = "PERMITTED"
    PARTIALLY_PERMITTED = "PARTIALLY_PERMITTED"
    DENIED = "DENIED"


class RetentionState(StrEnum):
    """Closed lifecycle of a retention record (bookkeeping states only)."""

    ACTIVE = "ACTIVE"
    DUE = "DUE"
    EXPIRED = "EXPIRED"
    ARCHIVED = "ARCHIVED"


class RetentionOutcome(StrEnum):
    """Closed outcome vocabulary of the pure retention evaluation."""

    RETAINED = "RETAINED"
    DUE = "DUE"
    HELD = "HELD"


class CaseState(StrEnum):
    """Closed lifecycle of a recourse case.

    ``OPEN -> INVESTIGATED -> DECIDED -> EXECUTED -> CLOSED`` with the
    reject path ``DECIDED (decision REJECT) -> CLOSED``.
    """

    OPEN = "OPEN"
    INVESTIGATED = "INVESTIGATED"
    DECIDED = "DECIDED"
    EXECUTED = "EXECUTED"
    CLOSED = "CLOSED"


class ClaimType(StrEnum):
    """Closed vocabulary of user claim kinds."""

    UNAUTHORIZED_TRANSACTION = "UNAUTHORIZED_TRANSACTION"
    BILLING_ERROR = "BILLING_ERROR"
    FRAUD = "FRAUD"
    SERVICE_FAILURE = "SERVICE_FAILURE"
    PRIVACY_VIOLATION = "PRIVACY_VIOLATION"


class DecisionKind(StrEnum):
    """Closed recourse decision vocabulary (frozen Recourse family)."""

    APPROVE_REFUND = "APPROVE_REFUND"
    APPROVE_REVERSAL = "APPROVE_REVERSAL"
    REJECT = "REJECT"


class ProofState(StrEnum):
    """Closed lifecycle of a selective-disclosure proof."""

    ISSUED = "ISSUED"
    REVOKED = "REVOKED"


# -- internal command/event types (kernel binding) --------------------------

# Command types are internal free-form strings per the sibling convention
# (``integration/<family>.<verb>`` precedent); they are not
# protocol-visible names. Events use the frozen ``governance`` namespace.

POLICY_DECLARE_COMMAND = "data/policy.declare"
POLICY_ACTIVATE_COMMAND = "data/policy.activate"
POLICY_RETIRE_COMMAND = "data/policy.retire"

DISCLOSURE_REQUEST_COMMAND = "disclosure/request"
DISCLOSURE_DISCLOSE_COMMAND = "disclosure/disclose"
DISCLOSURE_REJECT_COMMAND = "disclosure/reject"

PROOF_PRODUCE_COMMAND = "selective/produce-proof"
PROOF_REVOKE_COMMAND = "selective/revoke-proof"

RETENTION_RECORD_COMMAND = "retention/record"
RETENTION_MARK_DUE_COMMAND = "retention/mark-due"
RETENTION_MARK_EXPIRED_COMMAND = "retention/mark-expired"
RETENTION_ARCHIVE_COMMAND = "retention/archive"
RETENTION_HOLD_COMMAND = "retention/declare-hold"
RETENTION_RELEASE_COMMAND = "retention/release-hold"

CASE_OPEN_COMMAND = "recourse/open-case"
CASE_CLAIM_COMMAND = "recourse/record-claim"
CASE_INVESTIGATE_COMMAND = "recourse/investigate"
CASE_DECIDE_COMMAND = "recourse/decide"
CASE_COMPILE_REFUND_COMMAND = "recourse/compile-refund"
CASE_COMPILE_REVERSAL_COMMAND = "recourse/compile-reversal"
CASE_EXECUTE_REFUND_COMMAND = "recourse/execute-refund"
CASE_EXECUTE_REVERSAL_COMMAND = "recourse/execute-reversal"
CASE_CLOSE_COMMAND = "recourse/close-case"

COMMAND_TYPES = frozenset(
    {
        POLICY_DECLARE_COMMAND,
        POLICY_ACTIVATE_COMMAND,
        POLICY_RETIRE_COMMAND,
        DISCLOSURE_REQUEST_COMMAND,
        DISCLOSURE_DISCLOSE_COMMAND,
        DISCLOSURE_REJECT_COMMAND,
        PROOF_PRODUCE_COMMAND,
        PROOF_REVOKE_COMMAND,
        RETENTION_RECORD_COMMAND,
        RETENTION_MARK_DUE_COMMAND,
        RETENTION_MARK_EXPIRED_COMMAND,
        RETENTION_ARCHIVE_COMMAND,
        RETENTION_HOLD_COMMAND,
        RETENTION_RELEASE_COMMAND,
        CASE_OPEN_COMMAND,
        CASE_CLAIM_COMMAND,
        CASE_INVESTIGATE_COMMAND,
        CASE_DECIDE_COMMAND,
        CASE_COMPILE_REFUND_COMMAND,
        CASE_COMPILE_REVERSAL_COMMAND,
        CASE_EXECUTE_REFUND_COMMAND,
        CASE_EXECUTE_REVERSAL_COMMAND,
        CASE_CLOSE_COMMAND,
    }
)

POLICY_DECLARED_EVENT = "governance/data-policy-declared"
POLICY_ACTIVATED_EVENT = "governance/data-policy-activated"
POLICY_RETIRED_EVENT = "governance/data-policy-retired"
DISCLOSURE_REQUESTED_EVENT = "governance/disclosure-requested"
DISCLOSURE_DISCLOSED_EVENT = "governance/disclosure-disclosed"
DISCLOSURE_REJECTED_EVENT = "governance/disclosure-rejected"
PROOF_PRODUCED_EVENT = "governance/selective-proof-produced"
PROOF_REVOKED_EVENT = "governance/selective-proof-revoked"
RETENTION_RECORDED_EVENT = "governance/retention-recorded"
RETENTION_DUE_EVENT = "governance/retention-due"
RETENTION_EXPIRED_EVENT = "governance/retention-expired"
RETENTION_ARCHIVED_EVENT = "governance/retention-archived"
RETENTION_HOLD_EVENT = "governance/retention-hold-declared"
RETENTION_RELEASE_EVENT = "governance/retention-hold-released"
CASE_OPENED_EVENT = "governance/case-opened"
CASE_CLAIM_EVENT = "governance/case-claim-recorded"
CASE_INVESTIGATED_EVENT = "governance/case-investigated"
CASE_DECIDED_EVENT = "governance/case-decided"
CASE_REFUND_COMPILED_EVENT = "governance/case-refund-compiled"
CASE_REVERSAL_COMPILED_EVENT = "governance/case-reversal-compiled"
CASE_REFUND_EXECUTED_EVENT = "governance/case-refund-executed"
CASE_REVERSAL_EXECUTED_EVENT = "governance/case-reversal-executed"
CASE_CLOSED_EVENT = "governance/case-closed"

EVENT_TYPES = frozenset(
    {
        POLICY_DECLARED_EVENT,
        POLICY_ACTIVATED_EVENT,
        POLICY_RETIRED_EVENT,
        DISCLOSURE_REQUESTED_EVENT,
        DISCLOSURE_DISCLOSED_EVENT,
        DISCLOSURE_REJECTED_EVENT,
        PROOF_PRODUCED_EVENT,
        PROOF_REVOKED_EVENT,
        RETENTION_RECORDED_EVENT,
        RETENTION_DUE_EVENT,
        RETENTION_EXPIRED_EVENT,
        RETENTION_ARCHIVED_EVENT,
        RETENTION_HOLD_EVENT,
        RETENTION_RELEASE_EVENT,
        CASE_OPENED_EVENT,
        CASE_CLAIM_EVENT,
        CASE_INVESTIGATED_EVENT,
        CASE_DECIDED_EVENT,
        CASE_REFUND_COMPILED_EVENT,
        CASE_REVERSAL_COMPILED_EVENT,
        CASE_REFUND_EXECUTED_EVENT,
        CASE_REVERSAL_EXECUTED_EVENT,
        CASE_CLOSED_EVENT,
    }
)

#: Default operator actor set marker used by the engine constructor.
DEFAULT_AUTHORIZED_ACTORS: frozenset[str] = frozenset()
