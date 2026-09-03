"""PaySwap protocol federation domain (WORK-023).

The public boundary is typed and versioned:

- **domains, federation and state commitments.** This package owns the
  frozen v0.1 ``Federation`` command family ``Register/Join/Leave/
  UpdateAuthority/PublishCommitment/AcceptCommitment/TransferDomain``
  (governance.md "Federated state": authoritative domains — no
  mandatory universal global ledger — with governed state authorities
  that publish state commitments and finality evidence). One
  :class:`FederationEngine` instance governs exactly one domain; the
  kernel's domain binding makes the Work Order's forbidden surface "no
  unilateral foreign-domain mutation" structural: a command of one
  domain can never read or write an object of another, and foreign
  state enters only as sealed composites decoded read-only through
  their trusted paths;
- **consumed dependencies, never reimplemented.** The authority and
  anchor keys are the trust domain's purpose-bound
  ``DOMAIN_STATE_COMMITMENT`` key records (WORK-004) through their
  trusted decode path; the finality evidence is the settlement domain's
  sealed finality certificates (WORK-016) through their trusted decode
  path — only ``ESTABLISHED`` certificates bind, so no false finality
  (constitution §4 and invariant 11); the transition machinery is the
  real kernel (WORK-003). Unmerged sibling domains are never
  reimplemented here;
- **signed state commitments and cross-domain messages.** A
  :class:`StateCommitment` is an immutable append-only record signing
  the canonical digest of the domain's committed journal history plus
  digest-bound finality evidence, with the deterministic
  purpose-bound signature scheme (no third-party cryptography; key
  secrets are caller-supplied at signing/verification time and never
  persisted). The companion :class:`InterDomainMessage` is created in
  the same atomic kernel transition and is an object of the ORIGIN
  domain; the destination domain accepts it via
  ``accept-commitment`` with full signature verification against the
  joined anchor key and explicit replay protection;
- **governed authority lifecycle.** Join records the federation anchor
  (the trust root for foreign commitments); leave is an explicit
  terminal departure; ``update-authority`` rotates the commitment key
  (same authority principal, secret-knowledge consent); and
  ``transfer-domain`` hands the authority to a successor principal in
  ONE atomic version bump with dual secret-knowledge consent — no
  dual-authority interval (ownership-lifecycle);
- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` and carries a domain seal
  computed with the single canonical hash authority, so tampered or
  spliced objects fail closed on the trusted deserialization path. All
  federation object types are internal non-registry ``federation/...``
  formats and all federation events use the registry-listed
  ``governance`` namespace (governance.md covers federation and
  institutional boundaries; the agents domain set the same precedent)
  — no new protocol-visible name is invented;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority), and every command validates its source state, membership
  and gate preconditions before advancing through the real transition
  kernel.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    ACCEPTANCE_OBJECT_TYPE,
    COMMAND_EVENT_TYPES,
    COMMITMENT_OBJECT_TYPE,
    DOMAIN_OBJECT_TYPE,
    DOMAIN_TERMINAL_STATES,
    FEDERATION_API_VERSION,
    FEDERATION_COMMANDS,
    FEDERATION_EVENT_NAMESPACE,
    FEDERATION_PROTOCOL_VERSION,
    FEDERATION_SCHEMA_VERSION,
    FEDERATION_TRANSITIONS,
    MESSAGE_OBJECT_TYPE,
    OBJECT_TYPES,
    AcceptanceState,
    CommitmentState,
    DomainState,
    MessageKind,
    MessageState,
    validate_command,
)
from .authority import (
    StateAuthority,
    decode_authority_key,
    sign_commitment,
    verify_commitment_signature,
)
from .domains import (
    AuthorityUpdate,
    DomainSpec,
    JoinFact,
    NetworkDomain,
    TransferFact,
    advance_domain,
    make_domain_record,
)
from .commitments import (
    CommitmentSpec,
    FinalityBinding,
    StateCommitment,
    commitment_payload_digest,
    make_commitment_record,
)
from .messages import (
    AcceptanceSpec,
    CommitmentAcceptance,
    InterDomainMessage,
    MessageSpec,
    make_acceptance_record,
    make_message_record,
)
from .engine import (
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    FederationEngine,
    FederationTransition,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

__all__ = [
    # versioned public boundary contracts
    "ACCEPTANCE_OBJECT_TYPE",
    "AcceptanceSpec",
    "AcceptanceState",
    "AuthorityUpdate",
    "COMMAND_EVENT_TYPES",
    "COMMITMENT_OBJECT_TYPE",
    "CommitmentSpec",
    "CommitmentState",
    "CoreValidationError",
    "DEFAULT_COMMAND_AUTHORITY_CLASS",
    "DEFAULT_ENGINE_ACTOR",
    "DOMAIN_OBJECT_TYPE",
    "DOMAIN_TERMINAL_STATES",
    "DomainSpec",
    "DomainState",
    "FEDERATION_API_VERSION",
    "FEDERATION_COMMANDS",
    "FEDERATION_EVENT_NAMESPACE",
    "FEDERATION_PROTOCOL_VERSION",
    "FEDERATION_SCHEMA_VERSION",
    "FEDERATION_TRANSITIONS",
    "FederationEngine",
    "FederationTransition",
    "FinalityBinding",
    "InterDomainMessage",
    "JoinFact",
    "MESSAGE_OBJECT_TYPE",
    "MessageKind",
    "MessageSpec",
    "MessageState",
    "NetworkDomain",
    "OBJECT_TYPES",
    "Provenance",
    "StateAuthority",
    "StateCommitment",
    "TransferFact",
    "advance_domain",
    "advance_envelope",
    "build_domain_envelope",
    "commitment_payload_digest",
    "composite_to_dict",
    "composite_to_json",
    "decode_authority_key",
    "decode_composite",
    "decode_composite_json",
    "make_acceptance_record",
    "make_commitment_record",
    "make_domain_record",
    "make_message_record",
    "seal_composite",
    "sign_commitment",
    "validate_command",
    "verify_commitment_signature",
    "verify_composite",
]
