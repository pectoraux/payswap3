"""PaySwap evidence domain (WORK-018): evidence, knowledge and uncertainty.

The public boundary is typed and versioned:

- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` (identity, state,
  provenance, version chain, integrity hash) owned by ``src.core`` and
  carries a domain seal computed with the single canonical hash
  authority, so tampered or spliced objects fail closed on the trusted
  deserialization path — no second verification authority is
  introduced;
- no evidence object type is protocol-visible in the frozen registry,
  so — per the sibling convention — object types use internal
  non-registry ``evidence/...`` formats and no new registry name is
  invented;
- the epistemic type (the frozen ``simulation.md`` vocabulary OBSERVED /
  ESTIMATED / PREDICTED / SIMULATED / COUNTERFACTUAL) is carried
  explicitly on every evidence and observation record; cross-type
  confusion fails closed at submission and at consumption (a simulated
  value can never masquerade as an observation);
- freshness is explicit: every observation and evidence record carries
  ``observed_at`` plus a half-open UTC validity window, and staleness
  is computed only from explicit ``as_of`` instants — never from a wall
  clock, and no entropy sources or UUIDs exist anywhere in the domain;
- lifecycles implement the frozen v0.1 command families: Evidence
  ``Submit/Verify/Reject/RevokeEvidence`` and Attestation
  ``Issue/Renew/RevokeAttestation`` as explicit state machines with
  terminal states; revocation is an explicit status transition and
  history is append-only (constitution invariant 17);
- uncertainty is typed and exact: intervals, quantiles and bands of
  exact integers with declared scale and unit — no floating-point
  value is ever constructed;
- the domain consumes the merged dependency domains only:
  ``src.transition`` (the kernel's append-only store semantics back the
  :class:`EvidenceArchive`) and ``src.trust` (attestation issuers are
  opaque trust-domain principal references, gated through the trust
  registry); unmerged sibling implementations are never imported;
- this domain is the typed evidence STORE/record domain: observations
  record what was observed, attestations record who attested what; the
  protocol registry and envelope integrity remain the authorities, and
  this package never claims to be authoritative about the outside
  world.
"""

from __future__ import annotations

from ..core import CoreValidationError, Provenance

from .contracts import (
    ATTESTATION_OBJECT_TYPE,
    EVIDENCE_OBJECT_TYPE,
    EVIDENCE_PROTOCOL_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    MAX_QUANTILE_BPS,
    MAX_SCALE,
    OBSERVATION_OBJECT_TYPE,
    UNCERTAINTY_OBJECT_TYPE,
    EpistemicType,
    PayloadRefKind,
    ScaledValue,
    UncertaintyForm,
)
from .observations import (
    Observation,
    ObservationSpec,
    ObservationState,
    observation_is_fresh,
    partition_observations_by_epistemic_type,
    record_observation,
    require_fresh_observation,
)
from .uncertainty import (
    MIN_QUANTILE_POINTS,
    QuantilePoint,
    Uncertainty,
    UncertaintySpec,
    UncertaintyState,
    express_uncertainty,
    quantile_at,
    uncertainty_bounds,
    value_within_bounds,
)
from .attestations import (
    ISSUER_PRINCIPAL_PREFIX,
    Attestation,
    AttestationRevocationReason,
    AttestationSpec,
    AttestationState,
    AttestedClaim,
    attestation_is_valid_at,
    issue_attestation,
    renew_attestation,
    require_trusted_issuer,
    revoke_attestation,
)
from .evidence import (
    REJECTION_REASONS,
    REVOCATION_REASONS,
    Evidence,
    EvidenceReasonCode,
    EvidenceSpec,
    EvidenceState,
    PayloadRef,
    check_payload_consistency,
    evidence_is_fresh,
    partition_evidence_by_epistemic_type,
    reject_evidence,
    require_fresh_evidence,
    require_observed_evidence,
    submit_evidence,
    verify_evidence,
    revoke_evidence,
)
from .store import EvidenceArchive

#: Version of this typed, versioned public boundary.
EVIDENCE_API_VERSION = "v0.1"

__all__ = [
    # versioned public boundary contracts
    "EVIDENCE_API_VERSION",
    "EVIDENCE_PROTOCOL_VERSION",
    "EVIDENCE_SCHEMA_VERSION",
    "EVIDENCE_OBJECT_TYPE",
    "ATTESTATION_OBJECT_TYPE",
    "OBSERVATION_OBJECT_TYPE",
    "UNCERTAINTY_OBJECT_TYPE",
    "MAX_QUANTILE_BPS",
    "MAX_SCALE",
    "MIN_QUANTILE_POINTS",
    "ISSUER_PRINCIPAL_PREFIX",
    "EpistemicType",
    "PayloadRefKind",
    "UncertaintyForm",
    "ScaledValue",
    # observations
    "Observation",
    "ObservationSpec",
    "ObservationState",
    "record_observation",
    "observation_is_fresh",
    "require_fresh_observation",
    "partition_observations_by_epistemic_type",
    # uncertainty
    "Uncertainty",
    "UncertaintySpec",
    "UncertaintyState",
    "QuantilePoint",
    "express_uncertainty",
    "uncertainty_bounds",
    "value_within_bounds",
    "quantile_at",
    # attestations
    "Attestation",
    "AttestationSpec",
    "AttestationState",
    "AttestationRevocationReason",
    "AttestedClaim",
    "issue_attestation",
    "renew_attestation",
    "revoke_attestation",
    "attestation_is_valid_at",
    "require_trusted_issuer",
    # evidence
    "Evidence",
    "EvidenceSpec",
    "EvidenceState",
    "EvidenceReasonCode",
    "EvidenceArchive",
    "PayloadRef",
    "REJECTION_REASONS",
    "REVOCATION_REASONS",
    "submit_evidence",
    "verify_evidence",
    "reject_evidence",
    "revoke_evidence",
    "evidence_is_fresh",
    "require_fresh_evidence",
    "require_observed_evidence",
    "check_payload_consistency",
    "partition_evidence_by_epistemic_type",
    # re-exported owning authorities (single source: src.core)
    "CoreValidationError",
    "Provenance",
]
