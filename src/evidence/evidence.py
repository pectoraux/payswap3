"""Evidence: typed submissions with an explicit verification lifecycle.

An :class:`Evidence` record is a submitted unit of typed knowledge: it
carries the epistemic type explicitly (constitution §3), the evidenced
value, an observation instant and a half-open freshness window, and typed
payload references to the observations, attestations and uncertainty
records it rests on. Evidence never claims to be authoritative about the
outside world — observations record what was observed and attestations
record who attested what; the protocol registry and envelope integrity
remain the authorities.

The lifecycle follows the frozen ``Evidence`` command family
``Submit/Verify/Reject/RevokeEvidence`` as an explicit state machine:

```text
SUBMITTED → VERIFIED → REVOKED (terminal)
SUBMITTED → REJECTED (terminal)
SUBMITTED → REVOKED (terminal)
```

``Verify`` models the evidence-domain verification lifecycle — it
re-uses the single core integrity authority (envelope integrity hash and
domain seal verification) and fails closed on stale evidence; it does
not create a second hash or verification authority. Revocation is an
explicit status transition: history is append-only and every prior
version keeps its exact bytes (constitution invariant 17).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .attestations import Attestation
from .contracts import EVIDENCE_OBJECT_TYPE, EpistemicType, PayloadRefKind, ScaledValue
from .observations import Observation
from .uncertainty import Uncertainty
from ._validation import (
    parse_enum,
    require_identifier,
    require_utc_timestamp,
    require_utc_timestamp_order,
    require_utc_timestamp_strictly_after,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_EVIDENCE_SPEC_FIELDS = frozenset(
    {
        "epistemic_type",
        "subject_ref",
        "observed_at",
        "valid_from",
        "valid_until",
        "value",
        "payload_refs",
    }
)


class EvidenceState(StrEnum):
    """Closed lifecycle vocabulary of an evidence record.

    ``SUBMITTED`` is the initial state; ``VERIFIED`` records an explicit
    verification transition; ``REJECTED`` and ``REVOKED`` are terminal.
    """

    SUBMITTED = "SUBMITTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class EvidenceReasonCode(StrEnum):
    """Closed internal vocabulary of evidence terminal reasons.

    ``UNVERIFIABLE``, ``STALE`` and ``INCONSISTENT`` are rejection
    reasons (pre-verification refusal); ``SOURCE_WITHDRAWN``,
    ``SUPERSEDED`` and ``DISPUTED`` are revocation reasons (explicit
    terminal status transitions).
    """

    UNVERIFIABLE = "UNVERIFIABLE"
    STALE = "STALE"
    INCONSISTENT = "INCONSISTENT"
    SOURCE_WITHDRAWN = "SOURCE_WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"
    DISPUTED = "DISPUTED"


#: Rejection reasons: the ``Reject`` command refuses evidence before
#: verification succeeds.
REJECTION_REASONS = frozenset(
    {
        EvidenceReasonCode.UNVERIFIABLE,
        EvidenceReasonCode.STALE,
        EvidenceReasonCode.INCONSISTENT,
    }
)

#: Revocation reasons: the ``RevokeEvidence`` command records an explicit
#: terminal status transition after (or instead of) verification.
REVOCATION_REASONS = frozenset(
    {
        EvidenceReasonCode.SOURCE_WITHDRAWN,
        EvidenceReasonCode.SUPERSEDED,
        EvidenceReasonCode.DISPUTED,
    }
)


@dataclass(frozen=True, slots=True)
class PayloadRef:
    """A typed reference from evidence to one of its source records."""

    kind: PayloadRefKind
    ref: str

    def __post_init__(self) -> None:
        parse_enum("payload ref kind", PayloadRefKind, self.kind)
        require_identifier("payload ref.ref", self.ref)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "ref": self.ref}

    @classmethod
    def from_dict(cls, value: object) -> "PayloadRef":
        if not isinstance(value, Mapping) or set(value) != {"kind", "ref"}:
            raise CoreValidationError(
                "payload ref fields are not canonical; expected {kind, ref}"
            )
        return cls(
            kind=parse_enum("payload ref kind", PayloadRefKind, value["kind"]),
            ref=value["ref"],
        )


@dataclass(frozen=True, slots=True)
class EvidenceSpec:
    """Immutable evidence payload.

    The epistemic type is carried explicitly on every evidence record and
    is sealed at submission: no transition changes it, so a predicted or
    simulated value can never be sealed as ``OBSERVED`` (constitution
    invariants 14/15). Freshness is explicit and half-open:
    ``[valid_from, valid_until)``, never computed from a clock.
    """

    epistemic_type: EpistemicType
    subject_ref: str
    observed_at: str
    valid_from: str
    valid_until: str
    value: ScaledValue
    payload_refs: tuple[PayloadRef, ...] = ()

    def __post_init__(self) -> None:
        parse_enum("evidence epistemic type", EpistemicType, self.epistemic_type)
        require_identifier("evidence.subject_ref", self.subject_ref)
        require_utc_timestamp("evidence.observed_at", self.observed_at)
        require_utc_timestamp("evidence.valid_from", self.valid_from)
        require_utc_timestamp("evidence.valid_until", self.valid_until)
        require_utc_timestamp_order(
            "evidence.observed_at", self.observed_at,
            "evidence.valid_from", self.valid_from,
        )
        require_utc_timestamp_strictly_after(
            "evidence.valid_from", self.valid_from,
            "evidence.valid_until", self.valid_until,
        )
        if not isinstance(self.value, ScaledValue):
            raise CoreValidationError("evidence.value must be a ScaledValue")
        if not isinstance(self.payload_refs, tuple):
            raise CoreValidationError("evidence.payload_refs must be a tuple")
        for ref in self.payload_refs:
            if not isinstance(ref, PayloadRef):
                raise CoreValidationError(
                    "evidence.payload_refs entries must be PayloadRef instances"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "epistemic_type": self.epistemic_type.value,
            "subject_ref": self.subject_ref,
            "observed_at": self.observed_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "value": self.value.to_dict(),
            "payload_refs": [ref.to_dict() for ref in self.payload_refs],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceSpec":
        strict_fields("evidence", value, _EVIDENCE_SPEC_FIELDS)
        raw_refs = value["payload_refs"]
        if not isinstance(raw_refs, list):
            raise CoreValidationError("evidence.payload_refs must deserialize from a list")
        return cls(
            epistemic_type=parse_enum(
                "evidence epistemic type", EpistemicType, value["epistemic_type"]
            ),
            subject_ref=value["subject_ref"],
            observed_at=value["observed_at"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            value=ScaledValue.from_dict(value["value"]),
            payload_refs=tuple(PayloadRef.from_dict(ref) for ref in raw_refs),
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    """Durable evidence record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: EvidenceSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = EVIDENCE_OBJECT_TYPE
    STATE_TYPE = EvidenceState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("evidence envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, EvidenceSpec):
            raise CoreValidationError("evidence spec must be an EvidenceSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != EVIDENCE_OBJECT_TYPE:
            raise CoreValidationError(
                f"evidence object_type must be {EVIDENCE_OBJECT_TYPE!r}"
            )
        try:
            EvidenceState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown evidence state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> EvidenceState:
        return EvidenceState(self.envelope.state)

    @property
    def epistemic_type(self) -> EpistemicType:
        return self.spec.epistemic_type

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Evidence":
        envelope, payload = decode_composite(
            value,
            expected_object_type=EVIDENCE_OBJECT_TYPE,
            state_type=EvidenceState,
        )
        spec = EvidenceSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Evidence":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=EVIDENCE_OBJECT_TYPE,
            state_type=EvidenceState,
        )
        spec = EvidenceSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(self, new_state: EvidenceState, *, provenance: Provenance) -> "Evidence":
        # The payload is sealed at submission and never changes across
        # transitions: evidence semantics are append-only.
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        return Evidence(
            envelope=envelope, spec=self.spec,
            integrity_hash=seal_composite(envelope, self.spec),
        )


def _require_evidence(evidence: Evidence) -> Evidence:
    if not isinstance(evidence, Evidence):
        raise CoreValidationError("operation requires an Evidence")
    return evidence


def submit_evidence(
    *,
    evidence_id: str,
    epistemic_type: EpistemicType,
    subject_ref: str,
    observed_at: str,
    valid_from: str,
    valid_until: str,
    value: ScaledValue,
    observations: tuple[Observation, ...] = (),
    attestations: tuple[Attestation, ...] = (),
    uncertainties: tuple[Uncertainty, ...] = (),
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Evidence:
    """Submit a typed evidence record (the ``Submit`` command).

    The supplied observations, attestations and uncertainty records are
    sealed into typed payload references. Cross-type confusion fails
    closed: every referenced observation must carry the SAME epistemic
    type as the evidence (an OBSERVED evidence record may only rest on
    OBSERVED observations; a predicted or simulated source is rejected),
    and duplicate source object ids are rejected.
    """
    epistemic = parse_enum("evidence epistemic type", EpistemicType, epistemic_type)
    seen_ids: set[str] = set()
    payload_refs: list[PayloadRef] = []
    for observation in observations:
        if not isinstance(observation, Observation):
            raise CoreValidationError("evidence observations must be Observation records")
        if observation.object_id in seen_ids:
            raise CoreValidationError(
                f"duplicate source object id: {observation.object_id}"
            )
        seen_ids.add(observation.object_id)
        if observation.spec.epistemic_type is not epistemic:
            raise CoreValidationError(
                f"evidence of epistemic type {epistemic.value} cannot rest on "
                f"observation {observation.object_id} of epistemic type "
                f"{observation.spec.epistemic_type.value}"
            )
        payload_refs.append(
            PayloadRef(kind=PayloadRefKind.OBSERVATION, ref=observation.object_id)
        )
    for attestation in attestations:
        if not isinstance(attestation, Attestation):
            raise CoreValidationError("evidence attestations must be Attestation records")
        if attestation.object_id in seen_ids:
            raise CoreValidationError(
                f"duplicate source object id: {attestation.object_id}"
            )
        seen_ids.add(attestation.object_id)
        payload_refs.append(
            PayloadRef(kind=PayloadRefKind.ATTESTATION, ref=attestation.object_id)
        )
    for uncertainty in uncertainties:
        if not isinstance(uncertainty, Uncertainty):
            raise CoreValidationError("evidence uncertainties must be Uncertainty records")
        if uncertainty.object_id in seen_ids:
            raise CoreValidationError(
                f"duplicate source object id: {uncertainty.object_id}"
            )
        seen_ids.add(uncertainty.object_id)
        payload_refs.append(
            PayloadRef(kind=PayloadRefKind.UNCERTAINTY, ref=uncertainty.object_id)
        )
    spec = EvidenceSpec(
        epistemic_type=epistemic,
        subject_ref=subject_ref,
        observed_at=observed_at,
        valid_from=valid_from,
        valid_until=valid_until,
        value=value,
        payload_refs=tuple(payload_refs),
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("evidence.evidence_id", evidence_id),
        object_type=EVIDENCE_OBJECT_TYPE,
        state=EvidenceState.SUBMITTED.value,
        environment_id=require_identifier("evidence.environment_id", environment_id),
        domain_id=require_identifier("evidence.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return Evidence(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def check_payload_consistency(
    evidence: Evidence,
    *,
    observations: tuple[Observation, ...] = (),
    attestations: tuple[Attestation, ...] = (),
) -> None:
    """Re-check the typed payload references of an evidence record.

    Every payload reference must resolve to a supplied record of the
    right kind (unknown references fail closed), and every referenced
    observation must carry the same epistemic type as the evidence —
    the cross-type discrimination holds after decoding, not only at
    submission.
    """
    record = _require_evidence(evidence)
    observation_map = {observation.object_id: observation for observation in observations}
    attestation_map = {attestation.object_id: attestation for attestation in attestations}
    for ref in record.spec.payload_refs:
        if ref.kind is PayloadRefKind.OBSERVATION:
            observation = observation_map.get(ref.ref)
            if observation is None:
                raise CoreValidationError(
                    f"evidence {record.object_id} references unknown "
                    f"observation {ref.ref}"
                )
            if observation.spec.epistemic_type is not record.spec.epistemic_type:
                raise CoreValidationError(
                    f"evidence {record.object_id} of epistemic type "
                    f"{record.spec.epistemic_type.value} cannot rest on "
                    f"observation {ref.ref} of epistemic type "
                    f"{observation.spec.epistemic_type.value}"
                )
        elif ref.kind is PayloadRefKind.ATTESTATION:
            if ref.ref not in attestation_map:
                raise CoreValidationError(
                    f"evidence {record.object_id} references unknown "
                    f"attestation {ref.ref}"
                )


def verify_evidence(
    evidence: Evidence,
    *,
    as_of: str,
    provenance: Provenance,
) -> Evidence:
    """Verify a submitted evidence record (the ``Verify`` command).

    This models the evidence-domain verification LIFECYCLE, re-using the
    single core integrity authority: the envelope integrity hash and the
    domain seal are verified (fail closed on tampered or unsealed
    records), the state machine must be in ``SUBMITTED``, and the record
    must be fresh at the explicit ``as_of`` instant. Stale or
    pre-window evidence fails closed.
    """
    record = _require_evidence(evidence)
    if record.state is not EvidenceState.SUBMITTED:
        raise CoreValidationError(
            f"only SUBMITTED evidence can be verified; state is {record.state.value}"
        )
    require_utc_timestamp("evidence as_of", as_of)
    record.envelope.verify_integrity()
    verify_composite(record.envelope, record.spec, record.integrity_hash, record.object_id)
    if not utc_timestamp_within(record.spec.valid_from, as_of, record.spec.valid_until):
        raise CoreValidationError(
            f"evidence {record.object_id} is not fresh at as_of {as_of} "
            f"(fresh window [{record.spec.valid_from}, {record.spec.valid_until}))"
        )
    return record._advance(EvidenceState.VERIFIED, provenance=provenance)


def reject_evidence(
    evidence: Evidence,
    *,
    reason: EvidenceReasonCode,
    provenance: Provenance,
) -> Evidence:
    """Reject a submitted evidence record (the ``Reject`` command).

    Rejection is a pre-verification refusal with a closed-vocabulary
    reason and lands in the terminal ``REJECTED`` state: history stays
    append-only and the submitted version keeps its exact bytes.
    """
    record = _require_evidence(evidence)
    if record.state is not EvidenceState.SUBMITTED:
        raise CoreValidationError(
            f"only SUBMITTED evidence can be rejected; state is {record.state.value}"
        )
    reason_code = parse_enum("evidence rejection reason", EvidenceReasonCode, reason)
    if reason_code not in REJECTION_REASONS:
        raise CoreValidationError(
            f"{reason_code.value} is not a rejection reason"
        )
    return record._advance(EvidenceState.REJECTED, provenance=provenance)


def revoke_evidence(
    evidence: Evidence,
    *,
    reason: EvidenceReasonCode,
    provenance: Provenance,
) -> Evidence:
    """Revoke evidence (the ``RevokeEvidence`` command).

    Revocation is an explicit terminal status transition (constitution
    invariant 17: historical financial evidence is append-only — the
    history is never mutated or rewritten, only extended by a new
    version whose state records the revocation).
    """
    record = _require_evidence(evidence)
    if record.state not in (EvidenceState.SUBMITTED, EvidenceState.VERIFIED):
        raise CoreValidationError(
            f"only SUBMITTED or VERIFIED evidence can be revoked; state is "
            f"{record.state.value}"
        )
    reason_code = parse_enum("evidence revocation reason", EvidenceReasonCode, reason)
    if reason_code not in REVOCATION_REASONS:
        raise CoreValidationError(
            f"{reason_code.value} is not a revocation reason"
        )
    return record._advance(EvidenceState.REVOKED, provenance=provenance)


def evidence_is_fresh(evidence: Evidence, as_of: str) -> bool:
    """Deterministic freshness test against an explicit ``as_of`` instant.

    Half-open semantics: fresh exactly on ``[valid_from, valid_until)``.
    Staleness is computed only from the declared window and the explicit
    ``as_of`` — never from a wall clock.
    """
    record = _require_evidence(evidence)
    require_utc_timestamp("evidence as_of", as_of)
    return utc_timestamp_within(record.spec.valid_from, as_of, record.spec.valid_until)


def require_fresh_evidence(evidence: Evidence, as_of: str) -> None:
    """Fail closed unless the evidence is fresh at ``as_of``."""
    if not evidence_is_fresh(evidence, as_of):
        raise CoreValidationError(
            f"evidence {evidence.object_id} is not fresh at as_of {as_of} "
            f"(fresh window [{evidence.spec.valid_from}, "
            f"{evidence.spec.valid_until}))"
        )


def require_observed_evidence(evidences: Iterable[Evidence]) -> tuple[Evidence, ...]:
    """Fail closed unless every evidence record is OBSERVED.

    Production ground-truth reads may only consume observational
    knowledge: predicted, estimated, simulated or counterfactual values
    masquerading as observations fail closed (constitution invariants
    14 and 15 — simulation must never masquerade as observation).
    """
    records = tuple(evidences)
    observed: list[Evidence] = []
    for record in records:
        _require_evidence(record)
        if record.spec.epistemic_type is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                f"evidence {record.object_id} is of epistemic type "
                f"{record.spec.epistemic_type.value} and cannot be consumed "
                "as observational knowledge"
            )
        observed.append(record)
    return tuple(observed)


def partition_evidence_by_epistemic_type(
    evidences: Iterable[Evidence],
) -> dict[EpistemicType, tuple[Evidence, ...]]:
    """Partition evidence records by their explicit epistemic type.

    Deterministic: every vocabulary member is present as a key (empty
    tuple when unused) and input order is preserved within each type.
    """
    partition: dict[EpistemicType, list[Evidence]] = {
        member: [] for member in EpistemicType
    }
    for record in evidences:
        _require_evidence(record)
        partition[record.spec.epistemic_type].append(record)
    return {member: tuple(partition[member]) for member in EpistemicType}
