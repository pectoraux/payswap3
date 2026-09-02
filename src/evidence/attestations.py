"""Attestations: who attested what, for which validity window.

An :class:`Attestation` is an immutable signed-statement record: an
issuer (an opaque trust-domain principal reference owned by
``src.trust``, WORK-004) attests typed claims about a subject for a
half-open validity window ``[valid_from, valid_until)``. Attestations
belong to the architecture's ``IMMUTABLE`` lifecycle class: renewal never
mutates — it creates a new version of the record with an extended
validity horizon — and revocation is an explicit terminal status
transition (constitution invariant 17: history is append-only).

The lifecycle follows the frozen ``Attestation`` command family:
``Issue/Renew/RevokeAttestation``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from src.trust import TrustRegistry, PrincipalRecord

from .contracts import ATTESTATION_OBJECT_TYPE, ScaledValue
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_text,
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

_ATTESTATION_SPEC_FIELDS = frozenset(
    {
        "issuer",
        "subject_ref",
        "issued_at",
        "valid_from",
        "valid_until",
        "claims",
        "evidence_refs",
    }
)

#: Attestation issuers are opaque trust-domain principal references
#: (owned by ``src.trust``); the prefix makes the reference explicit.
ISSUER_PRINCIPAL_PREFIX = "trust/principal/"


class AttestationState(StrEnum):
    """Closed lifecycle vocabulary of an attestation.

    ``ISSUED`` is the live state; ``REVOKED`` is terminal. Renewal keeps
    the ``ISSUED`` state and produces a new immutable version.
    """

    ISSUED = "ISSUED"
    REVOKED = "REVOKED"


class AttestationRevocationReason(StrEnum):
    """Closed internal vocabulary of attestation revocation reasons."""

    ISSUER_WITHDRAWN = "ISSUER_WITHDRAWN"
    SUBJECT_DISPUTED = "SUBJECT_DISPUTED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class AttestedClaim:
    """One typed claim of an attestation: an exact key/value pair."""

    claim_key: str
    claim_value: ScaledValue

    def __post_init__(self) -> None:
        require_text("claim.claim_key", self.claim_key)
        if not isinstance(self.claim_value, ScaledValue):
            raise CoreValidationError("claim.claim_value must be a ScaledValue")

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_key": self.claim_key,
            "claim_value": self.claim_value.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> "AttestedClaim":
        if not isinstance(value, Mapping) or set(value) != {"claim_key", "claim_value"}:
            raise CoreValidationError(
                "claim fields are not canonical; expected {claim_key, claim_value}"
            )
        return cls(
            claim_key=value["claim_key"],
            claim_value=ScaledValue.from_dict(value["claim_value"]),
        )


@dataclass(frozen=True, slots=True)
class AttestationSpec:
    """Immutable attestation payload: issuer, subject, claims, window."""

    issuer: str
    subject_ref: str
    issued_at: str
    valid_from: str
    valid_until: str
    claims: tuple[AttestedClaim, ...]
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier(
            "attestation.issuer", self.issuer, prefix=ISSUER_PRINCIPAL_PREFIX
        )
        require_identifier("attestation.subject_ref", self.subject_ref)
        require_utc_timestamp("attestation.issued_at", self.issued_at)
        require_utc_timestamp("attestation.valid_from", self.valid_from)
        require_utc_timestamp("attestation.valid_until", self.valid_until)
        require_utc_timestamp_order(
            "attestation.issued_at", self.issued_at,
            "attestation.valid_from", self.valid_from,
        )
        require_utc_timestamp_strictly_after(
            "attestation.valid_from", self.valid_from,
            "attestation.valid_until", self.valid_until,
        )
        if not isinstance(self.claims, tuple) or not self.claims:
            raise CoreValidationError("attestation.claims must be a non-empty tuple")
        keys = [claim.claim_key for claim in self.claims]
        if len(set(keys)) != len(keys):
            raise CoreValidationError("attestation claim keys must be unique")
        for claim in self.claims:
            if not isinstance(claim, AttestedClaim):
                raise CoreValidationError(
                    "attestation.claims entries must be AttestedClaim instances"
                )
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("attestation.evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            require_identifier("attestation.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "subject_ref": self.subject_ref,
            "issued_at": self.issued_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "claims": [claim.to_dict() for claim in self.claims],
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttestationSpec":
        strict_fields("attestation", value, _ATTESTATION_SPEC_FIELDS)
        raw_claims = value["claims"]
        if not isinstance(raw_claims, list):
            raise CoreValidationError("attestation.claims must deserialize from a list")
        raw_refs = value["evidence_refs"]
        if not isinstance(raw_refs, list):
            raise CoreValidationError(
                "attestation.evidence_refs must deserialize from a list"
            )
        return cls(
            issuer=value["issuer"],
            subject_ref=value["subject_ref"],
            issued_at=value["issued_at"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            claims=tuple(AttestedClaim.from_dict(claim) for claim in raw_claims),
            evidence_refs=tuple(raw_refs),
        )


@dataclass(frozen=True, slots=True)
class Attestation:
    """Durable attestation record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: AttestationSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = ATTESTATION_OBJECT_TYPE
    STATE_TYPE = AttestationState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("attestation envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, AttestationSpec):
            raise CoreValidationError("attestation spec must be an AttestationSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != ATTESTATION_OBJECT_TYPE:
            raise CoreValidationError(
                f"attestation object_type must be {ATTESTATION_OBJECT_TYPE!r}"
            )
        try:
            AttestationState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown attestation state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> AttestationState:
        return AttestationState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Attestation":
        envelope, payload = decode_composite(
            value,
            expected_object_type=ATTESTATION_OBJECT_TYPE,
            state_type=AttestationState,
        )
        spec = AttestationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Attestation":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=ATTESTATION_OBJECT_TYPE,
            state_type=AttestationState,
        )
        spec = AttestationSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(self, new_state: AttestationState, *, provenance: Provenance) -> "Attestation":
        envelope = advance_envelope(
            self.envelope, state=new_state.value, provenance=provenance,
            causation_id=self.envelope.object_id,
        )
        return Attestation(
            envelope=envelope, spec=self.spec,
            integrity_hash=seal_composite(envelope, self.spec),
        )


def issue_attestation(
    *,
    attestation_id: str,
    issuer: str,
    subject_ref: str,
    claims: tuple[AttestedClaim, ...],
    issued_at: str,
    valid_from: str,
    valid_until: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    evidence_refs: tuple[str, ...] = (),
    correlation_id: str | None = None,
) -> Attestation:
    """Issue a sealed attestation (the ``Issue`` command)."""
    spec = AttestationSpec(
        issuer=issuer,
        subject_ref=subject_ref,
        issued_at=issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        claims=claims,
        evidence_refs=evidence_refs,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("attestation.attestation_id", attestation_id),
        object_type=ATTESTATION_OBJECT_TYPE,
        state=AttestationState.ISSUED.value,
        environment_id=require_identifier("attestation.environment_id", environment_id),
        domain_id=require_identifier("attestation.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return Attestation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def _require_attestation(attestation: Attestation) -> Attestation:
    if not isinstance(attestation, Attestation):
        raise CoreValidationError("operation requires an Attestation")
    return attestation


def renew_attestation(
    attestation: Attestation,
    *,
    valid_from: str,
    valid_until: str,
    provenance: Provenance,
) -> Attestation:
    """Renew an attestation (the ``Renew`` command).

    Renewal creates a NEW immutable version of the record with an
    extended validity horizon; the issuer, subject and claims are carried
    byte-for-byte and the previous versions are never mutated. The new
    window must itself be valid half-open UTC and must extend the
    validity horizon beyond the previous window (shortening is not
    renewal).
    """
    record = _require_attestation(attestation)
    if record.state is not AttestationState.ISSUED:
        raise CoreValidationError(
            f"only an ISSUED attestation can be renewed; state is {record.state.value}"
        )
    require_utc_timestamp("attestation.valid_from", valid_from)
    require_utc_timestamp("attestation.valid_until", valid_until)
    require_utc_timestamp_order(
        "attestation.valid_from", valid_from,
        "attestation.valid_until", valid_until,
    )
    require_utc_timestamp_strictly_after(
        "attestation.valid_from", valid_from,
        "attestation.valid_until", valid_until,
    )
    if parse_utc_timestamp("attestation.valid_until", valid_until) <= parse_utc_timestamp(
        "attestation.valid_until", record.spec.valid_until
    ):
        raise CoreValidationError(
            "attestation renewal must extend valid_until beyond "
            f"{record.spec.valid_until}; got {valid_until}"
        )
    spec = AttestationSpec(
        issuer=record.spec.issuer,
        subject_ref=record.spec.subject_ref,
        issued_at=record.spec.issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        claims=record.spec.claims,
        evidence_refs=record.spec.evidence_refs,
    )
    envelope = advance_envelope(
        record.envelope, state=AttestationState.ISSUED.value,
        provenance=provenance, causation_id=record.envelope.object_id,
    )
    return Attestation(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def revoke_attestation(
    attestation: Attestation,
    *,
    reason: AttestationRevocationReason,
    provenance: Provenance,
) -> Attestation:
    """Revoke an attestation (the ``RevokeAttestation`` command).

    Revocation is an explicit terminal status transition to ``REVOKED``:
    it appends a new version and never rewrites the attested history.
    """
    record = _require_attestation(attestation)
    if record.state is not AttestationState.ISSUED:
        raise CoreValidationError(
            f"only an ISSUED attestation can be revoked; state is {record.state.value}"
        )
    parse_enum(
        "attestation revocation reason", AttestationRevocationReason, reason
    )
    return record._advance(AttestationState.REVOKED, provenance=provenance)


def attestation_is_valid_at(attestation: Attestation, as_of: str) -> bool:
    """Deterministic validity test against an explicit ``as_of`` instant.

    An attestation is valid at ``as_of`` exactly when it is ``ISSUED``
    and ``as_of`` is inside the half-open window
    ``[valid_from, valid_until)``. Never computed from a wall clock.
    """
    record = _require_attestation(attestation)
    require_utc_timestamp("attestation as_of", as_of)
    if record.state is not AttestationState.ISSUED:
        return False
    return utc_timestamp_within(record.spec.valid_from, as_of, record.spec.valid_until)


def require_trusted_issuer(
    attestation: Attestation, registry: TrustRegistry
) -> PrincipalRecord:
    """Fail closed unless the issuer is a registered ACTIVE trust principal.

    This consumes the trust domain (WORK-004) as the owning authority for
    principals: the evidence domain never decides who is trustworthy —
    it references the trust registry and fails closed on unknown,
    suspended or retired issuers.
    """
    record = _require_attestation(attestation)
    if not isinstance(registry, TrustRegistry):
        raise CoreValidationError("issuer validation requires a TrustRegistry")
    principal = registry.principal(record.spec.issuer)
    if principal.state != "ACTIVE":
        raise CoreValidationError(
            f"attestation issuer {record.spec.issuer} is {principal.state} "
            "and must be ACTIVE"
        )
    return principal
