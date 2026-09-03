"""The finality certificate: the registry-listed ``payswap/finality/v1``.

A :class:`Finality` certificate is the protocol's only claim of
settlement finality, and it is established under the strictest gates in
this domain (constitution §4 — "a payment status is never allowed to
stand in for settlement finality" — and invariant 11 — "PaySwap never
overstates settlement finality"; the Work Order's forbidden surface
"no false finality"):

* every claim binding is an ``OBSERVED`` external finality-class
  observation recorded by the execution domain
  (``ObservationKind.FINALITY``, ``FinalityClaim.FINAL`` or ``SETTLED``)
  — a rail payment status (``ObservationKind.STATUS``) can never
  validate into a certificate;
* every claim is digest-bound to the exact settled leg it covers
  (the observation's ``subject_request_digest`` must equal the leg's
  instruction digest), so a claim cannot be spliced onto another
  settlement;
* the certificate can be established only for a ``COMPLETED``
  settlement whose every settled leg is covered by a validated claim;
* once established, the certificate can only be challenged or revoked —
  never silently edited; a revoked certificate is terminal and any
  discharge already performed on it must be compensated through the
  explicit recourse reversal path (append-only history, constitution
  invariant 17).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.envelope import ObjectEnvelope, Provenance

from ._validation import (
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    FINALITY_OBJECT_TYPE,
    FinalityState,
)
from .seal import (
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_CLAIM_BINDING_FIELDS = frozenset(
    {
        "instruction_id",
        "native_reference",
        "claim",
        "observation_id",
        "observation_digest",
        "observed_at",
    }
)

_CHALLENGE_FIELDS = frozenset({"evidence_ref", "evidence_digest", "reason", "challenged_at"})
_REVOCATION_FIELDS = frozenset({"evidence_ref", "evidence_digest", "reason", "revoked_at"})

_SPEC_FIELDS = frozenset(
    {
        "finality_id",
        "settlement_id",
        "settlement_digest",
        "claims",
        "established_at",
        "challenge",
        "revocation",
    }
)

_VALIDATE_PAYLOAD_FIELDS = frozenset({"finality_id", "settlement_id", "observation"})
_ESTABLISH_PAYLOAD_FIELDS = frozenset()
_CHALLENGE_PAYLOAD_FIELDS = frozenset({"evidence_ref", "evidence_digest", "reason"})
_REVOKE_PAYLOAD_FIELDS = frozenset({"evidence_ref", "evidence_digest", "reason"})

#: The canonical finality-claim observation content shape the validate
#: path requires: exactly a finality claim and a native reference.
FINALITY_CONTENT_FIELDS = frozenset({"claim", "native_reference"})


@dataclass(frozen=True, slots=True)
class FinalityClaimBinding:
    """One validated external finality claim, digest-bound to one leg."""

    instruction_id: str
    native_reference: str
    claim: str
    observation_id: str
    observation_digest: str
    observed_at: str

    def __post_init__(self) -> None:
        require_identifier("claim.instruction_id", self.instruction_id)
        require_identifier("claim.native_reference", self.native_reference)
        require_text("claim.claim", self.claim)
        require_identifier("claim.observation_id", self.observation_id)
        for name, value in (
            ("claim.observation_digest", self.observation_digest),
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise CoreValidationError(f"{name} must be a canonical SHA-256 digest")
        require_utc_timestamp("claim.observed_at", self.observed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_id": self.instruction_id,
            "native_reference": self.native_reference,
            "claim": self.claim,
            "observation_id": self.observation_id,
            "observation_digest": self.observation_digest,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FinalityClaimBinding":
        require_mapping("finality claim binding", value)
        strict_fields("finality claim binding", value, _CLAIM_BINDING_FIELDS)
        return cls(
            instruction_id=value["instruction_id"],
            native_reference=value["native_reference"],
            claim=value["claim"],
            observation_id=value["observation_id"],
            observation_digest=value["observation_digest"],
            observed_at=value["observed_at"],
        )


@dataclass(frozen=True, slots=True)
class ChallengeRecord:
    """An explicit challenge against an established certificate."""

    evidence_ref: str
    evidence_digest: str
    reason: str
    challenged_at: str

    def __post_init__(self) -> None:
        require_identifier("challenge.evidence_ref", self.evidence_ref)
        if (
            len(self.evidence_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.evidence_digest)
        ):
            raise CoreValidationError(
                "challenge.evidence_digest must be a canonical SHA-256 digest"
            )
        require_text("challenge.reason", self.reason)
        require_utc_timestamp("challenge.challenged_at", self.challenged_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "evidence_digest": self.evidence_digest,
            "reason": self.reason,
            "challenged_at": self.challenged_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ChallengeRecord":
        require_mapping("finality challenge record", value)
        strict_fields("finality challenge record", value, _CHALLENGE_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            evidence_digest=value["evidence_digest"],
            reason=value["reason"],
            challenged_at=value["challenged_at"],
        )


@dataclass(frozen=True, slots=True)
class RevocationRecord:
    """The explicit revocation fact (terminal; requires OBSERVED evidence)."""

    evidence_ref: str
    evidence_digest: str
    reason: str
    revoked_at: str

    def __post_init__(self) -> None:
        require_identifier("revocation.evidence_ref", self.evidence_ref)
        if (
            len(self.evidence_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.evidence_digest)
        ):
            raise CoreValidationError(
                "revocation.evidence_digest must be a canonical SHA-256 digest"
            )
        require_text("revocation.reason", self.reason)
        require_utc_timestamp("revocation.revoked_at", self.revoked_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "evidence_digest": self.evidence_digest,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RevocationRecord":
        require_mapping("finality revocation record", value)
        strict_fields("finality revocation record", value, _REVOCATION_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            evidence_digest=value["evidence_digest"],
            reason=value["reason"],
            revoked_at=value["revoked_at"],
        )


@dataclass(frozen=True, slots=True)
class FinalitySpec:
    """Certificate identity, claim bindings and lifecycle facts."""

    finality_id: str
    settlement_id: str
    settlement_digest: str
    claims: tuple[FinalityClaimBinding, ...]
    established_at: str | None
    challenge: ChallengeRecord | None
    revocation: RevocationRecord | None

    def __post_init__(self) -> None:
        require_identifier("finality.finality_id", self.finality_id)
        require_identifier("finality.settlement_id", self.settlement_id)
        if (
            len(self.settlement_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.settlement_digest)
        ):
            raise CoreValidationError(
                "finality.settlement_digest must be a canonical SHA-256 digest"
            )
        claims = tuple(self.claims)
        seen: set[str] = set()
        for binding in claims:
            if not isinstance(binding, FinalityClaimBinding):
                raise CoreValidationError(
                    "finality.claims entries must be FinalityClaimBinding records"
                )
            if binding.instruction_id in seen:
                raise CoreValidationError(
                    f"duplicate finality claim for leg {binding.instruction_id}"
                )
            seen.add(binding.instruction_id)
        if self.established_at is not None:
            require_utc_timestamp("finality.established_at", self.established_at)
        if self.challenge is not None and not isinstance(self.challenge, ChallengeRecord):
            raise CoreValidationError("finality.challenge must be a ChallengeRecord")
        if self.revocation is not None and not isinstance(self.revocation, RevocationRecord):
            raise CoreValidationError("finality.revocation must be a RevocationRecord")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finality_id": self.finality_id,
            "settlement_id": self.settlement_id,
            "settlement_digest": self.settlement_digest,
            "claims": [binding.to_dict() for binding in self.claims],
            "established_at": self.established_at,
            "challenge": self.challenge.to_dict() if self.challenge else None,
            "revocation": self.revocation.to_dict() if self.revocation else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FinalitySpec":
        require_mapping("finality spec", value)
        strict_fields("finality spec", value, _SPEC_FIELDS)
        return cls(
            finality_id=value["finality_id"],
            settlement_id=value["settlement_id"],
            settlement_digest=value["settlement_digest"],
            claims=tuple(FinalityClaimBinding.from_dict(item) for item in value["claims"]),
            established_at=value["established_at"],
            challenge=(
                ChallengeRecord.from_dict(value["challenge"])
                if value["challenge"] is not None
                else None
            ),
            revocation=(
                RevocationRecord.from_dict(value["revocation"])
                if value["revocation"] is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class Finality:
    """The sealed registry-listed finality certificate object."""

    envelope: ObjectEnvelope
    spec: FinalitySpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FINALITY_OBJECT_TYPE
    STATE_TYPE = FinalityState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("finality envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, FinalitySpec):
            raise CoreValidationError("finality spec must be a FinalitySpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.finality_id:
            raise CoreValidationError(
                "finality envelope and spec must agree on the certificate id"
            )
        _validate_state_facts(FinalityState(self.envelope.state), self.spec)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> FinalityState:
        return FinalityState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        from src.core.serialization import canonical_json

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Finality":
        envelope, payload = decode_composite(
            value,
            object_type=FINALITY_OBJECT_TYPE,
            state_type=FinalityState,
        )
        return cls(
            envelope=envelope,
            spec=FinalitySpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "Finality":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            object_type=FINALITY_OBJECT_TYPE,
            state_type=FinalityState,
        )
        return cls(
            envelope=envelope,
            spec=FinalitySpec.from_dict(payload),
            integrity_hash=integrity_hash,
        )


def _validate_state_facts(state: FinalityState, spec: FinalitySpec) -> None:
    """State-specific coherence of the certificate facts (fail closed)."""
    if state is FinalityState.PENDING:
        if spec.established_at is not None:
            raise CoreValidationError("a PENDING certificate must not carry established_at")
        if spec.challenge is not None or spec.revocation is not None:
            raise CoreValidationError("a PENDING certificate must carry no lifecycle facts")
        if not spec.claims:
            raise CoreValidationError("a PENDING certificate must carry at least one claim")
    if state is FinalityState.ESTABLISHED:
        if spec.established_at is None:
            raise CoreValidationError(
                "an ESTABLISHED certificate must carry established_at"
            )
        if not spec.claims:
            raise CoreValidationError(
                "an ESTABLISHED certificate must carry at least one claim"
            )
        if spec.challenge is not None or spec.revocation is not None:
            raise CoreValidationError(
                "an ESTABLISHED certificate must carry no challenge or revocation"
            )
    if state is FinalityState.CHALLENGED:
        if spec.established_at is None:
            raise CoreValidationError("a CHALLENGED certificate must carry established_at")
        if spec.challenge is None:
            raise CoreValidationError("a CHALLENGED certificate must carry its challenge")
        if spec.revocation is not None:
            raise CoreValidationError(
                "a CHALLENGED certificate must not yet carry a revocation"
            )
    if state is FinalityState.REVOKED:
        if spec.revocation is None:
            raise CoreValidationError("a REVOKED certificate must carry its revocation")


def make_finality_record(
    *,
    finality_id: str,
    settlement_id: str,
    settlement_digest: str,
    claims: tuple[FinalityClaimBinding, ...],
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    state: str = FinalityState.PENDING.value,
    established_at: str | None = None,
    challenge: ChallengeRecord | None = None,
    revocation: RevocationRecord | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Finality:
    """Build and seal a fresh finality certificate record (version 1)."""
    spec = FinalitySpec(
        finality_id=finality_id,
        settlement_id=settlement_id,
        settlement_digest=settlement_digest,
        claims=claims,
        established_at=established_at,
        challenge=challenge,
        revocation=revocation,
    )
    envelope = build_domain_envelope(
        object_id=finality_id,
        object_type=FINALITY_OBJECT_TYPE,
        state=state,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return Finality(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def advance_finality(
    record: Finality,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str,
    correlation_id: str | None,
    spec: FinalitySpec | None = None,
) -> Finality:
    """Produce the next sealed certificate version (identity fields frozen)."""
    from .seal import advance_envelope

    envelope = advance_envelope(
        record.envelope,
        state=state,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    new_spec = spec if spec is not None else record.spec
    return type(record)(
        envelope=envelope, spec=new_spec, integrity_hash=seal_composite(envelope, new_spec)
    )


# -- payload parsers ---------------------------------------------------------


def parse_validate_claim_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``finality.validate`` payload (one sealed observation)."""
    strict_fields("finality.validate payload", value, _VALIDATE_PAYLOAD_FIELDS)
    require_identifier("finality.validate finality_id", value["finality_id"])
    require_identifier("finality.validate settlement_id", value["settlement_id"])
    require_mapping("finality.validate observation", value["observation"])
    return {
        "finality_id": value["finality_id"],
        "settlement_id": value["settlement_id"],
        "observation": value["observation"],
    }


def parse_challenge_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``finality.challenge`` payload (challenge evidence)."""
    strict_fields("finality.challenge payload", value, _CHALLENGE_PAYLOAD_FIELDS)
    require_identifier("finality.challenge evidence_ref", value["evidence_ref"])
    digest = value["evidence_digest"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CoreValidationError(
            "finality.challenge evidence_digest must be a canonical SHA-256 digest"
        )
    require_text("finality.challenge reason", value["reason"])
    return {
        "evidence_ref": value["evidence_ref"],
        "evidence_digest": digest,
        "reason": value["reason"],
    }


def parse_revoke_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``finality.revoke-claim`` payload (revocation evidence)."""
    strict_fields("finality.revoke-claim payload", value, _REVOKE_PAYLOAD_FIELDS)
    require_identifier("finality.revoke-claim evidence_ref", value["evidence_ref"])
    digest = value["evidence_digest"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CoreValidationError(
            "finality.revoke-claim evidence_digest must be a canonical SHA-256 digest"
        )
    require_text("finality.revoke-claim reason", value["reason"])
    return {
        "evidence_ref": value["evidence_ref"],
        "evidence_digest": digest,
        "reason": value["reason"],
    }
