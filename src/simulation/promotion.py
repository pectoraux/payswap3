"""The promotion boundary (WORK-019).

The frozen promotion path is::

    simulation → evidence → production decision → fresh validation →
    production authorization → real execution

This module implements the chain up to the authorization record and
NOTHING else: there is no state-copy path anywhere (the authorization
carries digests and metadata only — never object state), production
sources are not promotable (production state is never copied into
production financial state), and the real execution that an
``APPROVED`` authorization permits happens outside this package, behind
the explicit authorization boundary (constitution invariant 14).

Every record is a flat, sealed, typed object: the content seal is
computed with the single canonical hash authority, authority classes are
validated through the kernel's registry authority, windows are half-open
UTC intervals and every instant is explicit declared data.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition.registry import validate_authority_class

from ._validation import (
    parse_enum,
    require_identifier,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
    utc_timestamp_within,
)
from .contracts import EnvironmentMode
from .snapshots import SimulationCheckpoint

_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "source_checkpoint_digest",
        "source_environment_id",
        "source_domain_id",
        "source_mode",
        "source_state_digest",
        "requested_by",
        "requested_at",
        "evidence_refs",
        "valid_until",
        "integrity_hash",
    }
)
_VALIDATION_FIELDS = frozenset(
    {
        "validation_id",
        "request_digest",
        "source_checkpoint_digest",
        "validator",
        "validated_at",
        "valid_until",
        "result",
        "findings",
        "integrity_hash",
    }
)
_AUTHORIZATION_FIELDS = frozenset(
    {
        "authorization_id",
        "request_digest",
        "validation_digest",
        "source_checkpoint_digest",
        "authorized_by",
        "authority_class",
        "decided_at",
        "decision",
        "integrity_hash",
    }
)


class ValidationVerdict(StrEnum):
    """Closed vocabulary of fresh-validation outcomes."""

    PASS = "PASS"
    FAIL = "FAIL"


class PromotionVerdict(StrEnum):
    """Closed vocabulary of promotion decisions."""

    APPROVED = "APPROVED"
    DENIED = "DENIED"


@dataclass(frozen=True, slots=True)
class PromotionRequest:
    """A request to promote one sealed simulation checkpoint.

    The request references its source by DIGEST ONLY (checkpoint seal,
    snapshot content digest) and must carry evidence references: the
    chain is simulation → evidence → production decision, so a request
    without evidence fails closed. Production sources are refused.
    """

    request_id: str
    source_checkpoint_digest: str
    source_environment_id: str
    source_domain_id: str
    source_mode: EnvironmentMode
    source_state_digest: str
    requested_by: str
    requested_at: str
    evidence_refs: tuple[str, ...]
    valid_until: str
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        require_identifier("promotion request request_id", self.request_id)
        for name in (
            "source_checkpoint_digest",
            "source_state_digest",
        ):
            require_text(f"promotion request {name}", getattr(self, name))
        require_identifier(
            "promotion request source_environment_id", self.source_environment_id
        )
        require_identifier(
            "promotion request source_domain_id", self.source_domain_id
        )
        if not isinstance(self.source_mode, EnvironmentMode):
            raise CoreValidationError(
                "promotion request source_mode must be an EnvironmentMode"
            )
        if self.source_mode is EnvironmentMode.PRODUCTION:
            raise CoreValidationError(
                "production sources are not promotable: production state is "
                "never copied into production financial state"
            )
        require_identifier("promotion request requested_by", self.requested_by)
        require_utc_timestamp("promotion request requested_at", self.requested_at)
        require_utc_timestamp("promotion request valid_until", self.valid_until)
        require_utc_timestamp_order(
            "promotion request requested_at",
            self.requested_at,
            "promotion request valid_until",
            self.valid_until,
        )
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError(
                "promotion requires evidence: the chain is simulation → "
                "evidence → production decision, so a request without "
                "evidence refs fails closed"
            )
        for ref in self.evidence_refs:
            require_identifier("promotion request evidence_ref", ref)
        expected = canonical_sha256(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                "promotion request integrity hash mismatch; tampered "
                "requests fail closed"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "source_checkpoint_digest": self.source_checkpoint_digest,
            "source_environment_id": self.source_environment_id,
            "source_domain_id": self.source_domain_id,
            "source_mode": self.source_mode.value,
            "source_state_digest": self.source_state_digest,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "evidence_refs": list(self.evidence_refs),
            "valid_until": self.valid_until,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PromotionRequest":
        if not isinstance(value, Mapping):
            raise CoreValidationError("promotion request must be an object")
        strict_fields("promotion request", value, _REQUEST_FIELDS)
        refs_raw = value["evidence_refs"]
        if not isinstance(refs_raw, list):
            raise CoreValidationError(
                "promotion request evidence_refs must deserialize from a list"
            )
        return cls(
            request_id=value["request_id"],
            source_checkpoint_digest=value["source_checkpoint_digest"],
            source_environment_id=value["source_environment_id"],
            source_domain_id=value["source_domain_id"],
            source_mode=EnvironmentMode.parse(value["source_mode"]),
            source_state_digest=value["source_state_digest"],
            requested_by=value["requested_by"],
            requested_at=value["requested_at"],
            evidence_refs=tuple(refs_raw),
            valid_until=value["valid_until"],
            integrity_hash=value["integrity_hash"],
        )

    @property
    def digest(self) -> str:
        """Deterministic content digest binding this exact request."""
        return canonical_sha256(self._content())


@dataclass(frozen=True, slots=True)
class FreshValidation:
    """One fresh validation of the exact requested state.

    Fresh validation re-verifies the promoted state at decision time —
    it is never a stale historical verdict: the validation must target
    the exact requested checkpoint (digest equality) and must happen
    inside the request's half-open validity window.
    """

    validation_id: str
    request_digest: str
    source_checkpoint_digest: str
    validator: str
    validated_at: str
    valid_until: str
    result: ValidationVerdict
    findings: str
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        require_identifier("fresh validation validation_id", self.validation_id)
        for name in ("request_digest", "source_checkpoint_digest"):
            require_text(f"fresh validation {name}", getattr(self, name))
        require_identifier("fresh validation validator", self.validator)
        require_utc_timestamp("fresh validation validated_at", self.validated_at)
        require_utc_timestamp("fresh validation valid_until", self.valid_until)
        if not isinstance(self.result, ValidationVerdict):
            raise CoreValidationError(
                "fresh validation result must be a ValidationVerdict"
            )
        if not isinstance(self.findings, str):
            raise CoreValidationError("fresh validation findings must be a string")
        expected = canonical_sha256(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                "fresh validation integrity hash mismatch; tampered "
                "validations fail closed"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "validation_id": self.validation_id,
            "request_digest": self.request_digest,
            "source_checkpoint_digest": self.source_checkpoint_digest,
            "validator": self.validator,
            "validated_at": self.validated_at,
            "valid_until": self.valid_until,
            "result": self.result.value,
            "findings": self.findings,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FreshValidation":
        if not isinstance(value, Mapping):
            raise CoreValidationError("fresh validation must be an object")
        strict_fields("fresh validation", value, _VALIDATION_FIELDS)
        return cls(
            validation_id=value["validation_id"],
            request_digest=value["request_digest"],
            source_checkpoint_digest=value["source_checkpoint_digest"],
            validator=value["validator"],
            validated_at=value["validated_at"],
            valid_until=value["valid_until"],
            result=ValidationVerdict(value["result"]),
            findings=value["findings"],
            integrity_hash=value["integrity_hash"],
        )

    @property
    def digest(self) -> str:
        """Deterministic content digest binding this exact validation."""
        return canonical_sha256(self._content())


@dataclass(frozen=True, slots=True)
class PromotionAuthorization:
    """The terminal record of the promotion chain.

    The authorization binds the request digest, the passing fresh
    validation digest and the source checkpoint digest, and carries
    metadata only — never object state. Real execution happens outside
    this package, behind this explicit authorization boundary.
    """

    authorization_id: str
    request_digest: str
    validation_digest: str
    source_checkpoint_digest: str
    authorized_by: str
    authority_class: str
    decided_at: str
    decision: PromotionVerdict
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        require_identifier(
            "promotion authorization authorization_id", self.authorization_id
        )
        for name in (
            "request_digest",
            "validation_digest",
            "source_checkpoint_digest",
        ):
            require_text(
                f"promotion authorization {name}", getattr(self, name)
            )
        require_identifier(
            "promotion authorization authorized_by", self.authorized_by
        )
        validate_authority_class(
            "promotion authorization authority_class", self.authority_class
        )
        require_utc_timestamp("promotion authorization decided_at", self.decided_at)
        if not isinstance(self.decision, PromotionVerdict):
            raise CoreValidationError(
                "promotion authorization decision must be a PromotionVerdict"
            )
        expected = canonical_sha256(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                "promotion authorization integrity hash mismatch; tampered "
                "authorizations fail closed"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "request_digest": self.request_digest,
            "validation_digest": self.validation_digest,
            "source_checkpoint_digest": self.source_checkpoint_digest,
            "authorized_by": self.authorized_by,
            "authority_class": self.authority_class,
            "decided_at": self.decided_at,
            "decision": self.decision.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "integrity_hash": self.integrity_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PromotionAuthorization":
        if not isinstance(value, Mapping):
            raise CoreValidationError("promotion authorization must be an object")
        strict_fields("promotion authorization", value, _AUTHORIZATION_FIELDS)
        return cls(
            authorization_id=value["authorization_id"],
            request_digest=value["request_digest"],
            validation_digest=value["validation_digest"],
            source_checkpoint_digest=value["source_checkpoint_digest"],
            authorized_by=value["authorized_by"],
            authority_class=value["authority_class"],
            decided_at=value["decided_at"],
            decision=PromotionVerdict(value["decision"]),
            integrity_hash=value["integrity_hash"],
        )

    @property
    def digest(self) -> str:
        """Deterministic content digest binding this exact authorization."""
        return canonical_sha256(self._content())


def request_promotion(
    checkpoint: SimulationCheckpoint,
    *,
    requested_by: str,
    requested_at: str,
    evidence_refs: tuple[str, ...],
    valid_until: str,
) -> PromotionRequest:
    """Open a promotion request for one sealed simulation checkpoint."""
    if not isinstance(checkpoint, SimulationCheckpoint):
        raise CoreValidationError("request_promotion requires a SimulationCheckpoint")
    require_identifier("promotion requested_by", requested_by)
    require_utc_timestamp("promotion requested_at", requested_at)
    require_utc_timestamp("promotion valid_until", valid_until)
    require_utc_timestamp_order(
        "promotion requested_at", requested_at, "promotion valid_until", valid_until
    )
    if not isinstance(evidence_refs, tuple) or not evidence_refs:
        raise CoreValidationError(
            "promotion requires evidence: the chain is simulation → evidence "
            "→ production decision, so a request without evidence refs "
            "fails closed"
        )
    for ref in evidence_refs:
        require_identifier("promotion evidence_ref", ref)
    snapshot = checkpoint.snapshot  # verifies the sealed snapshot content
    if snapshot.mode is EnvironmentMode.PRODUCTION:
        raise CoreValidationError(
            "production sources are not promotable: production state is "
            "never copied into production financial state"
        )
    if snapshot.content_digest is None:  # pragma: no cover - snapshots self-seal
        raise CoreValidationError("promotion source snapshot is not sealed")
    request_id = "promotion/request/" + canonical_sha256(
        {
            "source_checkpoint_digest": checkpoint.checkpoint_digest,
            "requested_by": requested_by,
            "requested_at": requested_at,
        }
    )
    return PromotionRequest(
        request_id=request_id,
        source_checkpoint_digest=checkpoint.checkpoint_digest,
        source_environment_id=snapshot.environment_id,
        source_domain_id=snapshot.domain_id,
        source_mode=snapshot.mode,
        source_state_digest=snapshot.content_digest,
        requested_by=requested_by,
        requested_at=requested_at,
        evidence_refs=tuple(evidence_refs),
        valid_until=valid_until,
    )


def perform_fresh_validation(
    request: PromotionRequest,
    checkpoint: SimulationCheckpoint,
    *,
    validator: str,
    validated_at: str,
    result: ValidationVerdict,
    findings: str = "",
) -> FreshValidation:
    """Perform the fresh validation of the exact requested state.

    The provided checkpoint must be the requested one (digest equality)
    and the validation must happen inside the request's half-open
    window ``[requested_at, valid_until)``; both fail closed.
    """
    if not isinstance(request, PromotionRequest):
        raise CoreValidationError("fresh validation requires a PromotionRequest")
    if not isinstance(checkpoint, SimulationCheckpoint):
        raise CoreValidationError("fresh validation requires a SimulationCheckpoint")
    require_identifier("fresh validation validator", validator)
    require_utc_timestamp("fresh validation validated_at", validated_at)
    result = parse_enum("fresh validation result", result, ValidationVerdict)
    if not isinstance(findings, str):
        raise CoreValidationError("fresh validation findings must be a string")
    if checkpoint.checkpoint_digest != request.source_checkpoint_digest:
        raise CoreValidationError(
            "fresh validation must target the exact requested state: "
            f"checkpoint {checkpoint.checkpoint_digest} is not the requested "
            f"{request.source_checkpoint_digest}"
        )
    if not utc_timestamp_within(
        validated_at, request.requested_at, request.valid_until
    ):
        raise CoreValidationError(
            "fresh validation is only valid inside the request window ["
            f"{request.requested_at}, {request.valid_until}); it was performed "
            f"at {validated_at}"
        )
    validation_id = "promotion/validation/" + canonical_sha256(
        {
            "request_digest": request.digest,
            "validator": validator,
            "validated_at": validated_at,
        }
    )
    return FreshValidation(
        validation_id=validation_id,
        request_digest=request.digest,
        source_checkpoint_digest=request.source_checkpoint_digest,
        validator=validator,
        validated_at=validated_at,
        valid_until=request.valid_until,
        result=result,
        findings=findings,
    )


def decide_promotion_authorization(
    validation: FreshValidation,
    *,
    authorized_by: str,
    authority_class: str,
    decided_at: str,
    decision: PromotionVerdict,
) -> PromotionAuthorization:
    """Decide the promotion authorization over one fresh validation.

    ``APPROVED`` requires a PASSING fresh validation (a failed or
    diverged validation has no approval path) and the decision must
    happen inside the validation window. The result is a typed record
    only — real execution happens outside this package.
    """
    if not isinstance(validation, FreshValidation):
        raise CoreValidationError(
            "promotion authorization requires a FreshValidation"
        )
    require_identifier("promotion authorized_by", authorized_by)
    validate_authority_class("promotion authority_class", authority_class)
    require_utc_timestamp("promotion decided_at", decided_at)
    decision = parse_enum("promotion decision", decision, PromotionVerdict)
    if decision is PromotionVerdict.APPROVED and (
        validation.result is not ValidationVerdict.PASS
    ):
        raise CoreValidationError(
            "promotion authorization requires a PASSING fresh validation; "
            f"the validation verdict is {validation.result.value}"
        )
    if not utc_timestamp_within(
        decided_at, validation.validated_at, validation.valid_until
    ):
        raise CoreValidationError(
            "promotion decisions are only valid inside the validation window ["
            f"{validation.validated_at}, {validation.valid_until}); the "
            f"decision was made at {decided_at}"
        )
    authorization_id = "promotion/authorization/" + canonical_sha256(
        {
            "validation_digest": validation.digest,
            "authorized_by": authorized_by,
            "decided_at": decided_at,
        }
    )
    return PromotionAuthorization(
        authorization_id=authorization_id,
        request_digest=validation.request_digest,
        validation_digest=validation.digest,
        source_checkpoint_digest=validation.source_checkpoint_digest,
        authorized_by=authorized_by,
        authority_class=authority_class,
        decided_at=decided_at,
        decision=decision,
    )
