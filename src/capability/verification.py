"""Verification metadata attached to capability records.

Verification is declarative, verifiable metadata: who verified what, with
which method, against which evidence, and with which deterministic validity
bound. Recording a failed verification is an explicit, non-exceptional
outcome; advancing a capability's lifecycle on the basis of verification is
gated separately by the capability transitions in :mod:`records`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from ..core.errors import CoreValidationError

from ._validation import parse_enum, require_internal_id, require_text
from .windows import parse_utc_timestamp, validate_utc_timestamp

_VERIFICATION_FIELDS = frozenset(
    {"method", "verifier", "result", "verified_at", "valid_until", "evidence_refs"}
)


class VerificationMethod(StrEnum):
    """Closed internal vocabulary of verification methods."""

    SIMULATION = "simulation"
    CERTIFICATION = "certification"
    ATTESTATION = "attestation"
    TEST_EVIDENCE = "test_evidence"
    OPERATIONAL_EVIDENCE = "operational_evidence"


class VerificationResult(StrEnum):
    """Closed internal vocabulary of verification outcomes."""

    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class VerificationMetadata:
    """Verifiable metadata for one capability verification event."""

    method: VerificationMethod
    verifier: str
    result: VerificationResult
    verified_at: str
    valid_until: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.method, VerificationMethod):
            raise CoreValidationError("verification method must use the closed vocabulary")
        require_internal_id("verification verifier", self.verifier)
        if not isinstance(self.result, VerificationResult):
            raise CoreValidationError("verification result must use the closed vocabulary")
        validate_utc_timestamp("verification verified_at", self.verified_at)
        if self.valid_until is not None:
            validate_utc_timestamp("verification valid_until", self.valid_until)
            if parse_utc_timestamp("valid_until", self.valid_until) <= parse_utc_timestamp(
                "verified_at", self.verified_at
            ):
                raise CoreValidationError("verification valid_until must be strictly after verified_at")
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("verification evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            require_text("verification evidence_ref", ref)

    def is_valid_at(self, as_of: str) -> bool:
        """Deterministic validity test against an explicit timestamp."""
        if self.valid_until is None:
            return True
        return parse_utc_timestamp("valid_until", self.valid_until) > parse_utc_timestamp("as_of", as_of)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "verifier": self.verifier,
            "result": self.result.value,
            "verified_at": self.verified_at,
            "valid_until": self.valid_until,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerificationMetadata":
        if not isinstance(value, Mapping):
            raise CoreValidationError("verification must be an object")
        if set(value) != _VERIFICATION_FIELDS:
            missing = sorted(_VERIFICATION_FIELDS - set(value))
            extra = sorted(set(value) - _VERIFICATION_FIELDS)
            raise CoreValidationError(
                f"verification fields are not canonical; missing={missing}, extra={extra}"
            )
        method = parse_enum("verification method", VerificationMethod, value["method"])
        result = parse_enum("verification result", VerificationResult, value["result"])
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError("verification evidence_refs must deserialize from a list")
        return cls(
            method=method,
            verifier=value["verifier"],
            result=result,
            verified_at=value["verified_at"],
            valid_until=value["valid_until"],
            evidence_refs=tuple(refs),
        )
