"""The recourse case: refunds and reversals (the return boundaries).

A :class:`RecourseCase` is the internal ``settlement/recourse-case/v1``
record driving the frozen ``Recourse`` command families
``Request/Approve/Reject/Compile/ExecuteRefund`` and
``Request/Approve/Reject/ExecuteReversal`` (the Work Order's
"reversals/returns boundaries").

Consumed authorities (one authority per concept, never redefined here):

* the epistemic vocabulary of evidence-bearing commands is the evidence
  domain's :class:`src.evidence.EpistemicType` (WORK-018 contract): a
  refund or reversal request must be backed by ``OBSERVED`` knowledge —
  a simulated or predicted value can never open recourse;
* a reversal request is digest-bound to the REVOKED (or CHALLENGED)
  finality certificate whose discharge it compensates — reversals are
  only legitimate when the finality layer has explicitly withdrawn the
  claim (constitution invariant 11: no false finality, and no silent
  un-finality either);
* a refund compiles a NEW settlement linked to the original (the
  ledger-posting-model's ``Refund → new economic transaction linked to
  original``), while a reversal emits the exact compensation postings
  of the original discharge pair (``Reversal → explicit
  reversal/compensation journal``). Neither path ever edits an
  historical posting (the forbidden surface "no arbitrary ledger
  edits"; constitution invariant 17).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.envelope import ObjectEnvelope, Provenance
from src.evidence.contracts import EpistemicType

from ._validation import (
    parse_enum,
    require_identifier,
    require_identifier_tuple,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    RECOURSE_CASE_OBJECT_TYPE,
    RecourseKind,
    RecourseCaseState,
)
from .seal import (
    build_domain_envelope,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_REQUEST_PAYLOAD_FIELDS = frozenset(
    {
        "case_id",
        "kind",
        "settlement_id",
        "instruction_ids",
        "evidence_ref",
        "evidence_digest",
        "epistemic_type",
        "reason",
    }
)
_DECISION_PAYLOAD_FIELDS = frozenset({"reason"})
_EXECUTE_REFUND_PAYLOAD_FIELDS = frozenset({"settlement_id"})
_EXECUTE_REVERSAL_PAYLOAD_FIELDS = frozenset()

_EVIDENCE_GATE_FIELDS = frozenset(
    {"evidence_ref", "evidence_digest", "epistemic_type", "reason"}
)

_COMPILATION_FIELDS = frozenset({"compiled_settlement_id", "compiled_at"})
_EXECUTION_FIELDS = frozenset({"executed_at", "posting_refs"})
_REJECTION_FIELDS = frozenset({"reason", "rejected_at"})

_SPEC_FIELDS = frozenset(
    {
        "case_id",
        "kind",
        "settlement_id",
        "instruction_ids",
        "evidence",
        "compilation",
        "execution",
        "rejection",
    }
)


@dataclass(frozen=True, slots=True)
class RecourseEvidence:
    """One ``OBSERVED`` evidence binding opening a recourse case.

    The epistemic vocabulary is owned by ``src.evidence`` (WORK-018)
    and consumed here: only ``OBSERVED`` knowledge may open recourse —
    a simulated or predicted justification can never move money back.
    For reversal cases the evidence digest is additionally pinned to
    the withdrawn finality certificate by the engine's gates.
    """

    evidence_ref: str
    evidence_digest: str
    epistemic_type: str
    reason: str

    def __post_init__(self) -> None:
        require_identifier("recourse evidence.evidence_ref", self.evidence_ref)
        if (
            len(self.evidence_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.evidence_digest)
        ):
            raise CoreValidationError(
                "recourse evidence.evidence_digest must be a canonical SHA-256 digest"
            )
        parsed = EpistemicType(self.epistemic_type)
        if parsed is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                "recourse evidence must be OBSERVED knowledge; a "
                f"{parsed.value} justification can never open recourse"
            )
        require_text("recourse evidence.reason", self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "evidence_digest": self.evidence_digest,
            "epistemic_type": self.epistemic_type,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecourseEvidence":
        require_mapping("recourse evidence", value)
        strict_fields("recourse evidence", value, _EVIDENCE_GATE_FIELDS)
        return cls(
            evidence_ref=value["evidence_ref"],
            evidence_digest=value["evidence_digest"],
            epistemic_type=value["epistemic_type"],
            reason=value["reason"],
        )


@dataclass(frozen=True, slots=True)
class RefundCompilation:
    """The refund settlement draft compiled from an approved refund case."""

    compiled_settlement_id: str
    compiled_at: str

    def __post_init__(self) -> None:
        require_identifier("refund compilation.compiled_settlement_id", self.compiled_settlement_id)
        require_utc_timestamp("refund compilation.compiled_at", self.compiled_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "compiled_settlement_id": self.compiled_settlement_id,
            "compiled_at": self.compiled_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RefundCompilation":
        require_mapping("refund compilation", value)
        strict_fields("refund compilation", value, _COMPILATION_FIELDS)
        return cls(
            compiled_settlement_id=value["compiled_settlement_id"],
            compiled_at=value["compiled_at"],
        )


@dataclass(frozen=True, slots=True)
class RecourseExecution:
    """The execution fact of a refund or reversal case.

    ``posting_refs`` pins the exact append-only posting entries the
    execution emitted (reversal compensation postings, or the refund
    execution's linkage) — recourse is auditable to the journal entry.
    """

    executed_at: str
    posting_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_utc_timestamp("recourse execution.executed_at", self.executed_at)
        for ref in self.posting_refs:
            require_identifier("recourse execution.posting_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed_at": self.executed_at,
            "posting_refs": list(self.posting_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecourseExecution":
        require_mapping("recourse execution", value)
        strict_fields("recourse execution", value, _EXECUTION_FIELDS)
        return cls(
            executed_at=value["executed_at"],
            posting_refs=tuple(value["posting_refs"]),
        )


@dataclass(frozen=True, slots=True)
class RecourseRejection:
    """The explicit rejection fact of a recourse case."""

    reason: str
    rejected_at: str

    def __post_init__(self) -> None:
        require_text("recourse rejection.reason", self.reason)
        require_utc_timestamp("recourse rejection.rejected_at", self.rejected_at)

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "rejected_at": self.rejected_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecourseRejection":
        require_mapping("recourse rejection", value)
        strict_fields("recourse rejection", value, _REJECTION_FIELDS)
        return cls(reason=value["reason"], rejected_at=value["rejected_at"])


@dataclass(frozen=True, slots=True)
class RecourseCaseSpec:
    """Case identity, pinned instructions and lifecycle facts."""

    case_id: str
    kind: str
    settlement_id: str
    instruction_ids: tuple[str, ...]
    evidence: RecourseEvidence
    compilation: RefundCompilation | None
    execution: RecourseExecution | None
    rejection: RecourseRejection | None

    def __post_init__(self) -> None:
        require_identifier("recourse case.case_id", self.case_id)
        parsed_kind = parse_enum("recourse case.kind", self.kind, RecourseKind)
        require_identifier("recourse case.settlement_id", self.settlement_id)
        instruction_ids = require_identifier_tuple(
            "recourse case.instruction_ids", self.instruction_ids
        )
        if not isinstance(self.evidence, RecourseEvidence):
            raise CoreValidationError(
                "recourse case.evidence must be a RecourseEvidence record"
            )
        if parsed_kind is RecourseKind.REFUND and self.compilation is None:
            # only enforced at EXECUTED state via state facts; here both
            # shapes are legal mid-lifecycle
            pass
        if self.compilation is not None and not isinstance(
            self.compilation, RefundCompilation
        ):
            raise CoreValidationError(
                "recourse case.compilation must be a RefundCompilation"
            )
        if self.execution is not None and not isinstance(self.execution, RecourseExecution):
            raise CoreValidationError(
                "recourse case.execution must be a RecourseExecution"
            )
        if self.rejection is not None and not isinstance(
            self.rejection, RecourseRejection
        ):
            raise CoreValidationError(
                "recourse case.rejection must be a RecourseRejection"
            )
        if self.rejection is not None and (
            self.compilation is not None or self.execution is not None
        ):
            raise CoreValidationError(
                "a rejected case must not carry a compilation or an execution"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "settlement_id": self.settlement_id,
            "instruction_ids": list(self.instruction_ids),
            "evidence": self.evidence.to_dict(),
            "compilation": self.compilation.to_dict() if self.compilation else None,
            "execution": self.execution.to_dict() if self.execution else None,
            "rejection": self.rejection.to_dict() if self.rejection else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecourseCaseSpec":
        require_mapping("recourse case spec", value)
        strict_fields("recourse case spec", value, _SPEC_FIELDS)
        return cls(
            case_id=value["case_id"],
            kind=value["kind"],
            settlement_id=value["settlement_id"],
            instruction_ids=tuple(value["instruction_ids"]),
            evidence=RecourseEvidence.from_dict(value["evidence"]),
            compilation=(
                RefundCompilation.from_dict(value["compilation"])
                if value["compilation"] is not None
                else None
            ),
            execution=(
                RecourseExecution.from_dict(value["execution"])
                if value["execution"] is not None
                else None
            ),
            rejection=(
                RecourseRejection.from_dict(value["rejection"])
                if value["rejection"] is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class RecourseCase:
    """The sealed recourse case object (internal ``settlement/recourse-case/v1``)."""

    envelope: ObjectEnvelope
    spec: RecourseCaseSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = RECOURSE_CASE_OBJECT_TYPE
    STATE_TYPE = RecourseCaseState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("recourse envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, RecourseCaseSpec):
            raise CoreValidationError("recourse spec must be a RecourseCaseSpec")
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.object_id)
        if self.envelope.object_id != self.spec.case_id:
            raise CoreValidationError(
                "recourse envelope and spec must agree on the case id"
            )
        _validate_state_facts(RecourseCaseState(self.envelope.state), self.spec)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> RecourseCaseState:
        return RecourseCaseState(self.envelope.state)

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
    def from_dict(cls, value: Mapping[str, Any]) -> "RecourseCase":
        envelope, payload = decode_composite(
            value,
            object_type=RECOURSE_CASE_OBJECT_TYPE,
            state_type=RecourseCaseState,
        )
        return cls(
            envelope=envelope,
            spec=RecourseCaseSpec.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "RecourseCase":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            object_type=RECOURSE_CASE_OBJECT_TYPE,
            state_type=RecourseCaseState,
        )
        return cls(
            envelope=envelope,
            spec=RecourseCaseSpec.from_dict(payload),
            integrity_hash=integrity_hash,
        )


def _validate_state_facts(state: RecourseCaseState, spec: RecourseCaseSpec) -> None:
    """State-specific coherence of the case facts (fail closed)."""
    if state is RecourseCaseState.REQUESTED:
        if (
            spec.compilation is not None
            or spec.execution is not None
            or spec.rejection is not None
        ):
            raise CoreValidationError(
                "a REQUESTED case must carry no decision facts"
            )
    if state is RecourseCaseState.APPROVED:
        if spec.compilation is not None or spec.execution is not None:
            raise CoreValidationError(
                "an APPROVED case must carry no compilation or execution yet"
            )
        if spec.rejection is not None:
            raise CoreValidationError("an APPROVED case must not carry a rejection")
    if state is RecourseCaseState.COMPILED:
        if RecourseKind(spec.kind) is not RecourseKind.REFUND:
            raise CoreValidationError(
                "a COMPILED case must be a refund case (reversals do not compile)"
            )
        if spec.compilation is None:
            raise CoreValidationError("a COMPILED case must carry its compilation")
        if spec.execution is not None or spec.rejection is not None:
            raise CoreValidationError(
                "a COMPILED case must not carry an execution or a rejection"
            )
    if state is RecourseCaseState.EXECUTED:
        if spec.execution is None:
            raise CoreValidationError("an EXECUTED case must carry its execution")
        if spec.rejection is not None:
            raise CoreValidationError("an EXECUTED case must not carry a rejection")
        if RecourseKind(spec.kind) is RecourseKind.REFUND and spec.compilation is None:
            raise CoreValidationError(
                "an EXECUTED refund case must carry its compilation"
            )
    if state is RecourseCaseState.REJECTED:
        if spec.rejection is None:
            raise CoreValidationError("a REJECTED case must carry its rejection")


def make_recourse_record(
    *,
    case_id: str,
    kind: str,
    settlement_id: str,
    instruction_ids: tuple[str, ...],
    evidence: RecourseEvidence,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    state: str = RecourseCaseState.REQUESTED.value,
    compilation: RefundCompilation | None = None,
    execution: RecourseExecution | None = None,
    rejection: RecourseRejection | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> RecourseCase:
    """Build and seal a fresh recourse case record (version 1)."""
    spec = RecourseCaseSpec(
        case_id=case_id,
        kind=kind,
        settlement_id=settlement_id,
        instruction_ids=instruction_ids,
        evidence=evidence,
        compilation=compilation,
        execution=execution,
        rejection=rejection,
    )
    envelope = build_domain_envelope(
        object_id=case_id,
        object_type=RECOURSE_CASE_OBJECT_TYPE,
        state=state,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return RecourseCase(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def advance_recourse(
    record: RecourseCase,
    *,
    state: str,
    provenance: Provenance,
    causation_id: str,
    correlation_id: str | None,
    spec: RecourseCaseSpec | None = None,
) -> RecourseCase:
    """Produce the next sealed case version (identity fields frozen)."""
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


def parse_request_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``recourse/{refund,reversal}.request`` payload."""
    strict_fields("recourse request payload", value, _REQUEST_PAYLOAD_FIELDS)
    require_identifier("recourse request case_id", value["case_id"])
    kind = parse_enum("recourse request kind", value["kind"], RecourseKind)
    require_identifier("recourse request settlement_id", value["settlement_id"])
    instruction_ids = require_identifier_tuple(
        "recourse request instruction_ids", value["instruction_ids"]
    )
    require_identifier("recourse request evidence_ref", value["evidence_ref"])
    digest = value["evidence_digest"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CoreValidationError(
            "recourse request evidence_digest must be a canonical SHA-256 digest"
        )
    require_text("recourse request reason", value["reason"])
    return {
        "case_id": value["case_id"],
        "kind": kind,
        "settlement_id": value["settlement_id"],
        "instruction_ids": instruction_ids,
        "evidence_ref": value["evidence_ref"],
        "evidence_digest": digest,
        "epistemic_type": value["epistemic_type"],
        "reason": value["reason"],
    }


def parse_decision_payload(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse an approve/reject decision payload."""
    strict_fields(name, value, _DECISION_PAYLOAD_FIELDS)
    require_text(f"{name} reason", value["reason"])
    return {"reason": value["reason"]}


def parse_execute_refund_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``recourse/refund.execute`` payload (the linked settlement)."""
    strict_fields("recourse refund.execute payload", value, _EXECUTE_REFUND_PAYLOAD_FIELDS)
    require_identifier(
        "recourse refund.execute settlement_id", value["settlement_id"]
    )
    return {"settlement_id": value["settlement_id"]}
