r"""Cases, claims and recourse: the user-dispute lifecycle.

A :class:`Case` (canonical object model "Federation and operations"
family: ``Case`` / ``Investigation``) carries typed :class:`Claim`
records through the closed lifecycle

```text
OPEN -> INVESTIGATED -> DECIDED -> EXECUTED -> CLOSED
                     \-- DECIDED (decision REJECT) ----> CLOSED
```

implementing the frozen Recourse command family
``Request/Approve/Reject/Compile/ExecuteRefund; Request/Approve/Reject/
ExecuteReversal`` (approve/reject collapse into the decision kind;
"request" is the case opening; compile assembles the typed refund or
reversal package; execute records the execution outcome).

No ledger authority: recourse outcomes are recorded as CASES and
DECISIONS with explicit references. A refund or reversal is compiled
into a typed package referencing the domain that would execute it and
is then recorded as EXECUTED with an opaque external execution
reference supplied by the caller — the actual financial execution
(settlement, ledger posting, finality) belongs to other domains and is
explicitly out of scope here.

Provenance is preserved on every material step (constitution invariant
13): investigation, decision, disclosure and execution transitions all
require provenance evidence references, and the evidence referenced by
investigations and decisions must resolve in the real evidence archive
(WORK-018, consumed read-only). Participants (openers, claimants,
investigators, deciders) are gated through the real trust registry
(WORK-004): unknown, suspended or retired principals fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.evidence import EvidenceArchive, ScaledValue

from .contracts import (
    CASE_ID_PREFIX,
    CASE_OBJECT_TYPE,
    PRINCIPAL_PREFIX,
    CaseState,
    ClaimType,
    DecisionKind,
)
from .disclosure import require_active_principal
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
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


def _require_amount(name: str, value: Any) -> ScaledValue:
    if not isinstance(value, ScaledValue):
        raise CoreValidationError(f"{name} must be a ScaledValue")
    return value


@dataclass(frozen=True, slots=True)
class Claim:
    """One typed user claim attached to a case."""

    claim_id: str
    claimant: str
    claim_type: Any
    subject_ref: str
    description: str
    asserted_at: str
    amount: ScaledValue | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_text("claim.claim_id", self.claim_id)
        require_identifier("claim.claimant", self.claimant, prefix=PRINCIPAL_PREFIX)
        object.__setattr__(
            self, "claim_type", parse_enum("claim.claim_type", ClaimType, self.claim_type)
        )
        require_identifier("claim.subject_ref", self.subject_ref)
        require_text("claim.description", self.description)
        require_utc_timestamp("claim.asserted_at", self.asserted_at)
        if self.amount is not None:
            _require_amount("claim.amount", self.amount)
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("claim.evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            require_identifier("claim.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claimant": self.claimant,
            "claim_type": self.claim_type.value,
            "subject_ref": self.subject_ref,
            "description": self.description,
            "asserted_at": self.asserted_at,
            "amount": self.amount.to_dict() if self.amount is not None else None,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: object) -> "Claim":
        strict_fields(
            "claim",
            value,
            {
                "claim_id",
                "claimant",
                "claim_type",
                "subject_ref",
                "description",
                "asserted_at",
                "amount",
                "evidence_refs",
            },
        )
        return cls(
            claim_id=value["claim_id"],
            claimant=value["claimant"],
            claim_type=value["claim_type"],
            subject_ref=value["subject_ref"],
            description=value["description"],
            asserted_at=value["asserted_at"],
            amount=(
                ScaledValue.from_dict(value["amount"]) if value["amount"] is not None else None
            ),
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True, slots=True)
class Investigation:
    """One typed investigation attached while the case is OPEN."""

    investigator: str
    investigated_at: str
    findings: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(
            "investigation.investigator", self.investigator, prefix=PRINCIPAL_PREFIX
        )
        require_utc_timestamp("investigation.investigated_at", self.investigated_at)
        require_text("investigation.findings", self.findings)
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError(
                "investigation.evidence_refs must be a non-empty tuple"
            )
        for ref in self.evidence_refs:
            require_identifier("investigation.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigator": self.investigator,
            "investigated_at": self.investigated_at,
            "findings": self.findings,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: object) -> "Investigation":
        strict_fields(
            "investigation",
            value,
            {"investigator", "investigated_at", "findings", "evidence_refs"},
        )
        return cls(
            investigator=value["investigator"],
            investigated_at=value["investigated_at"],
            findings=value["findings"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True, slots=True)
class RecourseDecision:
    """One typed recourse decision (approve refund/reversal or reject)."""

    decision_id: str
    kind: Any
    decided_by: str
    decided_at: str
    rationale: str
    evidence_refs: tuple[str, ...]
    amount: ScaledValue | None = None

    def __post_init__(self) -> None:
        require_text("decision.decision_id", self.decision_id)
        object.__setattr__(
            self, "kind", parse_enum("decision.kind", DecisionKind, self.kind)
        )
        require_identifier("decision.decided_by", self.decided_by, prefix=PRINCIPAL_PREFIX)
        require_utc_timestamp("decision.decided_at", self.decided_at)
        require_text("decision.rationale", self.rationale)
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError("decision.evidence_refs must be a non-empty tuple")
        for ref in self.evidence_refs:
            require_identifier("decision.evidence_ref", ref)
        if self.amount is not None:
            _require_amount("decision.amount", self.amount)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "kind": self.kind.value,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "amount": self.amount.to_dict() if self.amount is not None else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RecourseDecision":
        strict_fields(
            "decision",
            value,
            {
                "decision_id",
                "kind",
                "decided_by",
                "decided_at",
                "rationale",
                "evidence_refs",
                "amount",
            },
        )
        return cls(
            decision_id=value["decision_id"],
            kind=value["kind"],
            decided_by=value["decided_by"],
            decided_at=value["decided_at"],
            rationale=value["rationale"],
            evidence_refs=tuple(value["evidence_refs"]),
            amount=(
                ScaledValue.from_dict(value["amount"]) if value["amount"] is not None else None
            ),
        )


@dataclass(frozen=True, slots=True)
class RefundPackage:
    """The compiled refund package: exact amount, target and execution domain.

    The package is a RECORD: the actual financial execution belongs to
    the referenced execution domain (out of scope by Work Order).
    """

    package_id: str
    compiled_by: str
    compiled_at: str
    amount: ScaledValue
    target_ref: str
    execution_domain: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text("refund_package.package_id", self.package_id)
        require_identifier(
            "refund_package.compiled_by", self.compiled_by, prefix=PRINCIPAL_PREFIX
        )
        require_utc_timestamp("refund_package.compiled_at", self.compiled_at)
        _require_amount("refund_package.amount", self.amount)
        require_identifier("refund_package.target_ref", self.target_ref)
        require_text("refund_package.execution_domain", self.execution_domain)
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError("refund_package.evidence_refs must be a non-empty tuple")
        for ref in self.evidence_refs:
            require_identifier("refund_package.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "compiled_by": self.compiled_by,
            "compiled_at": self.compiled_at,
            "amount": self.amount.to_dict(),
            "target_ref": self.target_ref,
            "execution_domain": self.execution_domain,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: object) -> "RefundPackage":
        strict_fields(
            "refund package",
            value,
            {
                "package_id",
                "compiled_by",
                "compiled_at",
                "amount",
                "target_ref",
                "execution_domain",
                "evidence_refs",
            },
        )
        return cls(
            package_id=value["package_id"],
            compiled_by=value["compiled_by"],
            compiled_at=value["compiled_at"],
            amount=ScaledValue.from_dict(value["amount"]),
            target_ref=value["target_ref"],
            execution_domain=value["execution_domain"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True, slots=True)
class ReversalPackage:
    """The compiled reversal package: transaction target and execution domain."""

    package_id: str
    compiled_by: str
    compiled_at: str
    target_transaction_ref: str
    execution_domain: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text("reversal_package.package_id", self.package_id)
        require_identifier(
            "reversal_package.compiled_by", self.compiled_by, prefix=PRINCIPAL_PREFIX
        )
        require_utc_timestamp("reversal_package.compiled_at", self.compiled_at)
        require_identifier(
            "reversal_package.target_transaction_ref", self.target_transaction_ref
        )
        require_text("reversal_package.execution_domain", self.execution_domain)
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError(
                "reversal_package.evidence_refs must be a non-empty tuple"
            )
        for ref in self.evidence_refs:
            require_identifier("reversal_package.evidence_ref", ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "compiled_by": self.compiled_by,
            "compiled_at": self.compiled_at,
            "target_transaction_ref": self.target_transaction_ref,
            "execution_domain": self.execution_domain,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: object) -> "ReversalPackage":
        strict_fields(
            "reversal package",
            value,
            {
                "package_id",
                "compiled_by",
                "compiled_at",
                "target_transaction_ref",
                "execution_domain",
                "evidence_refs",
            },
        )
        return cls(
            package_id=value["package_id"],
            compiled_by=value["compiled_by"],
            compiled_at=value["compiled_at"],
            target_transaction_ref=value["target_transaction_ref"],
            execution_domain=value["execution_domain"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    """The recorded execution outcome: an explicit external reference."""

    executed_by: str
    executed_at: str
    execution_ref: str

    def __post_init__(self) -> None:
        require_identifier("execution.executed_by", self.executed_by, prefix=PRINCIPAL_PREFIX)
        require_utc_timestamp("execution.executed_at", self.executed_at)
        require_identifier("execution.execution_ref", self.execution_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed_by": self.executed_by,
            "executed_at": self.executed_at,
            "execution_ref": self.execution_ref,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ExecutionRecord":
        strict_fields("execution", value, {"executed_by", "executed_at", "execution_ref"})
        return cls(
            executed_by=value["executed_by"],
            executed_at=value["executed_at"],
            execution_ref=value["execution_ref"],
        )


_CASE_PAYLOAD_FIELDS = frozenset(
    {
        "case_id",
        "subject_ref",
        "opened_by",
        "opened_at",
        "claims",
        "investigation",
        "decision",
        "refund_package",
        "reversal_package",
        "execution",
        "closed_at",
        "close_reason",
    }
)


@dataclass(frozen=True, slots=True)
class CasePayload:
    """Immutable case payload across the whole recourse lifecycle."""

    case_id: str
    subject_ref: str
    opened_by: str
    opened_at: str
    claims: tuple[Claim, ...]
    investigation: Investigation | None = None
    decision: RecourseDecision | None = None
    refund_package: RefundPackage | None = None
    reversal_package: ReversalPackage | None = None
    execution: ExecutionRecord | None = None
    closed_at: str | None = None
    close_reason: str | None = None

    def __post_init__(self) -> None:
        require_identifier("case.case_id", self.case_id, prefix=CASE_ID_PREFIX)
        require_identifier("case.subject_ref", self.subject_ref)
        require_identifier("case.opened_by", self.opened_by, prefix=PRINCIPAL_PREFIX)
        require_utc_timestamp("case.opened_at", self.opened_at)
        if not isinstance(self.claims, tuple) or not self.claims:
            raise CoreValidationError("case.claims must be a non-empty tuple")
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise CoreValidationError("case claim ids must be unique")
        for claim in self.claims:
            if not isinstance(claim, Claim):
                raise CoreValidationError("case.claims entries must be Claim records")
            if claim.subject_ref != self.subject_ref:
                raise CoreValidationError(
                    f"claim {claim.claim_id} targets {claim.subject_ref} but the case "
                    f"subject is {self.subject_ref}"
                )
        for name, kind in (
            ("investigation", Investigation),
            ("decision", RecourseDecision),
            ("refund_package", RefundPackage),
            ("reversal_package", ReversalPackage),
            ("execution", ExecutionRecord),
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, kind):
                raise CoreValidationError(f"case.{name} has the wrong type")
        if self.closed_at is not None:
            require_utc_timestamp("case.closed_at", self.closed_at)
            require_text("case.close_reason", self.close_reason or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "subject_ref": self.subject_ref,
            "opened_by": self.opened_by,
            "opened_at": self.opened_at,
            "claims": [claim.to_dict() for claim in self.claims],
            "investigation": (
                self.investigation.to_dict() if self.investigation is not None else None
            ),
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "refund_package": (
                self.refund_package.to_dict() if self.refund_package is not None else None
            ),
            "reversal_package": (
                self.reversal_package.to_dict() if self.reversal_package is not None else None
            ),
            "execution": self.execution.to_dict() if self.execution is not None else None,
            "closed_at": self.closed_at,
            "close_reason": self.close_reason,
        }

    @classmethod
    def from_dict(cls, value: object) -> "CasePayload":
        strict_fields("case", value, _CASE_PAYLOAD_FIELDS)
        return cls(
            case_id=value["case_id"],
            subject_ref=value["subject_ref"],
            opened_by=value["opened_by"],
            opened_at=value["opened_at"],
            claims=tuple(Claim.from_dict(item) for item in value["claims"]),
            investigation=(
                Investigation.from_dict(value["investigation"])
                if value["investigation"] is not None
                else None
            ),
            decision=(
                RecourseDecision.from_dict(value["decision"])
                if value["decision"] is not None
                else None
            ),
            refund_package=(
                RefundPackage.from_dict(value["refund_package"])
                if value["refund_package"] is not None
                else None
            ),
            reversal_package=(
                ReversalPackage.from_dict(value["reversal_package"])
                if value["reversal_package"] is not None
                else None
            ),
            execution=(
                ExecutionRecord.from_dict(value["execution"])
                if value["execution"] is not None
                else None
            ),
            closed_at=value["closed_at"],
            close_reason=value["close_reason"],
        )


def _validate_case_state(envelope: ObjectEnvelope, payload: CasePayload) -> None:
    state = CaseState(envelope.state)
    if state is CaseState.OPEN:
        if payload.investigation or payload.decision or payload.execution:
            raise CoreValidationError("an OPEN case carries no investigation, decision or execution")
        if payload.refund_package or payload.reversal_package:
            raise CoreValidationError("an OPEN case carries no compiled packages")
        if payload.closed_at is not None or payload.close_reason is not None:
            raise CoreValidationError("an OPEN case carries no close fields")
    elif state is CaseState.INVESTIGATED:
        if payload.investigation is None:
            raise CoreValidationError("an INVESTIGATED case must carry its investigation")
        if payload.decision or payload.execution:
            raise CoreValidationError(
                "an INVESTIGATED case carries no decision or execution"
            )
        if payload.refund_package or payload.reversal_package:
            raise CoreValidationError("an INVESTIGATED case carries no compiled packages")
        if payload.closed_at is not None or payload.close_reason is not None:
            raise CoreValidationError("an INVESTIGATED case carries no close fields")
    elif state is CaseState.DECIDED:
        if payload.investigation is None or payload.decision is None:
            raise CoreValidationError("a DECIDED case carries its investigation and decision")
        if payload.execution is not None:
            raise CoreValidationError("a DECIDED case carries no execution")
        kind = payload.decision.kind
        if kind is DecisionKind.APPROVE_REFUND:
            if payload.reversal_package is not None:
                raise CoreValidationError(
                    "a refund-approved case carries no reversal package"
                )
        elif kind is DecisionKind.APPROVE_REVERSAL:
            if payload.refund_package is not None:
                raise CoreValidationError(
                    "a reversal-approved case carries no refund package"
                )
        else:
            if payload.refund_package is not None or payload.reversal_package is not None:
                raise CoreValidationError("a rejected case carries no compiled packages")
        if payload.closed_at is not None or payload.close_reason is not None:
            raise CoreValidationError("a DECIDED case carries no close fields")
    elif state is CaseState.EXECUTED:
        if payload.investigation is None or payload.decision is None or payload.execution is None:
            raise CoreValidationError("an EXECUTED case carries investigation, decision and execution")
        kind = payload.decision.kind
        if kind is DecisionKind.APPROVE_REFUND:
            if payload.refund_package is None or payload.reversal_package is not None:
                raise CoreValidationError(
                    "an executed refund case must carry exactly its refund package"
                )
        elif kind is DecisionKind.APPROVE_REVERSAL:
            if payload.reversal_package is None or payload.refund_package is not None:
                raise CoreValidationError(
                    "an executed reversal case must carry exactly its reversal package"
                )
        else:
            raise CoreValidationError("a rejected case is never executed")
        if payload.closed_at is not None or payload.close_reason is not None:
            raise CoreValidationError("an EXECUTED case carries no close fields")
    else:  # CLOSED
        if payload.investigation is None or payload.decision is None:
            raise CoreValidationError("a CLOSED case carries its investigation and decision")
        if payload.closed_at is None or not payload.close_reason:
            raise CoreValidationError("a CLOSED case records its close instant and reason")
        kind = payload.decision.kind
        if kind is DecisionKind.REJECT:
            if payload.execution is not None or payload.refund_package or payload.reversal_package:
                raise CoreValidationError("a closed rejected case carries no execution or packages")
        else:
            if payload.execution is None:
                raise CoreValidationError("a closed approved case records its execution")


@dataclass(frozen=True, slots=True)
class Case:
    """Immutable durable recourse case (envelope + payload + seal)."""

    envelope: ObjectEnvelope
    payload: CasePayload
    integrity_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.payload, CasePayload):
            raise CoreValidationError("case payload must be a CasePayload")
        decode_composite(
            composite_to_dict(self.envelope, self.payload, self.integrity_hash),
            expected_object_type=CASE_OBJECT_TYPE,
            state_type=CaseState,
        )
        if self.envelope.object_id != self.payload.case_id:
            raise CoreValidationError("case object id must equal the case identifier")
        _validate_case_state(self.envelope, self.payload)
        verify_composite(
            self.envelope, self.payload, self.integrity_hash, self.envelope.object_id
        )

    @property
    def case_id(self) -> str:
        return self.payload.case_id

    @property
    def state(self) -> CaseState:
        return CaseState(self.envelope.state)

    @property
    def subject_ref(self) -> str:
        return self.payload.subject_ref

    @property
    def opened_by(self) -> str:
        return self.payload.opened_by

    @property
    def opened_at(self) -> str:
        return self.payload.opened_at

    @property
    def closed_at(self) -> str | None:
        return self.payload.closed_at

    @property
    def close_reason(self) -> str | None:
        return self.payload.close_reason

    @property
    def claims(self) -> tuple[Claim, ...]:
        return self.payload.claims

    @property
    def investigation(self) -> Investigation:
        return self.payload.investigation

    @property
    def decision(self) -> RecourseDecision:
        return self.payload.decision

    @property
    def refund_package(self) -> RefundPackage:
        return self.payload.refund_package

    @property
    def reversal_package(self) -> ReversalPackage:
        return self.payload.reversal_package

    @property
    def execution(self) -> ExecutionRecord:
        return self.payload.execution

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "Case":
        envelope, payload = decode_composite(
            value, expected_object_type=CASE_OBJECT_TYPE, state_type=CaseState
        )
        return cls(
            envelope=envelope,
            payload=CasePayload.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "Case":
        decoded = decode_composite_json(
            value, expected_object_type=CASE_OBJECT_TYPE, state_type=CaseState
        )
        return cls.from_dict(
            {"envelope": decoded[0].to_dict(), "payload": decoded[1], "integrity_hash": decoded[2]}
        )


def open_case(
    *,
    case_id: str,
    subject_ref: str,
    opened_by: str,
    opened_at: str,
    claims: tuple[Claim, ...],
    trust_registry: Any,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Case:
    """Open a recourse case (the Recourse ``Request`` verb) with typed claims."""
    require_active_principal(opened_by, trust_registry)
    for claim in claims:
        require_active_principal(claim.claimant, trust_registry)
    payload = CasePayload(
        case_id=case_id,
        subject_ref=subject_ref,
        opened_by=opened_by,
        opened_at=opened_at,
        claims=tuple(claims),
    )
    envelope = build_domain_envelope(
        object_id=case_id,
        object_type=CASE_OBJECT_TYPE,
        state=CaseState.OPEN.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def record_claim(
    case: Case,
    *,
    claim: Claim,
    trust_registry: Any,
    provenance: Provenance,
) -> Case:
    """Attach one more typed claim to an OPEN case."""
    if case.state is not CaseState.OPEN:
        raise CoreValidationError(
            f"case {case.case_id} cannot take new claims from state {case.state.value}"
        )
    require_active_principal(claim.claimant, trust_registry)
    if claim.claim_id in {existing.claim_id for existing in case.claims}:
        raise CoreValidationError(f"case {case.case_id} already carries claim {claim.claim_id}")
    if claim.subject_ref != case.payload.subject_ref:
        raise CoreValidationError(
            f"claim {claim.claim_id} targets {claim.subject_ref} but the case subject is "
            f"{case.payload.subject_ref}"
        )
    from dataclasses import replace

    payload = replace(case.payload, claims=case.payload.claims + (claim,))
    envelope = advance_envelope(case.envelope, state=CaseState.OPEN.value, provenance=provenance)
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def _require_resolvable_evidence(evidence_refs: tuple[str, ...], archive: EvidenceArchive) -> None:
    if not isinstance(archive, EvidenceArchive):
        raise CoreValidationError("recourse evidence validation requires an EvidenceArchive")
    for ref in evidence_refs:
        archive.get(ref)  # fail closed on unknown evidence


def investigate_case(
    case: Case,
    *,
    investigation: Investigation,
    evidence_archive: EvidenceArchive,
    provenance: Provenance,
    trust_registry: Any | None = None,
) -> Case:
    """OPEN -> INVESTIGATED: attach the investigation and its evidence."""
    if case.state is not CaseState.OPEN:
        raise CoreValidationError(
            f"case {case.case_id} cannot be investigated from state {case.state.value}"
        )
    if not isinstance(investigation, Investigation):
        raise CoreValidationError("investigate_case requires an Investigation")
    if trust_registry is not None:
        require_active_principal(investigation.investigator, trust_registry)
    _require_resolvable_evidence(investigation.evidence_refs, evidence_archive)
    missing = set(investigation.evidence_refs) - set(provenance.evidence_refs)
    if missing:
        raise CoreValidationError(
            "the investigation provenance must preserve the investigation evidence "
            f"references; missing {sorted(missing)}"
        )
    if parse_utc_timestamp("investigation.investigated_at", investigation.investigated_at) < parse_utc_timestamp(
        "case.opened_at", case.payload.opened_at
    ):
        raise CoreValidationError(
            "the investigation cannot precede the case opening"
        )
    from dataclasses import replace

    payload = replace(case.payload, investigation=investigation)
    envelope = advance_envelope(
        case.envelope, state=CaseState.INVESTIGATED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def decide_case(
    case: Case,
    *,
    decision: RecourseDecision,
    trust_registry: Any,
    evidence_archive: EvidenceArchive,
    provenance: Provenance,
) -> Case:
    """INVESTIGATED -> DECIDED: record the recourse decision with provenance."""
    if case.state is not CaseState.INVESTIGATED:
        raise CoreValidationError(
            f"case {case.case_id} cannot be decided from state {case.state.value}"
        )
    if not isinstance(decision, RecourseDecision):
        raise CoreValidationError("decide_case requires a RecourseDecision")
    if decision.kind is DecisionKind.APPROVE_REFUND and decision.amount is None:
        raise CoreValidationError(
            "an APPROVE_REFUND decision must state the exact approved amount"
        )
    require_active_principal(decision.decided_by, trust_registry)
    _require_resolvable_evidence(decision.evidence_refs, evidence_archive)
    if not provenance.evidence_refs:
        raise CoreValidationError(
            "deciding a recourse case is a material decision and must preserve provenance "
            "evidence references"
        )
    if parse_utc_timestamp("decision.decided_at", decision.decided_at) < parse_utc_timestamp(
        "investigation.investigated_at", case.payload.investigation.investigated_at
    ):
        raise CoreValidationError("the decision cannot precede the investigation")
    from dataclasses import replace

    payload = replace(case.payload, decision=decision)
    envelope = advance_envelope(
        case.envelope, state=CaseState.DECIDED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def compile_refund(case: Case, *, package: RefundPackage, provenance: Provenance) -> Case:
    """Compile the refund package for a refund-approved case (Recourse ``Compile``)."""
    if case.state is not CaseState.DECIDED:
        raise CoreValidationError(
            f"case {case.case_id} cannot compile a refund package from state {case.state.value}"
        )
    decision = case.payload.decision
    if decision.kind is not DecisionKind.APPROVE_REFUND:
        raise CoreValidationError(
            f"case {case.case_id} decision is {decision.kind.value}; only a refund-approved "
            "case compiles a refund package"
        )
    if case.payload.refund_package is not None:
        raise CoreValidationError(
            f"case {case.case_id} already carries a compiled refund package"
        )
    if not isinstance(package, RefundPackage):
        raise CoreValidationError("compile_refund requires a RefundPackage")
    if package.amount != decision.amount:
        raise CoreValidationError(
            "the compiled refund amount must equal the approved decision amount exactly"
        )
    from dataclasses import replace

    payload = replace(case.payload, refund_package=package)
    envelope = advance_envelope(
        case.envelope, state=CaseState.DECIDED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def compile_reversal(case: Case, *, package: ReversalPackage, provenance: Provenance) -> Case:
    """Compile the reversal package for a reversal-approved case (``Compile``)."""
    if case.state is not CaseState.DECIDED:
        raise CoreValidationError(
            f"case {case.case_id} cannot compile a reversal package from state {case.state.value}"
        )
    decision = case.payload.decision
    if decision.kind is not DecisionKind.APPROVE_REVERSAL:
        raise CoreValidationError(
            f"case {case.case_id} decision is {decision.kind.value}; only a reversal-approved "
            "case compiles a reversal package"
        )
    if case.payload.reversal_package is not None:
        raise CoreValidationError(
            f"case {case.case_id} already carries a compiled reversal package"
        )
    if not isinstance(package, ReversalPackage):
        raise CoreValidationError("compile_reversal requires a ReversalPackage")
    from dataclasses import replace

    payload = replace(case.payload, reversal_package=package)
    envelope = advance_envelope(
        case.envelope, state=CaseState.DECIDED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def _require_execution_provenance(provenance: Provenance) -> None:
    if not provenance.evidence_refs:
        raise CoreValidationError(
            "executing a recourse outcome is a material decision and must preserve provenance "
            "evidence references"
        )


def execute_refund(case: Case, *, execution: ExecutionRecord, provenance: Provenance) -> Case:
    """DECIDED -> EXECUTED: record the executed refund with its external reference."""
    if case.state is not CaseState.DECIDED:
        raise CoreValidationError(
            f"case {case.case_id} cannot execute a refund from state {case.state.value}"
        )
    decision = case.payload.decision
    if decision.kind is not DecisionKind.APPROVE_REFUND:
        raise CoreValidationError(
            f"case {case.case_id} decision is {decision.kind.value}; refunds are executed only "
            "for refund-approved cases"
        )
    if case.payload.refund_package is None:
        raise CoreValidationError(
            f"case {case.case_id} carries no compiled refund package to execute"
        )
    if not isinstance(execution, ExecutionRecord):
        raise CoreValidationError("execute_refund requires an ExecutionRecord")
    _require_execution_provenance(provenance)
    if parse_utc_timestamp("execution.executed_at", execution.executed_at) < parse_utc_timestamp(
        "decision.decided_at", decision.decided_at
    ):
        raise CoreValidationError("the execution cannot precede the decision")
    from dataclasses import replace

    payload = replace(case.payload, execution=execution)
    envelope = advance_envelope(
        case.envelope, state=CaseState.EXECUTED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def execute_reversal(case: Case, *, execution: ExecutionRecord, provenance: Provenance) -> Case:
    """DECIDED -> EXECUTED: record the executed reversal with its external reference."""
    if case.state is not CaseState.DECIDED:
        raise CoreValidationError(
            f"case {case.case_id} cannot execute a reversal from state {case.state.value}"
        )
    decision = case.payload.decision
    if decision.kind is not DecisionKind.APPROVE_REVERSAL:
        raise CoreValidationError(
            f"case {case.case_id} decision is {decision.kind.value}; reversals are executed only "
            "for reversal-approved cases"
        )
    if case.payload.reversal_package is None:
        raise CoreValidationError(
            f"case {case.case_id} carries no compiled reversal package to execute"
        )
    if not isinstance(execution, ExecutionRecord):
        raise CoreValidationError("execute_reversal requires an ExecutionRecord")
    _require_execution_provenance(provenance)
    if parse_utc_timestamp("execution.executed_at", execution.executed_at) < parse_utc_timestamp(
        "decision.decided_at", decision.decided_at
    ):
        raise CoreValidationError("the execution cannot precede the decision")
    from dataclasses import replace

    payload = replace(case.payload, execution=execution)
    envelope = advance_envelope(
        case.envelope, state=CaseState.EXECUTED.value, provenance=provenance
    )
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))


def close_case(
    case: Case,
    *,
    closed_at: str,
    close_reason: str,
    provenance: Provenance,
) -> Case:
    """EXECUTED (or DECIDED with a REJECT decision) -> CLOSED (terminal)."""
    if case.state is CaseState.EXECUTED:
        pass
    elif case.state is CaseState.DECIDED and case.payload.decision.kind is DecisionKind.REJECT:
        pass
    else:
        raise CoreValidationError(
            f"case {case.case_id} cannot be closed from state {case.state.value}"
        )
    require_utc_timestamp("closed_at", closed_at)
    require_text("close_reason", close_reason)
    decision = case.payload.decision
    if parse_utc_timestamp("closed_at", closed_at) < parse_utc_timestamp(
        "decision.decided_at", decision.decided_at
    ):
        raise CoreValidationError("the case cannot be closed before its decision")
    from dataclasses import replace

    payload = replace(case.payload, closed_at=closed_at, close_reason=close_reason)
    envelope = advance_envelope(case.envelope, state=CaseState.CLOSED.value, provenance=provenance)
    return Case(envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload))
