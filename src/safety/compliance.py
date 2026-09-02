"""Compliance assessments and the constraint precedence engine.

This module implements the frozen Compliance command family
``RequestAssessment/RecordResult/InvalidateResult`` as an explicit state
machine (REQUESTED -> RECORDED -> INVALIDATED, terminal INVALIDATED)
over the canonical :class:`ComplianceAssessment` object.

Compliance constraints are versioned, typed records carrying their own
evidence references and effective half-open windows. Constraint
precedence is the frozen ordered vocabulary
``LEGAL > REGULATORY > CONTRACTUAL > POLICY`` (constitution hard
invariant 10): within one requirement the highest-precedence constraint
is authoritative and lower-precedence constraints are recorded as
overridden with explicit override provenance; ambiguity (two constraints
on the same requirement at the same precedence level) fails closed.

The resolved verdict is binding: a BLOCKED compliance result is a hard
input for routing and execution decisions made in other domains —
compliance cannot be bypassed through routing. This module is a
control/decision plane: it records and resolves verdicts, never executes
anything and never mutates financial state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .contracts import (
    COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
    COMPLIANCE_TERMINAL_STATES,
    CONSTRAINT_PRECEDENCE_ORDER,
    CONSTRAINT_PRECEDENCE_RANK,
    ComplianceAssessmentState,
    ComplianceVerdict,
    ConstraintOutcome,
    ConstraintPrecedence,
)
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_int,
    require_provenance_evidence,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
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

# -- constraints: versioned, evidenced, effective-time-bounded --------------------


_CONSTRAINT_FIELDS = frozenset(
    {
        "constraint_id",
        "requirement",
        "precedence",
        "outcome",
        "version",
        "effective_from",
        "effective_until",
        "evidence_refs",
    }
)


@dataclass(frozen=True, slots=True)
class ComplianceConstraint:
    """One versioned compliance constraint check with explicit evidence.

    A constraint declares the outcome of one check performed under
    declared evidence (opaque references owned by the evidence domain):
    the safety domain owns the deterministic resolution of constraint
    sets, not the screening itself. The precedence and outcome
    vocabularies are closed; the effective window is half-open.
    """

    constraint_id: str
    requirement: str
    precedence: ConstraintPrecedence
    outcome: ConstraintOutcome
    version: int
    effective_from: str
    effective_until: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier("constraint constraint_id", self.constraint_id)
        require_identifier("constraint requirement", self.requirement)
        if not isinstance(self.precedence, ConstraintPrecedence):
            raise CoreValidationError(
                "constraint precedence must use the closed ConstraintPrecedence "
                f"vocabulary ordered {CONSTRAINT_PRECEDENCE_ORDER}"
            )
        if not isinstance(self.outcome, ConstraintOutcome):
            raise CoreValidationError(
                "constraint outcome must use the closed ConstraintOutcome vocabulary"
            )
        require_int("constraint version", self.version, minimum=1)
        require_utc_timestamp("constraint effective_from", self.effective_from)
        require_utc_timestamp("constraint effective_until", self.effective_until)
        require_utc_timestamp_order(
            "constraint effective_from", self.effective_from,
            "constraint effective_until", self.effective_until,
        )
        if not isinstance(self.evidence_refs, tuple):
            raise CoreValidationError("constraint evidence_refs must be a tuple")
        if not self.evidence_refs:
            raise CoreValidationError(
                "constraint evidence_refs must not be empty; every constraint "
                "check is evidence-backed"
            )
        for ref in self.evidence_refs:
            require_identifier("constraint evidence_ref", ref)

    @classmethod
    def build(
        cls,
        *,
        constraint_id: str,
        requirement: str,
        precedence: Any,
        outcome: Any,
        version: int,
        effective_from: str,
        effective_until: str,
        evidence_refs: Iterable[str],
    ) -> "ComplianceConstraint":
        if not isinstance(evidence_refs, (list, tuple)):
            raise CoreValidationError("constraint evidence_refs must be a sequence")
        return cls(
            constraint_id=constraint_id,
            requirement=requirement,
            precedence=parse_enum("constraint precedence", ConstraintPrecedence, precedence),
            outcome=parse_enum("constraint outcome", ConstraintOutcome, outcome),
            version=version,
            effective_from=effective_from,
            effective_until=effective_until,
            evidence_refs=tuple(evidence_refs),
        )

    def effective_at(self, as_of: str) -> bool:
        """Half-open effective-time membership: ``[from, until)``."""
        return (
            parse_utc_timestamp("constraint effective_from", self.effective_from)
            <= parse_utc_timestamp("constraint as_of", as_of)
            < parse_utc_timestamp("constraint effective_until", self.effective_until)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "requirement": self.requirement,
            "precedence": self.precedence.value,
            "outcome": self.outcome.value,
            "version": self.version,
            "effective_from": self.effective_from,
            "effective_until": self.effective_until,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComplianceConstraint":
        strict_fields("constraint", value, _CONSTRAINT_FIELDS)
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError(
                "constraint evidence_refs must deserialize from an array"
            )
        return cls(
            constraint_id=value["constraint_id"],
            requirement=value["requirement"],
            precedence=parse_enum(
                "constraint precedence", ConstraintPrecedence, value["precedence"]
            ),
            outcome=parse_enum(
                "constraint outcome", ConstraintOutcome, value["outcome"]
            ),
            version=value["version"],
            effective_from=value["effective_from"],
            effective_until=value["effective_until"],
            evidence_refs=tuple(refs),
        )


# -- resolution records (explicit override provenance) -----------------------------


_OVERRIDE_FIELDS = frozenset({"constraint_id", "precedence", "outcome", "overridden_by"})


@dataclass(frozen=True, slots=True)
class OverrideRecord:
    """Explicit provenance that one constraint was overridden by another."""

    constraint_id: str
    precedence: ConstraintPrecedence
    outcome: ConstraintOutcome
    overridden_by: str

    def __post_init__(self) -> None:
        require_identifier("override constraint_id", self.constraint_id)
        if not isinstance(self.precedence, ConstraintPrecedence):
            raise CoreValidationError(
                "override precedence must use the closed ConstraintPrecedence vocabulary"
            )
        if not isinstance(self.outcome, ConstraintOutcome):
            raise CoreValidationError(
                "override outcome must use the closed ConstraintOutcome vocabulary"
            )
        require_identifier("override overridden_by", self.overridden_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "precedence": self.precedence.value,
            "outcome": self.outcome.value,
            "overridden_by": self.overridden_by,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OverrideRecord":
        strict_fields("override record", value, _OVERRIDE_FIELDS)
        return cls(
            constraint_id=value["constraint_id"],
            precedence=parse_enum(
                "override precedence", ConstraintPrecedence, value["precedence"]
            ),
            outcome=parse_enum("override outcome", ConstraintOutcome, value["outcome"]),
            overridden_by=value["overridden_by"],
        )


_RESOLUTION_FIELDS = frozenset(
    {
        "requirement",
        "authoritative_constraint_id",
        "authoritative_precedence",
        "authoritative_outcome",
        "overridden",
    }
)


@dataclass(frozen=True, slots=True)
class ResolutionRecord:
    """Deterministic per-requirement resolution with override provenance."""

    requirement: str
    authoritative_constraint_id: str
    authoritative_precedence: ConstraintPrecedence
    authoritative_outcome: ConstraintOutcome
    overridden: tuple[OverrideRecord, ...]

    def __post_init__(self) -> None:
        require_identifier("resolution requirement", self.requirement)
        require_identifier(
            "resolution authoritative_constraint_id", self.authoritative_constraint_id
        )
        if not isinstance(self.authoritative_precedence, ConstraintPrecedence):
            raise CoreValidationError(
                "resolution precedence must use the closed ConstraintPrecedence vocabulary"
            )
        if not isinstance(self.authoritative_outcome, ConstraintOutcome):
            raise CoreValidationError(
                "resolution outcome must use the closed ConstraintOutcome vocabulary"
            )
        if not isinstance(self.overridden, tuple):
            raise CoreValidationError("resolution overridden must be a tuple")
        for record in self.overridden:
            if not isinstance(record, OverrideRecord):
                raise CoreValidationError(
                    "resolution overridden entries must be OverrideRecord values"
                )
        ids = [record.constraint_id for record in self.overridden]
        if ids != sorted(ids):
            raise CoreValidationError(
                "resolution overridden records must be sorted by constraint_id"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement": self.requirement,
            "authoritative_constraint_id": self.authoritative_constraint_id,
            "authoritative_precedence": self.authoritative_precedence.value,
            "authoritative_outcome": self.authoritative_outcome.value,
            "overridden": [record.to_dict() for record in self.overridden],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResolutionRecord":
        strict_fields("resolution record", value, _RESOLUTION_FIELDS)
        overridden = value["overridden"]
        if not isinstance(overridden, list):
            raise CoreValidationError(
                "resolution overridden must deserialize from an array"
            )
        return cls(
            requirement=value["requirement"],
            authoritative_constraint_id=value["authoritative_constraint_id"],
            authoritative_precedence=parse_enum(
                "resolution precedence", ConstraintPrecedence,
                value["authoritative_precedence"],
            ),
            authoritative_outcome=parse_enum(
                "resolution outcome", ConstraintOutcome,
                value["authoritative_outcome"],
            ),
            overridden=tuple(OverrideRecord.from_dict(item) for item in overridden),
        )


_RESULT_FIELDS = frozenset(
    {
        "verdict",
        "binding_constraint_id",
        "resolution",
        "recorded_as_of",
    }
)


@dataclass(frozen=True, slots=True)
class ComplianceResult:
    """Immutable resolved compliance result recorded by ``RecordResult``."""

    verdict: ComplianceVerdict
    binding_constraint_id: str | None
    resolution: tuple[ResolutionRecord, ...]
    recorded_as_of: str

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, ComplianceVerdict):
            raise CoreValidationError(
                "compliance verdict must use the closed ComplianceVerdict vocabulary"
            )
        if self.verdict is ComplianceVerdict.BLOCKED:
            require_identifier(
                "compliance binding_constraint_id", self.binding_constraint_id
            )
        elif self.binding_constraint_id is not None:
            raise CoreValidationError(
                "a SATISFIED compliance result has no binding constraint"
            )
        if not isinstance(self.resolution, tuple) or not self.resolution:
            raise CoreValidationError(
                "compliance resolution must be a non-empty tuple of ResolutionRecord"
            )
        requirements = [record.requirement for record in self.resolution]
        if requirements != sorted(requirements):
            raise CoreValidationError(
                "compliance resolution must be sorted by requirement"
            )
        if len(set(requirements)) != len(requirements):
            raise CoreValidationError(
                "compliance resolution must map each requirement at most once"
            )
        for record in self.resolution:
            if not isinstance(record, ResolutionRecord):
                raise CoreValidationError(
                    "compliance resolution entries must be ResolutionRecord values"
                )
        require_utc_timestamp("compliance recorded_as_of", self.recorded_as_of)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "binding_constraint_id": self.binding_constraint_id,
            "resolution": [record.to_dict() for record in self.resolution],
            "recorded_as_of": self.recorded_as_of,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComplianceResult":
        strict_fields("compliance result", value, _RESULT_FIELDS)
        resolution = value["resolution"]
        if not isinstance(resolution, list):
            raise CoreValidationError(
                "compliance resolution must deserialize from an array"
            )
        return cls(
            verdict=parse_enum("compliance verdict", ComplianceVerdict, value["verdict"]),
            binding_constraint_id=value["binding_constraint_id"],
            resolution=tuple(ResolutionRecord.from_dict(item) for item in resolution),
            recorded_as_of=value["recorded_as_of"],
        )


_INVALIDATION_FIELDS = frozenset({"reason", "invalidated_as_of"})


@dataclass(frozen=True, slots=True)
class InvalidationRecord:
    """Append-only correction provenance for the ``InvalidateResult`` command."""

    reason: str
    invalidated_as_of: str

    def __post_init__(self) -> None:
        require_text("invalidation reason", self.reason)
        require_utc_timestamp("invalidation invalidated_as_of", self.invalidated_as_of)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "invalidated_as_of": self.invalidated_as_of,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InvalidationRecord":
        strict_fields("invalidation record", value, _INVALIDATION_FIELDS)
        return cls(
            reason=value["reason"],
            invalidated_as_of=value["invalidated_as_of"],
        )


# -- the constraint precedence engine -----------------------------------------------


def _validate_constraint_set(constraints: tuple[ComplianceConstraint, ...]) -> None:
    if not constraints:
        raise CoreValidationError(
            "compliance assessment requires at least one constraint"
        )
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, ConstraintPrecedence]] = set()
    for constraint in constraints:
        if not isinstance(constraint, ComplianceConstraint):
            raise CoreValidationError(
                "compliance constraints must be ComplianceConstraint records"
            )
        if constraint.constraint_id in seen_ids:
            raise CoreValidationError(
                f"duplicate constraint id {constraint.constraint_id}"
            )
        seen_ids.add(constraint.constraint_id)
        pair = (constraint.requirement, constraint.precedence)
        if pair in seen_pairs:
            raise CoreValidationError(
                "ambiguous constraint precedence: requirement "
                f"{constraint.requirement!r} is governed by more than one "
                f"{constraint.precedence.value} constraint "
                f"({pair[0]}); neither outranks the other, so the set fails closed"
            )
        seen_pairs.add(pair)


def resolve_constraints(
    constraints: Iterable[ComplianceConstraint],
    *,
    recorded_as_of: str,
) -> ComplianceResult:
    """Resolve a constraint set deterministically under the precedence engine.

    Resolution rule (documented, deterministic):

    1. Constraints are grouped by ``requirement``; within a requirement
       the highest-precedence constraint is AUTHORITATIVE and every
       strictly lower-precedence constraint is recorded as overridden
       with explicit override provenance (``overridden_by``).
    2. Two constraints on the same requirement at the same precedence
       level are AMBIGUOUS: neither outranks the other, so resolution
       fails closed (CoreValidationError).
    3. The final verdict is BLOCKED iff any authoritative constraint is
       VIOLATED (a violated authoritative constraint can never be
       overridden by a lower-precedence satisfied constraint); the
       binding constraint is the violated authoritative constraint with
       the highest precedence, ties broken by the smallest constraint id.
    4. Otherwise the verdict is SATISFIED.

    The resolution is constraint-order independent: groups and records
    are emitted in canonical (requirement, constraint id) order.
    """
    require_utc_timestamp("compliance recorded_as_of", recorded_as_of)
    if not isinstance(constraints, (list, tuple)):
        raise CoreValidationError("constraints must be provided as a sequence")
    ordered = tuple(sorted(constraints, key=lambda c: c.constraint_id))
    _validate_constraint_set(ordered)
    groups: dict[str, list[ComplianceConstraint]] = {}
    for constraint in ordered:
        groups.setdefault(constraint.requirement, []).append(constraint)
    resolution: list[ResolutionRecord] = []
    violated: list[ComplianceConstraint] = []
    for requirement in sorted(groups):
        members = sorted(
            groups[requirement],
            key=lambda c: (-CONSTRAINT_PRECEDENCE_RANK[c.precedence], c.constraint_id),
        )
        authoritative = members[0]
        overridden = tuple(
            OverrideRecord(
                constraint_id=member.constraint_id,
                precedence=member.precedence,
                outcome=member.outcome,
                overridden_by=authoritative.constraint_id,
            )
            for member in members[1:]
        )
        resolution.append(
            ResolutionRecord(
                requirement=requirement,
                authoritative_constraint_id=authoritative.constraint_id,
                authoritative_precedence=authoritative.precedence,
                authoritative_outcome=authoritative.outcome,
                overridden=overridden,
            )
        )
        if authoritative.outcome is ConstraintOutcome.VIOLATED:
            violated.append(authoritative)
    if violated:
        binding = min(
            violated,
            key=lambda c: (
                -CONSTRAINT_PRECEDENCE_RANK[c.precedence], c.constraint_id,
            ),
        )
        verdict = ComplianceVerdict.BLOCKED
        binding_id: str | None = binding.constraint_id
    else:
        verdict = ComplianceVerdict.SATISFIED
        binding_id = None
    return ComplianceResult(
        verdict=verdict,
        binding_constraint_id=binding_id,
        resolution=tuple(resolution),
        recorded_as_of=recorded_as_of,
    )


# -- the compliance assessment lifecycle ---------------------------------------------


_ASSESSMENT_SPEC_FIELDS = frozenset(
    {
        "subject_id",
        "jurisdiction",
        "as_of",
        "constraints",
        "constraint_set_digest",
        "result",
        "invalidation",
    }
)


@dataclass(frozen=True, slots=True)
class ComplianceAssessmentSpec:
    """Immutable compliance assessment payload for one lifecycle version.

    State/payload consistency: a REQUESTED version carries no result and
    no invalidation; a RECORDED version carries the result; an
    INVALIDATED version carries the invalidation record and retains the
    result if one had been recorded.
    """

    subject_id: str
    jurisdiction: str
    as_of: str
    constraints: tuple[ComplianceConstraint, ...]
    constraint_set_digest: str
    result: ComplianceResult | None = None
    invalidation: InvalidationRecord | None = None

    def __post_init__(self) -> None:
        require_identifier("compliance subject_id", self.subject_id)
        require_identifier("compliance jurisdiction", self.jurisdiction)
        require_utc_timestamp("compliance as_of", self.as_of)
        if not isinstance(self.constraints, tuple) or not self.constraints:
            raise CoreValidationError(
                "compliance constraints must be a non-empty tuple"
            )
        for constraint in self.constraints:
            if not isinstance(constraint, ComplianceConstraint):
                raise CoreValidationError(
                    "compliance constraints must be ComplianceConstraint records"
                )
        ids = [constraint.constraint_id for constraint in self.constraints]
        if ids != sorted(ids):
            raise CoreValidationError(
                "compliance constraints must be canonically sorted by constraint_id"
            )
        _validate_constraint_set(self.constraints)
        require_digest("compliance constraint_set_digest", self.constraint_set_digest)
        if self.result is not None and not isinstance(self.result, ComplianceResult):
            raise CoreValidationError(
                "compliance result must be a ComplianceResult"
            )
        if self.invalidation is not None and not isinstance(
            self.invalidation, InvalidationRecord
        ):
            raise CoreValidationError(
                "compliance invalidation must be an InvalidationRecord"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "jurisdiction": self.jurisdiction,
            "as_of": self.as_of,
            "constraints": [constraint.to_dict() for constraint in self.constraints],
            "constraint_set_digest": self.constraint_set_digest,
            "result": None if self.result is None else self.result.to_dict(),
            "invalidation": (
                None if self.invalidation is None else self.invalidation.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComplianceAssessmentSpec":
        strict_fields("compliance assessment", value, _ASSESSMENT_SPEC_FIELDS)
        constraints = value["constraints"]
        if not isinstance(constraints, list):
            raise CoreValidationError(
                "compliance constraints must deserialize from an array"
            )
        result = value["result"]
        invalidation = value["invalidation"]
        return cls(
            subject_id=value["subject_id"],
            jurisdiction=value["jurisdiction"],
            as_of=value["as_of"],
            constraints=tuple(
                ComplianceConstraint.from_dict(item) for item in constraints
            ),
            constraint_set_digest=value["constraint_set_digest"],
            result=None if result is None else ComplianceResult.from_dict(result),
            invalidation=(
                None if invalidation is None
                else InvalidationRecord.from_dict(invalidation)
            ),
        )


_COMPLIANCE_COMMANDS: dict[
    str, dict[ComplianceAssessmentState, ComplianceAssessmentState]
] = {
    "record": {ComplianceAssessmentState.REQUESTED: ComplianceAssessmentState.RECORDED},
    "invalidate": {
        ComplianceAssessmentState.REQUESTED: ComplianceAssessmentState.INVALIDATED,
        ComplianceAssessmentState.RECORDED: ComplianceAssessmentState.INVALIDATED,
    },
}


@dataclass(frozen=True, slots=True)
class ComplianceAssessment:
    """Durable compliance assessment (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ComplianceAssessmentSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = COMPLIANCE_ASSESSMENT_OBJECT_TYPE
    STATE_TYPE = ComplianceAssessmentState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                "compliance assessment envelope must be an ObjectEnvelope"
            )
        if not isinstance(self.spec, ComplianceAssessmentSpec):
            raise CoreValidationError(
                "compliance assessment spec must be a ComplianceAssessmentSpec"
            )
        self.envelope.verify_integrity()
        if self.envelope.object_type != COMPLIANCE_ASSESSMENT_OBJECT_TYPE:
            raise CoreValidationError(
                "compliance assessment object_type must be "
                f"{COMPLIANCE_ASSESSMENT_OBJECT_TYPE!r}"
            )
        state = parse_enum(
            "compliance assessment state", ComplianceAssessmentState,
            self.envelope.state,
        )
        _check_compliance_consistency(state, self.spec)
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ComplianceAssessmentState:
        return ComplianceAssessmentState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComplianceAssessment":
        envelope, payload = decode_composite(
            value,
            expected_object_type=COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
            state_type=ComplianceAssessmentState,
        )
        spec = ComplianceAssessmentSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "ComplianceAssessment":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
            state_type=ComplianceAssessmentState,
        )
        spec = ComplianceAssessmentSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: ComplianceAssessmentState,
        spec: ComplianceAssessmentSpec,
        *,
        provenance,
    ) -> "ComplianceAssessment":
        envelope = advance_envelope(
            self.envelope,
            state=new_state.value,
            provenance=provenance,
            causation_id=self.object_id,
        )
        return ComplianceAssessment(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )


def _check_compliance_consistency(
    state: ComplianceAssessmentState, spec: ComplianceAssessmentSpec
) -> None:
    if state is ComplianceAssessmentState.REQUESTED:
        if spec.result is not None:
            raise CoreValidationError(
                "a REQUESTED compliance assessment cannot carry a result"
            )
        if spec.invalidation is not None:
            raise CoreValidationError(
                "a REQUESTED compliance assessment cannot carry an invalidation"
            )
    elif state is ComplianceAssessmentState.RECORDED:
        if spec.result is None:
            raise CoreValidationError(
                "a RECORDED compliance assessment must carry its result"
            )
        if spec.invalidation is not None:
            raise CoreValidationError(
                "a RECORDED compliance assessment cannot carry an invalidation"
            )
    elif state is ComplianceAssessmentState.INVALIDATED:
        if spec.invalidation is None:
            raise CoreValidationError(
                "an INVALIDATED compliance assessment must carry its invalidation"
            )
    else:  # pragma: no cover - closed vocabulary
        raise CoreValidationError(
            f"unknown compliance assessment state: {state.value}"
        )


def request_compliance_assessment(
    *,
    assessment_id: str,
    subject_id: str,
    jurisdiction: str,
    constraints: Iterable[ComplianceConstraint],
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance,
    correlation_id: str | None = None,
) -> ComplianceAssessment:
    """Request a compliance assessment (the ``RequestAssessment`` command).

    The constraint set is validated fail-closed (unique ids, effective at
    the request instant, no ambiguous same-requirement/same-precedence
    pairs) and canonicalized (sorted by constraint id) so requests are
    constraint-order independent.
    """
    require_provenance_evidence("compliance request", provenance)
    require_utc_timestamp("compliance request as_of", as_of)
    if not isinstance(constraints, (list, tuple)):
        raise CoreValidationError("constraints must be provided as a sequence")
    if not constraints:
        raise CoreValidationError(
            "compliance assessment requires at least one constraint"
        )
    for constraint in constraints:
        if not isinstance(constraint, ComplianceConstraint):
            raise CoreValidationError(
                "compliance constraints must be ComplianceConstraint records"
            )
        if not constraint.effective_at(as_of):
            raise CoreValidationError(
                f"constraint {constraint.constraint_id} is not effective at the "
                f"request instant {as_of} (effective window "
                f"[{constraint.effective_from}, {constraint.effective_until}))"
            )
    canonical = tuple(sorted(constraints, key=lambda c: c.constraint_id))
    _validate_constraint_set(canonical)
    constraint_set_digest = canonical_sha256(
        {
            "constraints": [constraint.to_dict() for constraint in canonical],
            "subject_id": subject_id,
            "jurisdiction": jurisdiction,
            "as_of": as_of,
        }
    )
    spec = ComplianceAssessmentSpec(
        subject_id=subject_id,
        jurisdiction=jurisdiction,
        as_of=as_of,
        constraints=canonical,
        constraint_set_digest=constraint_set_digest,
    )
    _check_compliance_consistency(ComplianceAssessmentState.REQUESTED, spec)
    envelope = build_domain_envelope(
        object_id=require_identifier(
            "compliance assessment assessment_id", assessment_id
        ),
        object_type=COMPLIANCE_ASSESSMENT_OBJECT_TYPE,
        state=ComplianceAssessmentState.REQUESTED.value,
        environment_id=require_identifier(
            "compliance assessment environment_id", environment_id
        ),
        domain_id=require_identifier("compliance assessment domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return ComplianceAssessment(
        envelope=envelope, spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


def record_compliance_result(
    assessment: ComplianceAssessment,
    *,
    as_of: str,
    provenance,
) -> ComplianceAssessment:
    """Record the resolved result (the ``RecordResult`` command).

    The precedence engine resolves the pinned constraint set
    deterministically; the recording instant cannot precede the request
    instant. The recorded verdict is binding for other domains.
    """
    if not isinstance(assessment, ComplianceAssessment):
        raise CoreValidationError("record_compliance_result requires a ComplianceAssessment")
    require_provenance_evidence("compliance record", provenance)
    require_utc_timestamp("compliance record as_of", as_of)
    current = assessment.state
    transitions = _COMPLIANCE_COMMANDS["record"]
    if current not in transitions:
        raise CoreValidationError(
            f"compliance record command is not allowed from state {current.value}"
        )
    if parse_utc_timestamp("compliance record as_of", as_of) < parse_utc_timestamp(
        "compliance request as_of", assessment.spec.as_of
    ):
        raise CoreValidationError(
            "compliance result cannot be recorded before the request instant"
        )
    resolved = resolve_constraints(
        assessment.spec.constraints, recorded_as_of=as_of
    )
    spec = replace(assessment.spec, result=resolved)
    _check_compliance_consistency(ComplianceAssessmentState.RECORDED, spec)
    return assessment._advance(
        ComplianceAssessmentState.RECORDED, spec, provenance=provenance
    )


def invalidate_compliance_result(
    assessment: ComplianceAssessment,
    *,
    as_of: str,
    reason: str,
    provenance,
) -> ComplianceAssessment:
    """Invalidate the assessment (the ``InvalidateResult`` command, terminal).

    Invalidation is an append-only correction: the new version records
    the invalidation provenance and retains the recorded result, if any.
    """
    if not isinstance(assessment, ComplianceAssessment):
        raise CoreValidationError(
            "invalidate_compliance_result requires a ComplianceAssessment"
        )
    require_provenance_evidence("compliance invalidation", provenance)
    require_utc_timestamp("compliance invalidation as_of", as_of)
    require_text("compliance invalidation reason", reason)
    current = assessment.state
    transitions = _COMPLIANCE_COMMANDS["invalidate"]
    if current not in transitions:
        raise CoreValidationError(
            f"compliance invalidate command is not allowed from state {current.value}"
        )
    if parse_utc_timestamp("compliance invalidation as_of", as_of) < parse_utc_timestamp(
        "compliance request as_of", assessment.spec.as_of
    ):
        raise CoreValidationError(
            "compliance invalidation cannot precede the request instant"
        )
    if current is ComplianceAssessmentState.RECORDED:
        if parse_utc_timestamp(
            "compliance invalidation as_of", as_of
        ) < parse_utc_timestamp(
            "compliance recorded_as_of", assessment.spec.result.recorded_as_of
        ):
            raise CoreValidationError(
                "compliance invalidation cannot precede the recorded result"
            )
    invalidation = InvalidationRecord(reason=reason, invalidated_as_of=as_of)
    spec = replace(assessment.spec, invalidation=invalidation)
    _check_compliance_consistency(ComplianceAssessmentState.INVALIDATED, spec)
    return assessment._advance(
        ComplianceAssessmentState.INVALIDATED, spec, provenance=provenance
    )
