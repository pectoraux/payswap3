"""Conditional-commit conditions: the explicit condition vocabulary.

A protocol reservation may declare conditions that must be explicitly
satisfied before the reservation can be conditionally committed. Conditions
are declarative records referencing other domains' objects by opaque
identifiers only — the reservation domain never verifies, mutates or
re-implements the referenced domains' semantics; it only requires explicit
satisfaction evidence at the commit instant and fails closed otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError

from ._validation import (
    parse_enum,
    require_identifier,
    require_text,
    require_utc_timestamp,
    require_unique_identifiers,
    strict_fields,
)

_CONDITION_FIELDS = frozenset({"condition_key", "kind", "ref"})
_EVIDENCE_FIELDS = frozenset({"satisfied_keys", "evidence_refs", "decided_at"})


class ConditionKind(StrEnum):
    """Closed vocabulary of conditional-commit condition kinds.

    The kind records WHAT class of external fact the condition represents;
    the satisfaction decision itself is always explicit caller-supplied
    evidence, never an inference made by this domain.
    """

    ENCUMBRANCE = "ENCUMBRANCE"
    FUNDING = "FUNDING"
    CAPABILITY = "CAPABILITY"
    QUOTE = "QUOTE"
    EVIDENCE = "EVIDENCE"


@dataclass(frozen=True, slots=True)
class ConditionSpec:
    """One declared condition: unique key, closed kind, opaque reference."""

    condition_key: str
    kind: ConditionKind
    ref: str

    def __post_init__(self) -> None:
        require_identifier("condition.condition_key", self.condition_key)
        if not isinstance(self.kind, ConditionKind):
            raise CoreValidationError(
                "condition.kind must be a ConditionKind, got "
                f"{type(self.kind).__name__}"
            )
        require_identifier("condition.ref", self.ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "condition_key": self.condition_key,
            "kind": self.kind.value,
            "ref": self.ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConditionSpec":
        strict_fields("condition", value, _CONDITION_FIELDS)
        return cls(
            condition_key=value["condition_key"],
            kind=parse_enum("condition.kind", ConditionKind, value["kind"]),
            ref=value["ref"],
        )


@dataclass(frozen=True, slots=True)
class CommitEvidence:
    """The durable record of a conditional-commit satisfaction decision."""

    satisfied_keys: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    decided_at: str

    def __post_init__(self) -> None:
        for key in self.satisfied_keys:
            require_identifier("commit_evidence.satisfied_keys entry", key)
        if len(set(self.satisfied_keys)) != len(self.satisfied_keys):
            raise CoreValidationError(
                "commit_evidence.satisfied_keys contains duplicate keys"
            )
        for ref in self.evidence_refs:
            require_text("commit_evidence.evidence_refs entry", ref)
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise CoreValidationError(
                "commit_evidence.evidence_refs contains duplicate references"
            )
        require_utc_timestamp("commit_evidence.decided_at", self.decided_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "satisfied_keys": list(self.satisfied_keys),
            "evidence_refs": list(self.evidence_refs),
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CommitEvidence":
        strict_fields("commit evidence", value, _EVIDENCE_FIELDS)
        satisfied = value["satisfied_keys"]
        refs = value["evidence_refs"]
        if not isinstance(satisfied, list) or not isinstance(refs, list):
            raise CoreValidationError(
                "commit evidence keys and references must deserialize from lists"
            )
        return cls(
            satisfied_keys=tuple(satisfied),
            evidence_refs=tuple(refs),
            decided_at=value["decided_at"],
        )


@dataclass(frozen=True, slots=True)
class ConditionEvaluation:
    """Deterministic outcome of an explicit satisfaction check."""

    all_satisfied: bool
    missing: tuple[str, ...]
    unknown: tuple[str, ...]


def evaluate_condition_satisfaction(
    declared: Iterable[ConditionSpec],
    satisfied: Iterable[str],
) -> ConditionEvaluation:
    """Evaluate an explicit satisfaction set against the declared conditions.

    The rule is fail-closed and total:

    - every declared condition key must appear in ``satisfied`` (otherwise it
      is reported as ``missing``);
    - every satisfied key must be declared (otherwise it is ``unknown`` — a
      caller asserting satisfaction of an undeclared condition is a protocol
      violation, not a success);
    - duplicate satisfied keys are rejected outright;
    - ``all_satisfied`` holds only when both lists are empty.
    """
    declared_specs = tuple(declared)
    for spec in declared_specs:
        if not isinstance(spec, ConditionSpec):
            raise CoreValidationError(
                f"declared conditions must be ConditionSpec values, got {type(spec).__name__}"
            )
    declared_keys = {spec.condition_key for spec in declared_specs}
    if len(declared_keys) != len(declared_specs):
        raise CoreValidationError("declared conditions contain duplicate keys")
    satisfied_keys = require_unique_identifiers(
        "satisfied conditions", tuple(satisfied)
    )
    missing = tuple(sorted(declared_keys - set(satisfied_keys)))
    unknown = tuple(sorted(set(satisfied_keys) - declared_keys))
    return ConditionEvaluation(
        all_satisfied=not missing and not unknown,
        missing=missing,
        unknown=unknown,
    )
