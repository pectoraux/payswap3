from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .envelope import CoreValidationError, _normalize_pairs, _require_text


class RelationshipType(StrEnum):
    OWNS = "OWNS"
    CONTROLS = "CONTROLS"
    CUSTODIES = "CUSTODIES"
    AUTHORIZES = "AUTHORIZES"
    ADMINISTERS = "ADMINISTERS"
    ISSUES = "ISSUES"
    ATTESTS = "ATTESTS"
    SERVICES = "SERVICES"
    OWES = "OWES"
    IS_ENTITLED_TO = "IS_ENTITLED_TO"
    OBSERVES = "OBSERVES"
    DEPENDS_ON = "DEPENDS_ON"


@dataclass(frozen=True, slots=True)
class Relationship:
    relationship_type: RelationshipType
    subject_id: str
    object_id: str
    attributes: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.relationship_type, RelationshipType):
            raise CoreValidationError("relationship_type must use the closed vocabulary")
        _require_text("subject_id", self.subject_id)
        _require_text("object_id", self.object_id)
        if not isinstance(self.attributes, tuple):
            raise CoreValidationError("attributes must be a tuple")
        for key, _ in self.attributes:
            _require_text("relationship attribute key", key)

    @classmethod
    def build(
        cls,
        relationship_type: RelationshipType,
        subject_id: str,
        object_id: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> "Relationship":
        return cls(
            relationship_type=relationship_type,
            subject_id=subject_id,
            object_id=object_id,
            attributes=_normalize_pairs("relationship.attributes", attributes or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_type": self.relationship_type.value,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
            "attributes": {key: value for key, value in self.attributes},
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Relationship":
        if not isinstance(value, Mapping):
            raise CoreValidationError("relationship must be an object")
        if set(value) != {"relationship_type", "subject_id", "object_id", "attributes"}:
            raise CoreValidationError("relationship fields are not canonical")
        try:
            relationship_type = RelationshipType(value["relationship_type"])
        except ValueError as exc:
            raise CoreValidationError("unknown relationship type") from exc
        attrs = value["attributes"]
        return cls.build(relationship_type, value["subject_id"], value["object_id"], attrs)
