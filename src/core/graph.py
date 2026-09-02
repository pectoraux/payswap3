from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .envelope import CoreValidationError, ObjectEnvelope
from .relationships import Relationship
from .serialization import canonical_json, loads_canonical


@dataclass(frozen=True, slots=True)
class ObjectGraph:
    """Small immutable object graph used by core dogfooding and later runtimes."""

    objects: tuple[ObjectEnvelope, ...]
    relationships: tuple[Relationship, ...]

    @classmethod
    def build(
        cls,
        objects: Iterable[ObjectEnvelope],
        relationships: Iterable[Relationship],
    ) -> "ObjectGraph":
        object_tuple = tuple(objects)
        relationship_tuple = tuple(relationships)
        object_ids = [obj.object_id for obj in object_tuple]
        if len(object_ids) != len(set(object_ids)):
            raise CoreValidationError("object graph contains duplicate object_id values")
        known = set(object_ids)
        for relationship in relationship_tuple:
            if relationship.subject_id not in known or relationship.object_id not in known:
                raise CoreValidationError("relationship references an unknown object")
        return cls(object_tuple, relationship_tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objects": [obj.to_dict() for obj in self.objects],
            "relationships": [rel.to_dict() for rel in self.relationships],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObjectGraph":
        if not isinstance(value, Mapping):
            raise CoreValidationError("object graph must be an object")
        if set(value) != {"objects", "relationships"}:
            raise CoreValidationError("object graph fields are not canonical")
        objects_value = value["objects"]
        relationships_value = value["relationships"]
        if not isinstance(objects_value, list) or not isinstance(relationships_value, list):
            raise CoreValidationError("object graph collections must be arrays")
        objects = tuple(ObjectEnvelope.from_dict(item) for item in objects_value)
        relationships = tuple(Relationship.from_dict(item) for item in relationships_value)
        return cls.build(objects, relationships)

    @classmethod
    def from_json(cls, value: str) -> "ObjectGraph":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("object graph JSON must decode to an object")
        return cls.from_dict(decoded)
