from __future__ import annotations

import unittest

from . import (
    CoreValidationError,
    ObjectEnvelope,
    ObjectGraph,
    Provenance,
    Relationship,
    RelationshipType,
    envelope_from_json,
    envelope_to_json,
)


STAMP = "2026-09-02T00:00:00Z"


def envelope(object_id: str, object_type: str, state: str) -> ObjectEnvelope:
    return ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=1,
        environment_id="env/test",
        domain_id="domain/demo",
        schema_version=1,
        protocol_version="v0.1",
        state=state,
        provenance=Provenance(
            issuer="principal/test",
            source="dogfood",
            recorded_at=STAMP,
        ),
        correlation_id="corr/1",
    ).with_integrity_hash()


class CoreTests(unittest.TestCase):
    def test_envelope_round_trip_is_lossless(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        self.assertEqual(envelope_from_json(envelope_to_json(value)), value)

    def test_integrity_hash_is_deterministic(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        self.assertEqual(value.integrity_hash, envelope("intent/1", "payswap/intent/v1", "AUTHORIZED").integrity_hash)

    def test_next_version_is_immutable(self) -> None:
        first = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        second = first.next_version(state="DISCOVERING").with_integrity_hash()
        self.assertEqual(first.object_version, 1)
        self.assertEqual(second.object_version, 2)
        self.assertEqual(second.previous_version, 1)
        self.assertEqual(second.object_id, first.object_id)
        self.assertEqual(first.state, "AUTHORIZED")
        with self.assertRaises(CoreValidationError):
            first.next_version(object_id="intent/2")
        with self.assertRaises(CoreValidationError):
            first.next_version(object_version=9)
        with self.assertRaises(CoreValidationError):
            first.next_version(previous_version=9)

    def test_relationship_vocab_is_closed(self) -> None:
        rel = Relationship.build(RelationshipType.OWNS, "merchant/1", "endpoint/1")
        self.assertEqual(rel.to_dict()["relationship_type"], "OWNS")
        with self.assertRaises(CoreValidationError):
            Relationship.from_dict({
                "relationship_type": "INVENTS",
                "subject_id": "merchant/1",
                "object_id": "endpoint/1",
                "attributes": {},
            })

    def test_representative_intent_graph_round_trips(self) -> None:
        root = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        destination = envelope("endpoint/1", "payswap/endpoint/v1", "ACTIVE")
        relationship = Relationship.build(RelationshipType.IS_ENTITLED_TO, root.object_id, destination.object_id)
        graph = ObjectGraph.build([root, destination], [relationship])
        self.assertEqual(ObjectGraph.from_dict(graph.to_dict()), graph)
        self.assertEqual(ObjectGraph.from_json(graph.to_json()), graph)

    def test_unknown_envelope_fields_fail_closed(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED").to_dict()
        value["unknown"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            ObjectEnvelope.from_dict(value)


if __name__ == "__main__":
    unittest.main()
