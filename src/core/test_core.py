from __future__ import annotations

import unittest

from . import (
    CoreValidationError,
    ObjectEnvelope,
    ObjectGraph,
    Provenance,
    Relationship,
    RelationshipType,
    canonical_json,
    canonical_sha256,
    envelope_from_json,
    envelope_to_json,
    relationship_from_json,
    relationship_to_json,
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


class CanonicalValueDomainTests(unittest.TestCase):
    """W002-3: canonical JSON must accept only an explicit protocol-safe value domain."""

    def test_rejects_non_finite_and_floating_point_values(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf"), 0.5):
            with self.assertRaises(CoreValidationError):
                canonical_json(bad)
            with self.assertRaises(CoreValidationError):
                canonical_json({"payload": [bad]})

    def test_rejects_unsafe_container_values(self) -> None:
        for bad in ({"x": object()}, {"x": b"bytes"}, {"x": {"k"}}, {"x": {1: "v"}}):
            with self.assertRaises(CoreValidationError):
                canonical_json(bad)

    def test_accepts_explicit_protocol_safe_domain(self) -> None:
        encoded = canonical_json(
            {"text": "value", "integer": 7, "flag": True, "empty": None,
             "array": [1, "two", [False]], "nested": {"deeper": {"leaf": None}}}
        )
        self.assertEqual(encoded, '{"array":[1,"two",[false]],"empty":null,"flag":true,"integer":7,"nested":{"deeper":{"leaf":null}},"text":"value"}')

    def test_tuple_and_list_encode_identically(self) -> None:
        self.assertEqual(canonical_json([1, 2]), canonical_json((1, 2)))
        self.assertEqual(canonical_sha256([1, 2]), canonical_sha256((1, 2)))


class RelationshipDeepImmutabilityTests(unittest.TestCase):
    """W002-1: nested protocol values must be deeply immutable after construction."""

    def test_attribute_values_are_normalized_to_immutable_form(self) -> None:
        source = ["a", "b"]
        rel = Relationship.build(
            RelationshipType.OWNS,
            "merchant/1",
            "endpoint/1",
            attributes={"tags": source, "priority": 2, "verified": True, "note": None},
        )
        self.assertEqual(
            rel.attributes,
            (("note", None), ("priority", 2), ("tags", ("a", "b")), ("verified", True)),
        )
        source.append("mutated-after-construction")
        self.assertEqual(dict(rel.attributes)["tags"], ("a", "b"))

    def test_mutable_attribute_values_are_rejected(self) -> None:
        for attributes in (
            {"meta": {"key": "value"}},
            {"ratio": 0.5},
            {"not_a_number": float("nan")},
        ):
            with self.assertRaises(CoreValidationError):
                Relationship.build(RelationshipType.OWNS, "merchant/1", "endpoint/1", attributes=attributes)
        with self.assertRaises(CoreValidationError):
            Relationship(RelationshipType.OWNS, "m/1", "e/1", attributes=(("tags", ["a"]),))
        with self.assertRaises(CoreValidationError):
            Relationship(RelationshipType.OWNS, "m/1", "e/1", attributes=(("nested", ({"k": 1},)),))

    def test_attribute_values_round_trip_losslessly(self) -> None:
        rel = Relationship.build(
            RelationshipType.DEPENDS_ON,
            "intent/1",
            "endpoint/1",
            attributes={"priority": 1, "tags": ("alpha", "beta"), "verified": True, "note": None},
        )
        self.assertEqual(relationship_from_json(relationship_to_json(rel)), rel)
        self.assertEqual(Relationship.from_dict(rel.to_dict()), rel)


class IntegrityVerificationTests(unittest.TestCase):
    """W002-2: integrity hashes must be recomputed and verified on trusted deserialization."""

    def test_tampered_envelope_json_is_rejected(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        encoded = envelope_to_json(value)
        for tampered in (
            encoded.replace('"state":"AUTHORIZED"', '"state":"TAMPERED"'),
            encoded.replace('"issuer":"principal/test"', '"issuer":"principal/attacker"'),
        ):
            with self.assertRaises(CoreValidationError):
                envelope_from_json(tampered)

    def test_forged_integrity_hash_is_rejected(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        data = value.to_dict()
        data["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            ObjectEnvelope.from_dict(data)

    def test_unsealed_envelope_cannot_be_deserialized(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        unsealed = value.next_version(state="DISCOVERING")
        with self.assertRaises(CoreValidationError):
            envelope_from_json(envelope_to_json(unsealed))

    def test_tampered_object_graph_is_rejected(self) -> None:
        root = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        destination = envelope("endpoint/1", "payswap/endpoint/v1", "ACTIVE")
        graph = ObjectGraph.build([root, destination], [])
        tampered = graph.to_json().replace('"state":"ACTIVE"', '"state":"DISABLED"')
        with self.assertRaises(CoreValidationError):
            ObjectGraph.from_json(tampered)

    def test_round_trip_is_byte_stable(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        encoded = envelope_to_json(value)
        self.assertEqual(envelope_to_json(envelope_from_json(encoded)), encoded)
        twin = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        self.assertEqual(twin, value)
        self.assertEqual(envelope_to_json(twin), encoded)


class DuplicateKeyLossTests(unittest.TestCase):
    """W002-1: duplicate JSON object keys must not collapse silently."""

    def test_duplicate_envelope_keys_are_rejected(self) -> None:
        value = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        encoded = envelope_to_json(value)
        duplicated = encoded.replace('"state":"AUTHORIZED"}', '"state":"AUTHORIZED","state":"DUPLICATED"}')
        with self.assertRaises(CoreValidationError):
            envelope_from_json(duplicated)

    def test_duplicate_relationship_attribute_keys_are_rejected(self) -> None:
        rel = Relationship.build(RelationshipType.OWNS, "merchant/1", "endpoint/1", attributes={"note": "x"})
        duplicated = relationship_to_json(rel).replace('"note":"x"', '"note":"x","note":"y"')
        with self.assertRaises(CoreValidationError):
            relationship_from_json(duplicated)

    def test_duplicate_object_graph_keys_are_rejected(self) -> None:
        root = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        graph = ObjectGraph.build([root], [])
        duplicated = graph.to_json().replace('"objects":[', '"objects":[],"objects":[')
        with self.assertRaises(CoreValidationError):
            ObjectGraph.from_json(duplicated)


class VersionIdentityTests(unittest.TestCase):
    """W002-4: version transitions must preserve immutable identity fields."""

    def test_next_version_rejects_identity_field_changes(self) -> None:
        first = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        for field, replacement in (
            ("object_id", "intent/2"),
            ("object_type", "payswap/other/v1"),
            ("environment_id", "env/other"),
            ("domain_id", "domain/other"),
            ("schema_version", 2),
            ("protocol_version", "v0.2"),
        ):
            with self.assertRaises(CoreValidationError):
                first.next_version(**{field: replacement})
        with self.assertRaises(CoreValidationError):
            first.next_version(integrity_hash="0" * 64)

    def test_next_version_accepts_same_identity_and_valid_progression(self) -> None:
        first = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        same_id = first.next_version(object_id=first.object_id)
        self.assertEqual(same_id.object_id, first.object_id)
        advanced = first.next_version(state="DISCOVERING", correlation_id="corr/2").with_integrity_hash()
        self.assertEqual(advanced.object_version, 2)
        self.assertEqual(advanced.previous_version, 1)
        self.assertEqual(
            advanced.integrity_hash,
            canonical_sha256(advanced.canonical_dict(include_integrity_hash=False)),
        )


class IntentGraphDogfoodingTests(unittest.TestCase):
    """DOGFOOD-032: construct, serialize, tamper, deserialize and version a representative intent object graph."""

    def test_intent_graph_integrity_conformance(self) -> None:
        root = envelope("intent/1", "payswap/intent/v1", "AUTHORIZED")
        destination = envelope("endpoint/1", "payswap/endpoint/v1", "ACTIVE")
        relationship = Relationship.build(
            RelationshipType.IS_ENTITLED_TO,
            root.object_id,
            destination.object_id,
            attributes={"priority": 1, "tags": ("settlement", "instant")},
        )
        graph = ObjectGraph.build([root, destination], [relationship])

        encoded = graph.to_json()
        self.assertEqual(ObjectGraph.from_json(encoded), graph)
        self.assertEqual(ObjectGraph.from_json(encoded).to_json(), encoded)

        for tampered in (
            encoded.replace('"state":"AUTHORIZED"', '"state":"SETTLED"'),
            encoded.replace('"issuer":"principal/test"', '"issuer":"principal/attacker"'),
        ):
            with self.assertRaises(CoreValidationError):
                ObjectGraph.from_json(tampered)

        with self.assertRaises(CoreValidationError):
            root.next_version(object_type="payswap/other/v1")
        with self.assertRaises(CoreValidationError):
            root.next_version(environment_id="env/other")

        advanced_root = root.next_version(state="DISCOVERING").with_integrity_hash()
        advanced_graph = ObjectGraph.build([advanced_root, destination], [relationship])
        advanced_encoded = advanced_graph.to_json()
        self.assertEqual(ObjectGraph.from_json(advanced_encoded), advanced_graph)
        self.assertEqual(ObjectGraph.from_json(advanced_encoded).to_json(), advanced_encoded)


if __name__ == "__main__":
    unittest.main()
