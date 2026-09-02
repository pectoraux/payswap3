"""W003 correction regressions: MemoryStateStore.commit must be atomic.

Architect review (PR #8, head 4b51935, CHANGES_REQUESTED): the store's
commit() validated and mutated ``_objects`` in the same loop, so a
multi-object batch with an early valid envelope followed by a later
invalid envelope left the early object authoritative — partial-commit
semantics inside the authoritative store. These regressions prove the
all-or-nothing contract: a rejected batch must leave the store snapshot
byte-identical to the pre-commit state.
"""

from __future__ import annotations

import unittest

from src.core import (
    CoreValidationError,
    ObjectEnvelope,
    Provenance,
    canonical_sha256,
)

from .store import MemoryStateStore

STAMP = "2026-09-02T00:00:00Z"


def _envelope(
    object_id: str = "intent/1",
    *,
    state: str = "AUTHORIZED",
    version: int = 1,
    environment_id: str = "env/test",
    domain_id: str = "domain/demo",
    object_type: str = "payswap/intent/v1",
) -> ObjectEnvelope:
    envelope = ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=1,
        environment_id=environment_id,
        domain_id=domain_id,
        schema_version=1,
        protocol_version="v0.1",
        state=state,
        provenance=Provenance(
            issuer="principal/test",
            source="transition",
            recorded_at=STAMP,
        ),
        correlation_id="corr/1",
    ).with_integrity_hash()
    for _ in range(version - 1):
        envelope = envelope.next_version(state=state).with_integrity_hash()
    return envelope


def _forged_identity(
    object_id: str,
    *,
    previous_version: int,
    object_type: str = "payswap/other/v1",
) -> ObjectEnvelope:
    """A sealed next version whose identity field differs from the stored object."""
    return ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=previous_version + 1,
        environment_id="env/test",
        domain_id="domain/demo",
        schema_version=1,
        protocol_version="v0.1",
        state="DISCOVERING",
        provenance=Provenance(issuer="principal/test", source="transition", recorded_at=STAMP),
        previous_version=previous_version,
        correlation_id="corr/1",
    ).with_integrity_hash()


def _snapshot_digest(store: MemoryStateStore) -> str:
    """Byte-level digest of the authoritative store snapshot."""
    return canonical_sha256([obj.to_dict() for obj in store.snapshot()])


class StoreCommitAtomicityTests(unittest.TestCase):
    """W003 correction: multi-object commits are all-or-nothing."""

    def test_multi_object_commit_with_later_version_jump_rolls_back_all(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1"), _envelope("intent/2")])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        valid_a = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        jumped_b = _envelope("intent/2", version=3)
        with self.assertRaises(CoreValidationError):
            store.commit((valid_a, jumped_b))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertEqual(store.get("intent/1").object_version, 1)

    def test_multi_object_commit_with_later_chain_break_rolls_back_all(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1"), _envelope("intent/2")])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        valid_a = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        broken_b = ObjectEnvelope(
            object_id="intent/2",
            object_type="payswap/intent/v1",
            object_version=2,
            environment_id="env/test",
            domain_id="domain/demo",
            schema_version=1,
            protocol_version="v0.1",
            state="DISCOVERING",
            provenance=Provenance(issuer="principal/test", source="transition", recorded_at=STAMP),
            previous_version=None,
            correlation_id="corr/1",
        ).with_integrity_hash()
        with self.assertRaises(CoreValidationError):
            store.commit((valid_a, broken_b))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertEqual(store.get("intent/1").object_version, 1)

    def test_multi_object_commit_with_later_identity_violation_rolls_back_all(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1"), _envelope("intent/2")])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        valid_a = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        forged_b = _forged_identity("intent/2", previous_version=1)
        with self.assertRaises(CoreValidationError):
            store.commit((valid_a, forged_b))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertEqual(store.get("intent/1").object_version, 1)

    def test_multi_object_commit_with_later_creation_violation_rolls_back_all(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1")])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        valid_creation_a = _envelope("intent/2", state="CREATED")
        bad_creation_b = _envelope("intent/3", version=2)
        with self.assertRaises(CoreValidationError):
            store.commit((valid_creation_a, bad_creation_b))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertIsNone(store.get("intent/2"))

    def test_three_object_commit_rolls_back_every_valid_envelope(self) -> None:
        store = MemoryStateStore(objects=[
            _envelope("intent/1"),
            _envelope("intent/2"),
            _envelope("intent/3"),
        ])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        valid_a = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        valid_b = _envelope("intent/2").next_version(state="DISCOVERING").with_integrity_hash()
        invalid_c = _envelope("intent/3", version=5)
        with self.assertRaises(CoreValidationError):
            store.commit((valid_a, valid_b, invalid_c))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertEqual(store.get("intent/1").object_version, 1)
        self.assertEqual(store.get("intent/2").object_version, 1)
        self.assertEqual(store.get("intent/3").object_version, 1)

    def test_multi_object_batch_with_duplicate_ids_commits_nothing(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1")])
        before_snapshot = store.snapshot()
        before_digest = _snapshot_digest(store)
        advanced = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        other = _envelope("intent/2", state="CREATED")
        with self.assertRaises(CoreValidationError):
            store.commit((advanced, other, advanced))
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(_snapshot_digest(store), before_digest)
        self.assertIsNone(store.get("intent/2"))

    def test_valid_multi_object_commit_applies_every_envelope(self) -> None:
        store = MemoryStateStore(objects=[_envelope("intent/1")])
        updated = _envelope("intent/1").next_version(state="DISCOVERING").with_integrity_hash()
        created = _envelope("intent/2", state="CREATED")
        store.commit((updated, created))
        self.assertEqual(store.get("intent/1"), updated)
        self.assertEqual(store.get("intent/2"), created)
        self.assertEqual(
            [obj.object_id for obj in store.snapshot()],
            ["intent/1", "intent/2"],
        )


if __name__ == "__main__":
    unittest.main()
