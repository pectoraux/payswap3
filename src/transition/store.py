from __future__ import annotations

from typing import Iterable, Protocol

from src.core.envelope import IDENTITY_FIELDS, ObjectEnvelope
from src.core.errors import CoreValidationError


class StateStore(Protocol):
    """Contract for authoritative object state behind the transition kernel."""

    def get(self, object_id: str) -> ObjectEnvelope | None: ...

    def commit(self, resulting: tuple[ObjectEnvelope, ...]) -> None: ...


class StateStoreView:
    """Read-only projection handed to authorization, policy, invariant and
    transition handlers so hooks cannot bypass the kernel's commit gate."""

    __slots__ = ("_store",)

    def __init__(self, store: StateStore) -> None:
        self._store = store

    def get(self, object_id: str) -> ObjectEnvelope | None:
        return self._store.get(object_id)


class MemoryStateStore:
    """Deterministic in-memory object store with strict version-chain commits."""

    __slots__ = ("_objects",)

    def __init__(self, objects: Iterable[ObjectEnvelope] = ()) -> None:
        self._objects: dict[str, ObjectEnvelope] = {}
        for envelope in objects:
            if not isinstance(envelope, ObjectEnvelope):
                raise CoreValidationError("store objects must be ObjectEnvelope instances")
            envelope.verify_integrity()
            if envelope.object_id in self._objects:
                raise CoreValidationError("store contains duplicate object_id values")
            self._objects[envelope.object_id] = envelope

    def get(self, object_id: str) -> ObjectEnvelope | None:
        return self._objects.get(object_id)

    def commit(self, resulting: tuple[ObjectEnvelope, ...]) -> None:
        """Atomically publish a batch of resulting envelopes.

        The entire batch — instance, integrity, duplicate, version-chain,
        identity and creation constraints — is validated against the
        pre-commit snapshot before any mutation. A rejected batch leaves
        the store byte-identical to its pre-commit state (all-or-nothing);
        partial commits are impossible. Batch entries carry distinct
        object_id values (enforced below), so validation never observes
        another entry's would-be mutation.
        """
        if not isinstance(resulting, tuple) or not resulting:
            raise CoreValidationError("commit requires a non-empty tuple of resulting envelopes")
        for envelope in resulting:
            if not isinstance(envelope, ObjectEnvelope):
                raise CoreValidationError("resulting envelopes must be ObjectEnvelope instances")
            envelope.verify_integrity()
        object_ids = [envelope.object_id for envelope in resulting]
        if len(set(object_ids)) != len(object_ids):
            raise CoreValidationError("commit batch contains duplicate object_id values")
        for envelope in resulting:
            current = self._objects.get(envelope.object_id)
            if current is None:
                if envelope.object_version != 1 or envelope.previous_version is not None:
                    raise CoreValidationError(
                        f"object {envelope.object_id} must be created at version 1"
                    )
            else:
                if envelope.object_version != current.object_version + 1:
                    raise CoreValidationError(
                        f"object {envelope.object_id} must advance exactly one version at a time"
                    )
                if envelope.previous_version != current.object_version:
                    raise CoreValidationError(
                        f"object {envelope.object_id} breaks the immutable version chain"
                    )
                for field in IDENTITY_FIELDS:
                    if field == "object_id":
                        continue
                    if getattr(envelope, field) != getattr(current, field):
                        raise CoreValidationError(
                            f"identity field {field} of object {envelope.object_id} cannot change"
                        )
        for envelope in resulting:
            self._objects[envelope.object_id] = envelope

    def snapshot(self) -> tuple[ObjectEnvelope, ...]:
        """Deterministic ordered view of the current object state."""
        return tuple(self._objects[object_id] for object_id in sorted(self._objects))
