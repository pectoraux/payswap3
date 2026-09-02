"""The versioned reservation store: keyed, expected-version, atomic.

The store is the authoritative in-memory home of protocol reservation
records. Its contract mirrors the transition kernel's discipline
(WORK-003, consumed — never reimplemented):

- **expected-version preconditions** — every apply declares, per
  reservation, the exact object version the writer expects (version 0
  means "must not exist yet"); a mismatch fails closed with an explicit
  expected-vs-actual diagnostic. This is the optimistic-concurrency half
  of the frozen "optimistic concurrency with conditional resource commit"
  architecture rule;
- **keyed serialization** — every apply runs under the per-resource-key
  gates of :class:`~src.reservation.concurrency.KeyedLockManager` (acquired
  in lexicographic order for multi-key batches), so writers on one key
  serialize deterministically while independent keys never block each
  other — no global mutex exists anywhere in the apply path;
- **atomic validate-all-then-apply batches** — the entire batch (instances,
  integrity, duplicates, expected versions, version chains, identity,
  creation constraints and live-key exclusivity) is validated against the
  pre-apply snapshot before any mutation; a rejected batch leaves the
  store byte-identical to its pre-apply state;
- **live-key exclusivity** — a resource key admits at most one non-terminal
  reservation: racing creators of the same resource key leave exactly one
  winner, which is the reservation-safety half of the concurrency contract.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import ExpectedVersion

from .concurrency import KeyedLockManager, WriterClaim
from .records import RESERVATION_TERMINAL_STATES, Reservation, ReservationState

#: Payload identity fields that can never change across reservation
#: versions. Envelope identity is already frozen by the core
#: (:data:`src.core.envelope.IDENTITY_FIELDS`); the payload identity below
#: is the reservation-specific supplement enforced by this store.
PAYLOAD_IDENTITY_FIELDS = (
    "resource_key",
    "provider",
    "beneficiary",
    "asset",
    "source_ref",
    "funding_refs",
    "amount_scale",
)


def _require_expected_versions(
    expected_versions: object,
    resulting_ids: list[str],
) -> dict[str, int]:
    if not isinstance(expected_versions, tuple) or not expected_versions:
        raise CoreValidationError(
            "apply requires a non-empty tuple of expected versions"
        )
    expected: dict[str, int] = {}
    for entry in expected_versions:
        if not isinstance(entry, ExpectedVersion):
            raise CoreValidationError(
                "expected versions must use the transition kernel's ExpectedVersion"
            )
        if entry.object_ref in expected:
            raise CoreValidationError(
                f"expected versions declare duplicate object references: {entry.object_ref!r}"
            )
        expected[entry.object_ref] = entry.object_version
    expected_ids = set(expected)
    resulting_set = set(resulting_ids)
    if expected_ids != resulting_set:
        missing = sorted(resulting_set - expected_ids)
        extra = sorted(expected_ids - resulting_set)
        raise CoreValidationError(
            "expected-version coverage mismatch: expected_versions must cover exactly "
            f"the resulting reservations; missing={missing}, extra={extra}"
        )
    return expected


class ReservationStore:
    """In-memory authoritative store of sealed reservation records."""

    def __init__(
        self,
        reservations: Iterable[Reservation] = (),
        *,
        locks: KeyedLockManager | None = None,
    ) -> None:
        self._records: dict[str, Reservation] = {}
        self._locks = locks if locks is not None else KeyedLockManager()
        seed = tuple(reservations)
        for record in seed:
            if not isinstance(record, Reservation):
                raise CoreValidationError(
                    "store reservations must be Reservation instances"
                )
            if record.object_id in self._records:
                raise CoreValidationError(
                    f"store contains duplicate reservation id {record.object_id!r}"
                )
            self._records[record.object_id] = record
        # Seed live-key exclusivity (validate-all-then-apply discipline).
        live: dict[str, str] = {}
        for record in seed:
            if record.state in RESERVATION_TERMINAL_STATES:
                continue
            key = record.spec.resource_key
            existing = live.get(key)
            if existing is not None:
                raise CoreValidationError(
                    f"resource key {key!r} is already reserved by live reservation "
                    f"{existing} (state {self._records[existing].state.value}); "
                    "a resource key admits at most one live reservation"
                )
            live[key] = record.object_id

    # -- reads ---------------------------------------------------------------

    def get(self, reservation_id: str) -> Reservation | None:
        return self._records.get(reservation_id)

    def snapshot(self) -> tuple[Reservation, ...]:
        """Deterministic ordered view of the current reservation state."""
        return tuple(self._records[object_id] for object_id in sorted(self._records))

    def snapshot_digest(self) -> str:
        """Byte-level digest of the authoritative snapshot."""
        return canonical_sha256([record.to_dict() for record in self.snapshot()])

    def locks(self) -> KeyedLockManager:
        """The keyed lock manager serializing this store's applies."""
        return self._locks

    # -- writes --------------------------------------------------------------

    def apply(
        self,
        resulting: tuple[Reservation, ...],
        *,
        expected_versions: tuple[ExpectedVersion, ...],
        writer: WriterClaim,
    ) -> None:
        """Atomically publish a batch of resulting reservation versions.

        The whole batch is validated against the pre-apply snapshot under
        the keyed gates (acquired in lexicographic resource-key order)
        before any mutation: a rejected batch leaves the store
        byte-identical to its pre-apply state.
        """
        if not isinstance(resulting, tuple) or not resulting:
            raise CoreValidationError(
                "apply requires a non-empty tuple of resulting reservations"
            )
        if not isinstance(writer, WriterClaim):
            raise CoreValidationError(
                f"apply requires a WriterClaim, got {type(writer).__name__}"
            )
        for record in resulting:
            if not isinstance(record, Reservation):
                raise CoreValidationError(
                    "resulting reservations must be Reservation instances"
                )
            record.envelope.verify_integrity()
        resulting_ids = [record.object_id for record in resulting]
        if len(set(resulting_ids)) != len(resulting_ids):
            raise CoreValidationError(
                "apply batch contains duplicate reservation ids"
            )
        expected = _require_expected_versions(expected_versions, resulting_ids)
        keys = sorted({record.spec.resource_key for record in resulting})
        with self._locks.locked_all(keys, claim=writer):
            # -- validate everything against the pre-apply snapshot --------
            for record in resulting:
                self._validate_one(record, expected[record.object_id])
            self._validate_live_key_exclusivity(resulting)
            # -- apply the whole batch --------------------------------------
            for record in resulting:
                self._records[record.object_id] = record

    def _validate_one(self, record: Reservation, expected_version: int) -> None:
        reservation_id = record.object_id
        current = self._records.get(reservation_id)
        if expected_version == 0:
            if current is not None:
                raise CoreValidationError(
                    f"expected-version conflict on reservation {reservation_id}: "
                    f"writer expected creation (version 0), store holds version "
                    f"{current.envelope.object_version}"
                )
            if record.envelope.object_version != 1 or record.envelope.previous_version is not None:
                raise CoreValidationError(
                    f"reservation {reservation_id} must be created at version 1"
                )
            return
        if current is None:
            raise CoreValidationError(
                f"expected-version conflict on reservation {reservation_id}: "
                f"writer expected version {expected_version}, store holds no reservation"
            )
        if current.envelope.object_version != expected_version:
            raise CoreValidationError(
                f"expected-version conflict on reservation {reservation_id}: "
                f"writer expected version {expected_version}, store holds version "
                f"{current.envelope.object_version}"
            )
        if record.envelope.object_version != current.envelope.object_version + 1:
            raise CoreValidationError(
                f"reservation {reservation_id} must advance exactly one version at a time"
            )
        if record.envelope.previous_version != current.envelope.object_version:
            raise CoreValidationError(
                f"reservation {reservation_id} breaks the immutable version chain"
            )
        for field in ("object_type", "environment_id", "domain_id", "schema_version", "protocol_version"):
            if getattr(record.envelope, field) != getattr(current.envelope, field):
                raise CoreValidationError(
                    f"envelope identity field {field} of reservation {reservation_id} cannot change"
                )
        self._validate_payload_identity(reservation_id, current, record)

    def _validate_payload_identity(
        self, reservation_id: str, current: Reservation, record: Reservation
    ) -> None:
        for field in PAYLOAD_IDENTITY_FIELDS[:-1]:
            if getattr(record.spec, field) != getattr(current.spec, field):
                raise CoreValidationError(
                    f"payload identity field {field} of reservation {reservation_id} cannot change"
                )
        if record.spec.amount.scale != current.spec.amount.scale:
            raise CoreValidationError(
                f"payload identity field amount_scale of reservation {reservation_id} "
                "cannot change; rescaling is money-domain work"
            )

    def _validate_live_key_exclusivity(self, resulting: tuple[Reservation, ...]) -> None:
        """A resource key admits at most one non-terminal reservation.

        The post-apply live set per touched key is computed from (a) the
        batch entries that are live and (b) the stored live reservations on
        that key which the batch does not replace. A terminal transition in
        the batch frees its key for a same-batch successor creation.
        """
        batch_ids = {record.object_id for record in resulting}
        stored_live: dict[str, list[str]] = {}
        for stored in list(self._records.values()):
            if stored.object_id in batch_ids:
                continue
            if stored.state in RESERVATION_TERMINAL_STATES:
                continue
            stored_live.setdefault(stored.spec.resource_key, []).append(stored.object_id)
        batch_live: dict[str, list[str]] = {}
        batch_states: dict[str, ReservationState] = {}
        for record in resulting:
            if record.state in RESERVATION_TERMINAL_STATES:
                continue
            batch_live.setdefault(record.spec.resource_key, []).append(record.object_id)
            batch_states[record.object_id] = record.state
        for key in sorted(set(stored_live) | set(batch_live)):
            stored_ids = sorted(stored_live.get(key, []))
            batch_ids_on_key = sorted(batch_live.get(key, []))
            if len(stored_ids) + len(batch_ids_on_key) > 1:
                holder = stored_ids[0] if stored_ids else batch_ids_on_key[0]
                if holder in batch_states:
                    holder_state = batch_states[holder].value
                else:
                    holder_state = self._records[holder].state.value
                conflict_ids = sorted(set(stored_ids + batch_ids_on_key))
                raise CoreValidationError(
                    f"resource key {key!r} is already reserved by live reservation "
                    f"{holder} (state {holder_state}); a resource key admits at most "
                    f"one live reservation; conflicting ids {conflict_ids}"
                )


__all__ = [
    "PAYLOAD_IDENTITY_FIELDS",
    "ReservationStore",
]
