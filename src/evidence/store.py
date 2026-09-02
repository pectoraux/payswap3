"""Append-only archive of evidence-domain durable records.

The :class:`EvidenceArchive` is the typed evidence store: it keeps every
version of every record and never rewrites history. Appends are gated by
the transition kernel's :class:`~src.transition.store.MemoryStateStore`
(WORK-003): the kernel's strict commit semantics — instance checks,
envelope integrity, duplicate ids, exact version-chain advancement and
frozen identity fields, all validated before any mutation — are the
append-only authority, so re-appending an existing version, jumping
versions or splicing identity drift fails closed here without a second
store authority.
"""

from __future__ import annotations

from typing import Iterable

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import MemoryStateStore

from .attestations import Attestation
from .evidence import Evidence
from .observations import Observation
from .uncertainty import Uncertainty

_RECORD_TYPES = (Evidence, Attestation, Observation, Uncertainty)


def _require_record(record: object) -> None:
    if not isinstance(record, _RECORD_TYPES):
        raise CoreValidationError(
            "the archive stores Evidence, Attestation, Observation and "
            "Uncertainty records only"
        )


class EvidenceArchive:
    """Deterministic append-only archive with immutable version history."""

    __slots__ = ("_store", "_records")

    def __init__(self, records: Iterable[object] = ()) -> None:
        self._store = MemoryStateStore()
        self._records: dict[str, dict[int, object]] = {}
        for record in records:
            self.append(record)

    def append(self, record: object) -> object:
        """Append one record version (creation or exact next version).

        The transition kernel's commit gate validates the whole append
        against the pre-commit state — envelope integrity, version chain
        and identity fields — before anything is stored, so a rejected
        append leaves the archive byte-identical (all-or-nothing) and
        history can only ever be extended.
        """
        _require_record(record)
        envelope = record.envelope  # type: ignore[attr-defined]
        # commit validates integrity, exact version advancement, the
        # immutable version chain and frozen identity fields; it raises
        # CoreValidationError (the single error authority) otherwise.
        self._store.commit((envelope,))
        versions = self._records.setdefault(envelope.object_id, {})
        versions[envelope.object_version] = record
        return record

    def get(self, object_id: str) -> object:
        """Latest recorded version of one object (fail closed on unknown)."""
        versions = self._records.get(object_id)
        if not versions:
            raise CoreValidationError(f"unknown archived record: {object_id}")
        return versions[max(versions)]

    def get_version(self, object_id: str, version: int) -> object:
        """One exact recorded version (fail closed when absent)."""
        versions = self._records.get(object_id, {})
        if version not in versions:
            raise CoreValidationError(
                f"record {object_id} has no archived version {version}"
            )
        return versions[version]

    def history(self, object_id: str) -> tuple[object, ...]:
        """Every recorded version of one object, in version order."""
        versions = self._records.get(object_id, {})
        return tuple(versions[version] for version in sorted(versions))

    def latest(self) -> tuple[object, ...]:
        """Latest version of every archived object, sorted by object id."""
        return tuple(
            self._records[object_id][max(self._records[object_id])]
            for object_id in sorted(self._records)
        )

    def __len__(self) -> int:
        return len(self._records)

    def archive_digest(self) -> str:
        """Deterministic digest over the current archive state.

        A pure function of the archived (object id, version, seal)
        triples — used by tests and dogfooding to prove determinism.
        """
        rows = [
            [
                record.envelope.object_id,  # type: ignore[attr-defined]
                record.envelope.object_version,  # type: ignore[attr-defined]
                record.integrity_hash,  # type: ignore[attr-defined]
            ]
            for record in self.latest()
        ]
        return canonical_sha256({"records": rows})
