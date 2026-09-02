"""Effect-submission idempotency ledger (WORK-014).

The domain-side half of idempotent external effects (constitution
invariant 9): every declared effect request registers its idempotency
key and canonical request digest here, and every accepted submission
records its typed outcome. The ledger's discipline:

* **same key + same digest** → duplicate: the caller converges to the
  recorded request/submission — the port is NEVER called a second time;
* **same key + different digest** → idempotency conflict: fail closed
  (a key may never be silently re-bound to different content);
* **unknown key** → fresh request.

This mirrors the transition kernel's own input-level idempotency
(stage 1 of the frozen pipeline) at the effect-submission level: the
kernel remains the command-deduplication authority; this ledger is the
effect-request/submission authority. The ledger is journaled through
the kernel event payloads and rebuilds deterministically from the
journal (transformation completeness — no second source of truth).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from ._validation import (
    require_digest,
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import SubmissionStatus

_ENTRY_FIELDS = frozenset(
    {
        "request_id",
        "request_digest",
        "submission",
    }
)
_SUBMISSION_FIELDS = frozenset(
    {
        "status",
        "native_reference",
        "reason",
        "submitted_at",
        "command_id",
    }
)
_LEDGER_FIELDS = frozenset({"entries"})


def _validate_submission(value: Any) -> dict[str, Any]:
    submission = require_mapping("ledger submission", value)
    strict_fields("ledger submission", submission, _SUBMISSION_FIELDS)
    status = SubmissionStatus(submission["status"])
    native_reference = submission["native_reference"]
    reason = submission["reason"]
    if status is SubmissionStatus.ACCEPTED:
        require_text("ledger submission native_reference", native_reference)
    else:
        require_text("ledger submission reason", reason)
    require_utc_timestamp("ledger submission submitted_at", submission["submitted_at"])
    require_identifier("ledger submission command_id", submission["command_id"])
    return {
        "status": status.value,
        "native_reference": native_reference,
        "reason": reason,
        "submitted_at": submission["submitted_at"],
        "command_id": submission["command_id"],
    }


@dataclass(frozen=True, slots=True)
class _LedgerEntry:
    request_id: str
    request_digest: str
    submission: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "submission": dict(self.submission) if self.submission is not None else None,
        }


class EffectSubmissionLedger:
    """Idempotency ledger of declared effect requests and their submissions.

    Deterministic and canonical: ``to_dict`` round-trips byte-stably and
    the rebuild path reconstructs the ledger exactly from the kernel
    journal payloads.
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[str, _LedgerEntry] = {}

    # -- declaration ------------------------------------------------------

    def declare(self, *, key: str, request_id: str, request_digest: str) -> bool:
        """Register one effect request declaration under its idempotency key.

        Returns ``True`` when the key is fresh (declared now) and
        ``False`` when an identical declaration already exists (the
        caller converges). A key bound to different request content
        fails closed.
        """
        require_text("ledger key", key)
        require_identifier("ledger request_id", request_id)
        require_digest("ledger request_digest", request_digest)
        existing = self._entries.get(key)
        if existing is None:
            self._entries[key] = _LedgerEntry(
                request_id=request_id,
                request_digest=request_digest,
                submission=None,
            )
            return True
        if existing.request_digest != request_digest:
            raise CoreValidationError(
                f"idempotency key {key!r} was already used for different request "
                "content; an effect key may never be silently re-bound "
                "(idempotency conflict)"
            )
        if existing.request_id != request_id:
            raise CoreValidationError(
                f"idempotency key {key!r} is bound to request {existing.request_id!r}, "
                f"not {request_id!r}"
            )
        return False

    def request_declared(self, key: str) -> bool:
        """Whether a declaration exists under this idempotency key."""
        require_text("ledger key", key)
        return key in self._entries

    # -- submission -------------------------------------------------------

    def record_submission(
        self,
        *,
        key: str,
        submission: Mapping[str, Any],
    ) -> None:
        """Record the typed submission outcome for one declared key.

        Recording a submission twice for the same key fails closed: the
        port must be called at most once per key (the engine's duplicate
        pre-check guarantees the call never happens; this is the
        domain-side second line of defense).
        """
        require_text("ledger key", key)
        existing = self._entries.get(key)
        if existing is None:
            raise CoreValidationError(
                f"cannot record a submission for undeclared idempotency key {key!r}"
            )
        if existing.submission is not None:
            raise CoreValidationError(
                f"idempotency key {key!r} was already submitted; a second port "
                "call for one key is forbidden (constitution invariant 9)"
            )
        normalized = _validate_submission(submission)
        self._entries[key] = _LedgerEntry(
            request_id=existing.request_id,
            request_digest=existing.request_digest,
            submission=normalized,
        )

    # -- lookup -----------------------------------------------------------

    def _lookup(self, key: str) -> _LedgerEntry:
        existing = self._entries.get(key)
        if existing is None:
            raise CoreValidationError(
                f"idempotency key {key!r} has no recorded effect request"
            )
        return existing

    def entry_for(self, key: str) -> dict[str, Any]:
        return self._lookup(key).to_dict()

    def request_digest_for(self, key: str) -> str:
        return self._lookup(key).request_digest

    def request_id_for(self, key: str) -> str:
        return self._lookup(key).request_id

    def submission_for(self, key: str) -> dict[str, Any] | None:
        return dict(self._lookup(key).submission) if self._lookup(key).submission else None

    def is_submitted(self, key: str) -> bool:
        entry = self._entries.get(key)
        return entry is not None and entry.submission is not None

    def __len__(self) -> int:
        return len(self._entries)

    # -- canonical round-trip ---------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [
                {**entry.to_dict(), "key": key}
                for key, entry in sorted(self._entries.items())
            ]
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectSubmissionLedger":
        strict_fields("effect submission ledger", value, _LEDGER_FIELDS)
        entries_raw = value["entries"]
        if not isinstance(entries_raw, list):
            raise CoreValidationError("ledger entries must deserialize from a list")
        ledger = cls()
        for item in entries_raw:
            if not isinstance(item, Mapping):
                raise CoreValidationError("ledger entries must be objects")
            if set(item) != _ENTRY_FIELDS | {"key"}:
                raise CoreValidationError("ledger entry fields are not canonical")
            submission = item["submission"]
            ledger._entries[require_text("ledger key", item["key"])] = _LedgerEntry(
                request_id=item["request_id"],
                request_digest=item["request_digest"],
                submission=_validate_submission(submission)
                if submission is not None
                else None,
            )
        return ledger

    @classmethod
    def from_json(cls, value: str) -> "EffectSubmissionLedger":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("ledger JSON must decode to an object")
        return cls.from_dict(decoded)


__all__ = ["EffectSubmissionLedger"]
