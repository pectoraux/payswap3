"""Keyed concurrency: per-key serialization with deterministic precedence.

The reservation domain's concurrency contract is KEYED, never global:

- locking is scoped per reservation resource key — two writers on one key
  serialize, while writers on independent keys always make progress (the
  only shared state is a registry guard held solely for the O(1) key-gate
  lookup, never during grants or critical sections);
- competing writers on one key resolve by EXPLICIT precedence — earliest
  ``requested_at``, then command id, then actor — never by wall-clock
  timing, thread scheduling or hash order: :func:`resolve_precedence` is a
  pure total ranking, and the per-key gate grants queued waiters in exactly
  that order;
- multi-key acquisition takes the key set in lexicographic order (the
  documented deadlock-avoidance discipline).

This module provides scheduling and exclusion only: correctness of state
transitions (expected-version preconditions, version chains, atomic batch
apply) is owned by :mod:`.store`. Precedence decisions never read a clock;
``timeout`` parameters are bounded safety valves for scheduling, not
decision inputs.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator

from src.core.errors import CoreValidationError

from ._validation import require_identifier, require_utc_timestamp


@dataclass(frozen=True, slots=True)
class WriterClaim:
    """Identity of one competing writer for keyed conflict resolution."""

    actor: str
    requested_at: str
    command_id: str

    def __post_init__(self) -> None:
        require_identifier("writer.actor", self.actor)
        require_utc_timestamp("writer.requested_at", self.requested_at)
        require_identifier("writer.command_id", self.command_id)

    def precedence_key(self) -> tuple[str, str, str]:
        """Total deterministic ranking key: (requested_at, command_id, actor)."""
        return (self.requested_at, self.command_id, self.actor)


def resolve_precedence(claims: Iterable[WriterClaim]) -> tuple[WriterClaim, ...]:
    """Rank competing writer claims deterministically.

    Ordering is earliest ``requested_at`` first, then command id, then
    actor; fully duplicate claims (identical precedence keys) fail closed.
    The result is independent of input order.
    """
    ranked = tuple(claims)
    for claim in ranked:
        if not isinstance(claim, WriterClaim):
            raise CoreValidationError(
                f"precedence claims must be WriterClaim values, got {type(claim).__name__}"
            )
    precedence_keys = [claim.precedence_key() for claim in ranked]
    if len(set(precedence_keys)) != len(precedence_keys):
        raise CoreValidationError(
            "precedence claims contain duplicate claims (identical precedence keys)"
        )
    return tuple(sorted(ranked, key=WriterClaim.precedence_key))


class _KeyGate:
    """One key's exclusion gate: holder plus precedence-ordered waiters."""

    __slots__ = ("condition", "holder", "waiters")

    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.holder: WriterClaim | None = None
        self.waiters: list[WriterClaim] = []

    def _winner(self) -> WriterClaim | None:
        if not self.waiters:
            return None
        return min(self.waiters, key=WriterClaim.precedence_key)

    def acquire(self, key: str, claim: WriterClaim, timeout: float | None) -> None:
        with self.condition:
            if self.holder is not None and self.holder.command_id == claim.command_id:
                raise CoreValidationError(
                    f"reentrant acquisition of the keyed lock on {key!r} is forbidden"
                )
            for waiter in self.waiters:
                if waiter.command_id == claim.command_id:
                    raise CoreValidationError(
                        f"claim {claim.command_id!r} is already waiting for the keyed lock on {key!r}"
                    )
            self.waiters.append(claim)
            try:
                while True:
                    if self.holder is None:
                        winner = self._winner()
                        if winner is claim:
                            self.waiters.remove(claim)
                            self.holder = claim
                            self.condition.notify_all()
                            return
                    if not self.condition.wait(timeout):
                        # Timed out: one final grant check, then fail closed.
                        if self.holder is None:
                            winner = self._winner()
                            if winner is claim:
                                self.waiters.remove(claim)
                                self.holder = claim
                                self.condition.notify_all()
                                return
                        self.waiters.remove(claim)
                        self.condition.notify_all()
                        raise CoreValidationError(
                            f"timed out waiting for the keyed lock on {key!r}"
                        )
            except BaseException:
                if claim in self.waiters:
                    self.waiters.remove(claim)
                    self.condition.notify_all()
                raise

    def release(self, key: str, claim: WriterClaim) -> None:
        with self.condition:
            if self.holder is None or self.holder.command_id != claim.command_id:
                raise CoreValidationError(
                    f"cannot release the keyed lock on {key!r}: it is not held by "
                    f"claim {claim.command_id!r}"
                )
            self.holder = None
            self.condition.notify_all()

    def holder_claim(self) -> WriterClaim | None:
        with self.condition:
            return self.holder

    def waiting_claims(self) -> tuple[WriterClaim, ...]:
        with self.condition:
            return tuple(sorted(self.waiters, key=WriterClaim.precedence_key))


class KeyedLockManager:
    """Keyed lock manager: per-key gates, deterministic grant precedence."""

    def __init__(self) -> None:
        # The registry guard protects only the key -> gate lookup; it is
        # never held while a gate is granted, held or released, so keys
        # never serialize behind it.
        self._registry_guard = threading.Lock()
        self._gates: dict[str, _KeyGate] = {}

    def _gate_for(self, key: str) -> _KeyGate:
        require_identifier("keyed lock key", key)
        with self._registry_guard:
            gate = self._gates.get(key)
            if gate is None:
                gate = _KeyGate()
                self._gates[key] = gate
            return gate

    def acquire(self, key: str, *, claim: WriterClaim, timeout: float | None = None) -> None:
        """Acquire the key's gate for a writer claim (blocking)."""
        if not isinstance(claim, WriterClaim):
            raise CoreValidationError(
                f"keyed lock acquisition requires a WriterClaim, got {type(claim).__name__}"
            )
        self._gate_for(key).acquire(key, claim, timeout)

    def release(self, key: str, *, claim: WriterClaim) -> None:
        """Release the key's gate (fail closed when not held by the claim)."""
        if not isinstance(claim, WriterClaim):
            raise CoreValidationError(
                f"keyed lock release requires a WriterClaim, got {type(claim).__name__}"
            )
        self._gate_for(key).release(key, claim)

    @contextmanager
    def locked(self, key: str, *, claim: WriterClaim) -> Iterator[None]:
        self.acquire(key, claim=claim)
        try:
            yield
        finally:
            self.release(key, claim=claim)

    @contextmanager
    def locked_all(self, keys: Iterable[str], *, claim: WriterClaim) -> Iterator[None]:
        """Acquire several keys in lexicographic order, release in reverse.

        Sorted acquisition is the documented deadlock-avoidance discipline:
        every multi-key acquisition in the process takes its key set in the
        same total order, so no acquisition cycle can form.
        """
        ordered = sorted(set(keys))
        acquired: list[str] = []
        try:
            for key in ordered:
                self.acquire(key, claim=claim)
                acquired.append(key)
            yield
        finally:
            for key in reversed(acquired):
                self.release(key, claim=claim)

    def holder(self, key: str) -> WriterClaim | None:
        """The claim currently holding the key, if any (introspection)."""
        with self._registry_guard:
            gate = self._gates.get(key)
        return gate.holder_claim() if gate is not None else None

    def waiting(self, key: str) -> tuple[WriterClaim, ...]:
        """Queued claims for the key, in deterministic precedence order."""
        with self._registry_guard:
            gate = self._gates.get(key)
        return gate.waiting_claims() if gate is not None else ()


__all__ = [
    "KeyedLockManager",
    "WriterClaim",
    "resolve_precedence",
]
