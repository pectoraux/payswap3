"""PaySwap protocol reservation domain (WORK-012).

The public boundary is typed and versioned:

- **protocol-level resource reservations.** This package owns the frozen
  v0.1 ``Reservation`` command family
  ``Create/Hold/Commit/Amend/Release/Expire/Default/Consume`` with the
  closed state vocabulary ``RESERVED/HELD/COMMITTED/RELEASED/EXPIRED/
  DEFAULTED/CONSUMED``, versioned sealed transitions and terminal states.
  Boundary with WORK-010: ``src/market`` owns a bounded mechanism-local
  claim artifact restricted to ``Create/Commit/Release/Expire``; this
  package is the protocol resource-reservation domain — the full command
  family, encumbrance holding, amendment, conditional commit, default
  handling and consumption, plus keyed concurrency contracts;
- **conditional commit.** A commit succeeds only when the availability
  window is valid at ``as_of``, every declared condition is satisfied by
  explicit evidence and the writer expected the current object version;
  it fails closed otherwise;
- **keyed concurrency.** Locking is scoped per reservation resource key
  with deterministic precedence (earliest ``requested_at``, then command
  id, then actor); independent keys never serialize behind a global mutex;
  the versioned store enforces expected-version preconditions, atomic
  validate-all-then-apply batches with multi-object rollback, and
  live-key exclusivity (a resource key admits at most one non-terminal
  reservation);
- **consumed dependencies, never reimplemented.** The expected-version
  precondition type is the transition kernel's
  (:class:`src.transition.ExpectedVersion`, WORK-003), the exact amount is
  the value domain's (:class:`src.value.Amount`, WORK-005 — the sole
  accounting authority, referenced here with no ledger mutation), and the
  half-open availability window is the capability domain's
  (:class:`src.capability.OperatingWindow`, WORK-009). Unmerged sibling
  domains are never imported;
- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` and carries a domain seal
  computed with the single canonical hash authority, so tampered or
  spliced objects fail closed on the trusted deserialization path. No
  reservation object type is protocol-visible in the frozen registry, so —
  per the sibling convention — object types use internal non-registry
  ``reservation/...`` formats and no new registry name is invented;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority), and every command validates its source state, window and
  condition preconditions before advancing;
- this package mutates no accounting state and causes no external effect:
  a reservation reserves capacity — encumbrance postings belong to the
  value domain, execution and settlement to later sibling Work Orders.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.transition import ExpectedVersion
from src.value.amount import Amount
from src.capability.windows import OperatingWindow

from .concurrency import KeyedLockManager, WriterClaim, resolve_precedence
from .conditions import (
    CommitEvidence,
    ConditionEvaluation,
    ConditionKind,
    ConditionSpec,
    evaluate_condition_satisfaction,
)
from .contracts import (
    RESERVATION_API_VERSION,
    RESERVATION_COMMANDS,
    RESERVATION_OBJECT_TYPE,
    RESERVATION_PROTOCOL_VERSION,
    RESERVATION_SCHEMA_VERSION,
    ReservationCommand,
)
from .records import (
    DefaultReason,
    RESERVATION_TERMINAL_STATES,
    RESERVATION_TRANSITIONS,
    Reservation,
    ReservationSpec,
    ReservationState,
    amend_reservation,
    commit_reservation,
    consume_reservation,
    create_reservation,
    default_reservation,
    expire_reservation,
    hold_reservation,
    release_reservation,
)
from .store import PAYLOAD_IDENTITY_FIELDS, ReservationStore

__all__ = [
    # versioned public boundary contracts
    "RESERVATION_API_VERSION",
    "RESERVATION_PROTOCOL_VERSION",
    "RESERVATION_SCHEMA_VERSION",
    "RESERVATION_OBJECT_TYPE",
    "RESERVATION_COMMANDS",
    "ReservationCommand",
    # lifecycle records (frozen 8-command family)
    "Reservation",
    "ReservationSpec",
    "ReservationState",
    "DefaultReason",
    "RESERVATION_TERMINAL_STATES",
    "RESERVATION_TRANSITIONS",
    "create_reservation",
    "hold_reservation",
    "amend_reservation",
    "commit_reservation",
    "release_reservation",
    "expire_reservation",
    "default_reservation",
    "consume_reservation",
    # conditional-commit condition vocabulary
    "ConditionKind",
    "ConditionSpec",
    "CommitEvidence",
    "ConditionEvaluation",
    "evaluate_condition_satisfaction",
    # keyed concurrency
    "WriterClaim",
    "KeyedLockManager",
    "resolve_precedence",
    # versioned store
    "ReservationStore",
    "PAYLOAD_IDENTITY_FIELDS",
    # consumed owning authorities (single sources: src.core,
    # src.transition, src.value, src.capability)
    "CoreValidationError",
    "Provenance",
    "ExpectedVersion",
    "Amount",
    "OperatingWindow",
]
