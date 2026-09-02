from __future__ import annotations

from enum import StrEnum
from typing import Any

from src.core.errors import CoreValidationError


# The canonical payment lifecycle of the frozen interoperability contract:
# INITIATED -> AUTHORIZED -> ACCEPTED -> RESERVED -> COMMITTED -> SUBMITTED ->
# ACKNOWLEDGED -> PROCESSING -> CAPTURED/POSTED -> SETTLED -> FINAL with
# explicit RETURNED, REVERSED, FAILED, EXPIRED, DISPUTED and UNKNOWN branches.
# Adapters map native status into this vocabulary; they never redefine it.
class CanonicalPaymentStatus(StrEnum):
    INITIATED = "INITIATED"
    AUTHORIZED = "AUTHORIZED"
    ACCEPTED = "ACCEPTED"
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    SUBMITTED = "SUBMITTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    PROCESSING = "PROCESSING"
    CAPTURED_POSTED = "CAPTURED/POSTED"
    SETTLED = "SETTLED"
    FINAL = "FINAL"
    RETURNED = "RETURNED"
    REVERSED = "REVERSED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


CANONICAL_PAYMENT_STATUS_CHAIN: tuple[CanonicalPaymentStatus, ...] = (
    CanonicalPaymentStatus.INITIATED,
    CanonicalPaymentStatus.AUTHORIZED,
    CanonicalPaymentStatus.ACCEPTED,
    CanonicalPaymentStatus.RESERVED,
    CanonicalPaymentStatus.COMMITTED,
    CanonicalPaymentStatus.SUBMITTED,
    CanonicalPaymentStatus.ACKNOWLEDGED,
    CanonicalPaymentStatus.PROCESSING,
    CanonicalPaymentStatus.CAPTURED_POSTED,
    CanonicalPaymentStatus.SETTLED,
    CanonicalPaymentStatus.FINAL,
)

BRANCH_PAYMENT_STATUSES: tuple[CanonicalPaymentStatus, ...] = (
    CanonicalPaymentStatus.RETURNED,
    CanonicalPaymentStatus.REVERSED,
    CanonicalPaymentStatus.FAILED,
    CanonicalPaymentStatus.EXPIRED,
    CanonicalPaymentStatus.DISPUTED,
    CanonicalPaymentStatus.UNKNOWN,
)

# A payment status never stands in for settlement finality: SETTLED and FINAL
# here describe rail-reported payment completion, which is distinct from the
# settlement/finality authority owned by the settlement domain.
TERMINAL_PAYMENT_STATUSES: frozenset[CanonicalPaymentStatus] = frozenset({
    CanonicalPaymentStatus.SETTLED,
    CanonicalPaymentStatus.FINAL,
    CanonicalPaymentStatus.RETURNED,
    CanonicalPaymentStatus.REVERSED,
    CanonicalPaymentStatus.FAILED,
    CanonicalPaymentStatus.EXPIRED,
    CanonicalPaymentStatus.DISPUTED,
})

# Only an ambiguous outcome requires reconciliation before any retry decision;
# every other branch resolves the payment's rail-side outcome.
RECONCILIATION_REQUIRED_STATUSES: frozenset[CanonicalPaymentStatus] = frozenset({
    CanonicalPaymentStatus.UNKNOWN,
})

# Definitive negative outcomes after which a resubmission decision is safe to
# evaluate: known failure, expiry, return or reversal. Success outcomes, in
# flight states, disputes and ambiguity are never retry-safe.
RETRY_SAFE_PAYMENT_STATUSES: frozenset[CanonicalPaymentStatus] = frozenset({
    CanonicalPaymentStatus.FAILED,
    CanonicalPaymentStatus.EXPIRED,
    CanonicalPaymentStatus.RETURNED,
    CanonicalPaymentStatus.REVERSED,
})


def coerce_payment_status(status: Any) -> CanonicalPaymentStatus:
    from .records import coerce_enum

    return coerce_enum("payment status", CanonicalPaymentStatus, status)  # type: ignore[return-value]


def is_terminal_payment_status(status: Any) -> bool:
    return coerce_payment_status(status) in TERMINAL_PAYMENT_STATUSES


def requires_reconciliation(status: Any) -> bool:
    return coerce_payment_status(status) in RECONCILIATION_REQUIRED_STATUSES


def is_retry_safe_payment_status(status: Any) -> bool:
    return coerce_payment_status(status) in RETRY_SAFE_PAYMENT_STATUSES


__all__ = [
    "BRANCH_PAYMENT_STATUSES",
    "CANONICAL_PAYMENT_STATUS_CHAIN",
    "CanonicalPaymentStatus",
    "RECONCILIATION_REQUIRED_STATUSES",
    "RETRY_SAFE_PAYMENT_STATUSES",
    "TERMINAL_PAYMENT_STATUSES",
    "coerce_payment_status",
    "is_retry_safe_payment_status",
    "is_terminal_payment_status",
    "requires_reconciliation",
]
