"""Frozen domain contracts for the PaySwap value domain (WORK-005).

The value domain implements the frozen v0.1 ledger/posting model:
assets, value instruments, accounts, journals, postings, holds, derived
balances and reconciliation evidence, plus the funding-source object the
intent domain references (WORK-008).

Object identity discipline:

* the frozen protocol registry lists no value object types, so every
  durable value object uses an internal (non-registry) object type of
  the form ``value/<object>/v1``; registry-listed ``payswap/*`` types are
  foreign here and rejected by the record classes;
* ``VALUE_PROTOCOL_VERSION`` is the frozen governing architecture
  version and every record binds to it;
* ``MAX_SCALE`` bounds the declared decimal scale of an asset exactly as
  the sibling intent domain does; exact scale arithmetic (rounding,
  quantization, allocation, FX) is owned by the money domain (WORK-006).
"""

from __future__ import annotations

from enum import StrEnum

VALUE_SCHEMA_VERSION = 1
VALUE_PROTOCOL_VERSION = "v0.1"

ASSET_OBJECT_TYPE = "value/asset/v1"
ACCOUNT_OBJECT_TYPE = "value/account/v1"
INSTRUMENT_OBJECT_TYPE = "value/instrument/v1"
POSTING_OBJECT_TYPE = "value/posting/v1"
HOLD_OBJECT_TYPE = "value/hold/v1"
JOURNAL_OBJECT_TYPE = "value/journal/v1"
FUNDING_SOURCE_OBJECT_TYPE = "value/funding-source/v1"
RECONCILIATION_OBJECT_TYPE = "value/reconciliation/v1"
BALANCE_OBJECT_TYPE = "value/balances/v1"

# Structural sanity bound shared with the intent domain; exact scale and
# rounding semantics are owned by the money domain (WORK-006).
MAX_SCALE = 18


class EntrySide(StrEnum):
    """Double-entry leg side (and the account normal side)."""

    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class BalanceView(StrEnum):
    """The closed vocabulary of derived balance views.

    ``AVAILABLE``, ``PENDING``, ``ENCUMBERED``, ``RESTRICTED`` and
    ``SETTLED`` are ledger views: value is classified into them by the
    views carried on posting legs, and value only moves between views
    through explicit postings. ``HELD`` is derived exclusively from
    active hold records; its ledger mirror is the ``ENCUMBERED`` view,
    and equality of the two is the hold reconciliation invariant the
    reconciliation record verifies.
    """

    AVAILABLE = "AVAILABLE"
    HELD = "HELD"
    PENDING = "PENDING"
    ENCUMBERED = "ENCUMBERED"
    RESTRICTED = "RESTRICTED"
    SETTLED = "SETTLED"


#: Views that posting legs may carry. ``HELD`` is deliberately absent:
#: holds enter the ledger as ``ENCUMBERED`` legs, so a single mechanism
#: owns each view.
LEDGER_VIEWS = frozenset(
    {
        BalanceView.AVAILABLE,
        BalanceView.PENDING,
        BalanceView.ENCUMBERED,
        BalanceView.RESTRICTED,
        BalanceView.SETTLED,
    }
)

#: Ledger views that contribute to the conserved total position.
TOTAL_VIEWS = (
    BalanceView.AVAILABLE,
    BalanceView.PENDING,
    BalanceView.ENCUMBERED,
    BalanceView.RESTRICTED,
    BalanceView.SETTLED,
)
