"""PaySwap value domain (WORK-005) — public API surface.

The contract is defined by ``src/value/test_value.py`` (written red-first
against this boundary). Records are immutable sealed composites
(envelope + payload + domain seal) over the remediated canonical core; the
ledger facade applies the frozen ledger/posting model's guards fail-closed.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    ACCOUNT_OBJECT_TYPE,
    ASSET_OBJECT_TYPE,
    BALANCE_OBJECT_TYPE,
    FUNDING_SOURCE_OBJECT_TYPE,
    HOLD_OBJECT_TYPE,
    INSTRUMENT_OBJECT_TYPE,
    JOURNAL_OBJECT_TYPE,
    LEDGER_VIEWS,
    MAX_SCALE,
    POSTING_OBJECT_TYPE,
    BalanceView,
    EntrySide,
)
from .amount import Amount
from .asset import Asset, AssetKind, AssetState
from .account import (
    NON_NEGATIVE_CLASSES,
    Account,
    AccountState,
    SegregationClass,
)
from .instrument import InstrumentState, ValueInstrument
from .posting import (
    AssetTotals,
    Posting,
    PostingClass,
    PostingLeg,
    PostingState,
)
from .hold import Hold, HoldState
from .journal import Journal, JournalState
from .balances import Balance
from .reconciliation import (
    AccountHolds,
    AssetSheet,
    Reconciliation,
    ReconciliationState,
)
from .funding import FundingSource, FundingSourceState
from .ledger import ValueLedger

__all__ = [
    "ACCOUNT_OBJECT_TYPE",
    "ASSET_OBJECT_TYPE",
    "BALANCE_OBJECT_TYPE",
    "FUNDING_SOURCE_OBJECT_TYPE",
    "HOLD_OBJECT_TYPE",
    "INSTRUMENT_OBJECT_TYPE",
    "JOURNAL_OBJECT_TYPE",
    "LEDGER_VIEWS",
    "MAX_SCALE",
    "NON_NEGATIVE_CLASSES",
    "POSTING_OBJECT_TYPE",
    "Account",
    "AccountHolds",
    "AccountState",
    "Amount",
    "Asset",
    "AssetKind",
    "AssetSheet",
    "AssetState",
    "AssetTotals",
    "Balance",
    "BalanceView",
    "CoreValidationError",
    "EntrySide",
    "FundingSource",
    "FundingSourceState",
    "Hold",
    "HoldState",
    "InstrumentState",
    "Journal",
    "JournalState",
    "Posting",
    "PostingClass",
    "PostingLeg",
    "PostingState",
    "Reconciliation",
    "ReconciliationState",
    "SegregationClass",
    "ValueInstrument",
    "ValueLedger",
]
