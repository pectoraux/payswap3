"""Frozen public-boundary contracts for the market domain (WORK-010).

The market domain owns the frozen v0.1 lifecycles of the canonical object
vocabulary ``Quote``, ``MarketMechanism``, ``MarketSubmission``,
``LiquidityOffer`` and ``Reservation``. No market object type is listed in
the frozen protocol registry (the registry lists protocol-visible
``payswap/...`` object types and the ``market`` event namespace only), so —
following the sibling convention of ``src/intent`` and
``src/capability`` — every market object type below uses an internal
non-registry ``market/...`` format. No new protocol-visible name is
invented here.
"""

from __future__ import annotations

from enum import StrEnum

# -- typed, versioned public boundary --------------------------------------

MARKET_PROTOCOL_VERSION = "v0.1"
MARKET_SCHEMA_VERSION = 1


class MechanismKind(StrEnum):
    """Closed vocabulary of pluggable market mechanisms.

    ``RFQ`` is the default direct-accept mechanism; ``BATCH_AUCTION`` is
    the uniform-clearing batch mechanism. The vocabulary is frozen: new
    mechanisms are new immutable versions of this contract, not runtime
    extensions.
    """

    RFQ = "RFQ"
    BATCH_AUCTION = "BATCH_AUCTION"

# Internal (non-registry) object types of the market domain.
QUOTE_OBJECT_TYPE = "market/quote/v1"
MARKET_MECHANISM_OBJECT_TYPE = "market/mechanism/v1"
MARKET_SUBMISSION_OBJECT_TYPE = "market/submission/v1"
LIQUIDITY_OFFER_OBJECT_TYPE = "market/liquidity-offer/v1"
RESERVATION_OBJECT_TYPE = "market/reservation/v1"

# -- documented deterministic allocation rule ------------------------------

#: Identifier of the documented batch allocation rule: strict
#: (price_bps, flat_fee, submitted_at, sequence) ordering — price-time
#: priority — with exact fixed-point fees and partial fills.
ALLOCATION_CLASS = "PRICE_TIME_PRIORITY"

# -- frozen anti-gaming guard constants ------------------------------------

#: A firm quote must stay valid for at least this many seconds; shorter
#: validity windows (flicker quotes) fail closed.
MIN_QUOTE_VALIDITY_SECONDS = 10

#: Validity window of a default RFQ firm quote.
DEFAULT_QUOTE_VALIDITY_SECONDS = 60

#: Hold window of a reservation created by a batch allocation.
DEFAULT_RESERVATION_HOLD_SECONDS = 3600

#: Minimum number of distinct providers quoting the identical
#: (price, flat fee, amount) triple before a price-dispersed batch is
#: flagged as suspected collusion.
COLLUSION_CLUSTER_MIN = 3

#: Global price band, in basis points of the quoted amount.
MIN_PRICE_BPS = 1
MAX_PRICE_BPS = 10000
