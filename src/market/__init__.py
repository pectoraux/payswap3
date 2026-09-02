"""PaySwap market domain (WORK-010): market mechanisms, quotes and allocation.

The public boundary is typed and versioned:

- every durable object composes the canonical :class:`~src.core.envelope.ObjectEnvelope`
  (identity, state, provenance, version chain, integrity hash) owned by
  ``src.core`` and carries a domain seal computed with the single
  canonical hash authority, so tampered or spliced objects fail closed
  on the trusted deserialization path;
- no market object type is protocol-visible in the frozen registry, so —
  per the sibling convention — object types use internal non-registry
  ``market/...`` formats and no new registry name is invented;
- prices are exact integers in basis points and amounts are exact
  integers in minor units of the declared asset scale; fee arithmetic
  goes through the money domain's deterministic rounding authority
  (WORK-006) with a frozen rounding mode — no floating-point value is
  ever constructed;
- the demand side is consumed from the merged intent domain (WORK-008)
  and offers may reference capability provenance (WORK-009) as opaque
  identifiers; unmerged sibling implementations are never imported;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority) and market-level refusals use closed-vocabulary rejection
  reasons (submission rejections, allocation rejections, quote terminal
  reasons);
- lifecycles implement the frozen v0.1 command families: Quote
  ``Create/Amend/Accept/Reject/Commit/Cancel/Expire/Invalidate``,
  Market ``Create/Open/Close/Submit/Withdraw/Accept/Reject/Allocate/
  Cancel``, LiquidityOffer ``Create/Amend/Withdraw/Suspend/Resume/
  Expire`` and the bounded Reservation ``Create/Commit/Release/Expire``;
- mechanisms are pluggable: the RFQ default direct-accept mechanism and
  the uniform-clearing batch auction are frozen engines in
  ``MECHANISM_ENGINES``, and the documented allocation rule
  (``ALLOCATION_CLASS`` = price-time priority) is deterministic and
  exact;
- anti-gaming hooks fail closed: minimum quote validity, quote
  staleness/expiry enforcement, market price bands, self-dealing and
  duplicate-submission rejection, withdrawal locks after close and
  allocation, and the mirrored-quote collusion cluster check;
- this package mutates no accounting state and causes no external
  effect: encumbrance accounting, execution and settlement belong to
  later sibling Work Orders.
"""

from __future__ import annotations

from ..core import CoreValidationError, Provenance

from .contracts import (
    ALLOCATION_CLASS,
    COLLUSION_CLUSTER_MIN,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    DEFAULT_RESERVATION_HOLD_SECONDS,
    LIQUIDITY_OFFER_OBJECT_TYPE,
    MARKET_MECHANISM_OBJECT_TYPE,
    MARKET_PROTOCOL_VERSION,
    MARKET_SCHEMA_VERSION,
    MARKET_SUBMISSION_OBJECT_TYPE,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
    MIN_QUOTE_VALIDITY_SECONDS,
    QUOTE_OBJECT_TYPE,
    RESERVATION_OBJECT_TYPE,
    MechanismKind,
)
from .markets import (
    MarketMechanism,
    MarketSpec,
    MarketState,
    cancel_market,
    close_market,
    create_market,
    open_market,
)
from .mechanisms import (
    MECHANISM_ENGINES,
    AllocationRejection,
    AllocationRejectionReason,
    AllocationRequest,
    AllocationResult,
    AllocationStatus,
    BatchAuctionEngine,
    Fill,
    MechanismEngine,
    RfqEngine,
    resolve_engine,
)
from .offers import (
    LiquidityOffer,
    LiquidityOfferSpec,
    LiquidityOfferState,
    amend_liquidity_offer,
    create_liquidity_offer,
    expire_liquidity_offer,
    resume_liquidity_offer,
    suspend_liquidity_offer,
    withdraw_liquidity_offer,
)
from .pricing import MARKET_FEE_ROUNDING_MODE, fee_for_fill
from .quotes import (
    Quote,
    QuoteCommit,
    QuoteReasonCode,
    QuoteSpec,
    QuoteState,
    accept_quote,
    amend_quote,
    cancel_quote,
    commit_quote,
    create_quote,
    expire_quote,
    invalidate_quote,
    reject_quote,
    request_quote,
)
from .reservations import (
    Reservation,
    ReservationSpec,
    ReservationState,
    commit_reservation,
    create_reservation,
    expire_reservation,
    release_reservation,
)
from .session import MarketSession
from .submissions import (
    MarketSubmission,
    MarketSubmissionSpec,
    SubmissionRejectionReason,
    SubmissionResult,
    SubmissionState,
    build_submission,
    submission_object_id,
)

__all__ = [
    # versioned public boundary contracts
    "MARKET_PROTOCOL_VERSION",
    "MARKET_SCHEMA_VERSION",
    "QUOTE_OBJECT_TYPE",
    "MARKET_MECHANISM_OBJECT_TYPE",
    "MARKET_SUBMISSION_OBJECT_TYPE",
    "LIQUIDITY_OFFER_OBJECT_TYPE",
    "RESERVATION_OBJECT_TYPE",
    # frozen anti-gaming / rule constants
    "ALLOCATION_CLASS",
    "COLLUSION_CLUSTER_MIN",
    "MIN_QUOTE_VALIDITY_SECONDS",
    "DEFAULT_QUOTE_VALIDITY_SECONDS",
    "DEFAULT_RESERVATION_HOLD_SECONDS",
    "MIN_PRICE_BPS",
    "MAX_PRICE_BPS",
    "MARKET_FEE_ROUNDING_MODE",
    "MECHANISM_ENGINES",
    "MechanismKind",
    # liquidity offers
    "LiquidityOffer",
    "LiquidityOfferSpec",
    "LiquidityOfferState",
    "create_liquidity_offer",
    "amend_liquidity_offer",
    "suspend_liquidity_offer",
    "resume_liquidity_offer",
    "withdraw_liquidity_offer",
    "expire_liquidity_offer",
    # firm quotes
    "Quote",
    "QuoteSpec",
    "QuoteState",
    "QuoteReasonCode",
    "QuoteCommit",
    "create_quote",
    "amend_quote",
    "accept_quote",
    "reject_quote",
    "commit_quote",
    "cancel_quote",
    "expire_quote",
    "invalidate_quote",
    "request_quote",
    # reservations
    "Reservation",
    "ReservationSpec",
    "ReservationState",
    "create_reservation",
    "commit_reservation",
    "release_reservation",
    "expire_reservation",
    # markets
    "MarketMechanism",
    "MarketSpec",
    "MarketState",
    "create_market",
    "open_market",
    "close_market",
    "cancel_market",
    # submissions
    "MarketSubmission",
    "MarketSubmissionSpec",
    "SubmissionState",
    "SubmissionRejectionReason",
    "SubmissionResult",
    "build_submission",
    "submission_object_id",
    # mechanisms and allocation
    "MechanismEngine",
    "RfqEngine",
    "BatchAuctionEngine",
    "AllocationRequest",
    "AllocationResult",
    "AllocationStatus",
    "AllocationRejection",
    "AllocationRejectionReason",
    "Fill",
    "resolve_engine",
    # sessions and pricing
    "MarketSession",
    "fee_for_fill",
    # re-exported owning authorities (single source: src.core)
    "CoreValidationError",
    "Provenance",
]
