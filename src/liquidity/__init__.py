"""PaySwap liquidity domain (WORK-011): liquidity offers, credit offers and
exposure controls.

The public boundary is typed and versioned:

- every durable object composes the canonical :class:`~src.core.envelope.ObjectEnvelope`
  (identity, state, provenance, version chain, integrity hash) owned by
  ``src.core`` and carries a domain seal computed with the single
  canonical hash authority, so tampered or spliced objects fail closed
  on the trusted deserialization path;
- no liquidity object type is protocol-visible in the frozen registry, so —
  per the sibling convention — object types use internal non-registry
  ``liquidity/...`` formats and no new registry name is invented;
- liquidity is a bounded capability/resource model: offers and facilities
  carry explicit positive fixed-point capacity/limits
  (:class:`~src.money.amount.Amount`, the money authority's exact
  arithmetic), explicit REQUIRED provider capability references
  (WORK-009, opaque identifiers), half-open UTC windows
  ``[from, until)`` and corridor semantics (opaque source/target asset
  pairs). Nothing here is unbounded money creation;
- credit facilities implement the full frozen ``Credit`` command family
  including ``Draw/Repay/Restructure/Default``; the facility invariant
  ``utilized <= limit`` always holds, withdrawal and expiry require zero
  outstanding utilization, default requires outstanding exposure and is
  terminal, and collateral is carried as opaque value-domain references
  (the value domain, WORK-005, owns the actual collateral accounting);
- exposure is a CONTROL model, never a second financial authority:
  :class:`CreditExposure` records per-counterparty/per-corridor limits
  and utilization against offered capacity, :func:`assess_exposure`
  detects aggregate breaches, and :func:`evaluate_concentration` applies
  the frozen concentration caps with exact integer cross-multiplied
  basis-point shares and deterministic ``(kind, group)`` ordering and
  tie-breaks. No ledger, hold or posting is ever mutated;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority) and every command fails closed on unknown states, windows,
  currencies or limits — no silent coercion;
- timestamps are declared data (explicit ``as_of``), never clock reads:
  the domain is deterministic and wall-clock-free.
"""

from __future__ import annotations

from ..core import CoreValidationError, Provenance

from .contracts import (
    CONCENTRATION_DENOMINATOR_BPS,
    CREDIT_EXPOSURE_OBJECT_TYPE,
    CREDIT_OFFER_OBJECT_TYPE,
    LIQUIDITY_OFFER_OBJECT_TYPE,
    LIQUIDITY_PROTOCOL_VERSION,
    LIQUIDITY_SCHEMA_VERSION,
    MAX_CORRIDOR_CONCENTRATION_BPS,
    MAX_COUNTERPARTY_CONCENTRATION_BPS,
    MAX_PROVIDER_CONCENTRATION_BPS,
)
from .corridors import Corridor
from .credit import (
    CreditOffer,
    CreditOfferSpec,
    CreditOfferState,
    amend_credit_offer,
    create_credit_offer,
    credit_available_capacity,
    default_credit,
    draw_credit,
    expire_credit_offer,
    repay_credit,
    restructure_credit,
    resume_credit_offer,
    suspend_credit_offer,
    withdraw_credit_offer,
)
from .exposure import (
    AggregatedExposure,
    ConcentrationControlKind,
    ConcentrationEntry,
    ConcentrationReport,
    CreditExposure,
    CreditExposureSpec,
    CreditExposureState,
    ExposureAssessment,
    ExposureCheck,
    ExposureStatus,
    aggregate_credit_utilization,
    amend_credit_exposure,
    assess_exposure,
    create_credit_exposure,
    draw_against_exposure,
    evaluate_concentration,
    expire_credit_exposure,
    exposure_available_capacity,
    repay_against_exposure,
    resume_credit_exposure,
    suspend_credit_exposure,
    withdraw_credit_exposure,
)
from .offers import (
    LiquidityOffer,
    LiquidityOfferSpec,
    LiquidityOfferState,
    amend_liquidity_offer,
    create_liquidity_offer,
    expire_liquidity_offer,
    liquidity_offer_available_at,
    resume_liquidity_offer,
    suspend_liquidity_offer,
    withdraw_liquidity_offer,
)

__all__ = [
    # versioned public boundary contracts
    "LIQUIDITY_PROTOCOL_VERSION",
    "LIQUIDITY_SCHEMA_VERSION",
    "LIQUIDITY_OFFER_OBJECT_TYPE",
    "CREDIT_OFFER_OBJECT_TYPE",
    "CREDIT_EXPOSURE_OBJECT_TYPE",
    # frozen concentration-control constants
    "CONCENTRATION_DENOMINATOR_BPS",
    "MAX_PROVIDER_CONCENTRATION_BPS",
    "MAX_CORRIDOR_CONCENTRATION_BPS",
    "MAX_COUNTERPARTY_CONCENTRATION_BPS",
    # corridors
    "Corridor",
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
    "liquidity_offer_available_at",
    # credit offers (facilities)
    "CreditOffer",
    "CreditOfferSpec",
    "CreditOfferState",
    "create_credit_offer",
    "amend_credit_offer",
    "suspend_credit_offer",
    "resume_credit_offer",
    "withdraw_credit_offer",
    "expire_credit_offer",
    "draw_credit",
    "repay_credit",
    "restructure_credit",
    "default_credit",
    "credit_available_capacity",
    # credit exposure controls
    "CreditExposure",
    "CreditExposureSpec",
    "CreditExposureState",
    "ExposureStatus",
    "ExposureAssessment",
    "ExposureCheck",
    "create_credit_exposure",
    "amend_credit_exposure",
    "suspend_credit_exposure",
    "resume_credit_exposure",
    "withdraw_credit_exposure",
    "expire_credit_exposure",
    "draw_against_exposure",
    "repay_against_exposure",
    "exposure_available_capacity",
    # aggregation, assessment and concentration controls
    "AggregatedExposure",
    "ConcentrationControlKind",
    "ConcentrationEntry",
    "ConcentrationReport",
    "aggregate_credit_utilization",
    "assess_exposure",
    "evaluate_concentration",
    # re-exported owning authorities (single source: src.core)
    "CoreValidationError",
    "Provenance",
]
