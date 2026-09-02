"""Frozen public-boundary contracts for the liquidity domain (WORK-011).

The liquidity domain owns the frozen v0.1 lifecycles of the canonical
object vocabulary ``LiquidityOffer``, ``CreditOffer`` and
``CreditExposure``. No liquidity object type is listed in the frozen
protocol registry (the registry lists protocol-visible ``payswap/...``
object types only), so — following the sibling convention of
``src/market``, ``src/intent``, ``src/capability`` and ``src/value`` —
every liquidity object type below uses an internal non-registry
``liquidity/...`` format. No new protocol-visible name is invented here.
"""

from __future__ import annotations

# -- typed, versioned public boundary --------------------------------------

LIQUIDITY_PROTOCOL_VERSION = "v0.1"
LIQUIDITY_SCHEMA_VERSION = 1

# Internal (non-registry) object types of the liquidity domain.
LIQUIDITY_OFFER_OBJECT_TYPE = "liquidity/offer/v1"
CREDIT_OFFER_OBJECT_TYPE = "liquidity/credit-offer/v1"
CREDIT_EXPOSURE_OBJECT_TYPE = "liquidity/credit-exposure/v1"

# -- frozen concentration-control constants --------------------------------
#
# Concentration shares are measured in basis points of an explicitly
# declared denominator. The comparison against a cap is EXACT integer
# cross-multiplication (``part * 10000 > cap_bps * whole``) so a share of
# e.g. 5000.5 bps is flagged against a 5000 bps cap even though its floor
# display value equals the cap. Ratios are never computed in floating
# point.

#: Denominator of every concentration share (one hundred percent).
CONCENTRATION_DENOMINATOR_BPS = 10000

#: Maximum share of one corridor's offered capacity that a single
#: provider may contribute (per corridor, in the corridor's source
#: currency).
MAX_PROVIDER_CONCENTRATION_BPS = 5000

#: Maximum share of the total offered capacity of one currency that a
#: single corridor may contribute.
MAX_CORRIDOR_CONCENTRATION_BPS = 6000

#: Maximum share of the total drawn exposure of one currency that a
#: single counterparty may contribute.
MAX_COUNTERPARTY_CONCENTRATION_BPS = 4000

# -- documented deterministic ordering --------------------------------------
#
# Concentration and exposure reports order their entries by the explicit
# key ``(control kind, group)`` — lexicographic on the rendered group
# tuple. When two measured entities hold exactly equal shares, the
# lexicographic group key breaks the tie, so report order and digests are
# independent of input order and of insertion order.
CONCENTRATION_SORT_KEY = "KIND_GROUP_LEXICOGRAPHIC"
