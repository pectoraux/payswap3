"""Payment-chain execution and exact cross-asset cost arithmetic.

A payment chain pushes one source-side amount (in the intent asset)
forward through a route: every hop converts its input through the hop's
exact FX rate using the money authority's conversion (WORK-006) with the
frozen compiler FX rounding mode, and its fee is computed by the market
authority's ``fee_for_fill`` (WORK-010) on the hop's SOURCE-side fill.

The COST metric converts every hop's fee into the intent asset through
the exact rational composition of the suffix rates of the route (pure
integer cross-multiplication, rounded once by the money rounding
authority under the frozen compiler cost-reporting mode). Residuals are
carried explicitly; value is never silently created or dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from src.core.errors import CoreValidationError
from src.market import fee_for_fill
from src.money import Amount, convert

from ._validation import require_int
from .contracts import (
    BPS_DENOMINATOR,
    COMPILER_COST_ROUNDING_MODE,
    COMPILER_FX_ROUNDING_MODE,
)
from .inputs import RouteHopOffer
from .routing import Route


@dataclass(frozen=True, slots=True)
class HopExecution:
    """The deterministic execution record of one hop inside one payment."""

    hop: RouteHopOffer
    input_value: int
    output_value: int
    residual_numerator: int
    residual_denominator: int
    fee_value: int
    fx_numerator: int | None
    fx_denominator: int | None
    fx_source_currency: str | None
    fx_target_currency: str | None
    fx_rounding_mode: str | None


def execute_hop(hop: RouteHopOffer, input_value: int) -> HopExecution:
    """Execute one hop deterministically on an exact input value."""
    if not isinstance(hop, RouteHopOffer):
        raise CoreValidationError("hop execution requires a RouteHopOffer")
    require_int("hop input_value", input_value, minimum=0)
    if hop.fx_rate is None:
        output_value = input_value
        residual_numerator = 0
        residual_denominator = 1
        fx_numerator = None
        fx_denominator = None
        fx_source_currency = None
        fx_target_currency = None
        fx_rounding_mode = None
    else:
        source_amount = Amount(
            currency=hop.fx_rate.source,
            value=input_value,
            scale=hop.source_scale,
        )
        conversion = convert(
            hop.fx_rate, source_amount, COMPILER_FX_ROUNDING_MODE
        )
        output_value = conversion.target.value
        residual_numerator = conversion.residual_numerator
        residual_denominator = conversion.residual_denominator
        fx_numerator = hop.fx_rate.numerator
        fx_denominator = hop.fx_rate.denominator
        fx_source_currency = hop.fx_rate.source.code
        fx_target_currency = hop.fx_rate.target.code
        fx_rounding_mode = COMPILER_FX_ROUNDING_MODE.value
    fee_value = fee_for_fill(input_value, hop.price_bps, hop.flat_fee)
    return HopExecution(
        hop=hop,
        input_value=input_value,
        output_value=output_value,
        residual_numerator=residual_numerator,
        residual_denominator=residual_denominator,
        fee_value=fee_value,
        fx_numerator=fx_numerator,
        fx_denominator=fx_denominator,
        fx_source_currency=fx_source_currency,
        fx_target_currency=fx_target_currency,
        fx_rounding_mode=fx_rounding_mode,
    )


@dataclass(frozen=True, slots=True)
class PaymentChain:
    """One payment executed forward through its whole route."""

    route: Route
    source_value: int
    hops: tuple[HopExecution, ...]
    delivered_value: int
    cost_value: int
    latency_seconds: int
    capital_time: int
    reliability: Fraction
    liquidity_utilization: Fraction
    risk_penalty: int
    privacy_exposure: int


def execute_route(route: Route, source_value: int, *, base_scale: int) -> PaymentChain:
    """Execute one payment forward from the source-side amount.

    ``base_scale`` is the intent asset's minor-unit scale; the route's
    first hop source and last hop target are both the intent asset at
    that scale (validated by the compiler before enumeration output is
    used).
    """
    if not route:
        raise CoreValidationError("a payment route must contain at least one hop")
    require_int("payment source_value", source_value, minimum=1)
    require_int("payment base_scale", base_scale, minimum=0)
    executions: list[HopExecution] = []
    current = source_value
    for hop in route:
        execution = execute_hop(hop, current)
        executions.append(execution)
        current = execution.output_value
    delivered = current
    cost = _route_cost_in_base(route, executions, base_scale=base_scale)
    latency = sum(hop.latency_seconds for hop in route)
    capital_time = sum(
        execution.input_value * execution.hop.latency_seconds
        for execution in executions
    )
    reliability = Fraction(1, 1)
    liquidity = Fraction(0, 1)
    risk_penalty = 0
    for execution in executions:
        reliability *= Fraction(execution.hop.reliability_bps, BPS_DENOMINATOR)
        liquidity += Fraction(execution.input_value, execution.hop.capacity)
        risk_penalty += BPS_DENOMINATOR - execution.hop.reliability_bps
    return PaymentChain(
        route=route,
        source_value=source_value,
        hops=tuple(executions),
        delivered_value=delivered,
        cost_value=cost,
        latency_seconds=latency,
        capital_time=capital_time,
        reliability=reliability,
        liquidity_utilization=liquidity,
        risk_penalty=risk_penalty,
        privacy_exposure=len(route) - 1,
    )


def _route_cost_in_base(
    route: Route,
    executions: tuple[HopExecution, ...] | list[HopExecution],
    *,
    base_scale: int,
) -> int:
    """Total route fee expressed in the intent asset's minor units.

    Hop ``i``'s fee is in its source asset; the exact suffix composition
    of the route's rates (rational product, no intermediate rounding)
    carries it to the intent asset, where the money rounding authority
    rounds once under the frozen compiler cost-reporting mode.
    """
    from src.money.rounding import round_ratio

    total = 0
    hop_count = len(route)
    for index, execution in enumerate(executions):
        hop = route[index]
        suffix_num = 1
        suffix_den = 1
        for later in route[index:]:
            if later.fx_rate is None:
                continue
            suffix_num *= later.fx_rate.numerator
            suffix_den *= later.fx_rate.denominator
        if hop.fx_rate is None and suffix_num == 1 and suffix_den == 1:
            # Same-asset fee at the base scale: exact.
            total += execution.fee_value
            continue
        scaled_numerator = execution.fee_value * suffix_num * 10**base_scale
        scaled_denominator = suffix_den * 10**hop.source_scale
        total += round_ratio(
            scaled_numerator, scaled_denominator, COMPILER_COST_ROUNDING_MODE
        )
    return total


def hop_plan_dict(execution: HopExecution) -> dict[str, Any]:
    """Canonical serialization projection of one executed hop."""
    return {
        "hop_id": execution.hop.hop_id,
        "provider": execution.hop.provider,
        "capability_id": execution.hop.capability_id,
        "offer_id": execution.hop.offer_id,
        "quote_id": execution.hop.quote_id,
        "reservation_id": execution.hop.reservation_id,
        "compliance_assessment_id": execution.hop.compliance_assessment_id,
        "source_asset": execution.hop.corridor.source_asset,
        "target_asset": execution.hop.corridor.target_asset,
        "source_scale": execution.hop.source_scale,
        "target_scale": execution.hop.target_scale,
        "input_value": execution.input_value,
        "output_value": execution.output_value,
        "fx_source_currency": execution.fx_source_currency,
        "fx_target_currency": execution.fx_target_currency,
        "fx_numerator": execution.fx_numerator,
        "fx_denominator": execution.fx_denominator,
        "fx_rounding_mode": execution.fx_rounding_mode,
        "residual_numerator": execution.residual_numerator,
        "residual_denominator": execution.residual_denominator,
        "fee_value": execution.fee_value,
        "price_bps": execution.hop.price_bps,
        "flat_fee": execution.hop.flat_fee,
        "reliability_bps": execution.hop.reliability_bps,
        "latency_seconds": execution.hop.latency_seconds,
    }
