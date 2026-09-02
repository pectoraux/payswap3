"""Constraint precedence, soft-objective ranking and deterministic tie-breaks.

Hard constraints dominate soft objectives — the constitution's
optimization clause. This module makes the precedence explicit and
machine-checkable:

* **Hard gates** (in the frozen precedence order ``compliance > authority
  > settlement > safety > accounting``) reject candidates outright. A
  route is evaluated against the four static gates and rejected at the
  FIRST failing gate; the accounting gate then evaluates complete
  payment shapes (fill windows, capacity, funding sufficiency, delivery
  window). No objective ranking ever sees a rejected candidate.
* **Soft objectives** use the intent domain's closed
  ``OptimizationObjective`` vocabulary (the ten frozen objective
  dimensions of the constitution's optimization clause). Each objective
  maps to exactly one deterministic, exactly-computed metric (integer or
  exact ``Fraction``; never a float):
  ``COST`` total fee in intent-asset minor units; ``RELIABILITY`` exact
  product of per-hop basis-point reliabilities (higher is better);
  ``TIME`` (completion instant, total latency); ``ROUTE`` hop count;
  ``AMOUNT`` |delivered − intent amount|; ``PAYMENT_SHAPE`` payment
  count; ``LIQUIDITY`` exact capacity-utilization fraction (the frozen
  capital-utilization objective); ``RISK`` reliability deficit sum;
  ``PRIVACY`` intermediate-custodian count; ``CREDIT`` zero (no credit
  draw exists in the v0.1 compiler input set — neutral, documented).
  The Work Order's capital-efficiency dimension is materialized as the
  exact capital-time metric (minor-unit-seconds in transit) carried in
  every plan's totals, and as the ``LIQUIDITY`` objective's exact
  capacity-utilization ranking; a dedicated ``CAPITAL_EFFICIENCY``
  objective member does not exist in the frozen intent-domain
  vocabulary and is deliberately NOT invented here (one authority per
  concept — the intent domain owns the objective vocabulary).
* **Ties** are broken by the canonical shape digest (byte order): the
  same input always selects the same winner — no entropy, no
  insertion-order dependence.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable, Sequence

from src.capability import CapabilityState
from src.core.errors import CoreValidationError
from src.intent import EconomicSlack, Intent, OptimizationObjective
from src.reservation import ReservationState
from src.safety import ComplianceVerdict, FraudDecisionState

from ._validation import (
    format_utc_timestamp,
    parse_utc_timestamp,
    require_int,
    utc_epoch_seconds,
)
from .candidates import PaymentChain
from .contracts import (
    AUTHORITY_TIER_RANK,
    COMPILER_PROTOCOL_VERSION,
    HARD_GATE_AUTHORITY,
    HARD_GATE_COMPLIANCE,
    HARD_GATE_SAFETY,
    HARD_GATE_SETTLEMENT,
)
from .inputs import CompilationRequest
from .routing import Route, route_latency_seconds
from .shapes import ShapeCandidate


@dataclass(frozen=True, slots=True)
class RouteRejection:
    """One route rejected at one hard gate, with the explicit reason."""

    gate: str
    reason: str


@dataclass(frozen=True, slots=True)
class CandidateMetrics:
    """The exact, deterministic metric vector of one feasible shape."""

    total_cost_value: int
    total_source_value: int
    total_delivered_value: int
    amount_distance: int
    completion_epoch: int
    completion: str
    total_latency_seconds: int
    hop_count: int
    payment_count: int
    reliability: Fraction
    capital_time: int
    liquidity_utilization: Fraction
    risk_penalty: int
    privacy_exposure: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "total_cost_value": self.total_cost_value,
            "total_source_value": self.total_source_value,
            "total_delivered_value": self.total_delivered_value,
            "amount_distance": self.amount_distance,
            "completion_epoch": self.completion_epoch,
            "completion": self.completion,
            "total_latency_seconds": self.total_latency_seconds,
            "hop_count": self.hop_count,
            "payment_count": self.payment_count,
            "reliability_numerator": self.reliability.numerator,
            "reliability_denominator": self.reliability.denominator,
            "capital_time": self.capital_time,
            "liquidity_numerator": self.liquidity_utilization.numerator,
            "liquidity_denominator": self.liquidity_utilization.denominator,
            "risk_penalty": self.risk_penalty,
            "privacy_exposure": self.privacy_exposure,
        }


@dataclass(frozen=True, slots=True)
class FeasibleCandidate:
    """A feasible payment shape with its chains, metrics and digest."""

    shape: ShapeCandidate
    chains: tuple[PaymentChain, ...]
    metrics: CandidateMetrics
    digest: str


def evaluate_route(
    route: Route,
    *,
    request: CompilationRequest,
    intent: Intent,
    slack: EconomicSlack,
) -> RouteRejection | None:
    """Evaluate the four static hard gates for one route.

    Returns the first rejection in precedence order, or ``None`` when
    the route is statically feasible.
    """
    checks = (
        (HARD_GATE_COMPLIANCE, _compliance_check),
        (HARD_GATE_AUTHORITY, _authority_check),
        (HARD_GATE_SETTLEMENT, _settlement_check),
        (HARD_GATE_SAFETY, _safety_check),
    )
    for gate, check in checks:
        reason = check(route, request=request, intent=intent, slack=slack)
        if reason is not None:
            return RouteRejection(gate=gate, reason=reason)
    return None


def _compliance_check(
    route: Route, *, request: CompilationRequest, intent: Intent, slack: EconomicSlack
) -> str | None:
    for hop in route:
        if hop.compliance_verdict != ComplianceVerdict.SATISFIED.value:
            return (
                f"hop {hop.hop_id}: compliance verdict {hop.compliance_verdict} is "
                "binding — compliance cannot be bypassed through routing"
            )
        if request.required_jurisdiction not in hop.jurisdictions:
            return (
                f"hop {hop.hop_id}: jurisdictions {list(hop.jurisdictions)} do not "
                f"cover the required jurisdiction {request.required_jurisdiction}"
            )
    return None


def _authority_check(
    route: Route, *, request: CompilationRequest, intent: Intent, slack: EconomicSlack
) -> str | None:
    minimum_rank = AUTHORITY_TIER_RANK.index(request.minimum_authority_tier)
    for hop in route:
        if hop.capability_state != CapabilityState.ACTIVE.value:
            return (
                f"hop {hop.hop_id}: capability state {hop.capability_state} is not "
                f"{CapabilityState.ACTIVE.value}"
            )
        if hop.capability_protocol_version != COMPILER_PROTOCOL_VERSION:
            return (
                f"hop {hop.hop_id}: capability protocol version "
                f"{hop.capability_protocol_version} is not the frozen "
                f"{COMPILER_PROTOCOL_VERSION}"
            )
        if AUTHORITY_TIER_RANK.index(hop.authority_tier) < minimum_rank:
            return (
                f"hop {hop.hop_id}: authority tier {hop.authority_tier} is below the "
                f"required minimum {request.minimum_authority_tier}"
            )
    return None


def _settlement_check(
    route: Route, *, request: CompilationRequest, intent: Intent, slack: EconomicSlack
) -> str | None:
    as_of_epoch = utc_epoch_seconds("request.as_of", request.as_of)
    for hop in route:
        if not _window_contains(hop.window_opens_at, request.as_of, hop.window_closes_at):
            return (
                f"hop {hop.hop_id}: as_of {request.as_of} is outside the hop "
                f"operating window [{hop.window_opens_at}, {hop.window_closes_at})"
            )
        if not _window_contains(
            hop.quote_valid_from, request.as_of, hop.quote_valid_until
        ):
            return (
                f"hop {hop.hop_id}: quote {hop.quote_id} is not valid at "
                f"{request.as_of} (validity [{hop.quote_valid_from}, "
                f"{hop.quote_valid_until}))"
            )
        if hop.reservation_state not in (
            ReservationState.RESERVED.value,
            ReservationState.HELD.value,
        ):
            return (
                f"hop {hop.hop_id}: reservation state {hop.reservation_state} is not "
                f"{ReservationState.RESERVED.value} or {ReservationState.HELD.value}"
            )
        if not _window_contains(
            hop.reservation_opens_at, request.as_of, hop.reservation_closes_at
        ):
            return (
                f"hop {hop.hop_id}: as_of {request.as_of} is outside the reservation "
                f"window [{hop.reservation_opens_at}, {hop.reservation_closes_at})"
            )
    completion = as_of_epoch + route_latency_seconds(route)
    deadline_epoch = utc_epoch_seconds("intent.deadline", intent.spec.deadline)
    latest_epoch = utc_epoch_seconds(
        "slack.latest_completion", slack.spec.latest_completion
    )
    earliest_epoch = utc_epoch_seconds(
        "slack.earliest_completion", slack.spec.earliest_completion
    )
    if completion > min(deadline_epoch, latest_epoch):
        boundary = min(intent.spec.deadline, slack.spec.latest_completion)
        return (
            f"route completion {format_utc_timestamp(completion)} is after the "
            f"deadline boundary {boundary}"
        )
    if completion < earliest_epoch:
        return (
            f"route completion {format_utc_timestamp(completion)} is before the "
            f"earliest completion {slack.spec.earliest_completion}"
        )
    return None


def _safety_check(
    route: Route, *, request: CompilationRequest, intent: Intent, slack: EconomicSlack
) -> str | None:
    for hop in route:
        if hop.fraud_decision_state in (
            FraudDecisionState.BLOCKED.value,
            FraudDecisionState.HELD.value,
        ):
            return (
                f"hop {hop.hop_id}: fraud decision state {hop.fraud_decision_state} "
                "blocks routing"
            )
    return None


def _window_contains(start: str, moment: str, end: str) -> bool:
    return (
        parse_utc_timestamp("window start", start)
        <= parse_utc_timestamp("moment", moment)
        < parse_utc_timestamp("window end", end)
    )


def evaluate_shape_accounting(
    chains: Sequence[PaymentChain],
    *,
    intent: Intent,
    slack: EconomicSlack,
    total_cost_value: int,
) -> str | None:
    """The accounting hard gate for one complete payment shape.

    Checks, in order: per-hop fill windows and capacity, funding
    sufficiency, and delivery within the economic slack amount window.
    Returns the explicit rejection reason or ``None``.
    """
    for chain in chains:
        for execution in chain.hops:
            hop = execution.hop
            if not hop.amount_min <= execution.input_value <= hop.amount_max:
                return (
                    f"hop {hop.hop_id}: fill amount {execution.input_value} is "
                    f"outside the quote amount window "
                    f"[{hop.amount_min}, {hop.amount_max}]"
                )
            if execution.input_value > hop.capacity:
                return (
                    f"hop {hop.hop_id}: fill amount {execution.input_value} exceeds "
                    f"the reserved capacity {hop.capacity}"
                )
    total_source = sum(chain.source_value for chain in chains)
    spend = total_source + total_cost_value
    caps = [ref.cap for ref in intent.spec.funding.sources]
    if caps and all(cap is not None for cap in caps):
        total_caps = sum(cap.value for cap in caps)
        if spend > total_caps:
            return (
                f"funding sources total cap {total_caps} is below the required "
                f"spend {spend} (source {total_source} + fees {total_cost_value})"
            )
    delivered = sum(chain.delivered_value for chain in chains)
    if not slack.spec.amount_min.value <= delivered <= slack.spec.amount_max.value:
        return (
            f"delivered amount {delivered} is outside the economic slack amount "
            f"window [{slack.spec.amount_min.value}, {slack.spec.amount_max.value}]"
        )
    return None


def shape_metrics(
    chains: Sequence[PaymentChain],
    *,
    request: CompilationRequest,
    intent_amount_value: int,
) -> CandidateMetrics:
    """Compute the exact metric vector of one feasible shape."""
    require_int("intent_amount_value", intent_amount_value, minimum=1)
    as_of_epoch = utc_epoch_seconds("request.as_of", request.as_of)
    completion_epoch = as_of_epoch + max(
        chain.latency_seconds for chain in chains
    )
    reliability = Fraction(1, 1)
    liquidity = Fraction(0, 1)
    for chain in chains:
        reliability *= chain.reliability
        liquidity += chain.liquidity_utilization
    total_delivered = sum(chain.delivered_value for chain in chains)
    return CandidateMetrics(
        total_cost_value=sum(chain.cost_value for chain in chains),
        total_source_value=sum(chain.source_value for chain in chains),
        total_delivered_value=total_delivered,
        amount_distance=abs(total_delivered - intent_amount_value),
        completion_epoch=completion_epoch,
        completion=format_utc_timestamp(completion_epoch),
        total_latency_seconds=sum(chain.latency_seconds for chain in chains),
        hop_count=sum(len(chain.route) for chain in chains),
        payment_count=len(chains),
        reliability=reliability,
        capital_time=sum(chain.capital_time for chain in chains),
        liquidity_utilization=liquidity,
        risk_penalty=sum(chain.risk_penalty for chain in chains),
        privacy_exposure=sum(chain.privacy_exposure for chain in chains),
    )


def objective_sort_key(
    candidate: FeasibleCandidate,
    objective_order: Sequence[OptimizationObjective],
) -> tuple:
    """The total deterministic ordering key of one feasible candidate.

    Lexicographic over the policy's strict objective ranking, with the
    canonical shape digest as the final tie-break (byte order — never
    insertion order, never coincidence).
    """
    metrics = candidate.metrics
    key: list = []
    for objective in objective_order:
        if objective is OptimizationObjective.COST:
            key.append(metrics.total_cost_value)
        elif objective is OptimizationObjective.RELIABILITY:
            key.append(-metrics.reliability)
        elif objective is OptimizationObjective.TIME:
            key.append((metrics.completion_epoch, metrics.total_latency_seconds))
        elif objective is OptimizationObjective.ROUTE:
            key.append(metrics.hop_count)
        elif objective is OptimizationObjective.AMOUNT:
            key.append(metrics.amount_distance)
        elif objective is OptimizationObjective.PAYMENT_SHAPE:
            key.append(metrics.payment_count)
        elif objective is OptimizationObjective.LIQUIDITY:
            key.append(metrics.liquidity_utilization)
        elif objective is OptimizationObjective.RISK:
            key.append(metrics.risk_penalty)
        elif objective is OptimizationObjective.PRIVACY:
            key.append(metrics.privacy_exposure)
        elif objective is OptimizationObjective.CREDIT:
            # No credit facility draw exists in the v0.1 compiler input
            # set: the CREDIT metric is exactly zero (neutral, documented).
            key.append(0)
        else:  # pragma: no cover - closed vocabulary
            raise CoreValidationError(
                f"unknown optimization objective {objective!r}"
            )
    key.append(candidate.digest)
    return tuple(key)


def rank_candidates(
    candidates: Iterable[FeasibleCandidate],
    objective_order: Sequence[OptimizationObjective],
) -> tuple[FeasibleCandidate, ...]:
    """Rank feasible candidates best-first under the objective order."""
    ordered = tuple(candidates)
    if not ordered:
        raise CoreValidationError("ranking requires at least one feasible candidate")
    if not objective_order:
        raise CoreValidationError("the policy must rank at least one objective")
    seen: list[OptimizationObjective] = []
    for objective in objective_order:
        if objective in seen:
            raise CoreValidationError(
                f"policy objectives must be a strict ranking; {objective.value} repeats"
            )
        seen.append(objective)
    return tuple(
        sorted(
            ordered, key=lambda candidate: objective_sort_key(candidate, objective_order)
        )
    )
