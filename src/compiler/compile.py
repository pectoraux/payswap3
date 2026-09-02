"""The deterministic fulfillment compiler: intent → optimal plan.

``compile_fulfillment`` is the pure function at the heart of WORK-013.
It consumes one typed :class:`~src.compiler.inputs.CompilationInput`
(request, intent, fulfillment policy, economic slack, hop offers) and
produces the sealed :class:`~src.compiler.plan.FulfillmentPlanSpec` of
the best achievable fulfillment, or fails closed with an explicit
reason. It consults no clock, no entropy and no external state: the
same input always produces the byte-identical plan.

Pipeline (all steps explicit, all failures typed
:class:`~src.core.errors.CoreValidationError`):

1. input contract validation (intent AUTHORIZED, policy/slack ACTIVE,
   referenced object identities match, one environment, slack brackets
   the intent amount, as_of before the deadline);
2. route enumeration over the hop graph (simple paths, substitute
   assets gated by the policy's substitution flags);
3. hard-gate evaluation in the frozen precedence order
   ``compliance > authority > settlement > safety`` per route;
4. bounded payment-shape enumeration (exact money-domain splits);
5. forward execution of every shape with exact money arithmetic and the
   accounting hard gate (fill windows, capacity, funding, delivery
   window);
6. lexicographic ranking under the policy's strict objective order with
   the canonical shape digest as the final tie-break;
7. the sealed plan spec with the full gate report, objective order,
   runner-up digests and the semantic plan digest.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Sequence

from src.core.errors import CoreValidationError
from src.intent import EconomicSlack, FulfillmentPolicy, Intent, PolicyState, SlackState
from src.intent.amount import Amount as IntentAmount
from src.intent.intent import IntentState
from src.money import Amount, get_currency

from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_utc_timestamp,
)
from .candidates import PaymentChain, execute_route, hop_plan_dict
from .contracts import (
    HARD_GATE_ACCOUNTING,
    HARD_GATE_PRECEDENCE,
    RUNNER_UP_DIGEST_COUNT,
)
from .inputs import CompilationInput, CompilationRequest, RouteHopOffer
from .optimization import (
    FeasibleCandidate,
    evaluate_route,
    evaluate_shape_accounting,
    rank_candidates,
    shape_metrics,
)
from .plan import FulfillmentPlanSpec, HopPlanSpec, PaymentPlanSpec
from .routing import enumerate_routes
from .shapes import enumerate_shapes

#: Maximum number of rejection reasons embedded in failure messages.
FAILURE_REASON_LIMIT = 5


def currency_for_asset(asset_id: str):
    """Resolve the money authority's currency for an ``asset/<CODE>`` id.

    Fails closed on identifiers outside the canonical liquidity-domain
    asset form or on unknown currency codes.
    """
    require_identifier("asset id", asset_id)
    if not asset_id.startswith("asset/"):
        raise CoreValidationError(
            f"asset id {asset_id!r} must use the canonical 'asset/<CODE>' form"
        )
    code = asset_id[len("asset/"):]
    return get_currency(code)


def compile_fulfillment(
    *,
    request: CompilationRequest,
    intent: Intent,
    policy: FulfillmentPolicy,
    slack: EconomicSlack,
    hop_offers: Iterable[RouteHopOffer],
) -> FulfillmentPlanSpec:
    """Compile one authorized intent into the optimal fulfillment plan."""
    offers = _validate_inputs(request, intent, policy, slack, hop_offers)
    base_asset = intent.spec.amount.asset
    base_currency = currency_for_asset(base_asset)
    base_scale = intent.spec.amount.scale
    if base_scale != base_currency.scale:
        raise CoreValidationError(
            f"intent amount scale {base_scale} must be the money authority's "
            f"canonical scale {base_currency.scale} of {base_asset}"
        )
    intent_value = intent.spec.amount.value

    allow_intermediates = policy.spec.allow_asset_substitution
    routes = enumerate_routes(
        offers,
        source_asset=base_asset,
        allowed_intermediate_assets=(
            slack.spec.substitute_assets if allow_intermediates else ()
        ),
    )
    if not policy.spec.allow_route_substitution:
        routes = tuple(route for route in routes if len(route) == 1)

    rejections: dict[str, int] = {gate: 0 for gate in HARD_GATE_PRECEDENCE}
    reasons: list[str] = []
    feasible_routes = []
    for route in routes:
        rejection = evaluate_route(route, request=request, intent=intent, slack=slack)
        if rejection is not None:
            rejections[rejection.gate] += 1
            reasons.append(f"[{rejection.gate}] {rejection.reason}")
            continue
        feasible_routes.append(route)
    if not feasible_routes:
        raise CoreValidationError(
            f"no statically feasible route from {base_asset} back to {base_asset} "
            f"over the declared hop offers; hard-gate rejections: "
            f"{_summarize_rejections(rejections)}; reasons: "
            f"{'; '.join(reasons[:FAILURE_REASON_LIMIT])}"
        )

    intent_amount = Amount(
        currency=base_currency, value=intent_value, scale=base_scale
    )
    shapes = enumerate_shapes(
        feasible_routes,
        intent_amount=intent_amount,
        allow_split=policy.spec.allow_split,
        max_payment_count=slack.spec.max_payment_count,
    )

    feasible: list[FeasibleCandidate] = []
    accounting_reasons: list[str] = []
    for shape in shapes:
        chains = tuple(
            execute_route(payment.route, payment.source_value, base_scale=base_scale)
            for payment in shape.payments
        )
        total_cost = sum(chain.cost_value for chain in chains)
        rejection = evaluate_shape_accounting(
            chains,
            intent=intent,
            slack=slack,
            total_cost_value=total_cost,
        )
        if rejection is not None:
            accounting_reasons.append(f"[{HARD_GATE_ACCOUNTING}] {rejection}")
            continue
        metrics = shape_metrics(
            chains, request=request, intent_amount_value=intent_value
        )
        feasible.append(
            FeasibleCandidate(
                shape=shape,
                chains=chains,
                metrics=metrics,
                digest=shape.digest,
            )
        )
    if not feasible:
        raise CoreValidationError(
            "no feasible payment shape satisfies the hard constraints "
            f"(fill windows, capacity, funding, delivery window); accounting "
            f"rejected {len(shapes)} shape(s); reasons: "
            f"{'; '.join(accounting_reasons[:FAILURE_REASON_LIMIT])}"
        )

    ranked = rank_candidates(feasible, policy.spec.objectives)
    winner = ranked[0]
    runner_up_digests = tuple(
        candidate.digest for candidate in ranked[1 : 1 + RUNNER_UP_DIGEST_COUNT]
    )

    gate_report = {
        "routes_considered": len(routes),
        "routes_rejected_per_gate": rejections,
        "shapes_evaluated": len(shapes),
        "shapes_rejected_accounting": len(shapes) - len(feasible),
        "shapes_feasible": len(feasible),
    }
    spec = FulfillmentPlanSpec(
        intent_id=intent.object_id,
        policy_id=policy.object_id,
        slack_id=slack.object_id,
        destination_id=intent.spec.destination_id,
        as_of=request.as_of,
        environment_id=request.environment_id,
        domain_id=request.domain_id,
        intent_amount={
            "value": intent_value,
            "scale": base_scale,
            "asset": base_asset,
        },
        payments=_payment_specs(winner.chains),
        totals=winner.metrics.to_dict(),
        gate_report=gate_report,
        objective_order=tuple(
            objective.value for objective in policy.spec.objectives
        ),
        runner_up_digests=runner_up_digests,
        plan_digest="0" * 64,
    )
    digest = spec.recompute_plan_digest()
    spec = replace(spec, plan_digest=digest)
    if spec.recompute_plan_digest() != digest:  # pragma: no cover - self-check
        raise CoreValidationError("plan digest self-check failed")
    return spec


def _payment_specs(
    chains: Sequence[PaymentChain],
) -> tuple[PaymentPlanSpec, ...]:
    payments: list[PaymentPlanSpec] = []
    for index, chain in enumerate(chains, start=1):
        hops = tuple(
            HopPlanSpec(**hop_plan_dict(execution)) for execution in chain.hops
        )
        payments.append(
            PaymentPlanSpec(
                payment_index=index,
                route_hops=hops,
                source_value=chain.source_value,
                delivered_value=chain.delivered_value,
            )
        )
    return tuple(payments)


def _validate_inputs(
    request: CompilationRequest,
    intent: Intent,
    policy: FulfillmentPolicy,
    slack: EconomicSlack,
    hop_offers: Iterable[RouteHopOffer],
) -> tuple[RouteHopOffer, ...]:
    """Validate the whole input contract, failing closed on every path."""
    if not isinstance(request, CompilationRequest):
        raise CoreValidationError("compile requires a CompilationRequest")
    if not isinstance(intent, Intent):
        raise CoreValidationError("compile requires an Intent")
    if not isinstance(policy, FulfillmentPolicy):
        raise CoreValidationError("compile requires a FulfillmentPolicy")
    if not isinstance(slack, EconomicSlack):
        raise CoreValidationError("compile requires an EconomicSlack")
    if intent.state is not IntentState.AUTHORIZED:
        raise CoreValidationError(
            f"only an AUTHORIZED intent can be compiled; state is "
            f"{intent.state.value}"
        )
    if policy.state is not PolicyState.ACTIVE:
        raise CoreValidationError(
            f"the fulfillment policy must be ACTIVE; state is {policy.state.value}"
        )
    if slack.state is not SlackState.ACTIVE:
        raise CoreValidationError(
            f"the economic slack must be ACTIVE; state is {slack.state.value}"
        )
    if intent.spec.policy_id != policy.object_id:
        raise CoreValidationError(
            f"intent references policy {intent.spec.policy_id} but the compiled "
            f"policy is {policy.object_id}"
        )
    if intent.spec.slack_id != slack.object_id:
        raise CoreValidationError(
            f"intent references slack {intent.spec.slack_id} but the compiled "
            f"slack is {slack.object_id}"
        )
    environment_id = request.environment_id
    domain_id = request.domain_id
    for name, obj in (("intent", intent), ("policy", policy), ("slack", slack)):
        if obj.envelope.environment_id != environment_id:
            raise CoreValidationError(
                f"{name} belongs to environment {obj.envelope.environment_id}, "
                f"not the request environment {environment_id}"
            )
        if obj.envelope.domain_id != domain_id:
            raise CoreValidationError(
                f"{name} belongs to domain {obj.envelope.domain_id}, not the "
                f"request domain {domain_id}"
            )
    require_utc_timestamp("request.as_of", request.as_of)
    if parse_utc_timestamp("request.as_of", request.as_of) >= parse_utc_timestamp(
        "intent.deadline", intent.spec.deadline
    ):
        raise CoreValidationError(
            f"as_of {request.as_of} is not before the intent deadline "
            f"{intent.spec.deadline}"
        )
    _require_slack_brackets_intent(slack, intent.spec.amount)
    offers = tuple(hop_offers)
    if not offers:
        raise CoreValidationError(
            "the compilation input declares no hop offers: no route can exist "
            "without at least one routable hop"
        )
    for offer in offers:
        if not isinstance(offer, RouteHopOffer):
            raise CoreValidationError("hop_offers entries must be RouteHopOffer")
        if offer.environment_id != environment_id:
            raise CoreValidationError(
                f"hop {offer.hop_id} belongs to environment {offer.environment_id}, "
                f"not the request environment {environment_id}"
            )
        if offer.domain_id != domain_id:
            raise CoreValidationError(
                f"hop {offer.hop_id} belongs to domain {offer.domain_id}, not the "
                f"request domain {domain_id}"
            )
    hop_ids = [offer.hop_id for offer in offers]
    if len(set(hop_ids)) != len(hop_ids):
        raise CoreValidationError("hop_offers must not repeat a hop_id")
    return offers


def _require_slack_brackets_intent(slack: EconomicSlack, amount: IntentAmount) -> None:
    window_min = slack.spec.amount_min
    window_max = slack.spec.amount_max
    if window_min.asset != amount.asset or window_max.asset != amount.asset:
        raise CoreValidationError(
            f"the economic slack amount window must use the intent asset "
            f"{amount.asset}; got {window_min.asset}"
        )
    if window_min.scale != amount.scale or window_max.scale != amount.scale:
        raise CoreValidationError(
            "the economic slack amount window must use the intent amount scale "
            f"{amount.scale}"
        )
    if not window_min.value <= amount.value <= window_max.value:
        raise CoreValidationError(
            f"the economic slack amount window [{window_min.value}, "
            f"{window_max.value}] must bracket the intent amount {amount.value}"
        )


def _summarize_rejections(rejections: dict[str, int]) -> str:
    return ", ".join(
        f"{gate}={rejections[gate]}" for gate in HARD_GATE_PRECEDENCE
    )


def compile_from_input(payload: CompilationInput) -> FulfillmentPlanSpec:
    """Compile from a full typed input bundle (the kernel handler path)."""
    if not isinstance(payload, CompilationInput):
        raise CoreValidationError("compilation requires a CompilationInput")
    return compile_fulfillment(
        request=payload.request,
        intent=payload.intent,
        policy=payload.policy,
        slack=payload.slack,
        hop_offers=payload.hop_offers,
    )
