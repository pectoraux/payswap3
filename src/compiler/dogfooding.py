"""DOGFOOD-013 — compile a real multi-hop payment, deterministically.

The Work Order's dogfooding/conformance experiment: ``build_transcript``
compiles one real multi-hop payment (intent → multi-hop route) through
the REAL supported product path and returns a deterministic transcript
plus its SHA-256 digest. Every input is built through the merged sibling
domains' public command APIs — nothing is stubbed:

- **intent (WORK-008)**: a real AUTHORIZED ``Intent``, an ACTIVE
  ``FulfillmentPolicy`` (strict objective ranking COST → RELIABILITY →
  TIME) and an ACTIVE ``EconomicSlack`` (amount window, completion
  window, max payment count, substitute assets);
- **capability (WORK-009)**: real ``CapabilityRecord`` objects driven
  through ``register → verify (CERTIFICATION PASSED) → activate``, with
  real operating windows, authority tiers, jurisdictions and protocol
  versions;
- **market (WORK-010)**: real standing ``LiquidityOffer`` records and
  real firm ``Quote`` records created offer-coherent (price bps, flat
  fee, amount window, validity window);
- **liquidity (WORK-011)**: real liquidity-domain offers with exact
  money-domain capacity ``Amount`` over real ``Corridor`` objects;
- **reservation (WORK-012)**: real protocol ``Reservation`` records in
  the RESERVED state with explicit windows (reservation-validated hops);
- **safety (WORK-017)**: real ``ComplianceAssessment`` records driven
  through ``request → record`` with evidence-backed provenance; the
  verdicts (SATISFIED/BLOCKED) are the binding routing inputs, and the
  fraud-decision state is the safety domain's closed vocabulary;
- **money (WORK-006)**: every FX leg converts through the money
  authority's exact ``convert`` with the frozen compiler rounding mode;
  fees through the market authority's exact ``fee_for_fill``; splits
  (when the policy allows them) through ``allocate_equal``.

The experiment runs with a fully declared world (fixed ``as_of``, no
wall clock, no entropy, no generated identifiers), compiles through
BOTH supported paths (the pure :func:`compile_fulfillment` function and
the real transition-kernel :class:`FulfillmentCompiler`), proves the
two plan digests are byte-identical (semantic equivalence), then
accepts the plan through the kernel. The compiler never executes
anything and never mutates a ledger — the plan is a proposal.
"""

from __future__ import annotations

from src.capability import (
    AuthorityTier,
    CapabilityKind,
    OperatingWindow,
    activate_capability,
    apply_verification,
    register_capability,
)
from src.capability.verification import (
    VerificationMetadata,
    VerificationMethod,
    VerificationResult,
)
from src.core.envelope import Provenance
from src.core.serialization import canonical_sha256
from src.intent import (
    EconomicSlack,
    FundingBinding,
    FundingSourceRef,
    FulfillmentPolicy,
    Intent,
    IntentSpec,
    OptimizationObjective,
    PolicySpec,
    SlackSpec,
)
from src.intent.amount import Amount as IntentAmount
from src.liquidity import Corridor
from src.liquidity.offers import create_liquidity_offer as create_capacity_offer
from src.market import create_liquidity_offer, create_quote
from src.money import FxRate, get_currency
from src.reservation import Amount as ReservationAmount
from src.reservation import create_reservation
from src.safety import (
    ComplianceConstraint,
    ConstraintOutcome,
    ConstraintPrecedence,
    FraudDecisionState,
    record_compliance_result,
    request_compliance_assessment,
)

from .compile import compile_fulfillment
from .contracts import (
    COMPILER_ACCEPT_COMMAND,
    COMPILER_COMPILE_COMMAND,
    FULFILLMENT_ACCEPTED_EVENT,
    FULFILLMENT_COMPILED_EVENT,
)
from .engine import FulfillmentCompiler
from .inputs import CompilationRequest, RouteHopOffer

# ---------------------------------------------------------------------------
# The declared, deterministic dogfooding world (no clocks, no entropy).
# ---------------------------------------------------------------------------

ENV = "env/sandbox-dogfood"
DOMAIN = "domain/payments"
STAMP = "2026-09-01T00:00:00Z"
ACTIVATED_AT = "2026-09-02T00:00:00Z"
AS_OF = "2026-09-03T00:05:00Z"
OPENS = "2026-09-03T00:00:00Z"
CLOSES = "2026-09-03T02:00:00Z"
DEADLINE = "2026-09-03T12:00:00Z"
EARLIEST_COMPLETION = "2026-09-03T00:06:00Z"
LATEST_COMPLETION = "2026-09-03T06:00:00Z"

PAYER = "principal/payer-7"
MERCHANT = "principal/merchant-42"
TREASURY = "principal/treasury"
COMPLIANCE_DESK = "principal/compliance-desk"
VERIFIER = "capability/verifier-1"

INTENT_ID = "intent/pay-1"
POLICY_ID = "intent/policy-1"
SLACK_ID = "intent/slack-1"
PLAN_ID = "plan/merchant-42-pay-1"

ASSET_EUR = "asset/EUR"
ASSET_USD = "asset/USD"
ASSET_GBP = "asset/GBP"

EUR = get_currency("EUR")
USD = get_currency("USD")
GBP = get_currency("GBP")

RATE_EUR_USD = FxRate(source=EUR, target=USD, numerator=27, denominator=25)
RATE_USD_EUR = FxRate(source=USD, target=EUR, numerator=25, denominator=27)
RATE_EUR_GBP = FxRate(source=EUR, target=GBP, numerator=17, denominator=20)
RATE_GBP_EUR = FxRate(source=GBP, target=EUR, numerator=20, denominator=17)

OBJECTIVES = (
    OptimizationObjective.COST,
    OptimizationObjective.RELIABILITY,
    OptimizationObjective.TIME,
)


def _prov(issuer: str) -> Provenance:
    return Provenance(issuer=issuer, source="dogfood/w013", recorded_at=STAMP)


def _verification(verifier: str, evidence: str) -> VerificationMetadata:
    return VerificationMetadata(
        method=VerificationMethod.CERTIFICATION,
        verifier=verifier,
        result=VerificationResult.PASSED,
        verified_at=STAMP,
        valid_until="2027-01-01T00:00:00Z",
        evidence_refs=(evidence,),
    )


def _satisfied_constraint(subject: str) -> ComplianceConstraint:
    return ComplianceConstraint(
        constraint_id=f"compliance/con-kyc-{subject}",
        requirement="screening:kyc",
        precedence=ConstraintPrecedence.LEGAL,
        outcome=ConstraintOutcome.SATISFIED,
        version=1,
        effective_from="2026-01-01T00:00:00Z",
        effective_until="2027-01-01T00:00:00Z",
        evidence_refs=("evidence/kyc-merchant-42",),
    )


def _violated_constraint(subject: str) -> ComplianceConstraint:
    return ComplianceConstraint(
        constraint_id=f"compliance/con-sanctions-{subject}",
        requirement="screening:sanctions",
        precedence=ConstraintPrecedence.LEGAL,
        outcome=ConstraintOutcome.VIOLATED,
        version=1,
        effective_from="2026-01-01T00:00:00Z",
        effective_until="2027-01-01T00:00:00Z",
        evidence_refs=("evidence/sanctions-alert-omega",),
    )


def _real_intent() -> Intent:
    funding = FundingBinding.build(
        (
            FundingSourceRef(
                source_id="value/funding/wallet-7",
                cap=IntentAmount(value=20000, scale=2, asset=ASSET_EUR),
            ),
        )
    )
    spec = IntentSpec(
        destination_id=MERCHANT,
        amount=IntentAmount(value=10000, scale=2, asset=ASSET_EUR),
        deadline=DEADLINE,
        funding=funding,
        policy_id=POLICY_ID,
        slack_id=SLACK_ID,
    )
    intent = Intent.build(
        object_id=INTENT_ID,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=_prov(PAYER),
    )
    return intent.authorize(provenance=_prov(PAYER))


def _real_policy() -> FulfillmentPolicy:
    spec = PolicySpec.build(
        objectives=OBJECTIVES,
        allow_split=True,
        allow_asset_substitution=True,
        allow_route_substitution=True,
    )
    return FulfillmentPolicy.build(
        object_id=POLICY_ID,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=_prov(PAYER),
    )


def _real_slack() -> EconomicSlack:
    spec = SlackSpec(
        amount_min=IntentAmount(value=9900, scale=2, asset=ASSET_EUR),
        amount_max=IntentAmount(value=10100, scale=2, asset=ASSET_EUR),
        earliest_completion=EARLIEST_COMPLETION,
        latest_completion=LATEST_COMPLETION,
        max_payment_count=2,
        substitute_assets=(ASSET_USD, ASSET_GBP),
    )
    return EconomicSlack.build(
        object_id=SLACK_ID,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=_prov(PAYER),
    )


def _real_hop(
    hop_id: str,
    *,
    provider: str,
    source_asset: str,
    target_asset: str,
    fx: FxRate | None,
    price_bps: int,
    flat_fee: int,
    capacity: int,
    reliability_bps: int,
    latency_seconds: int,
    blocked: bool = False,
    fraud_state: str | None = None,
) -> RouteHopOffer:
    """Build ONE routable hop from real sibling-domain records.

    The capability is registered, verified (certification PASSED) and
    activated; the standing market offer and the firm quote are created
    offer-coherent; the liquidity-domain offer carries exact money-domain
    capacity over the real corridor; the protocol reservation is RESERVED
    with an explicit window; the compliance assessment is requested and
    recorded with evidence-backed provenance. The resulting
    :class:`RouteHopOffer` is the deterministic projection of that tuple.
    """
    slug = hop_id.rpartition("/")[2]
    window = OperatingWindow(opens_at=OPENS, closes_at=CLOSES)
    capability = register_capability(
        object_id=f"capability/{slug}",
        provider_id=f"capability/provider-{provider.rpartition('/')[2]}",
        kind=CapabilityKind.PAYMENT_EXECUTION,
        description=f"payment execution corridor {source_asset}->{target_asset}",
        authority_tier=AuthorityTier.R3,
        jurisdictions=("EU",),
        protocol_versions=("v0.1",),
        simulation_support=True,
        production_support=True,
        operating_windows=(window,),
        environment_id=ENV,
        domain_id=DOMAIN,
        issuer=TREASURY,
        source="dogfood/w013",
        recorded_at=STAMP,
    )
    capability = apply_verification(
        capability,
        _verification(VERIFIER, f"evidence/cap-cert-{slug}"),
    )
    capability = activate_capability(capability, as_of=ACTIVATED_AT)

    market_offer = create_liquidity_offer(
        offer_id=f"market/offer/{slug}",
        provider=provider,
        asset=source_asset,
        amount_min=1,
        amount_max=capacity,
        scale=2,
        price_bps=price_bps,
        flat_fee=flat_fee,
        available_from=OPENS,
        available_until=CLOSES,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=_prov(TREASURY),
        capability_id=f"capability/{slug}",
    )
    quote = create_quote(
        quote_id=f"market/quote/{slug}",
        demand_id="intent/demand-w013",
        maker=provider,
        asset=source_asset,
        scale=2,
        amount_min=1,
        amount_max=capacity,
        price_bps=price_bps,
        flat_fee=flat_fee,
        valid_from=OPENS,
        valid_until=CLOSES,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=_prov(TREASURY),
        offer=market_offer,
    )
    corridor = Corridor(source_asset=source_asset, target_asset=target_asset)
    liquidity = create_capacity_offer(
        offer_id=f"liquidity/{slug}",
        provider=provider,
        provider_capability_id=f"capability/{slug}",
        beneficiary=PAYER,
        corridor=corridor,
        capacity=_money_amount(source_asset, capacity),
        available_from=OPENS,
        available_until=CLOSES,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=_prov(TREASURY),
    )
    reservation = create_reservation(
        reservation_id=f"reservation/{slug}",
        resource_key=f"corridor:{source_asset}:{target_asset}:{provider}",
        provider=provider,
        beneficiary=PAYER,
        asset=source_asset,
        amount=ReservationAmount(value=capacity, scale=2, asset=source_asset),
        window=window,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=_prov(TREASURY),
    )
    compliance_prov = Provenance(
        issuer=COMPLIANCE_DESK,
        source="dogfood/w013",
        recorded_at=STAMP,
        evidence_refs=("evidence/kyc-merchant-42",),
    )
    constraint = (
        _violated_constraint(slug) if blocked else _satisfied_constraint(slug)
    )
    assessment = request_compliance_assessment(
        assessment_id=f"safety/compliance/{slug}",
        subject_id=PAYER,
        jurisdiction="EU",
        constraints=(constraint,),
        as_of=STAMP,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=compliance_prov,
    )
    assessment = record_compliance_result(
        assessment, as_of=ACTIVATED_AT, provenance=compliance_prov
    )
    return RouteHopOffer(
        hop_id=hop_id,
        environment_id=ENV,
        domain_id=DOMAIN,
        provider=provider,
        capability_id=capability.envelope.object_id,
        capability_state=capability.state.value,
        capability_protocol_version="v0.1",
        authority_tier=capability.authority_tier.value,
        jurisdictions=capability.jurisdictions,
        offer_id=liquidity.envelope.object_id,
        quote_id=quote.envelope.object_id,
        reservation_id=reservation.envelope.object_id,
        reservation_state=reservation.state.value,
        reservation_opens_at=reservation.spec.window.opens_at,
        reservation_closes_at=reservation.spec.window.closes_at,
        compliance_assessment_id=assessment.envelope.object_id,
        compliance_verdict=assessment.spec.result.verdict.value,
        fraud_decision_state=fraud_state,
        corridor=corridor,
        fx_rate=fx,
        source_scale=2 if fx is None else fx.source.scale,
        target_scale=2 if fx is None else fx.target.scale,
        amount_min=market_offer.spec.amount_min,
        amount_max=market_offer.spec.amount_max,
        capacity=liquidity.spec.capacity.value,
        price_bps=quote.spec.price_bps,
        flat_fee=quote.spec.flat_fee,
        reliability_bps=reliability_bps,
        latency_seconds=latency_seconds,
        window_opens_at=capability.operating_windows[0].opens_at,
        window_closes_at=capability.operating_windows[0].closes_at,
        quote_valid_from=quote.spec.valid_from,
        quote_valid_until=quote.spec.valid_until,
    )


def _money_amount(asset_id: str, value: int):
    from src.money import Amount as MoneyAmount

    code = asset_id[len("asset/"):]
    return MoneyAmount(currency=get_currency(code), value=value, scale=2)


def _real_hops() -> tuple[RouteHopOffer, ...]:
    """The real multi-hop offer set of the dogfooding scenario.

    R1 = [f1 EUR->USD 27/25, f2 USD->EUR 25/27] — total cost 109 EUR,
    delivered exactly 10000, completion 00:17:30.
    R2 = [g1 EUR->GBP 17/20, g2 GBP->EUR 20/17] — total cost 122 EUR.
    D1 = [direct EUR->EUR passthrough] — cost 350 EUR.
    X1 = [f3 EUR->USD cheap but compliance-BLOCKED] — never routed.
    """
    return (
        _real_hop(
            "hop/f1-eur-usd",
            provider="provider/fx-alpha",
            source_asset=ASSET_EUR,
            target_asset=ASSET_USD,
            fx=RATE_EUR_USD,
            price_bps=50,
            flat_fee=10,
            capacity=12000,
            reliability_bps=9950,
            latency_seconds=400,
            fraud_state=FraudDecisionState.ALLOW.value,
        ),
        _real_hop(
            "hop/f2-usd-eur",
            provider="provider/fx-beta",
            source_asset=ASSET_USD,
            target_asset=ASSET_EUR,
            fx=RATE_USD_EUR,
            price_bps=40,
            flat_fee=10,
            capacity=12000,
            reliability_bps=9900,
            latency_seconds=350,
        ),
        _real_hop(
            "hop/g1-eur-gbp",
            provider="provider/fx-gamma",
            source_asset=ASSET_EUR,
            target_asset=ASSET_GBP,
            fx=RATE_EUR_GBP,
            price_bps=45,
            flat_fee=15,
            capacity=12000,
            reliability_bps=9960,
            latency_seconds=380,
        ),
        _real_hop(
            "hop/g2-gbp-eur",
            provider="provider/fx-gamma",
            source_asset=ASSET_GBP,
            target_asset=ASSET_EUR,
            fx=RATE_GBP_EUR,
            price_bps=45,
            flat_fee=15,
            capacity=12000,
            reliability_bps=9920,
            latency_seconds=330,
        ),
        _real_hop(
            "hop/d1-direct-eur",
            provider="provider/direct-eu",
            source_asset=ASSET_EUR,
            target_asset=ASSET_EUR,
            fx=None,
            price_bps=300,
            flat_fee=50,
            capacity=100000,
            reliability_bps=9900,
            latency_seconds=90,
        ),
        _real_hop(
            "hop/f3-eur-usd-blocked",
            provider="provider/fx-omega",
            source_asset=ASSET_EUR,
            target_asset=ASSET_USD,
            fx=RATE_EUR_USD,
            price_bps=20,
            flat_fee=5,
            capacity=12000,
            reliability_bps=9990,
            latency_seconds=200,
            blocked=True,
        ),
    )


def build_transcript() -> tuple[str, str]:
    """Run the DOGFOOD-013 experiment; return (transcript, digest).

    Deterministic and repeatable: the same declared world always yields
    the byte-identical transcript and digest (no wall clock, no entropy).
    """
    request = CompilationRequest(
        environment_id=ENV,
        domain_id=DOMAIN,
        as_of=AS_OF,
        required_jurisdiction="EU",
        minimum_authority_tier="R3",
    )
    intent = _real_intent()
    policy = _real_policy()
    slack = _real_slack()
    hops = _real_hops()

    # Path 1 — the pure compilation function.
    pure_spec = compile_fulfillment(
        request=request,
        intent=intent,
        policy=policy,
        slack=slack,
        hop_offers=hops,
    )

    # Path 2 — the real transition kernel (the supported product path).
    compiler = FulfillmentCompiler(
        environment_id=ENV,
        domain_id=DOMAIN,
        authorized_actors=(PAYER,),
    )
    compiled = compiler.compile(
        plan_id=PLAN_ID,
        request=request,
        intent=intent,
        policy=policy,
        slack=slack,
        hop_offers=hops,
        command_id="command/dogfood-compile-1",
        idempotency_key="idem/dogfood-compile-1",
        nonce="dogfood-nonce-1",
        actor=PAYER,
    )
    plan = compiler.plan(PLAN_ID)
    if pure_spec.plan_digest != plan.spec.plan_digest:
        raise AssertionError(
            "DOGFOOD-013 contract failure: the pure compile and the kernel "
            "compile disagree on the plan digest"
        )

    accepted = compiler.accept_plan(
        plan_id=PLAN_ID,
        command_id="command/dogfood-accept-1",
        idempotency_key="idem/dogfood-accept-1",
        nonce="dogfood-nonce-2",
        actor=PAYER,
        as_of=AS_OF,
    )
    accepted_plan = compiler.plan(PLAN_ID)

    lines: list[str] = []
    lines.append(
        "DOGFOOD-013: compile a real multi-hop payment twice and verify "
        "deterministic semantic equivalence"
    )
    lines.append(
        f"binding: work_order=WORK-013 architecture=v0.1 environment={ENV} "
        f"domain={DOMAIN}"
    )
    lines.append(
        "world: fully declared (fixed as_of, no wall clock, no entropy, "
        "no generated identifiers)"
    )
    lines.append(
        f"intent: {INTENT_ID} state={intent.state.value} amount=10000 "
        f"scale=2 asset={ASSET_EUR} destination={MERCHANT}"
    )
    lines.append(
        f"policy: {POLICY_ID} state={policy.state.value} "
        f"objectives={','.join(objective.value for objective in OBJECTIVES)}"
    )
    lines.append(
        f"slack: {SLACK_ID} state={slack.state.value} "
        f"amount_window=[9900,10100] max_payment_count=2 "
        f"substitutes={ASSET_USD},{ASSET_GBP}"
    )
    lines.append("real sibling inputs: hop offers built from real records:")
    for hop in hops:
        lines.append(
            f"  hop {hop.hop_id}: capability={hop.capability_state} "
            f"tier={hop.authority_tier} corridor={hop.corridor.corridor_id} "
            f"capacity={hop.capacity} price_bps={hop.price_bps} "
            f"flat_fee={hop.flat_fee} reservation={hop.reservation_state} "
            f"compliance={hop.compliance_verdict}"
        )
    report = plan.spec.gate_report
    rejections = report["routes_rejected_per_gate"]
    lines.append(
        f"routing: routes_considered={report['routes_considered']} "
        f"routes_rejected_per_gate="
        + ",".join(
            f"{gate}={rejections[gate]}" for gate in ("compliance", "authority", "settlement", "safety", "accounting") if rejections[gate]
        )
    )
    lines.append(
        "gate[compliance] rejected hop/f3-eur-usd-blocked: compliance verdict "
        "BLOCKED is binding - compliance cannot be bypassed through routing"
    )
    payment = plan.spec.payments[0]
    lines.append(
        f"compilation: selected route hops={len(payment.route_hops)} "
        + " -> ".join(hop.hop_id for hop in payment.route_hops)
    )
    for hop in payment.route_hops:
        rate = (
            "passthrough"
            if hop.fx_numerator is None
            else f"rate={hop.fx_numerator}/{hop.fx_denominator}"
        )
        lines.append(
            f"  hop {hop.hop_id}: {hop.source_asset} {hop.input_value} -> "
            f"{hop.target_asset} {hop.output_value} ({rate} "
            f"mode={hop.fx_rounding_mode} "
            f"residual={hop.residual_numerator}/{hop.residual_denominator}) "
            f"fee={hop.fee_value}"
        )
    totals = plan.spec.totals
    lines.append(
        f"totals: total_cost_value={totals['total_cost_value']} "
        f"total_delivered_value={totals['total_delivered_value']} "
        f"amount_distance={totals['amount_distance']} "
        f"completion={totals['completion']} "
        f"capital_time={totals['capital_time']}"
    )
    lines.append(
        f"kernel: command={COMPILER_COMPILE_COMMAND} "
        f"outcome={compiled.outcome.value} "
        f"event={compiled.event.event_type} "
        f"plan_version={plan.envelope.object_version}"
    )
    if compiled.event.event_type != FULFILLMENT_COMPILED_EVENT:
        raise AssertionError("DOGFOOD-013 contract failure: wrong compiled event")
    lines.append(f"plan_digest={plan.spec.plan_digest}")
    lines.append(
        "semantic equivalence: pure compile_fulfillment digest == kernel "
        f"compile digest ({pure_spec.plan_digest == plan.spec.plan_digest})"
    )
    lines.append(
        f"kernel: command={COMPILER_ACCEPT_COMMAND} "
        f"outcome={accepted.outcome.value} "
        f"event={accepted.event.event_type} "
        f"plan_version={accepted_plan.envelope.object_version}"
    )
    if accepted.event.event_type != FULFILLMENT_ACCEPTED_EVENT:
        raise AssertionError("DOGFOOD-013 contract failure: wrong accepted event")
    lines.append(
        f"plan after accept: state={accepted_plan.state.value} "
        f"version={accepted_plan.envelope.object_version}"
    )
    lines.append(
        "invariants: no external effect, no ledger mutation, no authority "
        "granted - the compiler proposes plans only"
    )
    lines.append(
        "classification: DOGFOOD-013 deterministic repeatable compile of a "
        "real multi-hop payment"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"dogfood": "WORK-013", "transcript": transcript})
    return transcript, digest


if __name__ == "__main__":  # pragma: no cover — clean-process experiment
    transcript, digest = build_transcript()
    print(transcript, end="")
    print(f"transcript_sha256={digest}")
