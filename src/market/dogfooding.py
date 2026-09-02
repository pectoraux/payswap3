"""DOGFOOD-010: RFQ and batch auction compared on one demand/offer fixture.

The dogfooding/conformance contract of WORK-010: drive the SAME demand
and offer fixture through the RFQ default mechanism (request → firm
quote → accept → commit) and through the batch auction mechanism (open
→ submit → admit → close → allocate), and print a deterministic
comparison transcript. The harness is a real supported product path of
this package — it consumes only the public boundary — and is fully
deterministic: two clean-process runs produce byte-identical output and
the same SHA-256 digest.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.serialization import canonical_sha256

from . import (
    MarketSession,
    MechanismKind,
    fee_for_fill,
    request_quote,
    accept_quote,
    commit_quote,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"
DEMAND_ASSET = "asset/USD"
OFFER_WINDOWS = ("2026-09-02T00:00:00Z", "2026-09-03T06:00:00Z")
MARKET_WINDOW = ("2026-09-03T00:00:00Z", "2026-09-03T01:00:00Z")

RFQ_INSTANT = "2026-09-03T00:05:00Z"
RFQ_ACCEPT_AT = "2026-09-03T00:05:30Z"
RFQ_COMMIT_AT = "2026-09-03T00:05:40Z"
BATCH_ALLOCATE_AT = "2026-09-03T01:00:01Z"
BATCH_ACCEPT_AT = "2026-09-03T01:00:30Z"


def prov(source: str) -> Provenance:
    return Provenance(
        issuer="principal/market-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-010-dogfooding",),
    )


def _demand():
    from src.intent import (
        Amount,
        EconomicSlack,
        FundingBinding,
        FundingSourceRef,
        FulfillmentPolicy,
        Intent,
        IntentSpec,
        OptimizationObjective,
        PolicySpec,
        SlackSpec,
        derive_demand,
    )

    policy = FulfillmentPolicy.build(
        object_id="intent/policy/market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=PolicySpec(
            objectives=(OptimizationObjective.COST, OptimizationObjective.RELIABILITY),
            allow_split=True,
            allow_asset_substitution=True,
            allow_route_substitution=True,
        ),
        provenance=prov("intent/fulfillment-policy"),
        correlation_id="corr/market-fixture",
    )
    slack = EconomicSlack.build(
        object_id="intent/slack/market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=SlackSpec(
            amount_min=Amount(125000, 2, DEMAND_ASSET),
            amount_max=Amount(130000, 2, DEMAND_ASSET),
            earliest_completion="2026-09-03T00:00:00Z",
            latest_completion="2026-09-03T12:00:00Z",
            max_payment_count=2,
            substitute_assets=("asset/USDC",),
        ),
        provenance=prov("intent/economic-slack"),
        correlation_id="corr/market-fixture",
    )
    intent = Intent.build(
        object_id="intent/pay-market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=IntentSpec(
            destination_id="endpoint/merchant-42",
            amount=Amount(125000, 2, DEMAND_ASSET),
            deadline="2026-09-03T12:00:00Z",
            funding=FundingBinding.build(
                [
                    FundingSourceRef(
                        "value/funding-source/wallet-7", Amount(125000, 2, DEMAND_ASSET)
                    ),
                    FundingSourceRef("value/funding-source/bank-7"),
                ]
            ),
            policy_id="intent/policy/market-fixture",
            slack_id="intent/slack/market-fixture",
        ),
        provenance=prov("intent/merchant-checkout"),
        correlation_id="corr/market-fixture",
    )
    authorized = intent.authorize(
        provenance=prov("intent/authorize-command"),
        causation_id="command/authorize-market-fixture",
    )
    return derive_demand(
        authorized,
        slack=slack,
        policy=policy,
        provenance=prov("intent/demand-derivation"),
    )


def _offers():
    from . import create_liquidity_offer

    return (
        create_liquidity_offer(
            offer_id="market/offer/alpha",
            provider="provider/alpha",
            asset=DEMAND_ASSET,
            amount_min=50000,
            amount_max=140000,
            scale=2,
            price_bps=250,
            flat_fee=10,
            available_from=OFFER_WINDOWS[0],
            available_until=OFFER_WINDOWS[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("market/liquidity-offer"),
        ),
        create_liquidity_offer(
            offer_id="market/offer/beta",
            provider="provider/beta",
            asset=DEMAND_ASSET,
            amount_min=50000,
            amount_max=60000,
            scale=2,
            price_bps=200,
            flat_fee=20,
            available_from=OFFER_WINDOWS[0],
            available_until=OFFER_WINDOWS[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("market/liquidity-offer"),
        ),
        create_liquidity_offer(
            offer_id="market/offer/gamma",
            provider="provider/gamma",
            asset=DEMAND_ASSET,
            amount_min=50000,
            amount_max=70000,
            scale=2,
            price_bps=300,
            flat_fee=5,
            available_from=OFFER_WINDOWS[0],
            available_until=OFFER_WINDOWS[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("market/liquidity-offer"),
        ),
    )


def _rfq_leg(demand, offers):
    """The RFQ default mechanism: request, accept, commit."""
    quote = request_quote(
        demand, offers=offers, as_of=RFQ_INSTANT, provenance=prov("market/rfq-request")
    )
    accepted = accept_quote(
        quote,
        taker="principal/merchant-42",
        as_of=RFQ_ACCEPT_AT,
        provenance=prov("market/rfq-accept"),
    )
    commit = commit_quote(
        accepted,
        fill_value=130000,
        as_of=RFQ_COMMIT_AT,
        provenance=prov("market/rfq-commit"),
    )
    fill = commit.reservation.spec.amount_value
    lines = [
        "mechanism=RFQ",
        f"rfq.maker={commit.quote.spec.maker}",
        f"rfq.allocated_amount={fill}",
        "rfq.fill_count=1",
        f"rfq.price_bps={commit.quote.spec.price_bps}",
        f"rfq.total_fee_value={fee_for_fill(fill, commit.quote.spec.price_bps, commit.quote.spec.flat_fee)}",
        f"rfq.quote_state={commit.quote.state.value}",
        f"rfq.reservation_state={commit.reservation.state.value}",
    ]
    return lines


def _batch_leg(demand, offers):
    """The batch auction mechanism: open, submit, admit, close, allocate."""
    from . import create_market

    market = create_market(
        market_id="market/batch-001",
        mechanism_kind=MechanismKind.BATCH_AUCTION,
        demand_id=demand.envelope.object_id,
        taker="principal/merchant-42",
        asset=DEMAND_ASSET,
        amount_min=125000,
        amount_max=130000,
        scale=2,
        price_min_bps=1,
        price_max_bps=1000,
        opens_at=MARKET_WINDOW[0],
        closes_at=MARKET_WINDOW[1],
        max_submissions=64,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("market/create-market"),
    )
    session = MarketSession(market)
    session.open(MARKET_WINDOW[0], provenance=prov("market/open"))
    offer_map = {offer.envelope.object_id: offer for offer in offers}
    for offer_id, amount in (
        ("market/offer/alpha", 140000),
        ("market/offer/beta", 60000),
        ("market/offer/gamma", 70000),
    ):
        offer = offer_map[offer_id]
        result = session.submit(
            provider=offer.spec.provider,
            offer=offer,
            amount=amount,
            submitted_at="2026-09-03T00:05:00Z",
            provenance=prov("market/submit"),
        )
        assert result.reason is None, result.reason
        session.admit(
            result.submission.envelope.object_id,
            as_of="2026-09-03T00:06:00Z",
            provenance=prov("market/admit"),
        )
    session.close("2026-09-03T01:00:00Z", provenance=prov("market/close"))
    result = session.allocate(
        demand=demand,
        offers=offer_map,
        as_of=BATCH_ALLOCATE_AT,
        provenance=prov("market/allocate"),
    )
    session.accept(as_of=BATCH_ACCEPT_AT, provenance=prov("market/accept"))
    lines = [
        f"mechanism={MechanismKind.BATCH_AUCTION.value}",
        f"batch.allocated_amount={result.allocated_amount}",
        f"batch.fill_count={len(result.fills)}",
        f"batch.clearing_price_bps={result.clearing_price_bps}",
        f"batch.total_fee_value={result.total_fee_value}",
        f"batch.reservation_count={len(session.reservations)}",
        f"batch.market_state={session.market.state.value}",
        f"batch.allocation_digest={result.digest()}",
    ]
    for index, fill in enumerate(result.fills, start=1):
        lines.append(
            f"batch.fill.{index}={fill.provider}:{fill.amount_value}@{fill.price_bps}+{fill.fee_value}"
        )
    return lines


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-010 transcript and its digest.

    The SAME demand/offer fixture drives both mechanisms; the transcript
    compares their outcomes (distribution of fills, pricing and fees).
    """
    demand = _demand()
    offers = _offers()
    lines = [
        "DOGFOOD-010: RFQ vs batch auction on one demand/offer fixture",
        f"demand={demand.envelope.object_id}",
        f"asset={demand.spec.asset}",
        f"amount_min={demand.spec.amount_min}",
        f"amount_max={demand.spec.amount_max}",
        f"max_payment_count={demand.spec.max_payment_count}",
        f"offer_count={len(offers)}",
    ]
    lines.extend(_rfq_leg(demand, offers))
    lines.extend(_batch_leg(demand, offers))
    transcript = "\n".join(lines)
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> str:
    """Run DOGFOOD-010, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
