"""Contract and discrimination test suite for the market domain (WORK-010).

Authored RED-FIRST against the declared public boundary of ``src.market``
before any implementation module exists. The suite covers:

- static boundary contracts (versions, internal non-registry object types,
  forbidden sibling imports, no wall-clock/randomness in domain code);
- the frozen v0.1 lifecycles: LiquidityOffer (Create/Amend/Withdraw/
  Suspend/Resume/Expire), Quote (Create/Amend/Accept/Reject/Commit/Cancel/
  Expire/Invalidate), Market (Create/Open/Close/Submit/Withdraw/Accept/
  Reject/Allocate/Cancel) and the bounded Reservation record (Create/
  Commit/Release/Expire — Hold/Amend/Default/Consume are deliberately left
  to ledger/execution-coupled sibling Work Orders);
- deterministic allocation (documented price-time priority, exact
  fixed-point fees via the money rounding authority, partial fills,
  uniform clearing price for the batch auction);
- anti-gaming fail-closed guards (quote staleness/expiry, minimum quote
  validity, price-band and collusion-style batch checks, duplicate and
  self-dealing submission rejection, withdrawal-after-allocation rejection);
- quality-attribute measurement (scaled deterministic fixture through the
  batch auction allocation);
- DOGFOOD-010 conformance (same demand/offer fixture through RFQ and the
  batch auction).
"""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256
from src.core.envelope import Provenance
from src.intent import (
    Amount,
    Demand,
    DemandState,
    EconomicSlack,
    FundingBinding,
    FundingSourceRef,
    FulfillmentPolicy,
    Intent,
    OptimizationObjective,
    PolicySpec,
    SlackSpec,
    derive_demand,
    withdraw_demand,
)

from src.market import (
    ALLOCATION_CLASS,
    COLLUSION_CLUSTER_MIN,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    DEFAULT_RESERVATION_HOLD_SECONDS,
    LIQUIDITY_OFFER_OBJECT_TYPE,
    MARKET_FEE_ROUNDING_MODE,
    MARKET_MECHANISM_OBJECT_TYPE,
    MARKET_PROTOCOL_VERSION,
    MARKET_SCHEMA_VERSION,
    MARKET_SUBMISSION_OBJECT_TYPE,
    MAX_PRICE_BPS,
    MIN_QUOTE_VALIDITY_SECONDS,
    MIN_PRICE_BPS,
    MECHANISM_ENGINES,
    QUOTE_OBJECT_TYPE,
    RESERVATION_OBJECT_TYPE,
    AllocationRejection,
    AllocationRejectionReason,
    AllocationResult,
    AllocationStatus,
    BatchAuctionEngine,
    Fill,
    LiquidityOffer,
    LiquidityOfferState,
    LiquidityOfferSpec,
    MarketMechanism,
    MarketSession,
    MarketSpec,
    MarketState,
    MarketSubmission,
    MarketSubmissionSpec,
    MechanismEngine,
    MechanismKind,
    Quote,
    QuoteCommit,
    QuoteReasonCode,
    QuoteSpec,
    QuoteState,
    Reservation,
    ReservationSpec,
    ReservationState,
    RfqEngine,
    SubmissionRejectionReason,
    SubmissionState,
    SubmissionResult,
    accept_quote,
    amend_liquidity_offer,
    amend_quote,
    cancel_market,
    cancel_quote,
    close_market,
    commit_quote,
    commit_reservation,
    create_liquidity_offer,
    create_market,
    create_quote,
    create_reservation,
    expire_liquidity_offer,
    expire_quote,
    expire_reservation,
    fee_for_fill,
    invalidate_quote,
    open_market,
    reject_quote,
    release_reservation,
    request_quote,
    resume_liquidity_offer,
    suspend_liquidity_offer,
    withdraw_liquidity_offer,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"
DEMAND_ASSET = "asset/USD"


def prov(source: str = "market/test") -> Provenance:
    return Provenance(
        issuer="principal/market-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-010",),
    )


# ---------------------------------------------------------------------------
# Demand fixtures built through the merged intent public contract (WORK-008).
# ---------------------------------------------------------------------------


def policy() -> FulfillmentPolicy:
    return FulfillmentPolicy.build(
        object_id="intent/policy/market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=PolicySpec(
            objectives=(
                OptimizationObjective.COST,
                OptimizationObjective.RELIABILITY,
            ),
            allow_split=True,
            allow_asset_substitution=True,
            allow_route_substitution=True,
        ),
        provenance=prov(source="intent/fulfillment-policy"),
        correlation_id="corr/market-fixture",
    )


def slack(
    amount_min: int = 125000,
    amount_max: int = 130000,
    max_payment_count: int = 2,
) -> EconomicSlack:
    return EconomicSlack.build(
        object_id="intent/slack/market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=SlackSpec(
            amount_min=Amount(amount_min, 2, DEMAND_ASSET),
            amount_max=Amount(amount_max, 2, DEMAND_ASSET),
            earliest_completion="2026-09-03T00:00:00Z",
            latest_completion="2026-09-03T12:00:00Z",
            max_payment_count=max_payment_count,
            substitute_assets=("asset/USDC",),
        ),
        provenance=prov(source="intent/economic-slack"),
        correlation_id="corr/market-fixture",
    )


def intent_for(slack_object: EconomicSlack, amount_value: int) -> Intent:
    return Intent.build(
        object_id="intent/pay-market-fixture",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=None
        or _intent_spec(slack_object, amount_value),
        provenance=prov(source="intent/merchant-checkout"),
        correlation_id="corr/market-fixture",
    )


def _intent_spec(slack_object: EconomicSlack, amount_value: int):
    from src.intent import IntentSpec

    return IntentSpec(
        destination_id="endpoint/merchant-42",
        amount=Amount(amount_value, 2, DEMAND_ASSET),
        deadline="2026-09-03T12:00:00Z",
        funding=FundingBinding.build(
            [
                FundingSourceRef(
                    "value/funding-source/wallet-7",
                    Amount(amount_value, 2, DEMAND_ASSET),
                ),
                FundingSourceRef("value/funding-source/bank-7"),
            ]
        ),
        policy_id="intent/policy/market-fixture",
        slack_id=slack_object.envelope.object_id,
    )


def demand_fixture(
    amount_min: int = 125000,
    amount_max: int = 130000,
    amount_value: int = 125000,
    max_payment_count: int = 2,
) -> Demand:
    slack_object = slack(
        amount_min=amount_min,
        amount_max=amount_max,
        max_payment_count=max_payment_count,
    )
    intent = intent_for(slack_object, amount_value)
    authorized = intent.authorize(
        provenance=prov(source="intent/authorize-command"),
        causation_id="command/authorize-market-fixture",
    )
    return derive_demand(
        authorized,
        slack=slack_object,
        policy=policy(),
        provenance=prov(source="intent/demand-derivation"),
    )


# ---------------------------------------------------------------------------
# Liquidity offer fixtures.
# ---------------------------------------------------------------------------

OFFER_WINDOWS = ("2026-09-02T00:00:00Z", "2026-09-03T06:00:00Z")


def offer_fixture(
    offer_id: str,
    provider: str,
    *,
    price_bps: int,
    flat_fee: int = 0,
    amount_min: int = 50000,
    amount_max: int = 140000,
    environment_id: str = ENV,
    capability_commitment_id: str | None = None,
    available_from: str = OFFER_WINDOWS[0],
    available_until: str = OFFER_WINDOWS[1],
) -> LiquidityOffer:
    return create_liquidity_offer(
        offer_id=offer_id,
        provider=provider,
        asset=DEMAND_ASSET,
        amount_min=amount_min,
        amount_max=amount_max,
        scale=2,
        price_bps=price_bps,
        flat_fee=flat_fee,
        available_from=available_from,
        available_until=available_until,
        environment_id=environment_id,
        domain_id=DOMAIN,
        provenance=prov(source="market/liquidity-offer"),
        capability_commitment_id=capability_commitment_id,
    )


OFFER_ALPHA = ("market/offer/alpha", "provider/alpha", 250, 10)
OFFER_BETA = ("market/offer/beta", "provider/beta", 200, 20)
OFFER_GAMMA = ("market/offer/gamma", "provider/gamma", 300, 5)


def default_offers() -> tuple[LiquidityOffer, ...]:
    return (
        offer_fixture(*OFFER_ALPHA[:2], price_bps=OFFER_ALPHA[2], flat_fee=OFFER_ALPHA[3]),
        offer_fixture(*OFFER_BETA[:2], price_bps=OFFER_BETA[2], flat_fee=OFFER_BETA[3],
                      amount_max=60000),
        offer_fixture(*OFFER_GAMMA[:2], price_bps=OFFER_GAMMA[2], flat_fee=OFFER_GAMMA[3],
                      amount_max=70000),
    )


def offers_map() -> dict[str, LiquidityOffer]:
    offers = default_offers()
    return {offer.envelope.object_id: offer for offer in offers}


# ---------------------------------------------------------------------------
# Market fixtures.
# ---------------------------------------------------------------------------

MARKET_WINDOW = ("2026-09-03T00:00:00Z", "2026-09-03T01:00:00Z")


def market_fixture(
    mechanism: MechanismKind = MechanismKind.BATCH_AUCTION,
    *,
    amount_min: int = 125000,
    amount_max: int = 130000,
    price_min_bps: int = 1,
    price_max_bps: int = 1000,
    demand_id: str = "intent/pay-market-fixture/demand",
    max_submissions: int = 64,
) -> MarketMechanism:
    return create_market(
        market_id="market/batch-001",
        mechanism_kind=mechanism,
        demand_id=demand_id,
        taker="principal/merchant-42",
        asset=DEMAND_ASSET,
        amount_min=amount_min,
        amount_max=amount_max,
        scale=2,
        price_min_bps=price_min_bps,
        price_max_bps=price_max_bps,
        opens_at=MARKET_WINDOW[0],
        closes_at=MARKET_WINDOW[1],
        max_submissions=max_submissions,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(source="market/create-market"),
    )


def batch_session(
    submissions: tuple[tuple[str, int], ...] = (
        ("market/offer/alpha", 140000),
        ("market/offer/beta", 60000),
        ("market/offer/gamma", 70000),
    ),
    *,
    offers: dict[str, LiquidityOffer] | None = None,
    market: MarketMechanism | None = None,
    admit: bool = True,
) -> MarketSession:
    """Open a batch market and submit/admit the given (offer id, amount) pairs."""
    offer_map = offers if offers is not None else offers_map()
    if market is None:
        market = market_fixture(MechanismKind.BATCH_AUCTION)
    session = MarketSession(market)
    session.open(as_of=MARKET_WINDOW[0], provenance=prov())
    for offer_id, amount in submissions:
        offer = offer_map[offer_id]
        result = session.submit(
            provider=offer.spec.provider,
            offer=offer,
            amount=amount,
            submitted_at="2026-09-03T00:05:00Z",
            provenance=prov(source="market/submit"),
        )
        if result.reason is not None:
            raise AssertionError(f"fixture submit rejected: {result.reason}")
        if admit:
            session.admit(
                result.submission.envelope.object_id,
                as_of="2026-09-03T00:06:00Z",
                provenance=prov(source="market/admit"),
            )
    return session


# ---------------------------------------------------------------------------
# 1. Static boundary contracts.
# ---------------------------------------------------------------------------


class StaticContractTests(unittest.TestCase):
    """The typed, versioned public boundary of the market domain."""

    def test_protocol_and_schema_versions_are_frozen(self) -> None:
        self.assertEqual(MARKET_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(MARKET_SCHEMA_VERSION, 1)

    def test_object_types_are_internal_non_registry_formats(self) -> None:
        # No market protocol-visible type is registry-listed (frozen
        # registry lists no market object type), so — per the sibling
        # convention — every market object type uses an internal
        # non-registry "market/..." format and never invents a
        # "payswap/..." registry name.
        for object_type in (
            QUOTE_OBJECT_TYPE,
            MARKET_MECHANISM_OBJECT_TYPE,
            MARKET_SUBMISSION_OBJECT_TYPE,
            LIQUIDITY_OFFER_OBJECT_TYPE,
            RESERVATION_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("market/"), object_type)
            self.assertFalse(object_type.startswith("payswap/"), object_type)

    def test_domain_never_imports_unmerged_or_forbidden_siblings(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_market.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in ("src.transition", "src.trust", "src.value", "src.interoperability"):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_domain_code_has_no_wall_clock_or_randomness(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name in ("test_market.py", "dogfooding.py"):
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in ("time.time", "datetime.now", "utcnow", "random", "time.monotonic"):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_mechanism_kinds_are_a_closed_vocabulary(self) -> None:
        self.assertEqual(
            {kind.value for kind in MechanismKind},
            {"RFQ", "BATCH_AUCTION"},
        )
        with self.assertRaises(ValueError):
            MechanismKind("CONTINUOUS")

    def test_frozen_anti_gaming_constants_are_declared(self) -> None:
        self.assertGreaterEqual(MIN_QUOTE_VALIDITY_SECONDS, 1)
        self.assertGreaterEqual(DEFAULT_QUOTE_VALIDITY_SECONDS, MIN_QUOTE_VALIDITY_SECONDS)
        self.assertGreaterEqual(COLLUSION_CLUSTER_MIN, 3)
        self.assertGreaterEqual(MIN_PRICE_BPS, 1)
        self.assertLessEqual(MAX_PRICE_BPS, 10000)
        self.assertGreaterEqual(DEFAULT_RESERVATION_HOLD_SECONDS, 1)

    def test_mechanism_registry_exposes_both_frozen_engines(self) -> None:
        self.assertEqual(set(MECHANISM_ENGINES), set(MechanismKind))
        self.assertIsInstance(MECHANISM_ENGINES[MechanismKind.RFQ], RfqEngine)
        self.assertIsInstance(MECHANISM_ENGINES[MechanismKind.BATCH_AUCTION], BatchAuctionEngine)
        for engine in MECHANISM_ENGINES.values():
            self.assertIsInstance(engine, MechanismEngine)

    def test_state_vocabularies_are_closed(self) -> None:
        self.assertEqual(
            {state.value for state in QuoteState},
            {
                "FIRM", "ACCEPTED", "COMMITTED", "REJECTED",
                "CANCELLED", "EXPIRED", "INVALIDATED",
            },
        )
        self.assertEqual(
            {state.value for state in MarketState},
            {
                "CREATED", "OPEN", "CLOSED", "ALLOCATED",
                "ACCEPTED", "REJECTED", "CANCELLED",
            },
        )
        self.assertEqual(
            {state.value for state in ReservationState},
            {"RESERVED", "COMMITTED", "RELEASED", "EXPIRED"},
        )
        self.assertEqual(
            {state.value for state in AllocationStatus},
            {"FILLED", "PARTIALLY_FILLED", "REJECTED"},
        )

    def test_quote_terminal_reasons_are_closed(self) -> None:
        self.assertEqual(
            {reason.value for reason in QuoteReasonCode},
            {
                "TAKER_DECLINED", "MAKER_CANCELLED", "QUOTE_EXPIRED",
                "OFFER_WITHDRAWN", "OFFER_SUSPENDED", "CAPABILITY_UNAVAILABLE",
            },
        )


# ---------------------------------------------------------------------------
# 2. Liquidity offers.
# ---------------------------------------------------------------------------


class LiquidityOfferTests(unittest.TestCase):
    """LiquidityOffer records and their frozen lifecycle."""

    def test_create_builds_a_sealed_active_offer(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=OFFER_ALPHA[2],
                              flat_fee=OFFER_ALPHA[3],
                              capability_commitment_id="capability/commitment/c-77")
        self.assertEqual(offer.envelope.object_type, LIQUIDITY_OFFER_OBJECT_TYPE)
        self.assertEqual(offer.state, LiquidityOfferState.ACTIVE)
        self.assertEqual(offer.envelope.protocol_version, MARKET_PROTOCOL_VERSION)
        self.assertEqual(offer.envelope.schema_version, MARKET_SCHEMA_VERSION)
        self.assertEqual(offer.envelope.object_version, 1)
        self.assertIsNone(offer.envelope.previous_version)
        self.assertEqual(offer.spec.capability_commitment_id, "capability/commitment/c-77")
        offer.envelope.verify_integrity()

    def test_create_fails_closed_on_invalid_windows_and_bounds(self) -> None:
        with self.assertRaises(CoreValidationError):
            offer_fixture("market/offer/bad", "provider/bad", price_bps=250,
                          available_from="2026-09-03T06:00:00Z",
                          available_until="2026-09-02T00:00:00Z")
        with self.assertRaises(CoreValidationError):
            offer_fixture("market/offer/bad", "provider/bad", price_bps=250,
                          amount_min=60000, amount_max=50000)
        with self.assertRaises(CoreValidationError):
            offer_fixture("market/offer/bad", "provider/bad", price_bps=0)
        with self.assertRaises(CoreValidationError):
            offer_fixture("market/offer/bad", "provider/bad", price_bps=250, flat_fee=-1)
        with self.assertRaises(CoreValidationError):
            offer_fixture("market/offer/bad", "provider/bad", price_bps=250,
                          available_until="2026-09-03T06:00:00+02:00")

    def test_amend_advances_the_version_and_keeps_identity(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=OFFER_ALPHA[2])
        amended = amend_liquidity_offer(
            offer, provenance=prov(), price_bps=240, amount_max=150000
        )
        self.assertEqual(amended.state, LiquidityOfferState.ACTIVE)
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(amended.envelope.previous_version, 1)
        self.assertEqual(amended.envelope.object_id, offer.envelope.object_id)
        self.assertEqual(amended.spec.price_bps, 240)
        self.assertEqual(amended.spec.amount_max, 150000)
        self.assertEqual(amended.spec.provider, offer.spec.provider)

    def test_amend_is_rejected_on_terminal_states(self) -> None:
        offer = withdraw_liquidity_offer(
            offer_fixture(*OFFER_ALPHA[:2], price_bps=250), provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            amend_liquidity_offer(offer, provenance=prov(), price_bps=1)

    def test_suspend_resume_and_withdraw_transitions(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=250)
        suspended = suspend_liquidity_offer(offer, provenance=prov())
        self.assertEqual(suspended.state, LiquidityOfferState.SUSPENDED)
        resumed = resume_liquidity_offer(suspended, provenance=prov())
        self.assertEqual(resumed.state, LiquidityOfferState.ACTIVE)
        withdrawn = withdraw_liquidity_offer(resumed, provenance=prov())
        self.assertEqual(withdrawn.state, LiquidityOfferState.WITHDRAWN)

    def test_expire_requires_the_window_to_have_elapsed(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=250)
        with self.assertRaises(CoreValidationError):
            expire_liquidity_offer(
                offer, as_of="2026-09-03T00:00:00Z", provenance=prov()
            )
        expired = expire_liquidity_offer(
            offer, as_of="2026-09-03T06:00:00Z", provenance=prov()
        )
        self.assertEqual(expired.state, LiquidityOfferState.EXPIRED)

    def test_offer_round_trip_is_lossless_and_byte_stable(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=250, flat_fee=10)
        encoded = offer.to_json()
        decoded = LiquidityOffer.from_json(encoded)
        self.assertEqual(decoded, offer)
        self.assertEqual(decoded.to_json(), encoded)

    def test_tampered_offers_fail_closed(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=250)
        forged = dict(offer.to_dict())
        forged["payload"] = dict(forged["payload"])
        forged["payload"]["price_bps"] = 1
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(forged)

    def test_floats_are_rejected_everywhere(self) -> None:
        with self.assertRaises(CoreValidationError):
            LiquidityOfferSpec.from_dict(
                {
                    "provider": "provider/alpha",
                    "asset": DEMAND_ASSET,
                    "amount_min": 50000,
                    "amount_max": 140000,
                    "scale": 2,
                    "price_bps": 250.5,
                    "flat_fee": 0,
                    "available_from": OFFER_WINDOWS[0],
                    "available_until": OFFER_WINDOWS[1],
                    "capability_commitment_id": None,
                    "capability_id": None,
                }
            )


# ---------------------------------------------------------------------------
# 3. Firm quote lifecycle (RFQ bilateral path).
# ---------------------------------------------------------------------------


class QuoteLifecycleTests(unittest.TestCase):
    """Quote objects follow the frozen Create/Amend/Accept/Reject/Commit/
    Cancel/Expire/Invalidate family with explicit validity windows."""

    def quote(self) -> Quote:
        return create_quote(
            quote_id="market/quote/q-1",
            demand_id="intent/pay-market-fixture/demand",
            maker="provider/alpha",
            asset=DEMAND_ASSET,
            scale=2,
            amount_min=125000,
            amount_max=130000,
            price_bps=250,
            flat_fee=10,
            valid_from="2026-09-03T00:00:10Z",
            valid_until="2026-09-03T00:01:10Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(source="market/quote-create"),
        )

    def test_create_builds_a_sealed_firm_quote(self) -> None:
        quote = self.quote()
        self.assertEqual(quote.envelope.object_type, QUOTE_OBJECT_TYPE)
        self.assertEqual(quote.state, QuoteState.FIRM)
        self.assertEqual(quote.envelope.protocol_version, MARKET_PROTOCOL_VERSION)
        self.assertEqual(quote.envelope.schema_version, MARKET_SCHEMA_VERSION)
        self.assertIsNone(quote.spec.taker)
        self.assertIsNone(quote.spec.reason)
        quote.envelope.verify_integrity()

    def test_create_enforces_the_minimum_quote_validity(self) -> None:
        # Anti-gaming hook: a quote whose validity window is shorter than
        # MIN_QUOTE_VALIDITY_SECONDS can never be acted on (flicker quote).
        with self.assertRaises(CoreValidationError):
            create_quote(
                quote_id="market/quote/q-flicker",
                demand_id="intent/pay-market-fixture/demand",
                maker="provider/alpha",
                asset=DEMAND_ASSET,
                scale=2,
                amount_min=125000,
                amount_max=130000,
                price_bps=250,
                flat_fee=10,
                valid_from="2026-09-03T00:00:10Z",
                valid_until="2026-09-03T00:00:19Z",
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_create_fails_closed_on_price_and_amount_bounds(self) -> None:
        base = dict(
            quote_id="market/quote/q-bad",
            demand_id="intent/pay-market-fixture/demand",
            maker="provider/alpha",
            asset=DEMAND_ASSET,
            scale=2,
            price_bps=250,
            flat_fee=10,
            valid_from="2026-09-03T00:00:10Z",
            valid_until="2026-09-03T00:01:10Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        for bad in (
            {**base, "price_bps": 0},
            {**base, "price_bps": MAX_PRICE_BPS + 1},
            {**base, "flat_fee": -1},
            {**base, "amount_min": 130000, "amount_max": 125000},
        ):
            with self.assertRaises(CoreValidationError):
                create_quote(**{**bad, "amount_min": bad.get("amount_min", 125000),
                                "amount_max": bad.get("amount_max", 130000)})

    def test_create_coheres_with_the_referenced_offer(self) -> None:
        offer = offer_fixture(*OFFER_ALPHA[:2], price_bps=250, flat_fee=10)
        good = create_quote(
            quote_id="market/quote/q-coherent",
            demand_id="intent/pay-market-fixture/demand",
            maker="provider/alpha",
            asset=DEMAND_ASSET,
            scale=2,
            amount_min=125000,
            amount_max=130000,
            price_bps=250,
            flat_fee=10,
            valid_from="2026-09-03T00:00:10Z",
            valid_until="2026-09-03T00:01:10Z",
            offer=offer,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertEqual(good.spec.offer_id, offer.envelope.object_id)
        for mutation in (
            {"price_bps": 240},
            {"flat_fee": 5},
            {"maker": "provider/beta"},
            {"asset": "asset/EUR"},
            {"environment_id": "env/prod"},
            {"amount_max": 200000},
        ):
            with self.assertRaises(CoreValidationError):
                create_quote(
                    quote_id="market/quote/q-incoherent",
                    demand_id="intent/pay-market-fixture/demand",
                    maker=mutation.get("maker", "provider/alpha"),
                    asset=mutation.get("asset", DEMAND_ASSET),
                    scale=2,
                    amount_min=125000,
                    amount_max=mutation.get("amount_max", 130000),
                    price_bps=mutation.get("price_bps", 250),
                    flat_fee=mutation.get("flat_fee", 10),
                    valid_from="2026-09-03T00:00:10Z",
                    valid_until="2026-09-03T00:01:10Z",
                    offer=offer,
                    environment_id=mutation.get("environment_id", ENV),
                    domain_id=DOMAIN,
                    provenance=prov(),
                )

    def test_amend_keeps_firm_state_and_identity(self) -> None:
        quote = self.quote()
        amended = amend_quote(
            quote, provenance=prov(), price_bps=230, amount_min=125000
        )
        self.assertEqual(amended.state, QuoteState.FIRM)
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(amended.spec.price_bps, 230)
        self.assertEqual(amended.envelope.object_id, quote.envelope.object_id)
        self.assertEqual(amended.spec.maker, quote.spec.maker)

    def test_amend_cannot_break_the_minimum_validity_or_identity(self) -> None:
        quote = self.quote()
        with self.assertRaises(CoreValidationError):
            amend_quote(
                quote, provenance=prov(),
                valid_from="2026-09-03T00:00:30Z",
                valid_until="2026-09-03T00:00:39Z",
            )

    def test_amend_is_rejected_after_terminal_transitions(self) -> None:
        quote = reject_quote(self.quote(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_quote(quote, provenance=prov(), price_bps=1)

    def test_accept_records_the_taker_inside_the_validity_window(self) -> None:
        quote = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        self.assertEqual(quote.state, QuoteState.ACCEPTED)
        self.assertEqual(quote.spec.taker, "principal/merchant-42")
        self.assertEqual(quote.envelope.object_version, 2)

    def test_accept_rejects_stale_and_premature_acceptance(self) -> None:
        quote = self.quote()
        for bad_at in ("2026-09-03T00:01:10Z", "2026-09-03T00:05:00Z",
                       "2026-09-03T00:00:00Z"):
            with self.assertRaises(CoreValidationError):
                accept_quote(
                    quote, taker="principal/merchant-42",
                    as_of=bad_at, provenance=prov(),
                )

    def test_accept_rejects_self_dealing(self) -> None:
        # Anti-gaming hook: the maker may not accept its own quote.
        with self.assertRaises(CoreValidationError):
            accept_quote(
                self.quote(), taker="provider/alpha",
                as_of="2026-09-03T00:00:30Z", provenance=prov(),
            )

    def test_reject_records_a_typed_reason(self) -> None:
        quote = reject_quote(self.quote(), provenance=prov())
        self.assertEqual(quote.state, QuoteState.REJECTED)
        self.assertEqual(quote.spec.reason, QuoteReasonCode.TAKER_DECLINED.value)

    def test_commit_produces_an_exact_reservation(self) -> None:
        accepted = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        commit = commit_quote(
            accepted, fill_value=130000,
            as_of="2026-09-03T00:00:40Z", provenance=prov(),
        )
        self.assertEqual(commit.quote.state, QuoteState.COMMITTED)
        reservation = commit.reservation
        self.assertEqual(reservation.state, ReservationState.RESERVED)
        self.assertEqual(reservation.spec.amount_value, 130000)
        self.assertEqual(reservation.spec.provider, "provider/alpha")
        self.assertEqual(reservation.spec.beneficiary, "principal/merchant-42")
        self.assertEqual(reservation.spec.source_quote_id, "market/quote/q-1")
        self.assertEqual(reservation.spec.asset, DEMAND_ASSET)
        self.assertEqual(reservation.spec.reserved_from, "2026-09-03T00:00:40Z")
        self.assertEqual(reservation.spec.reserved_until, "2026-09-03T00:01:10Z")

    def test_commit_rejects_stale_commitment_and_bad_fill_amounts(self) -> None:
        accepted = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            commit_quote(accepted, fill_value=130000,
                         as_of="2026-09-03T00:01:10Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            commit_quote(accepted, fill_value=124999,
                         as_of="2026-09-03T00:00:40Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            commit_quote(accepted, fill_value=130001,
                         as_of="2026-09-03T00:00:40Z", provenance=prov())

    def test_cancel_is_possible_before_commit_only(self) -> None:
        firm = self.quote()
        cancelled = cancel_quote(firm, provenance=prov())
        self.assertEqual(cancelled.state, QuoteState.CANCELLED)
        self.assertEqual(cancelled.spec.reason, QuoteReasonCode.MAKER_CANCELLED.value)
        accepted = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        self.assertEqual(
            cancel_quote(accepted, provenance=prov()).state, QuoteState.CANCELLED
        )
        commit = commit_quote(
            accepted, fill_value=125000,
            as_of="2026-09-03T00:00:40Z", provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            cancel_quote(commit.quote, provenance=prov())

    def test_expire_requires_the_validity_window_to_have_elapsed(self) -> None:
        quote = self.quote()
        with self.assertRaises(CoreValidationError):
            expire_quote(quote, as_of="2026-09-03T00:01:09Z", provenance=prov())
        expired = expire_quote(
            quote, as_of="2026-09-03T00:01:10Z", provenance=prov()
        )
        self.assertEqual(expired.state, QuoteState.EXPIRED)
        self.assertEqual(expired.spec.reason, QuoteReasonCode.QUOTE_EXPIRED.value)

    def test_invalidate_records_typed_provenance_reasons(self) -> None:
        quote = self.quote()
        invalidated = invalidate_quote(
            quote, reason=QuoteReasonCode.OFFER_WITHDRAWN, provenance=prov()
        )
        self.assertEqual(invalidated.state, QuoteState.INVALIDATED)
        self.assertEqual(invalidated.spec.reason, QuoteReasonCode.OFFER_WITHDRAWN.value)
        accepted = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        invalidated_accepted = invalidate_quote(
            accepted, reason=QuoteReasonCode.CAPABILITY_UNAVAILABLE, provenance=prov()
        )
        self.assertEqual(invalidated_accepted.state, QuoteState.INVALIDATED)

    def test_quote_round_trip_is_lossless_and_byte_stable(self) -> None:
        quote = accept_quote(
            self.quote(), taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        encoded = quote.to_json()
        self.assertEqual(Quote.from_json(encoded).to_json(), encoded)

    def test_tampered_quotes_fail_closed(self) -> None:
        quote = self.quote()
        forged = dict(quote.to_dict())
        forged["payload"] = dict(forged["payload"])
        forged["payload"]["price_bps"] = 1
        with self.assertRaises(CoreValidationError):
            Quote.from_dict(forged)


# ---------------------------------------------------------------------------
# 4. RFQ default mechanism (request for quote over standing offers).
# ---------------------------------------------------------------------------


class RequestQuoteTests(unittest.TestCase):
    """request_quote: the RFQ default direct-accept mechanism over offers."""

    def test_selects_the_best_eligible_offer(self) -> None:
        demand = demand_fixture()
        offers = default_offers()
        quote = request_quote(
            demand, offers=offers, as_of="2026-09-03T00:05:00Z", provenance=prov()
        )
        # beta is cheapest but its capacity (60000) cannot bracket the
        # demand minimum (125000); alpha is the best eligible offer.
        self.assertEqual(quote.state, QuoteState.FIRM)
        self.assertEqual(quote.spec.maker, "provider/alpha")
        self.assertEqual(quote.spec.price_bps, 250)
        self.assertEqual(quote.spec.flat_fee, 10)
        self.assertEqual(quote.spec.amount_min, 125000)
        self.assertEqual(quote.spec.amount_max, 130000)
        self.assertEqual(quote.spec.offer_id, "market/offer/alpha")
        self.assertEqual(quote.spec.demand_id, demand.envelope.object_id)
        self.assertEqual(quote.spec.valid_from, "2026-09-03T00:05:00Z")
        self.assertEqual(
            quote.spec.valid_until,
            "2026-09-03T00:06:00Z",  # as_of + DEFAULT_QUOTE_VALIDITY_SECONDS
        )

    def test_no_eligible_offer_fails_closed(self) -> None:
        demand = demand_fixture()
        with self.assertRaises(CoreValidationError):
            request_quote(
                demand, offers=default_offers()[1:],
                as_of="2026-09-03T00:05:00Z", provenance=prov(),
            )

    def test_withdrawn_demand_cannot_be_quoted(self) -> None:
        demand = withdraw_demand(demand_fixture(), provenance=prov())
        self.assertEqual(demand.state, DemandState.WITHDRAWN)
        with self.assertRaises(CoreValidationError):
            request_quote(
                demand, offers=default_offers(),
                as_of="2026-09-03T00:05:00Z", provenance=prov(),
            )

    def test_flicker_offers_are_ineligible(self) -> None:
        # An offer whose remaining availability is below the minimum quote
        # validity cannot back a firm quote.
        demand = demand_fixture()
        short = create_liquidity_offer(
            offer_id="market/offer/short",
            provider="provider/epsilon",
            asset=DEMAND_ASSET,
            amount_min=1000,
            amount_max=200000,
            scale=2,
            price_bps=100,
            flat_fee=0,
            available_from="2026-09-02T00:00:00Z",
            available_until="2026-09-03T00:05:05Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            request_quote(
                demand, offers=(short,),
                as_of="2026-09-03T00:05:00Z", provenance=prov(),
            )

    def test_environment_mismatch_fails_closed(self) -> None:
        demand = demand_fixture()
        foreign = offer_fixture(
            "market/offer/foreign", "provider/foreign",
            price_bps=100, environment_id="env/prod",
        )
        with self.assertRaises(CoreValidationError):
            request_quote(
                demand, offers=(foreign,),
                as_of="2026-09-03T00:05:00Z", provenance=prov(),
            )

    def test_partial_coverage_quote_for_splittable_demand(self) -> None:
        demand = demand_fixture(amount_min=50000, amount_max=130000, amount_value=125000)
        offers = default_offers()
        quote = request_quote(
            demand, offers=offers, as_of="2026-09-03T00:05:00Z", provenance=prov()
        )
        # beta is eligible now (60000 brackets the 50000 minimum) and is
        # the cheapest offer, so the RFQ quote is partial by capacity.
        self.assertEqual(quote.spec.maker, "provider/beta")
        self.assertEqual(quote.spec.amount_min, 50000)
        self.assertEqual(quote.spec.amount_max, 60000)


# ---------------------------------------------------------------------------
# 5. Reservations (bounded market-level artifact).
# ---------------------------------------------------------------------------


class ReservationTests(unittest.TestCase):
    """Reservation records: exact amounts, explicit windows, bounded
    Create/Commit/Release/Expire lifecycle (no ledger mutation)."""

    def reservation(self) -> Reservation:
        return create_reservation(
            reservation_id="market/reservation/r-1",
            provider="provider/alpha",
            beneficiary="principal/merchant-42",
            asset=DEMAND_ASSET,
            scale=2,
            amount_value=130000,
            source_quote_id="market/quote/q-1",
            reserved_from="2026-09-03T00:00:40Z",
            reserved_until="2026-09-03T01:00:40Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )

    def test_create_builds_a_sealed_reserved_record(self) -> None:
        reservation = self.reservation()
        self.assertEqual(reservation.envelope.object_type, RESERVATION_OBJECT_TYPE)
        self.assertEqual(reservation.state, ReservationState.RESERVED)
        reservation.envelope.verify_integrity()

    def test_create_fails_closed_on_nonpositive_amounts_and_windows(self) -> None:
        for bad in (0, -1):
            with self.assertRaises(CoreValidationError):
                create_reservation(
                    reservation_id="market/reservation/r-bad",
                    provider="provider/alpha",
                    beneficiary="principal/merchant-42",
                    asset=DEMAND_ASSET,
                    scale=2,
                    amount_value=bad,
                    source_quote_id="market/quote/q-1",
                    reserved_from="2026-09-03T00:00:40Z",
                    reserved_until="2026-09-03T01:00:40Z",
                    environment_id=ENV,
                    domain_id=DOMAIN,
                    provenance=prov(),
                )

    def test_commit_release_and_expire_transitions(self) -> None:
        committed = commit_reservation(
            self.reservation(), as_of="2026-09-03T00:01:00Z", provenance=prov()
        )
        self.assertEqual(committed.state, ReservationState.COMMITTED)
        released = release_reservation(self.reservation(), provenance=prov())
        self.assertEqual(released.state, ReservationState.RELEASED)
        expired = expire_reservation(
            self.reservation(), as_of="2026-09-03T01:00:40Z", provenance=prov()
        )
        self.assertEqual(expired.state, ReservationState.EXPIRED)

    def test_expire_requires_the_hold_window_to_have_elapsed(self) -> None:
        with self.assertRaises(CoreValidationError):
            expire_reservation(
                self.reservation(), as_of="2026-09-03T01:00:39Z", provenance=prov()
            )

    def test_terminal_reservations_are_immutable(self) -> None:
        released = release_reservation(self.reservation(), provenance=prov())
        for operation in (
            lambda r: commit_reservation(r, as_of="2026-09-03T00:01:00Z", provenance=prov()),
            lambda r: release_reservation(r, provenance=prov()),
            lambda r: expire_reservation(r, as_of="2026-09-03T02:00:00Z", provenance=prov()),
        ):
            with self.assertRaises(CoreValidationError):
                operation(released)

    def test_reservation_round_trip_is_lossless(self) -> None:
        reservation = self.reservation()
        encoded = reservation.to_json()
        self.assertEqual(Reservation.from_json(encoded), reservation)

    def test_reservation_never_touches_the_ledger_surface(self) -> None:
        # The market reservation is a declarative artifact only: it exposes
        # no posting/journal/balance surface (ledger semantics are WORK-005).
        package = Path(__file__).parent / "reservations.py"
        text = package.read_text(encoding="utf-8")
        for forbidden in ("ledger", "posting", "journal", "hold_create"):
            self.assertNotIn(forbidden, text)


# ---------------------------------------------------------------------------
# 6. Market objects (MarketMechanism) and phase commands.
# ---------------------------------------------------------------------------


class MarketObjectTests(unittest.TestCase):
    """Market Create/Open/Close/Cancel commands with explicit windows."""

    def test_create_builds_a_sealed_created_market(self) -> None:
        market = market_fixture()
        self.assertEqual(market.envelope.object_type, MARKET_MECHANISM_OBJECT_TYPE)
        self.assertEqual(market.state, MarketState.CREATED)
        self.assertEqual(market.spec.mechanism_kind, MechanismKind.BATCH_AUCTION.value)
        self.assertEqual(market.envelope.protocol_version, MARKET_PROTOCOL_VERSION)
        market.envelope.verify_integrity()

    def test_create_fails_closed_on_invalid_declarations(self) -> None:
        with self.assertRaises(CoreValidationError):
            market_fixture(price_min_bps=1000, price_max_bps=500)
        with self.assertRaises(CoreValidationError):
            market_fixture(amount_min=130000, amount_max=125000)
        with self.assertRaises(CoreValidationError):
            create_market(
                market_id="market/bad",
                mechanism_kind="CONTINUOUS",
                demand_id="intent/pay-market-fixture/demand",
                taker="principal/merchant-42",
                asset=DEMAND_ASSET,
                amount_min=125000,
                amount_max=130000,
                scale=2,
                price_min_bps=1,
                price_max_bps=1000,
                opens_at="2026-09-03T01:00:00Z",
                closes_at="2026-09-03T00:00:00Z",
                max_submissions=64,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            market_fixture(max_submissions=0)

    def test_open_requires_the_window_to_be_current(self) -> None:
        market = market_fixture()
        opened = open_market(market, as_of="2026-09-03T00:00:00Z", provenance=prov())
        self.assertEqual(opened.state, MarketState.OPEN)
        with self.assertRaises(CoreValidationError):
            open_market(market, as_of="2026-09-02T23:59:59Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            open_market(market, as_of="2026-09-03T01:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            open_market(opened, as_of="2026-09-03T00:00:30Z", provenance=prov())

    def test_close_requires_the_window_to_have_elapsed(self) -> None:
        market = open_market(
            market_fixture(), as_at := "2026-09-03T00:00:00Z", provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            close_market(market, as_of="2026-09-03T00:59:59Z", provenance=prov())
        closed = close_market(market, as_of="2026-09-03T01:00:00Z", provenance=prov())
        self.assertEqual(closed.state, MarketState.CLOSED)

    def test_cancel_is_rejected_after_allocation_and_from_terminal_states(self) -> None:
        market = market_fixture()
        cancelled = cancel_market(market, as_of="2026-09-03T00:00:00Z", provenance=prov())
        self.assertEqual(cancelled.state, MarketState.CANCELLED)
        with self.assertRaises(CoreValidationError):
            cancel_market(cancelled, as_of="2026-09-03T00:00:01Z", provenance=prov())

    def test_market_round_trip_is_lossless(self) -> None:
        market = open_market(
            market_fixture(), as_of="2026-09-03T00:00:00Z", provenance=prov()
        )
        encoded = market.to_json()
        self.assertEqual(MarketMechanism.from_json(encoded).to_json(), encoded)


# ---------------------------------------------------------------------------
# 7. Market session submission guards (typed anti-gaming rejections).
# ---------------------------------------------------------------------------


class MarketSessionSubmissionTests(unittest.TestCase):
    """Submit/Withdraw/Accept/Reject commands with typed rejection reasons."""

    def session(self) -> MarketSession:
        return batch_session(submissions=())

    def test_submit_creates_a_deterministic_sequential_submission(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        result = session.submit(
            provider="provider/alpha",
            offer=offer,
            amount=140000,
            submitted_at="2026-09-03T00:05:00Z",
            provenance=prov(),
        )
        self.assertIsNone(result.reason)
        submission = result.submission
        self.assertEqual(submission.envelope.object_type, MARKET_SUBMISSION_OBJECT_TYPE)
        self.assertEqual(
            submission.envelope.object_id, "market/batch-001/sub/000001"
        )
        self.assertEqual(submission.spec.sequence, 1)
        self.assertEqual(submission.spec.price_bps, 250)
        self.assertEqual(submission.spec.flat_fee, 10)
        self.assertEqual(submission.spec.market_id, "market/batch-001")
        submission.envelope.verify_integrity()

    def test_submit_rejects_submissions_outside_the_window(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        early = session.submit(
            provider="provider/alpha", offer=offer, amount=140000,
            submitted_at="2026-08-30T00:00:00Z", provenance=prov(),
        )
        self.assertEqual(early.reason, SubmissionRejectionReason.WINDOW_CLOSED)
        late = session.submit(
            provider="provider/alpha", offer=offer, amount=140000,
            submitted_at="2026-09-03T01:00:00Z", provenance=prov(),
        )
        self.assertEqual(late.reason, SubmissionRejectionReason.WINDOW_CLOSED)

    def test_submit_rejects_duplicates_from_one_provider(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        first = session.submit(
            provider="provider/alpha", offer=offer, amount=140000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertIsNone(first.reason)
        second = session.submit(
            provider="provider/alpha", offer=offer, amount=50000,
            submitted_at="2026-09-03T00:06:00Z", provenance=prov(),
        )
        self.assertEqual(second.reason, SubmissionRejectionReason.DUPLICATE_SUBMISSION)
        # After withdrawal a fresh submission is allowed again.
        session.withdraw(
            first.submission.envelope.object_id,
            as_of="2026-09-03T00:07:00Z", provenance=prov(),
        )
        third = session.submit(
            provider="provider/alpha", offer=offer, amount=50000,
            submitted_at="2026-09-03T00:08:00Z", provenance=prov(),
        )
        self.assertIsNone(third.reason)

    def test_submit_rejects_self_dealing_against_the_taker(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        result = session.submit(
            provider="principal/merchant-42", offer=offer, amount=140000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(result.reason, SubmissionRejectionReason.SELF_DEALING)

    def test_submit_rejects_out_of_band_prices(self) -> None:
        session = self.session()
        expensive = offer_fixture(
            "market/offer/expensive", "provider/expensive", price_bps=2500
        )
        result = session.submit(
            provider="provider/expensive", offer=expensive, amount=50000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(result.reason, SubmissionRejectionReason.PRICE_OUT_OF_BAND)

    def test_submit_rejects_incoherent_offer_references(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        wrong_provider = session.submit(
            provider="provider/beta", offer=offer, amount=140000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(wrong_provider.reason, SubmissionRejectionReason.OFFER_MISMATCH)
        wrong_amount = session.submit(
            provider="provider/alpha", offer=offer, amount=40000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(
            wrong_amount.reason, SubmissionRejectionReason.AMOUNT_OUT_OF_OFFER_BOUNDS
        )
        foreign_env = offer_fixture(
            "market/offer/foreign", "provider/foreign",
            price_bps=100, environment_id="env/prod",
        )
        env_result = session.submit(
            provider="provider/foreign", offer=foreign_env, amount=50000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(
            env_result.reason, SubmissionRejectionReason.ENVIRONMENT_MISMATCH
        )

    def test_submit_rejects_inactive_offers(self) -> None:
        session = self.session()
        offer = offers_map()["market/offer/alpha"]
        withdrawn = withdraw_liquidity_offer(offer, provenance=prov())
        result = session.submit(
            provider="provider/alpha", offer=withdrawn, amount=140000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(result.reason, SubmissionRejectionReason.OFFER_INACTIVE)

    def test_submit_rejects_when_the_market_is_at_capacity(self) -> None:
        market = market_fixture(max_submissions=1)
        session = MarketSession(market)
        session.open(as_of=MARKET_WINDOW[0], provenance=prov())
        offers = offers_map()
        first = session.submit(
            provider="provider/alpha", offer=offers["market/offer/alpha"],
            amount=140000, submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertIsNone(first.reason)
        second = session.submit(
            provider="provider/beta", offer=offers["market/offer/beta"],
            amount=60000, submitted_at="2026-09-03T00:05:30Z", provenance=prov(),
        )
        self.assertEqual(second.reason, SubmissionRejectionReason.MARKET_AT_CAPACITY)

    def test_submit_rejects_when_the_market_is_not_open(self) -> None:
        market = market_fixture()
        session = MarketSession(market)
        offer = offers_map()["market/offer/alpha"]
        result = session.submit(
            provider="provider/alpha", offer=offer, amount=140000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        self.assertEqual(result.reason, SubmissionRejectionReason.MARKET_NOT_OPEN)

    def test_withdraw_is_locked_after_close_and_after_allocation(self) -> None:
        session = batch_session(submissions=(("market/offer/alpha", 140000),))
        submission_id = session.submissions[0].envelope.object_id
        withdrawn = session.withdraw(
            submission_id, as_of="2026-09-03T00:10:00Z", provenance=prov()
        )
        self.assertIsNone(withdrawn.reason)
        self.assertEqual(withdrawn.submission.state, SubmissionState.WITHDRAWN)

        locked_session = batch_session(submissions=(("market/offer/alpha", 140000),))
        locked_id = locked_session.submissions[0].envelope.object_id
        locked_session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        locked = locked_session.withdraw(
            locked_id, as_of="2026-09-03T01:00:01Z", provenance=prov()
        )
        self.assertEqual(locked.reason, SubmissionRejectionReason.SUBMISSION_LOCKED)

        allocated_session = batch_session(submissions=(("market/offer/alpha", 140000),))
        allocated_id = allocated_session.submissions[0].envelope.object_id
        allocated_session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        allocated_session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        final = allocated_session.withdraw(
            allocated_id, as_of="2026-09-03T01:00:02Z", provenance=prov()
        )
        self.assertEqual(final.reason, SubmissionRejectionReason.ALLOCATION_FINAL)

    def test_admit_and_reject_submission_advance_the_state(self) -> None:
        session = batch_session(submissions=(("market/offer/alpha", 140000),), admit=False)
        submission_id = session.submissions[0].envelope.object_id
        admitted = session.admit(
            submission_id, as_of="2026-09-03T00:06:00Z", provenance=prov()
        )
        self.assertEqual(admitted.state, SubmissionState.ACCEPTED)
        with self.assertRaises(CoreValidationError):
            session.admit(
                submission_id, as_of="2026-09-03T00:07:00Z", provenance=prov()
            )
        rejected_session = batch_session(
            submissions=(("market/offer/beta", 60000),), admit=False
        )
        rejected_id = rejected_session.submissions[0].envelope.object_id
        rejected = rejected_session.reject_submission(
            rejected_id,
            reason=SubmissionRejectionReason.OPERATOR_POLICY,
            as_of="2026-09-03T00:06:00Z",
            provenance=prov(),
        )
        self.assertEqual(rejected.state, SubmissionState.REJECTED)
        self.assertEqual(
            rejected.spec.reason, SubmissionRejectionReason.OPERATOR_POLICY.value
        )

    def test_submission_round_trip_is_lossless(self) -> None:
        session = batch_session(submissions=(("market/offer/alpha", 140000),))
        submission = session.submissions[0]
        encoded = submission.to_json()
        self.assertEqual(MarketSubmission.from_json(encoded).to_json(), encoded)


# ---------------------------------------------------------------------------
# 8. Batch auction allocation.
# ---------------------------------------------------------------------------


class BatchAllocationTests(unittest.TestCase):
    """Deterministic price-time priority, partial fills, uniform clearing."""

    def allocate(self, session: MarketSession, demand: Demand | None = None,
                 offers: dict[str, LiquidityOffer] | None = None):
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        return session.allocate(
            demand=demand if demand is not None else demand_fixture(),
            offers=offers if offers is not None else offers_map(),
            as_of="2026-09-03T01:00:01Z",
            provenance=prov(source="market/allocate"),
        )

    def test_price_time_priority_with_partial_fill_and_uniform_clearing(self) -> None:
        session = batch_session()
        result = self.allocate(session)
        self.assertEqual(result.status, AllocationStatus.FILLED)
        self.assertEqual(result.mechanism_kind, MechanismKind.BATCH_AUCTION.value)
        self.assertEqual(result.market_id, "market/batch-001")
        self.assertEqual(result.demand_id, "intent/pay-market-fixture/demand")
        self.assertEqual(result.allocated_amount, 130000)
        self.assertEqual(result.unfilled_amount, 0)
        self.assertEqual(result.clearing_price_bps, 250)
        self.assertEqual(result.total_fee_value, 3280)
        self.assertEqual(len(result.fills), 2)
        first, second = result.fills
        self.assertEqual(first.submission_id, "market/batch-001/sub/000002")
        self.assertEqual(first.provider, "provider/beta")
        self.assertEqual(first.amount_value, 60000)
        self.assertEqual(first.price_bps, 250)  # uniform clearing price
        self.assertEqual(first.fee_value, 1520)  # floor(60000*250/10000)+20
        self.assertEqual(second.submission_id, "market/batch-001/sub/000001")
        self.assertEqual(second.provider, "provider/alpha")
        self.assertEqual(second.amount_value, 70000)  # partial fill
        self.assertEqual(second.fee_value, 1760)  # floor(70000*250/10000)+10
        # Value conservation: fills sum exactly to the allocated amount.
        self.assertEqual(
            sum(fill.amount_value for fill in result.fills), result.allocated_amount
        )
        self.assertEqual(
            sum(fill.fee_value for fill in result.fills), result.total_fee_value
        )

    def test_allocations_are_deterministic_across_identical_sessions(self) -> None:
        first = self.allocate(batch_session())
        second = self.allocate(batch_session())
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.digest(), second.digest())

    def test_submissions_advance_to_allocation_states(self) -> None:
        session = batch_session()
        self.allocate(session)
        by_state = {
            submission.envelope.object_id: submission.state
            for submission in session.submissions
        }
        self.assertEqual(by_state["market/batch-001/sub/000002"], SubmissionState.ALLOCATED_FULL)
        self.assertEqual(by_state["market/batch-001/sub/000001"], SubmissionState.ALLOCATED_PARTIAL)
        self.assertEqual(by_state["market/batch-001/sub/000003"], SubmissionState.UNALLOCATED)

    def test_reservations_are_created_and_finalized_on_accept(self) -> None:
        session = batch_session()
        result = self.allocate(session)
        self.assertEqual(len(session.reservations), 2)
        self.assertEqual(
            [reservation.state for reservation in session.reservations],
            [ReservationState.RESERVED, ReservationState.RESERVED],
        )
        self.assertEqual(result.reservation_ids[0], session.reservations[0].envelope.object_id)
        market = session.accept(as_of="2026-09-03T01:00:30Z", provenance=prov())
        self.assertEqual(market.state, MarketState.ACCEPTED)
        self.assertEqual(
            [reservation.state for reservation in session.reservations],
            [ReservationState.COMMITTED, ReservationState.COMMITTED],
        )

    def test_rejecting_the_allocation_releases_reservations(self) -> None:
        session = batch_session()
        self.allocate(session)
        market = session.reject_allocation(as_of="2026-09-03T01:00:30Z", provenance=prov())
        self.assertEqual(market.state, MarketState.REJECTED)
        self.assertEqual(
            [reservation.state for reservation in session.reservations],
            [ReservationState.RELEASED, ReservationState.RELEASED],
        )

    def test_demand_min_not_met_rejects_the_whole_allocation(self) -> None:
        session = batch_session(submissions=(("market/offer/beta", 60000),))
        result = self.allocate(session)
        self.assertEqual(result.status, AllocationStatus.REJECTED)
        self.assertEqual(result.reason, AllocationRejectionReason.DEMAND_MIN_NOT_MET)
        self.assertEqual(result.fills, ())
        self.assertEqual(session.reservations, ())
        self.assertEqual(session.market.state, MarketState.ALLOCATED)

    def test_partially_filled_status_when_liquidity_is_short_of_the_max(self) -> None:
        demand = demand_fixture(amount_min=50000, amount_max=130000, amount_value=125000)
        session = batch_session(submissions=(("market/offer/gamma", 70000),))
        result = self.allocate(session, demand=demand)
        self.assertEqual(result.status, AllocationStatus.PARTIALLY_FILLED)
        self.assertEqual(result.allocated_amount, 70000)
        self.assertEqual(result.unfilled_amount, 60000)
        self.assertIsNone(result.reason)

    def test_payment_count_cap_limits_the_number_of_fills(self) -> None:
        demand = demand_fixture(
            amount_min=50000, amount_max=130000, amount_value=125000, max_payment_count=1
        )
        session = batch_session(
            submissions=(("market/offer/beta", 60000), ("market/offer/alpha", 140000))
        )
        result = self.allocate(session, demand=demand)
        # The splittable demand allows only one payment, so only the best
        # submission (beta at 200 bps) is filled.
        self.assertEqual(len(result.fills), 1)
        self.assertEqual(result.fills[0].provider, "provider/beta")
        self.assertEqual(result.status, AllocationStatus.PARTIALLY_FILLED)

    def test_unadjudicated_submissions_are_not_admitted_to_allocation(self) -> None:
        session = batch_session(
            submissions=(("market/offer/alpha", 140000),), admit=False
        )
        result = self.allocate(session)
        self.assertEqual(result.status, AllocationStatus.REJECTED)
        self.assertEqual(
            result.rejections[0].reason, SubmissionRejectionReason.NOT_ADMITTED
        )

    def test_offers_withdrawn_before_allocation_reject_their_submissions(self) -> None:
        offers = offers_map()
        session = batch_session(submissions=(("market/offer/alpha", 140000),))
        offers["market/offer/alpha"] = withdraw_liquidity_offer(
            offers["market/offer/alpha"], provenance=prov()
        )
        result = self.allocate(session, offers=offers)
        self.assertEqual(result.status, AllocationStatus.REJECTED)
        self.assertEqual(
            result.rejections[0].reason, SubmissionRejectionReason.OFFER_INACTIVE
        )

    def test_allocate_requires_closed_state_and_coherent_demand(self) -> None:
        session = batch_session()
        with self.assertRaises(CoreValidationError):
            session.allocate(
                demand=demand_fixture(), offers=offers_map(),
                as_of="2026-09-03T00:30:00Z", provenance=prov(),
            )
        closed = batch_session()
        closed.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        withdrawn_demand = withdraw_demand(demand_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            closed.allocate(
                demand=withdrawn_demand, offers=offers_map(),
                as_of="2026-09-03T01:00:01Z", provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            closed.allocate(
                demand=demand_fixture(), offers=offers_map(),
                as_of="2026-09-03T01:00:01Z", provenance=prov(),
            )

    def test_cancel_after_allocation_is_rejected(self) -> None:
        session = batch_session()
        self.allocate(session)
        with self.assertRaises(CoreValidationError):
            session.cancel(as_of="2026-09-03T01:00:30Z", provenance=prov())

    def test_allocation_result_round_trip_is_lossless(self) -> None:
        result = self.allocate(batch_session())
        encoded = result.to_json()
        decoded = AllocationResult.from_json(encoded)
        self.assertEqual(decoded.to_dict(), result.to_dict())
        self.assertEqual(decoded.digest(), result.digest())


# ---------------------------------------------------------------------------
# 9. RFQ market engine (direct-accept through a market session).
# ---------------------------------------------------------------------------


class RfqMarketEngineTests(unittest.TestCase):
    """The RFQ engine inside a market session emits the firm quote that the
    taker accepts and commits (direct-accept default mechanism)."""

    def rfq_session(self) -> MarketSession:
        market = market_fixture(MechanismKind.RFQ)
        session = MarketSession(market)
        session.open(as_at := "2026-09-03T00:00:00Z", provenance=prov())
        offers = offers_map()
        for offer_id in ("market/offer/alpha", "market/offer/beta"):
            offer = offers[offer_id]
            session.submit(
                provider=offer.spec.provider,
                offer=offer,
                amount=140000 if offer_id.endswith("alpha") else 60000,
                submitted_at="2026-09-03T00:05:00Z",
                provenance=prov(),
            )
        for submission in session.submissions:
            session.admit(
                submission.envelope.object_id,
                as_of="2026-09-03T00:06:00Z", provenance=prov(),
            )
        session.close(as_at := "2026-09-03T01:00:00Z", provenance=prov())
        return session

    def test_allocate_selects_the_best_submission_and_emits_a_firm_quote(self) -> None:
        session = self.rfq_session()
        result = session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        self.assertEqual(result.mechanism_kind, MechanismKind.RFQ.value)
        self.assertEqual(result.status, AllocationStatus.FILLED)
        self.assertEqual(len(result.fills), 1)
        fill = result.fills[0]
        self.assertEqual(fill.provider, "provider/alpha")
        self.assertEqual(fill.amount_value, 130000)
        self.assertEqual(fill.price_bps, 250)  # pay-as-bid at the offer price
        self.assertEqual(fill.fee_value, 3260)  # floor(130000*250/10000)+10
        self.assertIsNone(result.clearing_price_bps)
        self.assertIsNotNone(result.quote_id)
        quote = session.quote
        self.assertEqual(quote.state, QuoteState.FIRM)
        self.assertEqual(quote.envelope.object_id, result.quote_id)
        self.assertEqual(quote.spec.maker, "provider/alpha")
        self.assertEqual(quote.spec.amount_min, 125000)
        self.assertEqual(quote.spec.amount_max, 130000)
        self.assertEqual(quote.spec.valid_from, "2026-09-03T01:00:01Z")
        self.assertEqual(quote.spec.valid_until, "2026-09-03T01:01:01Z")

    def test_market_accept_requires_the_quote_to_be_committed(self) -> None:
        session = self.rfq_session()
        session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            session.accept(as_of="2026-09-03T01:00:30Z", provenance=prov())
        accepted = accept_quote(
            session.quote, taker="principal/merchant-42",
            as_of="2026-09-03T01:00:30Z", provenance=prov(),
        )
        commit = commit_quote(
            accepted, fill_value=125000,
            as_of="2026-09-03T01:00:40Z", provenance=prov(),
        )
        market = session.accept(
            as_of="2026-09-03T01:00:50Z", provenance=prov(), quote=commit.quote
        )
        self.assertEqual(market.state, MarketState.ACCEPTED)

    def test_market_reject_invalidates_an_uncommitted_quote(self) -> None:
        session = self.rfq_session()
        session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        market = session.reject_allocation(as_of="2026-09-03T01:00:30Z", provenance=prov())
        self.assertEqual(market.state, MarketState.REJECTED)
        self.assertEqual(session.quote.state, QuoteState.INVALIDATED)

    def test_no_eligible_submission_is_a_typed_allocation_rejection(self) -> None:
        market = market_fixture(MechanismKind.RFQ)
        session = MarketSession(market)
        session.open(as_of="2026-09-03T00:00:00Z", provenance=prov())
        offer = offers_map()["market/offer/beta"]
        result = session.submit(
            provider="provider/beta", offer=offer, amount=60000,
            submitted_at="2026-09-03T00:05:00Z", provenance=prov(),
        )
        session.admit(
            result.submission.envelope.object_id,
            as_of="2026-09-03T00:06:00Z", provenance=prov(),
        )
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        allocation = session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        self.assertEqual(allocation.status, AllocationStatus.REJECTED)
        self.assertEqual(
            allocation.reason, AllocationRejectionReason.NO_ELIGIBLE_SUBMISSIONS
        )

    def test_engine_kind_mismatch_fails_closed(self) -> None:
        session = self.rfq_session()
        with self.assertRaises(CoreValidationError):
            session.allocate(
                demand=demand_fixture(), offers=offers_map(),
                as_of="2026-09-03T01:00:01Z", provenance=prov(),
                engine=MECHANISM_ENGINES[MechanismKind.BATCH_AUCTION],
            )


# ---------------------------------------------------------------------------
# 10. Anti-gaming discrimination over submitted batches.
# ---------------------------------------------------------------------------


class AntiGamingBatchTests(unittest.TestCase):
    """Fail-closed guards over submitted batches and quotes."""

    def collusion_offers(self) -> dict[str, LiquidityOffer]:
        offers = {
            "market/offer/cheap": offer_fixture(
                "market/offer/cheap", "provider/cheap", price_bps=200
            ),
            "market/offer/c1": offer_fixture("market/offer/c1", "provider/c1", price_bps=300),
            "market/offer/c2": offer_fixture("market/offer/c2", "provider/c2", price_bps=300),
            "market/offer/c3": offer_fixture("market/offer/c3", "provider/c3", price_bps=300),
        }
        return offers

    def test_identical_price_cluster_is_suspected_collusion(self) -> None:
        # >= COLLUSION_CLUSTER_MIN distinct providers quoting the exact
        # same price and flat fee while the batch shows genuine price
        # dispersion is rejected as COLLUSION_SUSPECTED (fail-closed).
        offers = self.collusion_offers()
        session = batch_session(
            submissions=(
                ("market/offer/cheap", 130000),
                ("market/offer/c1", 50000),
                ("market/offer/c2", 50000),
                ("market/offer/c3", 50000),
            ),
            offers=offers,
        )
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        result = session.allocate(
            demand=demand_fixture(), offers=offers,
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        collusion_ids = {
            "market/batch-001/sub/000002",
            "market/batch-001/sub/000003",
            "market/batch-001/sub/000004",
        }
        rejected = {rejection.submission_id for rejection in result.rejections}
        self.assertTrue(rejected.issuperset(collusion_ids))
        for rejection in result.rejections:
            if rejection.submission_id in collusion_ids:
                self.assertEqual(
                    rejection.reason, SubmissionRejectionReason.COLLUSION_SUSPECTED
                )
        self.assertEqual(result.status, AllocationStatus.FILLED)
        self.assertEqual(result.allocated_amount, 130000)
        self.assertEqual(len(result.fills), 1)

    def test_cluster_below_the_threshold_is_not_flagged(self) -> None:
        offers = self.collusion_offers()
        session = batch_session(
            submissions=(
                ("market/offer/cheap", 130000),
                ("market/offer/c1", 50000),
                ("market/offer/c2", 50000),
            ),
            offers=offers,
        )
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        result = session.allocate(
            demand=demand_fixture(), offers=offers,
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        for rejection in result.rejections:
            self.assertNotEqual(rejection.reason, SubmissionRejectionReason.COLLUSION_SUSPECTED)

    def test_single_price_batches_are_not_flagged(self) -> None:
        # With no price dispersion at all, identical pricing is
        # indistinguishable from a thin market and is not flagged.
        offers = {
            "market/offer/a": offer_fixture("market/offer/a", "provider/a", price_bps=300,
                                            amount_max=60000),
            "market/offer/b": offer_fixture("market/offer/b", "provider/b", price_bps=300,
                                            amount_max=60000),
            "market/offer/c": offer_fixture("market/offer/c", "provider/c", price_bps=300,
                                            amount_max=60000),
        }
        session = batch_session(
            submissions=(
                ("market/offer/a", 60000),
                ("market/offer/b", 60000),
                ("market/offer/c", 60000),
            ),
            offers=offers,
        )
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        result = session.allocate(
            demand=demand_fixture(), offers=offers,
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        self.assertEqual(result.status, AllocationStatus.FILLED)
        for rejection in result.rejections:
            self.assertNotEqual(rejection.reason, SubmissionRejectionReason.COLLUSION_SUSPECTED)

    def test_price_band_is_revalidated_by_the_engine(self) -> None:
        # Defense in depth: the engine re-validates the market price band
        # even for submissions that reached it (here: a crafted request).
        engine = MECHANISM_ENGINES[MechanismKind.BATCH_AUCTION]
        request = _build_out_of_band_request()
        outcome = engine.allocate(request)
        reasons = {rejection.reason for rejection in outcome.rejections}
        self.assertIn(SubmissionRejectionReason.PRICE_OUT_OF_BAND, reasons)

    def test_quote_commit_after_terminal_state_is_impossible(self) -> None:
        # Once a quote is COMMITTED it is terminal: cancellation, expiry,
        # invalidation and re-commitment all fail closed.
        quote = create_quote(
            quote_id="market/quote/q-final",
            demand_id="intent/pay-market-fixture/demand",
            maker="provider/alpha",
            asset=DEMAND_ASSET,
            scale=2,
            amount_min=125000,
            amount_max=130000,
            price_bps=250,
            flat_fee=10,
            valid_from="2026-09-03T00:00:10Z",
            valid_until="2026-09-03T00:01:10Z",
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        accepted = accept_quote(
            quote, taker="principal/merchant-42",
            as_of="2026-09-03T00:00:30Z", provenance=prov(),
        )
        commit = commit_quote(
            accepted, fill_value=125000,
            as_of="2026-09-03T00:00:40Z", provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            commit_quote(commit.quote, fill_value=125000,
                         as_of="2026-09-03T00:00:50Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            expire_quote(commit.quote, as_of="2026-09-03T01:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            invalidate_quote(
                commit.quote, reason=QuoteReasonCode.OFFER_WITHDRAWN, provenance=prov()
            )


class _RawSubmission(MarketSubmission):
    """Bypass envelope sealing to feed a crafted submission to the engine."""

    def __post_init__(self) -> None:  # noqa: D105 - test-only override
        pass


def _build_out_of_band_request():
    """Craft a batch request containing an out-of-band admitted submission."""
    from src.market import AllocationRequest, close_market, open_market

    market = open_market(
        market_fixture(MechanismKind.BATCH_AUCTION, price_max_bps=1000),
        as_of=MARKET_WINDOW[0],
        provenance=prov(),
    )
    market = close_market(market, as_of=MARKET_WINDOW[1], provenance=prov())
    offers = {
        "market/offer/oob": offer_fixture(
            "market/offer/oob", "provider/oob", price_bps=2500
        )
    }
    submission = _RawSubmission(
        envelope=None,
        spec=MarketSubmissionSpec(
            market_id="market/batch-001",
            provider="provider/oob",
            offer_id="market/offer/oob",
            amount=50000,
            price_bps=2500,
            flat_fee=0,
            submitted_at="2026-09-03T00:05:00Z",
            sequence=1,
            reason=None,
        ),
        integrity_hash=None,
    )
    return AllocationRequest(
        market=market,
        submissions=(submission,),
        offers=offers,
        demand=demand_fixture(),
        as_of="2026-09-03T01:00:01Z",
        provenance=prov(),
    )


# ---------------------------------------------------------------------------
# 11. Mechanism pluggability.
# ---------------------------------------------------------------------------


class MechanismPluggabilityTests(unittest.TestCase):
    """Auction mechanisms are pluggable: a custom engine changes the rule."""

    def test_custom_engine_is_used_when_injected(self) -> None:
        class UniformFeeEngine(BatchAuctionEngine):
            """Batch engine variant: flat-fee-only pricing (zero bps)."""

            def _fill_price(self, submission) -> int:  # override hook
                return MIN_PRICE_BPS

        session = batch_session()
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        result = session.allocate(
            demand=demand_fixture(), offers=offers_map(),
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
            engine=UniformFeeEngine(),
        )
        self.assertEqual(result.status, AllocationStatus.FILLED)
        for fill in result.fills:
            self.assertEqual(fill.price_bps, MIN_PRICE_BPS)

    def test_injected_engine_must_match_the_market_mechanism(self) -> None:
        session = batch_session()
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            session.allocate(
                demand=demand_fixture(), offers=offers_map(),
                as_of="2026-09-03T01:00:01Z", provenance=prov(),
                engine=MECHANISM_ENGINES[MechanismKind.RFQ],
            )

    def test_custom_engine_must_be_a_mechanism_engine(self) -> None:
        session = batch_session()
        session.close(as_of="2026-09-03T01:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            session.allocate(
                demand=demand_fixture(), offers=offers_map(),
                as_of="2026-09-03T01:00:01Z", provenance=prov(),
                engine="not-an-engine",
            )


# ---------------------------------------------------------------------------
# 12. Pricing (fixed-point fees through the money rounding authority).
# ---------------------------------------------------------------------------


class PricingTests(unittest.TestCase):
    """Fees use exact integer arithmetic via src.money round_ratio."""

    def test_fees_are_exact_and_floor_rounded_by_default(self) -> None:
        self.assertEqual(MARKET_FEE_ROUNDING_MODE.value, "FLOOR")
        self.assertEqual(fee_for_fill(130000, 250, 10), 3260)
        self.assertEqual(fee_for_fill(12345, 333, 0), 411)
        self.assertEqual(fee_for_fill(60000, 250, 20), 1520)

    def test_fees_reject_nonpositive_prices_and_negative_fees(self) -> None:
        for bad_price in (0, -1, 10001):
            with self.assertRaises(CoreValidationError):
                fee_for_fill(100000, bad_price, 0)
        with self.assertRaises(CoreValidationError):
            fee_for_fill(100000, 250, -1)
        with self.assertRaises(CoreValidationError):
            fee_for_fill(-1, 250, 0)


# ---------------------------------------------------------------------------
# 13. Quality-attribute proof (measured, per spec/proof-matrix.md).
# ---------------------------------------------------------------------------


class QualityAttributeTests(unittest.TestCase):
    """Scaled deterministic fixture (>= 1000 submissions) through the batch
    auction allocation: measured CPU time (harness only), asserted
    determinism and conservation. Complexity: the allocation is a sort by
    (price, flat fee, submitted_at, sequence) plus a linear fill pass, i.e.
    O(n log n) with no hidden quadratic behavior."""

    SCALED_SUBMISSIONS = 1200

    def scaled_session(self) -> tuple[MarketSession, dict[str, LiquidityOffer]]:
        market = create_market(
            market_id="market/scaled-batch",
            mechanism_kind=MechanismKind.BATCH_AUCTION,
            demand_id="intent/pay-market-fixture/demand",
            taker="principal/merchant-42",
            asset=DEMAND_ASSET,
            amount_min=125000,
            amount_max=130000,
            scale=2,
            price_min_bps=1,
            price_max_bps=10000,
            opens_at=MARKET_WINDOW[0],
            closes_at=MARKET_WINDOW[1],
            max_submissions=2000,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        session = MarketSession(market)
        session.open(as_of=MARKET_WINDOW[0], provenance=prov())
        offers: dict[str, LiquidityOffer] = {}
        for index in range(self.SCALED_SUBMISSIONS):
            price = 200 + (index % 400)
            amount = 1000 + (index % 97) * 100
            offer_id = f"market/offer/scaled/{index:05d}"
            provider = f"provider/scaled/{index:05d}"
            offers[offer_id] = offer_fixture(
                offer_id, provider, price_bps=price, flat_fee=0,
                amount_min=1000, amount_max=130000,
            )
            result = session.submit(
                provider=provider,
                offer=offers[offer_id],
                amount=amount,
                submitted_at="2026-09-03T00:05:00Z",
                provenance=prov(),
            )
            assert result.reason is None, result.reason
            session.admit(
                result.submission.envelope.object_id,
                as_of="2026-09-03T00:06:00Z", provenance=prov(),
            )
        session.close(as_of=MARKET_WINDOW[1], provenance=prov())
        return session, offers

    def test_scaled_batch_allocation_is_deterministic_and_bounded(self) -> None:
        first_session, offers = self.scaled_session()
        start = time.process_time()
        first = first_session.allocate(
            demand=demand_fixture(), offers=offers,
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        measured = time.process_time() - start
        second_session, _ = self.scaled_session()
        second = second_session.allocate(
            demand=demand_fixture(), offers=offers,
            as_of="2026-09-03T01:00:01Z", provenance=prov(),
        )
        self.assertEqual(first.digest(), second.digest())
        self.assertGreaterEqual(first.allocated_amount, 125000)
        self.assertEqual(
            sum(fill.amount_value for fill in first.fills), first.allocated_amount
        )
        self.assertLess(len(first.fills), 130)  # bounded by max_payment_count=2
        # Generous regression tripwire (not the reported number): a linear
        # scan over 1200 immutable submissions must stay far below this.
        self.assertLess(measured, 10.0)


# ---------------------------------------------------------------------------
# 14. DOGFOOD-010 conformance (RFQ vs batch auction on one fixture).
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    """The dogfooding harness is deterministic and byte-stable."""

    def test_transcript_is_deterministic_with_a_stable_digest(self) -> None:
        from src.market.dogfooding import build_transcript

        transcript_a, digest_a = build_transcript()
        transcript_b, digest_b = build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(
            digest_a, canonical_sha256({"transcript": transcript_a})
        )
        self.assertIn("RFQ", transcript_a)
        self.assertIn("BATCH_AUCTION", transcript_a)
        self.assertIn("allocated_amount", transcript_a)

    def test_transcript_compares_both_mechanisms_on_the_same_fixture(self) -> None:
        from src.market.dogfooding import build_transcript

        transcript, _ = build_transcript()
        # Both mechanisms fill the demand fully with different distributions.
        self.assertIn("rfq.allocated_amount=130000", transcript)
        self.assertIn("batch.allocated_amount=130000", transcript)
        self.assertIn("rfq.fill_count=1", transcript)
        self.assertIn("batch.fill_count=2", transcript)
        self.assertIn("rfq.total_fee_value=3260", transcript)
        self.assertIn("batch.total_fee_value=3280", transcript)

    def test_main_returns_the_digest(self) -> None:
        from src.market.dogfooding import build_transcript, main

        self.assertEqual(main(), build_transcript()[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
