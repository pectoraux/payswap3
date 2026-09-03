"""WORK-013 fulfillment compiler test suite (red-authored before implementation).

Every acceptance criterion and required proof class of the Work Order maps
to concrete tests here:

* static — boundary pins, forbidden-import containment, wall-clock/entropy
  scan, registry discipline, error authority;
* dynamic — candidate generation, routing, payment shape, optimization with
  constraint precedence, plan lifecycle, kernel binding, failure paths;
* discrimination — proven by the mutation battery (see
  ``/home/z/mut-w013.py``) driven by the load-bearing tests here;
* transformation-completeness — byte-stable canonical round-trips of every
  public serializable object;
* quality-attribute — scaling determinism and the bounded enumeration shape
  (measured numbers live in ``/home/z/bench-w013-output.txt``);
* dogfooding — DOGFOOD-013 conformance (two clean-process runs are persisted
  outside the repository by the orchestrator).
"""

from __future__ import annotations

import ast
import json
import unittest
from fractions import Fraction
from pathlib import Path

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256, loads_canonical
from src.intent import (
    EconomicSlack,
    FundingBinding,
    FundingSourceRef,
    FulfillmentPolicy,
    Intent,
    IntentState,
    OptimizationObjective,
    PolicySpec,
    SlackSpec,
)
from src.intent.amount import Amount as IntentAmount
from src.liquidity import Corridor
from src.money import FxRate, get_currency
from src.money.rounding import RoundingMode
from src.transition import Command, ExpectedVersion, Outcome
from src.transition.registry import validate_event_type

from src.compiler import (
    BPS_DENOMINATOR,
    COMPILER_ACCEPT_COMMAND,
    COMPILER_API_VERSION,
    COMPILER_AUTHORITY_CLASS,
    COMPILER_COMMANDS,
    COMPILER_COMPILE_COMMAND,
    COMPILER_EVENTS,
    COMPILER_COST_ROUNDING_MODE,
    COMPILER_FX_ROUNDING_MODE,
    COMPILER_INVALIDATE_COMMAND,
    COMPILER_PROTOCOL_VERSION,
    COMPILER_RECOMPILE_COMMAND,
    COMPILER_REJECT_COMMAND,
    COMPILER_SCHEMA_VERSION,
    FULFILLMENT_ACCEPTED_EVENT,
    FULFILLMENT_COMPILED_EVENT,
    FULFILLMENT_PLAN_OBJECT_TYPE,
    FULFILLMENT_PLAN_SPEC_TYPE,
    FULFILLMENT_RECOMPILED_EVENT,
    FULFILLMENT_REJECTED_EVENT,
    FULFILLMENT_INVALIDATED_EVENT,
    HARD_GATE_ACCOUNTING,
    HARD_GATE_AUTHORITY,
    HARD_GATE_COMPLIANCE,
    HARD_GATE_PRECEDENCE,
    HARD_GATE_SAFETY,
    HARD_GATE_SETTLEMENT,
    HARD_GATES,
    MAX_ROUTE_HOPS,
    MAX_SHAPE_CANDIDATES,
    ROUTE_HOP_OFFER_TYPE,
    COMPILATION_INPUT_TYPE,
    COMPILATION_REQUEST_TYPE,
    CompilationInput,
    CompilationRequest,
    FulfillmentPlan,
    FulfillmentPlanSpec,
    HopPlanSpec,
    PaymentPlanSpec,
    PlanState,
    RouteHopOffer,
    compile_fulfillment,
)
from src.compiler.dogfooding import build_transcript

# ---------------------------------------------------------------------------
# Fixed deterministic scenario fixtures (no clock reads anywhere).
# ---------------------------------------------------------------------------

ENV = "env/test"
DOMAIN = "domain/payments"
STAMP = "2026-09-02T00:00:00Z"
AS_OF = "2026-09-03T00:05:00Z"
ASSET_EUR = "asset/EUR"
ASSET_USD = "asset/USD"
ASSET_GBP = "asset/GBP"
OPENS = "2026-09-03T00:00:00Z"
CLOSES = "2026-09-03T02:00:00Z"
DEADLINE = "2026-09-03T12:00:00Z"
EARLIEST_COMPLETION = "2026-09-03T00:06:00Z"
LATEST_COMPLETION = "2026-09-03T06:00:00Z"

INTENT_ID = "intent/pay-1"
POLICY_ID = "intent/policy-1"
SLACK_ID = "intent/slack-1"
PAYER = "principal/payer-7"
MERCHANT = "principal/merchant-42"

PLAN_ID = "plan/merchant-42-pay-1"

EUR = get_currency("EUR")
USD = get_currency("USD")
GBP = get_currency("GBP")

RATE_EUR_USD = FxRate(source=EUR, target=USD, numerator=27, denominator=25)
RATE_USD_EUR = FxRate(source=USD, target=EUR, numerator=25, denominator=27)
RATE_EUR_GBP = FxRate(source=EUR, target=GBP, numerator=17, denominator=20)
RATE_GBP_EUR = FxRate(source=GBP, target=EUR, numerator=20, denominator=17)

REPO_ROOT = Path(__file__).resolve().parents[2]
DOMAIN_SOURCES = sorted(
    source
    for source in (Path(__file__).resolve().parent.glob("*.py"))
    if source.name != "test_compiler.py"
)


def prov(source: str):
    from src.core.envelope import Provenance

    return Provenance(issuer=PAYER, source=source, recorded_at=STAMP)


def build_policy(
    objectives,
    *,
    allow_split: bool = True,
    allow_asset_substitution: bool = True,
    allow_route_substitution: bool = True,
    policy_id: str = POLICY_ID,
):
    spec = PolicySpec.build(
        objectives=objectives,
        allow_split=allow_split,
        allow_asset_substitution=allow_asset_substitution,
        allow_route_substitution=allow_route_substitution,
    )
    return FulfillmentPolicy.build(
        object_id=policy_id,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=prov("test/policy"),
    )


def build_slack(
    *,
    amount_min: int = 9900,
    amount_max: int = 10100,
    max_payment_count: int = 2,
    substitute_assets=("asset/USD", "asset/GBP"),
    earliest: str = EARLIEST_COMPLETION,
    latest: str = LATEST_COMPLETION,
    slack_id: str = SLACK_ID,
):
    spec = SlackSpec(
        amount_min=IntentAmount(value=amount_min, scale=2, asset=ASSET_EUR),
        amount_max=IntentAmount(value=amount_max, scale=2, asset=ASSET_EUR),
        earliest_completion=earliest,
        latest_completion=latest,
        max_payment_count=max_payment_count,
        substitute_assets=tuple(substitute_assets),
    )
    return EconomicSlack.build(
        object_id=slack_id,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=prov("test/slack"),
    )


def build_intent_real(**kwargs):
    from src.intent import IntentSpec

    state = kwargs.pop("state", "AUTHORIZED")
    amount_value = kwargs.pop("amount_value", 10000)
    deadline = kwargs.pop("deadline", DEADLINE)
    cap = kwargs.pop("cap", 20000)
    policy_id = kwargs.pop("policy_id", POLICY_ID)
    slack_id = kwargs.pop("slack_id", SLACK_ID)
    funding = FundingBinding.build(
        (FundingSourceRef(
            source_id="value/funding/wallet-7",
            cap=None if cap is None else IntentAmount(value=cap, scale=2, asset=ASSET_EUR),
        ),)
    )
    spec = IntentSpec(
        destination_id=MERCHANT,
        amount=IntentAmount(value=amount_value, scale=2, asset=ASSET_EUR),
        deadline=deadline,
        funding=funding,
        policy_id=policy_id,
        slack_id=slack_id,
    )
    intent = Intent.build(
        object_id=INTENT_ID,
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=spec,
        provenance=prov("test/intent"),
    )
    if state == "DRAFT":
        return intent
    return intent.authorize(provenance=prov("test/intent/authorize"))


def make_hop(
    hop_id,
    *,
    source_asset=ASSET_EUR,
    target_asset=ASSET_EUR,
    fx=None,
    source_scale=None,
    target_scale=None,
    price_bps=300,
    flat_fee=50,
    amount_min=1,
    amount_max=100000,
    capacity=100000,
    reliability_bps=9900,
    latency_seconds=90,
    provider="provider/direct-eu",
    capability_state="ACTIVE",
    compliance_verdict="SATISFIED",
    reservation_state="RESERVED",
    jurisdictions=("EU",),
    authority_tier="R3",
    fraud_decision_state=None,
    capability_protocol_version="v0.1",
    window=(OPENS, CLOSES),
    quote_validity=(OPENS, CLOSES),
    reservation_window=(OPENS, CLOSES),
    environment_id=ENV,
    domain_id=DOMAIN,
    offer_id=None,
    quote_id=None,
    reservation_id=None,
    compliance_id=None,
):
    return RouteHopOffer(
        hop_id=hop_id,
        environment_id=environment_id,
        domain_id=domain_id,
        provider=provider,
        capability_id=f"capability/{provider.split('/')[-1]}",
        capability_state=capability_state,
        capability_protocol_version=capability_protocol_version,
        authority_tier=authority_tier,
        jurisdictions=jurisdictions,
        offer_id=offer_id or f"liquidity/{hop_id}",
        quote_id=quote_id or f"market/quote/{hop_id}",
        reservation_id=reservation_id or f"reservation/{hop_id}",
        reservation_state=reservation_state,
        reservation_opens_at=reservation_window[0],
        reservation_closes_at=reservation_window[1],
        compliance_assessment_id=compliance_id or f"safety/compliance/{hop_id}",
        compliance_verdict=compliance_verdict,
        fraud_decision_state=fraud_decision_state,
        corridor=Corridor(source_asset=source_asset, target_asset=target_asset),
        fx_rate=fx,
        source_scale=(
            fx.source.scale if fx is not None else 2
        ) if source_scale is None else source_scale,
        target_scale=(
            fx.target.scale if fx is not None else 2
        ) if target_scale is None else target_scale,
        amount_min=amount_min,
        amount_max=amount_max,
        capacity=capacity,
        price_bps=price_bps,
        flat_fee=flat_fee,
        reliability_bps=reliability_bps,
        latency_seconds=latency_seconds,
        window_opens_at=window[0],
        window_closes_at=window[1],
        quote_valid_from=quote_validity[0],
        quote_valid_until=quote_validity[1],
    )


def canonical_hops():
    """The canonical scenario hop set.

    R1 = [F1 EUR->USD 27/25, F2 USD->EUR 25/27] — total cost 109 EUR,
    delivered exactly 10000, completion 00:17:30.
    R2 = [G1 EUR->GBP 17/20, G2 GBP->EUR 20/17] — total cost 122 EUR.
    D1 = [direct EUR->EUR passthrough] — cost 350 EUR, latency 90s.
    X1 = [F3 EUR->USD cheap but compliance-BLOCKED] — must never route.
    """
    return (
        make_hop(
            "hop/f1-eur-usd",
            source_asset=ASSET_EUR,
            target_asset=ASSET_USD,
            fx=RATE_EUR_USD,
            price_bps=50,
            flat_fee=10,
            capacity=12000,
            reliability_bps=9950,
            latency_seconds=400,
            provider="provider/fx-alpha",
        ),
        make_hop(
            "hop/f2-usd-eur",
            source_asset=ASSET_USD,
            target_asset=ASSET_EUR,
            fx=RATE_USD_EUR,
            price_bps=40,
            flat_fee=10,
            capacity=12000,
            reliability_bps=9900,
            latency_seconds=350,
            provider="provider/fx-beta",
        ),
        make_hop(
            "hop/g1-eur-gbp",
            source_asset=ASSET_EUR,
            target_asset=ASSET_GBP,
            fx=RATE_EUR_GBP,
            price_bps=45,
            flat_fee=15,
            capacity=12000,
            reliability_bps=9960,
            latency_seconds=380,
            provider="provider/fx-gamma",
        ),
        make_hop(
            "hop/g2-gbp-eur",
            source_asset=ASSET_GBP,
            target_asset=ASSET_EUR,
            fx=RATE_GBP_EUR,
            price_bps=45,
            flat_fee=15,
            capacity=12000,
            reliability_bps=9920,
            latency_seconds=330,
            provider="provider/fx-gamma",
        ),
        make_hop(
            "hop/d1-direct-eur",
            source_asset=ASSET_EUR,
            target_asset=ASSET_EUR,
            fx=None,
            price_bps=300,
            flat_fee=50,
            capacity=100000,
            reliability_bps=9900,
            latency_seconds=90,
            provider="provider/direct-eu",
        ),
        make_hop(
            "hop/f3-eur-usd-blocked",
            source_asset=ASSET_EUR,
            target_asset=ASSET_USD,
            fx=RATE_EUR_USD,
            price_bps=20,
            flat_fee=5,
            capacity=12000,
            reliability_bps=9990,
            latency_seconds=200,
            provider="provider/fx-omega",
            compliance_verdict="BLOCKED",
        ),
    )


def make_request(**overrides):
    base = {
        "environment_id": ENV,
        "domain_id": DOMAIN,
        "as_of": AS_OF,
        "required_jurisdiction": "EU",
        "minimum_authority_tier": "R3",
    }
    base.update(overrides)
    return CompilationRequest(**base)


COST_FIRST = (OptimizationObjective.COST, OptimizationObjective.RELIABILITY,
              OptimizationObjective.TIME)


def compile_canonical(objectives=COST_FIRST, *, hops=None, request=None,
                      intent=None, policy=None, slack=None):
    return compile_fulfillment(
        request=request or make_request(),
        intent=intent or build_intent_real(),
        policy=policy or build_policy(objectives),
        slack=slack or build_slack(),
        hop_offers=hops if hops is not None else canonical_hops(),
    )


# ---------------------------------------------------------------------------
# 1. Static boundary.
# ---------------------------------------------------------------------------

class StaticBoundaryTests(unittest.TestCase):
    """The public boundary is typed, versioned and registry-disciplined."""

    def test_protocol_and_schema_versions_are_pinned(self) -> None:
        self.assertEqual(COMPILER_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(COMPILER_SCHEMA_VERSION, 1)
        self.assertEqual(COMPILER_API_VERSION, 1)

    def test_plan_object_type_is_registry_listed(self) -> None:
        registry = json.loads(
            (REPO_ROOT / "spec" / "registry" / "protocol-registry.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            FULFILLMENT_PLAN_OBJECT_TYPE,
            registry["registry"]["objectTypes"],
        )
        self.assertEqual(FULFILLMENT_PLAN_OBJECT_TYPE, "payswap/fulfillment-plan/v1")

    def test_internal_object_kinds_do_not_claim_registry_formats(self) -> None:
        for kind in (ROUTE_HOP_OFFER_TYPE, COMPILATION_INPUT_TYPE,
                     COMPILATION_REQUEST_TYPE, FULFILLMENT_PLAN_SPEC_TYPE):
            self.assertTrue(kind.startswith("compiler/"))
            self.assertNotIn("payswap/", kind)

    def test_event_types_use_the_registry_intent_namespace(self) -> None:
        for event in COMPILER_EVENTS:
            validate_event_type("compiler event", event)
            self.assertTrue(event.startswith("intent/"))
        self.assertEqual(len(COMPILER_EVENTS), 5)

    def test_command_types_follow_the_sibling_convention(self) -> None:
        self.assertEqual(
            COMPILER_COMMANDS,
            frozenset(
                {
                    COMPILER_COMPILE_COMMAND,
                    COMPILER_RECOMPILE_COMMAND,
                    COMPILER_ACCEPT_COMMAND,
                    COMPILER_REJECT_COMMAND,
                    COMPILER_INVALIDATE_COMMAND,
                }
            ),
        )
        for command in COMPILER_COMMANDS:
            self.assertTrue(command.startswith("compiler/"))

    def test_hard_gate_precedence_is_the_constitution_order(self) -> None:
        self.assertEqual(
            HARD_GATE_PRECEDENCE,
            ("compliance", "authority", "settlement", "safety", "accounting"),
        )
        self.assertEqual(
            HARD_GATES, frozenset(HARD_GATE_PRECEDENCE)
        )
        for gate in (HARD_GATE_COMPLIANCE, HARD_GATE_AUTHORITY,
                     HARD_GATE_SETTLEMENT, HARD_GATE_SAFETY,
                     HARD_GATE_ACCOUNTING):
            self.assertIn(gate, HARD_GATES)

    def test_frozen_arithmetic_constants(self) -> None:
        self.assertEqual(BPS_DENOMINATOR, 10000)
        self.assertEqual(COMPILER_FX_ROUNDING_MODE, RoundingMode.FLOOR)
        self.assertEqual(COMPILER_COST_ROUNDING_MODE, RoundingMode.HALF_EVEN)
        self.assertEqual(MAX_ROUTE_HOPS, 4)
        self.assertGreaterEqual(MAX_SHAPE_CANDIDATES, 1)
        self.assertEqual(COMPILER_AUTHORITY_CLASS, "A1")

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "time.monotonic",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "secrets",
                "time.sleep",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_domain_code_imports_only_declared_dependency_domains(self) -> None:
        allowed = {
            "core",
            "transition",
            "money",
            "intent",
            "capability",
            "market",
            "liquidity",
            "reservation",
            "safety",
        }
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        self.assertIn(
                            node.module.split(".")[1],
                            allowed,
                            f"{source.name} imports forbidden module {node.module!r}",
                        )
                    # Relative imports (level > 0) are intra-package
                    # (``.contracts``, ``._validation``) and always legal.
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            self.assertIn(
                                alias.name.split(".")[1],
                                allowed,
                                f"{source.name} imports forbidden module {alias.name!r}",
                            )

    def test_declared_dependency_domains_are_actually_consumed(self) -> None:
        consumed: set[str] = set()
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        consumed.add(node.module.split(".")[1])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            consumed.add(alias.name.split(".")[1])
        self.assertEqual(
            consumed,
            {"core", "transition", "money", "intent", "capability", "market",
             "liquidity", "reservation", "safety"},
        )

    def test_error_authority_is_core(self) -> None:
        with self.assertRaises(CoreValidationError):
            RouteHopOffer(
                **{**_hop_kwargs(), "price_bps": 0}
            )


def _hop_kwargs():
    hop = make_hop("hop/fixture")
    return {
        "hop_id": hop.hop_id,
        "environment_id": hop.environment_id,
        "domain_id": hop.domain_id,
        "provider": hop.provider,
        "capability_id": hop.capability_id,
        "capability_state": hop.capability_state,
        "capability_protocol_version": hop.capability_protocol_version,
        "authority_tier": hop.authority_tier,
        "jurisdictions": hop.jurisdictions,
        "offer_id": hop.offer_id,
        "quote_id": hop.quote_id,
        "reservation_id": hop.reservation_id,
        "reservation_state": hop.reservation_state,
        "reservation_opens_at": hop.reservation_opens_at,
        "reservation_closes_at": hop.reservation_closes_at,
        "compliance_assessment_id": hop.compliance_assessment_id,
        "compliance_verdict": hop.compliance_verdict,
        "fraud_decision_state": hop.fraud_decision_state,
        "corridor": hop.corridor,
        "fx_rate": hop.fx_rate,
        "source_scale": hop.source_scale,
        "target_scale": hop.target_scale,
        "amount_min": hop.amount_min,
        "amount_max": hop.amount_max,
        "capacity": hop.capacity,
        "price_bps": hop.price_bps,
        "flat_fee": hop.flat_fee,
        "reliability_bps": hop.reliability_bps,
        "latency_seconds": hop.latency_seconds,
        "window_opens_at": hop.window_opens_at,
        "window_closes_at": hop.window_closes_at,
        "quote_valid_from": hop.quote_valid_from,
        "quote_valid_until": hop.quote_valid_until,
    }


# ---------------------------------------------------------------------------
# 2. Input contract validation (fail closed on unknown everything).
# ---------------------------------------------------------------------------

class RouteHopOfferValidationTests(unittest.TestCase):

    def test_rejects_unknown_capability_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", capability_state="MAGICAL")

    def test_rejects_unknown_reservation_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", reservation_state="FROZEN")

    def test_rejects_unknown_compliance_verdict(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", compliance_verdict="MAYBE")

    def test_rejects_unknown_fraud_decision_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", fraud_decision_state="SUSPICIOUS")

    def test_rejects_unknown_authority_tier(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", authority_tier="R9")

    def test_rejects_price_bps_out_of_market_bounds(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", price_bps=0)
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", price_bps=10001)

    def test_rejects_nonpositive_reliability(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", reliability_bps=0)
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", reliability_bps=10001)

    def test_rejects_inverted_amount_window(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", amount_min=500, amount_max=100)

    def test_rejects_passthrough_with_fx_rate(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", fx=RATE_EUR_USD)  # corridor stays EUR->EUR

    def test_rejects_fx_rate_corridor_mismatch(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop(
                "hop/x",
                source_asset=ASSET_EUR,
                target_asset=ASSET_GBP,
                fx=RATE_EUR_USD,
            )

    def test_rejects_fx_rate_scale_mismatch(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop(
                "hop/x",
                source_asset=ASSET_EUR,
                target_asset=ASSET_USD,
                fx=RATE_EUR_USD,
                source_scale=3,
            )

    def test_rejects_nonpositive_capacity(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", capacity=0)

    def test_rejects_negative_latency(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", latency_seconds=-1)

    def test_rejects_inverted_windows(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", window=(CLOSES, OPENS))
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", quote_validity=(CLOSES, OPENS))
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", reservation_window=(CLOSES, OPENS))

    def test_rejects_empty_jurisdictions(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", jurisdictions=())

    def test_rejects_non_utc_timestamps(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_hop("hop/x", window=("2026-09-03T00:00:00+01:00", CLOSES))


class CompilationRequestValidationTests(unittest.TestCase):

    def test_rejects_missing_jurisdiction(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_request(required_jurisdiction="")

    def test_rejects_bad_as_of(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_request(as_of="not-a-timestamp")

    def test_rejects_unknown_minimum_authority_tier(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_request(minimum_authority_tier="Z9")

    def test_accepts_enum_minimum_authority_tier(self) -> None:
        from src.capability import AuthorityTier

        request = make_request(minimum_authority_tier=AuthorityTier.R3)
        self.assertEqual(request.minimum_authority_tier, AuthorityTier.R3)


# ---------------------------------------------------------------------------
# 3. Routing: candidate generation.
# ---------------------------------------------------------------------------

class RoutingTests(unittest.TestCase):

    def test_direct_passthrough_route_is_generated(self) -> None:
        spec = compile_canonical(hops=(make_hop("hop/d1-direct-eur"),))
        self.assertEqual(len(spec.payments), 1)
        self.assertEqual(len(spec.payments[0].route_hops), 1)
        self.assertEqual(spec.payments[0].route_hops[0].hop_id, "hop/d1-direct-eur")
        self.assertIsNone(spec.payments[0].route_hops[0].fx_numerator)

    def test_two_hop_fx_route_is_generated(self) -> None:
        spec = compile_canonical(
            hops=(canonical_hops()[0], canonical_hops()[1])
        )
        self.assertEqual(len(spec.payments[0].route_hops), 2)
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops],
            ["hop/f1-eur-usd", "hop/f2-usd-eur"],
        )

    def test_no_asset_substitution_removes_fx_routes(self) -> None:
        policy = build_policy(
            COST_FIRST, allow_asset_substitution=False
        )
        spec = compile_canonical(policy=policy)
        # Only the direct EUR->EUR route remains feasible.
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops],
            ["hop/d1-direct-eur"],
        )

    def test_routes_only_use_declared_substitute_assets(self) -> None:
        # GBP is not a declared substitute in this slack.
        slack = build_slack(substitute_assets=("asset/USD",))
        spec = compile_canonical(slack=slack)
        assets = {
            (h.source_asset, h.target_asset)
            for p in spec.payments
            for h in p.route_hops
        }
        self.assertNotIn((ASSET_EUR, ASSET_GBP), assets)
        self.assertNotIn((ASSET_GBP, ASSET_EUR), assets)

    def test_route_hops_are_bounded(self) -> None:
        self.assertEqual(MAX_ROUTE_HOPS, 4)
        # A three-intermediate route EUR->USD->GBP->...->EUR would need a
        # fourth asset; with three substitutes the maximum route length is
        # four hops, enforced by enumeration.
        spec = compile_canonical()
        for payment in spec.payments:
            self.assertLessEqual(len(payment.route_hops), MAX_ROUTE_HOPS)

    def test_blocked_compliance_provider_is_never_routed(self) -> None:
        spec = compile_canonical()
        routed = {h.hop_id for p in spec.payments for h in p.route_hops}
        self.assertNotIn("hop/f3-eur-usd-blocked", routed)
        self.assertEqual(spec.gate_report["routes_rejected_per_gate"]["compliance"], 1)

    def test_gate_precedence_records_the_first_failing_gate(self) -> None:
        # This hop fails compliance (BLOCKED) AND authority (R2 tier below
        # the R3 minimum) AND accounting (capacity 1): compliance has
        # precedence, so the rejection is recorded against compliance,
        # not authority (and the route never reaches the accounting
        # gate at all).
        bad = make_hop(
            "hop/both-bad",
            compliance_verdict="BLOCKED",
            authority_tier="R2",
            capacity=1,
            amount_min=1,
            amount_max=1,
        )
        spec = compile_canonical(hops=(bad, canonical_hops()[4]))
        report = spec.gate_report
        self.assertEqual(report["routes_rejected_per_gate"].get("compliance", 0), 1)
        self.assertEqual(report["routes_rejected_per_gate"].get("authority", 0), 0)
        self.assertEqual(report["routes_rejected_per_gate"].get("accounting", 0), 0)

    def test_no_route_at_all_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=())
        self.assertIn("no route", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# 4. Hard constraint gates (explicit failure paths, precedence).
# ---------------------------------------------------------------------------

class HardGateTests(unittest.TestCase):

    def test_compliance_blocked_is_a_hard_rejection(self) -> None:
        hops = (make_hop("hop/blocked", compliance_verdict="BLOCKED"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("compliance", str(ctx.exception).lower())

    def test_missing_jurisdiction_is_a_hard_rejection(self) -> None:
        hops = (make_hop("hop/us-only", jurisdictions=("US",)),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("jurisdiction", str(ctx.exception).lower())

    def test_suspended_capability_is_rejected(self) -> None:
        hops = (make_hop("hop/suspended", capability_state="SUSPENDED"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("capability", str(ctx.exception).lower())

    def test_capability_protocol_version_mismatch_is_rejected(self) -> None:
        hops = (
            make_hop("hop/oldproto", capability_protocol_version="v0.0"),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("protocol", str(ctx.exception).lower())

    def test_insufficient_authority_tier_is_rejected(self) -> None:
        hops = (make_hop("hop/weak", authority_tier="R2"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("authority", str(ctx.exception).lower())

    def test_as_of_outside_hop_window_is_rejected(self) -> None:
        hops = (
            make_hop("hop/closed", window=("2026-09-03T00:00:00Z",
                                           "2026-09-03T00:01:00Z")),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("window", str(ctx.exception).lower())

    def test_expired_quote_is_rejected(self) -> None:
        hops = (
            make_hop(
                "hop/stale-quote",
                quote_validity=("2026-09-03T00:00:00Z", "2026-09-03T00:04:00Z"),
            ),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("quote", str(ctx.exception).lower())

    def test_consumed_reservation_is_rejected(self) -> None:
        hops = (make_hop("hop/consumed", reservation_state="CONSUMED"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("reservation", str(ctx.exception).lower())

    def test_as_of_outside_reservation_window_is_rejected(self) -> None:
        hops = (
            make_hop(
                "hop/late-reservation",
                reservation_window=("2026-09-03T01:00:00Z", "2026-09-03T02:00:00Z"),
            ),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("reservation", str(ctx.exception).lower())

    def test_blocked_fraud_decision_is_rejected(self) -> None:
        hops = (make_hop("hop/fraud", fraud_decision_state="BLOCKED"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("fraud", str(ctx.exception).lower())

    def test_held_fraud_decision_is_rejected(self) -> None:
        hops = (make_hop("hop/fraud-hold", fraud_decision_state="HELD"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("fraud", str(ctx.exception).lower())

    def test_released_fraud_decision_is_allowed(self) -> None:
        hops = (make_hop("hop/fraud-released", fraud_decision_state="RELEASED"),)
        spec = compile_canonical(hops=hops)
        self.assertEqual(spec.payments[0].route_hops[0].hop_id, "hop/fraud-released")

    def test_deadline_bust_is_a_settlement_rejection(self) -> None:
        hops = (make_hop("hop/slow", latency_seconds=50000),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("deadline", str(ctx.exception).lower())

    def test_early_completion_is_a_settlement_rejection(self) -> None:
        # Completion before the slack earliest bound violates the window.
        hops = (make_hop("hop/fast", latency_seconds=10),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("completion", str(ctx.exception).lower())

    def test_fill_above_capacity_is_an_accounting_rejection(self) -> None:
        hops = (make_hop("hop/tiny", capacity=100),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("capacity", str(ctx.exception).lower())

    def test_fill_below_amount_min_is_an_accounting_rejection(self) -> None:
        # The quote window starts ABOVE the 10000 fill, so the fill is
        # below the quote amount minimum.
        hops = (make_hop("hop/min12000", amount_min=12000),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("amount", str(ctx.exception).lower())

    def test_funding_cap_breach_is_an_accounting_rejection(self) -> None:
        intent = build_intent_real(cap=10100)  # spend = 10000 + 109 = 10109
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(
                hops=(canonical_hops()[0], canonical_hops()[1]),
                intent=intent,
            )
        self.assertIn("funding", str(ctx.exception).lower())

    def test_uncapped_funding_source_is_not_binding(self) -> None:
        intent = build_intent_real(cap=None)
        spec = compile_canonical(
            hops=(canonical_hops()[0], canonical_hops()[1]),
            intent=intent,
        )
        self.assertEqual(spec.totals["total_cost_value"], 109)

    def test_delivered_below_slack_window_is_an_accounting_rejection(self) -> None:
        poor_rate = FxRate(source=USD, target=EUR, numerator=9, denominator=10)
        hops = (
            canonical_hops()[0],
            make_hop(
                "hop/f2-poor",
                source_asset=ASSET_USD,
                target_asset=ASSET_EUR,
                fx=poor_rate,
                price_bps=40,
                flat_fee=10,
                capacity=12000,
                reliability_bps=9900,
                latency_seconds=350,
                provider="provider/fx-beta",
            ),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("slack", str(ctx.exception).lower())

    def test_intent_must_be_authorized(self) -> None:
        intent = build_intent_real(state="DRAFT")
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(intent=intent)
        self.assertIn("AUTHORIZED", str(ctx.exception))

    def test_retired_policy_fails_closed(self) -> None:
        policy = build_policy(COST_FIRST).retire(provenance=prov("test/retire"))
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(policy=policy)
        self.assertIn("ACTIVE", str(ctx.exception))

    def test_retired_slack_fails_closed(self) -> None:
        slack = build_slack().retire(provenance=prov("test/retire"))
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(slack=slack)
        self.assertIn("ACTIVE", str(ctx.exception))

    def test_policy_object_identity_must_match_intent_reference(self) -> None:
        policy = build_policy(COST_FIRST, policy_id="intent/policy-OTHER")
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(policy=policy)
        self.assertIn("policy", str(ctx.exception).lower())

    def test_slack_object_identity_must_match_intent_reference(self) -> None:
        slack = build_slack(slack_id="intent/slack-OTHER")
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(slack=slack)
        self.assertIn("slack", str(ctx.exception).lower())

    def test_slack_window_must_bracket_the_intent_amount(self) -> None:
        slack = build_slack(amount_min=10100, amount_max=10200)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(slack=slack)
        self.assertIn("bracket", str(ctx.exception).lower())

    def test_environment_mismatch_fails_closed(self) -> None:
        request = make_request(environment_id="env/other")
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(request=request)
        self.assertIn("environment", str(ctx.exception).lower())

    def test_hop_environment_mismatch_fails_closed(self) -> None:
        hops = (make_hop("hop/elsewhere", environment_id="env/other"),)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("environment", str(ctx.exception).lower())

    def test_as_of_after_deadline_fails_closed(self) -> None:
        request = make_request(as_of="2026-09-03T13:00:00Z")
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(request=request)
        self.assertIn("deadline", str(ctx.exception).lower())

    def test_duplicate_hop_ids_fail_closed(self) -> None:
        first = make_hop("hop/dup")
        second = make_hop("hop/dup")
        with self.assertRaises(CoreValidationError):
            compile_canonical(hops=(first, second))


# ---------------------------------------------------------------------------
# 5. Economic optimization: soft objectives, deterministic tie-breaks.
# ---------------------------------------------------------------------------

class OptimizationTests(unittest.TestCase):

    def test_cost_objective_chooses_the_cheap_multi_hop_route(self) -> None:
        spec = compile_canonical(objectives=COST_FIRST)
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops],
            ["hop/f1-eur-usd", "hop/f2-usd-eur"],
        )
        self.assertEqual(spec.totals["total_cost_value"], 109)
        self.assertEqual(spec.totals["total_delivered_value"], 10000)
        self.assertEqual(spec.totals["amount_distance"], 0)

    def test_cost_arithmetic_is_exact_per_hop(self) -> None:
        spec = compile_canonical(objectives=COST_FIRST)
        hop1, hop2 = spec.payments[0].route_hops
        self.assertEqual(hop1.input_value, 10000)
        self.assertEqual(hop1.output_value, 10800)
        self.assertEqual(hop1.residual_numerator, 0)
        self.assertEqual(hop1.fee_value, 60)
        self.assertEqual(hop2.input_value, 10800)
        self.assertEqual(hop2.output_value, 10000)
        self.assertEqual(hop2.residual_numerator, 0)
        self.assertEqual(hop2.fee_value, 53)

    def test_fx_residual_is_carried_explicitly_when_rounding(self) -> None:
        # 10000 EUR -> 10800 USD exact; 10800 * 5/7 = 7714.28... floors to
        # 7714 with an explicit residual of 200/700 (== 2/7 minor units,
        # never dropped or created).
        odd_rate = FxRate(source=USD, target=EUR, numerator=5, denominator=7)
        hops = (
            canonical_hops()[0],
            make_hop(
                "hop/f2-odd",
                source_asset=ASSET_USD,
                target_asset=ASSET_EUR,
                fx=odd_rate,
                price_bps=40,
                flat_fee=10,
                capacity=12000,
                reliability_bps=9900,
                latency_seconds=350,
                provider="provider/fx-beta",
            ),
        )
        slack = build_slack(amount_min=7000, amount_max=10000)
        spec = compile_canonical(hops=hops, slack=slack)
        hop2 = spec.payments[0].route_hops[1]
        self.assertEqual(hop2.input_value, 10800)
        self.assertEqual(hop2.output_value, 7714)
        self.assertEqual(hop2.residual_numerator, 200)
        self.assertEqual(hop2.residual_denominator, 700)

    def test_reliability_objective_prefers_the_most_reliable_route(self) -> None:
        objectives = (OptimizationObjective.RELIABILITY, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives)
        # D1 reliability 0.99 beats R1 0.985050 and R2 0.988032.
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops], ["hop/d1-direct-eur"]
        )

    def test_time_objective_prefers_the_fastest_route(self) -> None:
        objectives = (OptimizationObjective.TIME, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives)
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops], ["hop/d1-direct-eur"]
        )

    def test_liquidity_objective_prefers_lowest_capacity_utilization(self) -> None:
        objectives = (
            OptimizationObjective.LIQUIDITY,
            OptimizationObjective.COST,
        )
        spec = compile_canonical(objectives=objectives)
        # D1 utilization 10000/100000 = 0.1 beats R1 1.733... and R2 1.541...
        # (exact capacity-utilization fractions, never floats).
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops], ["hop/d1-direct-eur"]
        )
        # The capital-efficiency dimension: exact capital-time
        # (minor-unit-seconds in transit) carried in every plan's totals.
        # D1 = 10000*90 << R1 = 10000*400 + 10800*350.
        self.assertEqual(spec.totals["capital_time"], 10000 * 90)

    def test_objectives_are_applied_lexicographically(self) -> None:
        # COST dominates TIME in this ordering even though the direct route
        # is much faster.
        objectives = (OptimizationObjective.COST, OptimizationObjective.TIME)
        spec = compile_canonical(objectives=objectives)
        self.assertEqual(len(spec.payments[0].route_hops), 2)

    def test_amount_objective_prefers_exact_delivery(self) -> None:
        # R2 delivers exactly 10000 while the 9/10 route delivers 9720;
        # with AMOUNT first, the exact route wins despite worse cost.
        poor_rate = FxRate(source=USD, target=EUR, numerator=9, denominator=10)
        poor = (
            canonical_hops()[0],
            make_hop(
                "hop/f2-poor",
                source_asset=ASSET_USD,
                target_asset=ASSET_EUR,
                fx=poor_rate,
                price_bps=10,
                flat_fee=0,
                capacity=12000,
                reliability_bps=9950,
                latency_seconds=300,
                provider="provider/fx-beta",
            ),
            canonical_hops()[2],
            canonical_hops()[3],
        )
        objectives = (OptimizationObjective.AMOUNT, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives, hops=poor,
                                  slack=build_slack(amount_min=9000))
        # The poor route delivers 9720 (distance 280); R2 delivers 10000.
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops],
            ["hop/g1-eur-gbp", "hop/g2-gbp-eur"],
        )

    def test_route_objective_prefers_fewer_hops(self) -> None:
        objectives = (OptimizationObjective.ROUTE, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives)
        self.assertEqual(len(spec.payments[0].route_hops), 1)

    def test_privacy_objective_prefers_fewer_intermediaries(self) -> None:
        objectives = (OptimizationObjective.PRIVACY, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives)
        self.assertEqual(spec.totals["privacy_exposure"], 0)

    def test_risk_objective_prefers_low_risk_penalty(self) -> None:
        objectives = (OptimizationObjective.RISK, OptimizationObjective.COST)
        spec = compile_canonical(objectives=objectives)
        # D1 risk penalty 100 is the lowest.
        self.assertEqual(
            [h.hop_id for h in spec.payments[0].route_hops], ["hop/d1-direct-eur"]
        )

    def test_tie_break_is_the_canonical_shape_digest(self) -> None:
        twin_a = make_hop("hop/twin-a", provider="provider/direct-eu")
        twin_b = make_hop("hop/twin-b", provider="provider/direct-eu2")
        spec = compile_canonical(hops=(twin_a, twin_b))
        digest_a = canonical_sha256(
            {"payments": [["hop/twin-a", 10000]]}
        )
        digest_b = canonical_sha256(
            {"payments": [["hop/twin-b", 10000]]}
        )
        winner = spec.payments[0].route_hops[0].hop_id
        expected = "hop/twin-a" if digest_a < digest_b else "hop/twin-b"
        self.assertEqual(winner, expected)

    def test_deterministic_tie_break_is_not_insertion_order(self) -> None:
        # Insertion order (a, b) and (b, a) must select the SAME winner.
        twin_a = make_hop("hop/twin-a", provider="provider/direct-eu")
        twin_b = make_hop("hop/twin-b", provider="provider/direct-eu2")
        spec_one = compile_canonical(hops=(twin_a, twin_b))
        spec_two = compile_canonical(hops=(twin_b, twin_a))
        self.assertEqual(
            spec_one.payments[0].route_hops[0].hop_id,
            spec_two.payments[0].route_hops[0].hop_id,
        )
        self.assertEqual(spec_one.plan_digest, spec_two.plan_digest)

    def test_rank_candidates_orders_equal_metrics_by_digest(self) -> None:
        # The objective sort key's final tie-break is the candidate digest
        # itself: candidates with IDENTICAL metric vectors are ranked by
        # digest byte order, never by the caller's input order.
        from src.compiler.optimization import (
            CandidateMetrics,
            FeasibleCandidate,
            rank_candidates,
        )

        def _candidate(digest: str) -> FeasibleCandidate:
            metrics = CandidateMetrics(
                total_cost_value=1,
                total_source_value=1,
                total_delivered_value=1,
                amount_distance=0,
                completion_epoch=0,
                completion="2026-09-03T00:00:00Z",
                total_latency_seconds=1,
                hop_count=1,
                payment_count=1,
                reliability=Fraction(1, 1),
                capital_time=1,
                liquidity_utilization=Fraction(1, 1),
                risk_penalty=0,
                privacy_exposure=0,
            )
            return FeasibleCandidate(
                shape=None, chains=(), metrics=metrics, digest=digest
            )

        low = _candidate("a" * 64)
        high = _candidate("f" * 64)
        objectives = (OptimizationObjective.COST,)
        self.assertEqual(
            [c.digest for c in rank_candidates((high, low), objectives)],
            ["a" * 64, "f" * 64],
        )
        self.assertEqual(
            [c.digest for c in rank_candidates((low, high), objectives)],
            ["a" * 64, "f" * 64],
        )

    def test_runner_up_digests_are_recorded_for_provenance(self) -> None:
        spec = compile_canonical()
        self.assertTrue(spec.runner_up_digests)
        self.assertLessEqual(len(spec.runner_up_digests), 2)
        self.assertNotIn(spec.plan_digest, spec.runner_up_digests)

    def test_objective_order_is_recorded_in_the_plan(self) -> None:
        spec = compile_canonical(objectives=COST_FIRST)
        self.assertEqual(
            spec.objective_order,
            ("COST", "RELIABILITY", "TIME"),
        )

    def test_gate_report_counts_routes_and_shapes(self) -> None:
        spec = compile_canonical()
        report = spec.gate_report
        self.assertEqual(report["routes_considered"], 4)
        self.assertEqual(report["routes_rejected_per_gate"]["compliance"], 1)
        self.assertEqual(report["shapes_evaluated"], 6)
        self.assertEqual(report["shapes_feasible"], 6)

    def test_repeated_compilation_is_byte_identical(self) -> None:
        first = compile_canonical()
        second = compile_canonical()
        self.assertEqual(first.plan_digest, second.plan_digest)
        self.assertEqual(first.to_json(), second.to_json())


# ---------------------------------------------------------------------------
# 6. Payment shape: splitting within slack.
# ---------------------------------------------------------------------------

class PaymentShapeTests(unittest.TestCase):

    def tight_capacity_hops(self):
        f1 = canonical_hops()[0]
        f2 = canonical_hops()[1]
        g1 = canonical_hops()[2]
        g2 = canonical_hops()[3]
        return (
            f1, f2, g1, g2,
            make_hop(
                "hop/d1-direct-eur",
                source_asset=ASSET_EUR,
                target_asset=ASSET_EUR,
                fx=None,
                price_bps=300,
                flat_fee=50,
                capacity=6000,
                reliability_bps=9900,
                latency_seconds=90,
                provider="provider/direct-eu",
            ),
        )

    def test_split_shape_wins_when_capacity_requires_it(self) -> None:
        # Every single-payment shape busts capacity, so the payment shape
        # must split; the R1+R2 split (cost 141) beats R1+D1 (264).
        hops = self.tight_capacity_hops()
        # R1/R2 capacity 12000 is above 10000, so tighten them too.
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in hops
        )
        spec = compile_canonical(hops=hops)
        self.assertEqual(spec.totals["payment_count"], 2)
        self.assertEqual(spec.totals["total_source_value"], 10000)
        self.assertEqual(spec.totals["total_delivered_value"], 10000)
        self.assertEqual(spec.totals["total_cost_value"], 141)
        parts = sorted(p.source_value for p in spec.payments)
        self.assertEqual(parts, [5000, 5000])

    def test_split_forbidden_fails_closed_when_capacity_is_tight(self) -> None:
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in self.tight_capacity_hops()
        )
        policy = build_policy(COST_FIRST, allow_split=False)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops, policy=policy)
        self.assertIn("shape", str(ctx.exception).lower())

    def test_max_payment_count_one_forces_single_payment(self) -> None:
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in self.tight_capacity_hops()
        )
        slack = build_slack(max_payment_count=1)
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops, slack=slack)
        self.assertIn("shape", str(ctx.exception).lower())

    def test_split_parts_sum_exactly_via_money_allocation(self) -> None:
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in self.tight_capacity_hops()
        )
        slack = build_slack(amount_min=9900, amount_max=10100)
        spec = compile_canonical(hops=hops, slack=slack)
        self.assertEqual(sum(p.source_value for p in spec.payments), 10000)
        self.assertEqual(
            sum(p.delivered_value for p in spec.payments),
            spec.totals["total_delivered_value"],
        )

    def test_single_payment_wins_when_flat_fees_penalize_splits(self) -> None:
        # With ample capacity, splitting doubles flat fees and loses on cost.
        spec = compile_canonical()
        self.assertEqual(spec.totals["payment_count"], 1)

    def test_payment_indices_are_canonical(self) -> None:
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in self.tight_capacity_hops()
        )
        spec = compile_canonical(hops=hops)
        indices = [p.payment_index for p in spec.payments]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(indices, list(range(1, len(indices) + 1)))


def _with_capacity(hop, capacity):
    from dataclasses import replace as _replace

    fields = _hop_kwargs()
    values = {
        field: getattr(hop, field)
        for field in fields
        if hasattr(hop, field)
    }
    values["capacity"] = capacity
    values["hop_id"] = hop.hop_id
    return RouteHopOffer(**values)


# ---------------------------------------------------------------------------
# 7. The fulfillment plan object (durable, versioned, sealed).
# ---------------------------------------------------------------------------

class FulfillmentPlanTests(unittest.TestCase):

    def _plan(self, **overrides) -> FulfillmentPlan:
        spec = compile_canonical()
        return FulfillmentPlan.build(
            object_id=PLAN_ID,
            environment_id=ENV,
            domain_id=DOMAIN,
            spec=spec,
            provenance=prov("test/plan"),
        )

    def test_plan_object_type_is_the_registry_listed_one(self) -> None:
        plan = self._plan()
        self.assertEqual(plan.envelope.object_type, FULFILLMENT_PLAN_OBJECT_TYPE)
        self.assertEqual(plan.envelope.schema_version, COMPILER_SCHEMA_VERSION)
        self.assertEqual(plan.envelope.protocol_version, COMPILER_PROTOCOL_VERSION)

    def test_plan_initial_state_is_compiled(self) -> None:
        plan = self._plan()
        self.assertEqual(plan.state, PlanState.COMPILED)
        self.assertEqual(plan.envelope.object_version, 1)

    def test_accept_transition(self) -> None:
        plan = self._plan().accept(provenance=prov("test/accept"))
        self.assertEqual(plan.state, PlanState.ACCEPTED)
        self.assertEqual(plan.envelope.object_version, 2)
        self.assertEqual(plan.spec, self._plan().spec)

    def test_reject_transition(self) -> None:
        plan = self._plan().reject(provenance=prov("test/reject"))
        self.assertEqual(plan.state, PlanState.REJECTED)
        self.assertEqual(plan.envelope.object_version, 2)

    def test_invalidate_transition_from_compiled(self) -> None:
        plan = self._plan().invalidate(provenance=prov("test/invalidate"))
        self.assertEqual(plan.state, PlanState.INVALIDATED)

    def test_invalidate_transition_from_accepted(self) -> None:
        plan = self._plan().accept(provenance=prov("test/accept"))
        plan = plan.invalidate(provenance=prov("test/invalidate"))
        self.assertEqual(plan.state, PlanState.INVALIDATED)
        self.assertEqual(plan.envelope.object_version, 3)

    def test_recompile_transition_replaces_the_spec(self) -> None:
        plan = self._plan()
        new_spec = compile_canonical(
            objectives=(OptimizationObjective.TIME, OptimizationObjective.COST)
        )
        recompiled = plan.recompile(
            spec=new_spec, provenance=prov("test/recompile")
        )
        self.assertEqual(recompiled.state, PlanState.COMPILED)
        self.assertEqual(recompiled.envelope.object_version, 2)
        self.assertEqual(recompiled.spec.plan_digest, new_spec.plan_digest)
        self.assertNotEqual(recompiled.spec.plan_digest, plan.spec.plan_digest)

    def test_terminal_states_reject_further_lifecycle(self) -> None:
        for terminal_command in ("accept", "reject", "invalidate", "recompile"):
            plan = self._plan().reject(provenance=prov("test/reject"))
            with self.assertRaises(CoreValidationError):
                if terminal_command == "accept":
                    plan.accept(provenance=prov("test/x"))
                elif terminal_command == "reject":
                    plan.reject(provenance=prov("test/x"))
                elif terminal_command == "invalidate":
                    plan.invalidate(provenance=prov("test/x"))
                else:
                    plan.recompile(spec=plan.spec, provenance=prov("test/x"))

    def test_accepted_plan_can_only_be_invalidated(self) -> None:
        plan = self._plan().accept(provenance=prov("test/accept"))
        with self.assertRaises(CoreValidationError):
            plan.accept(provenance=prov("test/x"))
        with self.assertRaises(CoreValidationError):
            plan.reject(provenance=prov("test/x"))
        with self.assertRaises(CoreValidationError):
            plan.recompile(spec=plan.spec, provenance=prov("test/x"))

    def test_tampered_payload_fails_the_domain_seal(self) -> None:
        plan = self._plan()
        decoded = loads_canonical(plan.to_json())
        decoded["payload"]["totals"]["total_cost_value"] = 0
        from src.core.serialization import canonical_json

        with self.assertRaises(CoreValidationError):
            FulfillmentPlan.from_json(canonical_json(decoded))

    def test_tampered_envelope_fails_integrity(self) -> None:
        plan = self._plan()
        decoded = loads_canonical(plan.to_json())
        decoded["envelope"]["state"] = "ACCEPTED"
        from src.core.serialization import canonical_json

        with self.assertRaises(CoreValidationError):
            FulfillmentPlan.from_json(canonical_json(decoded))

    def test_spliced_plan_fails_the_composite_seal(self) -> None:
        # A splice of plan A's envelope + plan B's payload passes BOTH
        # the core envelope integrity and the spec digest self-check (each
        # part is individually consistent), so ONLY the compiler domain's
        # composite seal can catch it.
        spec_a = compile_canonical()
        spec_b = compile_canonical(
            objectives=(OptimizationObjective.TIME, OptimizationObjective.COST)
        )
        plan_a = FulfillmentPlan.build(
            object_id=PLAN_ID,
            environment_id=ENV,
            domain_id=DOMAIN,
            spec=spec_a,
            provenance=prov("test/plan"),
        )
        plan_b = FulfillmentPlan.build(
            object_id=PLAN_ID,
            environment_id=ENV,
            domain_id=DOMAIN,
            spec=spec_b,
            provenance=prov("test/plan"),
        )
        with self.assertRaises(CoreValidationError):
            FulfillmentPlan(
                envelope=plan_a.envelope,
                spec=plan_b.spec,
                integrity_hash=plan_a.integrity_hash,
            )

    def test_unknown_plan_state_fails_closed(self) -> None:
        plan = self._plan()
        decoded = loads_canonical(plan.to_json())
        # Tampering with the state breaks the envelope integrity first; a
        # direct construction with an unknown state fails closed too.
        from src.core.envelope import ObjectEnvelope
        from src.core.serialization import canonical_json as _cj

        decoded["envelope"]["state"] = "COMPLETED"
        # Rebuild a consistent envelope+seal pair to reach the state check.
        forged = ObjectEnvelope.from_dict(plan.envelope.to_dict())
        forged = forged.next_version(state="COMPLETED", provenance=prov("test/forged"))
        forged = forged.with_integrity_hash()
        with self.assertRaises(CoreValidationError):
            FulfillmentPlan(
                envelope=forged,
                spec=plan.spec,
                integrity_hash=plan.integrity_hash,
            )

    def test_plan_digest_is_a_semantic_projection(self) -> None:
        plan = self._plan()
        again = self._plan()
        self.assertEqual(plan.spec.plan_digest, again.spec.plan_digest)
        # Different routes produce different digests.
        other = compile_canonical(
            objectives=(OptimizationObjective.TIME, OptimizationObjective.COST)
        )
        self.assertNotEqual(plan.spec.plan_digest, other.plan_digest)

    def test_plan_digest_distinguishes_payment_shapes(self) -> None:
        first = compile_canonical()
        second = compile_canonical(
            hops=tuple(
                hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
                for hop in (
                    canonical_hops()[0],
                    canonical_hops()[1],
                    canonical_hops()[2],
                    canonical_hops()[3],
                    make_hop(
                        "hop/d1-direct-eur",
                        capacity=6000,
                        price_bps=300,
                        flat_fee=50,
                        reliability_bps=9900,
                        latency_seconds=90,
                        provider="provider/direct-eu",
                    ),
                )
            )
        )
        self.assertNotEqual(first.plan_digest, second.plan_digest)


# ---------------------------------------------------------------------------
# 8. Kernel binding: the frozen Fulfillment command family.
# ---------------------------------------------------------------------------

class KernelBindingTests(unittest.TestCase):

    def _compiler(self):
        from src.compiler import FulfillmentCompiler

        return FulfillmentCompiler(
            environment_id=ENV,
            domain_id=DOMAIN,
            authorized_actors=(PAYER,),
        )

    def _compile_kwargs(self, **overrides):
        base = {
            "plan_id": PLAN_ID,
            "request": make_request(),
            "intent": build_intent_real(),
            "policy": build_policy(COST_FIRST),
            "slack": build_slack(),
            "hop_offers": canonical_hops(),
            "command_id": "command/compile-1",
            "idempotency_key": "idem/compile-1",
            "nonce": "nonce-1",
            "actor": PAYER,
        }
        base.update(overrides)
        return base

    def test_compiler_registers_the_frozen_command_family(self) -> None:
        compiler = self._compiler()
        for command in COMPILER_COMMANDS:
            self.assertIn(command, compiler.engine._handlers)

    def test_compile_command_emits_the_compiled_event(self) -> None:
        compiler = self._compiler()
        result = compiler.compile(**self._compile_kwargs())
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(result.event.event_type, FULFILLMENT_COMPILED_EVENT)
        self.assertEqual(result.event.object_refs, (PLAN_ID,))
        self.assertEqual(len(compiler.engine.journal), 1)

    def test_compile_authority_class_is_declared(self) -> None:
        compiler = self._compiler()
        result = compiler.compile(**self._compile_kwargs())
        self.assertEqual(result.event.authority, COMPILER_AUTHORITY_CLASS)

    def test_plan_is_rebuildable_from_the_kernel_state(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        plan = compiler.plan(PLAN_ID)
        self.assertEqual(plan.state, PlanState.COMPILED)
        self.assertEqual(plan.envelope.object_version, 1)
        expected = compile_canonical()
        self.assertEqual(plan.spec.plan_digest, expected.plan_digest)

    def test_duplicate_compile_converges_without_new_events(self) -> None:
        compiler = self._compiler()
        first = compiler.compile(**self._compile_kwargs())
        again = compiler.compile(**self._compile_kwargs())
        self.assertEqual(again.outcome, Outcome.DUPLICATE)
        self.assertEqual(len(compiler.engine.journal), 1)
        self.assertEqual(again.event.event_id, first.event.event_id)

    def test_idempotency_conflict_fails_closed(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        conflicting = self._compile_kwargs(
            command_id="command/compile-2",
            hop_offers=(make_hop("hop/other"),),
        )
        result = compiler.compile(**conflicting)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason.value, "idempotency_conflict")

    def test_unauthorized_actor_is_rejected(self) -> None:
        compiler = self._compiler()
        result = compiler.compile(
            **self._compile_kwargs(actor="principal/attacker-1")
        )
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason.value, "unauthorized")
        self.assertEqual(len(compiler.engine.journal), 0)

    def test_unknown_command_type_fails_closed(self) -> None:
        compiler = self._compiler()
        command = Command.build(
            command_id="command/unknown-1",
            command_type="compiler/fulfillment.explode",
            actor=PAYER,
            target_refs=(PLAN_ID,),
            payload={"anything": 1},
            environment_id=ENV,
            domain_id=DOMAIN,
            idempotency_key="idem/unknown-1",
            nonce="nonce-2",
            requested_at=AS_OF,
        )
        result = compiler.engine.process(command)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason.value, "unknown_command_type")

    def test_environment_mismatch_is_rejected_by_the_kernel(self) -> None:
        compiler = self._compiler()
        command = Command.build(
            command_id="command/env-1",
            command_type=COMPILER_COMPILE_COMMAND,
            actor=PAYER,
            target_refs=(PLAN_ID,),
            payload=make_request().to_dict(),
            environment_id="env/other",
            domain_id=DOMAIN,
            idempotency_key="idem/env-1",
            nonce="nonce-3",
            requested_at=AS_OF,
        )
        result = compiler.engine.process(command)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason.value, "environment_mismatch")

    def test_recompile_requires_expected_version_discipline(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        recompiled = compiler.recompile(
            **self._compile_kwargs(
                command_id="command/recompile-1",
                idempotency_key="idem/recompile-1",
                plan_id=PLAN_ID,
            )
        )
        self.assertEqual(recompiled.outcome, Outcome.ACCEPTED)
        self.assertEqual(recompiled.event.event_type, FULFILLMENT_RECOMPILED_EVENT)
        plan = compiler.plan(PLAN_ID)
        self.assertEqual(plan.envelope.object_version, 2)
        stale = compiler.recompile(
            **self._compile_kwargs(
                command_id="command/recompile-2",
                idempotency_key="idem/recompile-2",
                plan_id=PLAN_ID,
                expected_version=1,
            )
        )
        self.assertEqual(stale.outcome, Outcome.REJECTED)
        self.assertEqual(stale.reason.value, "version_conflict")

    def test_recompile_policy_change_selects_a_different_route(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        recompiled = compiler.recompile(
            **self._compile_kwargs(
                command_id="command/recompile-1",
                idempotency_key="idem/recompile-1",
                policy=build_policy(
                    (OptimizationObjective.TIME, OptimizationObjective.COST)
                ),
            )
        )
        self.assertEqual(recompiled.outcome, Outcome.ACCEPTED)
        plan = compiler.plan(PLAN_ID)
        self.assertEqual(
            [h.hop_id for h in plan.spec.payments[0].route_hops],
            ["hop/d1-direct-eur"],
        )

    def test_accept_command_advances_the_plan(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        result = compiler.accept_plan(
            plan_id=PLAN_ID,
            command_id="command/accept-1",
            idempotency_key="idem/accept-1",
            nonce="nonce-4",
            actor=PAYER,
            as_of=AS_OF,
        )
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(result.event.event_type, FULFILLMENT_ACCEPTED_EVENT)
        self.assertEqual(compiler.plan(PLAN_ID).state, PlanState.ACCEPTED)

    def test_reject_command_requires_a_reason(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        result = compiler.reject_plan(
            plan_id=PLAN_ID,
            reason="payer withdrew authorization",
            command_id="command/reject-1",
            idempotency_key="idem/reject-1",
            nonce="nonce-5",
            actor=PAYER,
            as_of=AS_OF,
        )
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(result.event.event_type, FULFILLMENT_REJECTED_EVENT)
        self.assertEqual(compiler.plan(PLAN_ID).state, PlanState.REJECTED)

    def test_reject_without_reason_fails_closed(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        with self.assertRaises(CoreValidationError):
            compiler.reject_plan(
                plan_id=PLAN_ID,
                reason="",
                command_id="command/reject-2",
                idempotency_key="idem/reject-2",
                nonce="nonce-6",
                actor=PAYER,
                as_of=AS_OF,
            )

    def test_invalidate_command_works_from_accepted(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        compiler.accept_plan(
            plan_id=PLAN_ID,
            command_id="command/accept-1",
            idempotency_key="idem/accept-1",
            nonce="nonce-4",
            actor=PAYER,
            as_of=AS_OF,
        )
        result = compiler.invalidate_plan(
            plan_id=PLAN_ID,
            reason="quotes expired before execution",
            command_id="command/invalidate-1",
            idempotency_key="idem/invalidate-1",
            nonce="nonce-7",
            actor=PAYER,
            as_of=AS_OF,
        )
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(result.event.event_type, FULFILLMENT_INVALIDATED_EVENT)
        self.assertEqual(compiler.plan(PLAN_ID).state, PlanState.INVALIDATED)

    def test_accept_twice_fails_closed(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        compiler.accept_plan(
            plan_id=PLAN_ID,
            command_id="command/accept-1",
            idempotency_key="idem/accept-1",
            nonce="nonce-4",
            actor=PAYER,
            as_of=AS_OF,
        )
        with self.assertRaises(CoreValidationError):
            compiler.accept_plan(
                plan_id=PLAN_ID,
                command_id="command/accept-2",
                idempotency_key="idem/accept-2",
                nonce="nonce-8",
                actor=PAYER,
                as_of=AS_OF,
            )

    def test_lifecycle_command_on_missing_plan_fails_closed(self) -> None:
        compiler = self._compiler()
        with self.assertRaises(CoreValidationError):
            compiler.accept_plan(
                plan_id="plan/does-not-exist",
                command_id="command/accept-99",
                idempotency_key="idem/accept-99",
                nonce="nonce-9",
                actor=PAYER,
                as_of=AS_OF,
            )

    def test_forged_plan_payload_fails_the_seal(self) -> None:
        compiler = self._compiler()
        compiler.compile(**self._compile_kwargs())
        # A forged accept command whose spec does not seal against the
        # stored envelope must fail closed inside the handler.
        command = Command.build(
            command_id="command/accept-forged",
            command_type=COMPILER_ACCEPT_COMMAND,
            actor=PAYER,
            target_refs=(PLAN_ID,),
            payload={
                "plan": _tampered_spec_dict(),
                "integrity_hash": "0" * 64,
                "reason": None,
            },
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(ExpectedVersion(PLAN_ID, 1),),
            idempotency_key="idem/accept-forged",
            nonce="nonce-10",
            requested_at=AS_OF,
        )
        with self.assertRaises(CoreValidationError):
            compiler.engine.process(command)

    def test_compile_pre_flight_leaves_zero_kernel_state(self) -> None:
        compiler = self._compiler()
        with self.assertRaises(CoreValidationError):
            compiler.compile(
                **self._compile_kwargs(hop_offers=(make_hop("hop/blocked",
                                                            compliance_verdict="BLOCKED"),))
            )
        self.assertEqual(len(compiler.engine.journal), 0)
        self.assertIsNone(compiler.store.get(PLAN_ID))


def _tampered_spec_dict():
    spec = compile_canonical()
    decoded = spec.to_dict()
    decoded["totals"]["total_cost_value"] = 0
    return decoded


# ---------------------------------------------------------------------------
# 9. Transformation completeness: byte-stable canonical round-trips.
# ---------------------------------------------------------------------------

class TransformationCompletenessTests(unittest.TestCase):

    def test_route_hop_offer_round_trip_is_byte_stable(self) -> None:
        hop = make_hop("hop/f1-eur-usd", source_asset=ASSET_EUR,
                       target_asset=ASSET_USD, fx=RATE_EUR_USD)
        encoded = hop.to_json()
        decoded = RouteHopOffer.from_json(encoded)
        self.assertEqual(decoded, hop)
        self.assertEqual(decoded.to_json(), encoded)

    def test_compilation_request_round_trip_is_byte_stable(self) -> None:
        request = make_request()
        encoded = request.to_json()
        decoded = CompilationRequest.from_json(encoded)
        self.assertEqual(decoded, request)
        self.assertEqual(decoded.to_json(), encoded)

    def test_compilation_input_round_trip_is_byte_stable(self) -> None:
        payload = CompilationInput(
            request=make_request(),
            intent=build_intent_real(),
            policy=build_policy(COST_FIRST),
            slack=build_slack(),
            hop_offers=canonical_hops(),
        )
        encoded = payload.to_json()
        decoded = CompilationInput.from_json(encoded)
        self.assertEqual(decoded, payload)
        self.assertEqual(decoded.to_json(), encoded)

    def test_fulfillment_plan_spec_round_trip_is_byte_stable(self) -> None:
        spec = compile_canonical()
        encoded = spec.to_json()
        decoded = FulfillmentPlanSpec.from_json(encoded)
        self.assertEqual(decoded, spec)
        self.assertEqual(decoded.to_json(), encoded)

    def test_fulfillment_plan_round_trip_is_byte_stable(self) -> None:
        spec = compile_canonical()
        plan = FulfillmentPlan.build(
            object_id=PLAN_ID,
            environment_id=ENV,
            domain_id=DOMAIN,
            spec=spec,
            provenance=prov("test/plan"),
        )
        encoded = plan.to_json()
        decoded = FulfillmentPlan.from_json(encoded)
        self.assertEqual(decoded, plan)
        self.assertEqual(decoded.to_json(), encoded)

    def test_fulfillment_plan_round_trip_survives_every_state(self) -> None:
        spec = compile_canonical()
        plan = FulfillmentPlan.build(
            object_id=PLAN_ID,
            environment_id=ENV,
            domain_id=DOMAIN,
            spec=spec,
            provenance=prov("test/plan"),
        )
        accepted = plan.accept(provenance=prov("test/accept"))
        encoded = accepted.to_json()
        decoded = FulfillmentPlan.from_json(encoded)
        self.assertEqual(decoded, accepted)
        self.assertEqual(decoded.state, PlanState.ACCEPTED)

    def test_round_trips_reject_duplicate_json_keys(self) -> None:
        hop = make_hop("hop/x")
        encoded = hop.to_json()
        doubled = encoded[:-1] + ',"hop_id":"hop/x"}'
        with self.assertRaises(CoreValidationError):
            RouteHopOffer.from_json(doubled)

    def test_plan_spec_survives_a_split_shape(self) -> None:
        hops = (
            canonical_hops()[0],
            canonical_hops()[1],
            canonical_hops()[2],
            canonical_hops()[3],
            make_hop("hop/d1-direct-eur", capacity=6000),
        )
        hops = tuple(
            hop if hop.hop_id.startswith("hop/d") else _with_capacity(hop, 6000)
            for hop in hops
        )
        spec = compile_canonical(hops=hops)
        encoded = spec.to_json()
        decoded = FulfillmentPlanSpec.from_json(encoded)
        self.assertEqual(decoded, spec)
        self.assertEqual(decoded.totals["payment_count"], 2)


# ---------------------------------------------------------------------------
# 10. Dogfooding conformance (in-process; clean-process runs are persisted).
# ---------------------------------------------------------------------------

class DogfoodingConformanceTests(unittest.TestCase):

    def test_transcript_is_deterministic_in_process(self) -> None:
        first, digest_one = build_transcript()
        second, digest_two = build_transcript()
        self.assertEqual(first, second)
        self.assertEqual(digest_one, digest_two)

    def test_transcript_compiles_a_real_multi_hop_payment(self) -> None:
        transcript, _ = build_transcript()
        self.assertIn("hops=2", transcript)
        self.assertIn("intent/fulfillment-compiled", transcript)
        self.assertIn("plan_digest=", transcript)

    def test_transcript_shows_the_compliance_gate_rejection(self) -> None:
        transcript, _ = build_transcript()
        self.assertIn("compliance", transcript)
        self.assertIn("hop/f3-eur-usd-blocked", transcript)

    def test_transcript_records_exact_fx_arithmetic(self) -> None:
        transcript, _ = build_transcript()
        self.assertIn("10800", transcript)
        self.assertIn("total_cost_value=109", transcript)

    def test_transcript_accepts_the_plan_through_the_kernel(self) -> None:
        transcript, _ = build_transcript()
        self.assertIn("intent/fulfillment-accepted", transcript)
        self.assertIn("state=ACCEPTED", transcript)


# ---------------------------------------------------------------------------
# 11. Quality-attribute shape: bounded, scaling-deterministic compilation.
# ---------------------------------------------------------------------------

class QualityAttributeShapeTests(unittest.TestCase):

    def _scaled_hops(self, providers_per_corridor: int):
        hops = []
        for index in range(providers_per_corridor):
            suffix = f"-{index}"
            hops.append(
                make_hop(
                    f"hop/eu-usd{suffix}",
                    source_asset=ASSET_EUR,
                    target_asset=ASSET_USD,
                    fx=RATE_EUR_USD,
                    price_bps=50 + index,
                    flat_fee=10,
                    capacity=12000,
                    reliability_bps=9950 - index,
                    latency_seconds=400,
                    provider=f"provider/fx-alpha{suffix}",
                )
            )
            hops.append(
                make_hop(
                    f"hop/usd-eu{suffix}",
                    source_asset=ASSET_USD,
                    target_asset=ASSET_EUR,
                    fx=RATE_USD_EUR,
                    price_bps=40 + index,
                    flat_fee=10,
                    capacity=12000,
                    reliability_bps=9900 - index,
                    latency_seconds=350,
                    provider=f"provider/fx-beta{suffix}",
                )
            )
            hops.append(
                make_hop(
                    f"hop/eu-gbp{suffix}",
                    source_asset=ASSET_EUR,
                    target_asset=ASSET_GBP,
                    fx=RATE_EUR_GBP,
                    price_bps=45 + index,
                    flat_fee=15,
                    capacity=12000,
                    reliability_bps=9960 - index,
                    latency_seconds=380,
                    provider=f"provider/fx-gamma{suffix}",
                )
            )
            hops.append(
                make_hop(
                    f"hop/gbp-eu{suffix}",
                    source_asset=ASSET_GBP,
                    target_asset=ASSET_EUR,
                    fx=RATE_GBP_EUR,
                    price_bps=45 + index,
                    flat_fee=15,
                    capacity=12000,
                    reliability_bps=9920 - index,
                    latency_seconds=330,
                    provider=f"provider/fx-gamma{suffix}",
                )
            )
        hops.append(
            make_hop(
                "hop/direct-a",
                price_bps=300,
                flat_fee=50,
                capacity=100000,
                reliability_bps=9900,
                latency_seconds=90,
                provider="provider/direct-a",
            )
        )
        hops.append(
            make_hop(
                "hop/direct-b",
                price_bps=310,
                flat_fee=45,
                capacity=100000,
                reliability_bps=9910,
                latency_seconds=95,
                provider="provider/direct-b",
            )
        )
        return tuple(hops)

    def test_scaled_scenario_is_deterministic(self) -> None:
        hops = self._scaled_hops(3)
        spec_one = compile_canonical(hops=hops)
        spec_two = compile_canonical(hops=hops)
        self.assertEqual(spec_one.plan_digest, spec_two.plan_digest)
        # 3 providers x 2 FX corridors + 2 direct routes = 20 routes.
        self.assertEqual(spec_one.gate_report["routes_considered"], 20)
        # K=1 (20 shapes) + K=2 (C(20,2)=190 shapes) = 210 evaluated.
        self.assertEqual(spec_one.gate_report["shapes_evaluated"], 210)

    def test_shape_enumeration_is_bounded(self) -> None:
        hops = tuple(
            make_hop(
                f"hop/direct-{index}",
                price_bps=300 + index,
                flat_fee=50,
                capacity=100000,
                reliability_bps=9900,
                latency_seconds=90,
                provider=f"provider/direct-{index}",
            )
            for index in range(50)
        )
        with self.assertRaises(CoreValidationError) as ctx:
            compile_canonical(hops=hops)
        self.assertIn("bound", str(ctx.exception).lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
