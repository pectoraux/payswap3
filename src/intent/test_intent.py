"""WORK-008 intent domain contract and discrimination tests.

Red-first note: this suite was authored before the implementation modules
existed. The first recorded run failed at the declared public boundary
(import of ``src.intent`` implementation modules) for the right reason — the
contract was declared and the implementation was absent.

Scope discipline (WORK-008): intent, funding binding, fulfillment policy,
economic slack, demand and demand classes. No market selection, no payment
execution, no events (transition kernel is WORK-003), no monetary arithmetic
(money domain is WORK-006), no FundingSource value objects (value domain is
WORK-005 — this domain only binds opaque funding source references).

DOGFOOD-008 (see ``IntentGraphDogfoodingTests``): create a real product
intent, derive demand, and preserve constraints through serialization.
"""

from __future__ import annotations

import unittest
from datetime import datetime

from src.core import (
    CoreValidationError,
    ObjectEnvelope,
    ObjectGraph,
    Provenance,
    Relationship,
    RelationshipType,
    canonical_json,
    canonical_sha256,
)

from . import (
    DEADLINE_WINDOW_SECONDS,
    IMMEDIATE_WINDOW_SECONDS,
    Amount,
    Demand,
    DemandClass,
    DemandClassSpec,
    DemandShape,
    DemandSpec,
    DemandState,
    FulfillmentPolicy,
    FundingBinding,
    FundingSourceRef,
    INTENT_OBJECT_TYPE,
    INTENT_PROTOCOL_VERSION,
    INTENT_SCHEMA_VERSION,
    Intent,
    IntentSpec,
    IntentState,
    OptimizationObjective,
    PolicySpec,
    PolicyState,
    SlackSpec,
    SlackState,
    EconomicSlack,
    UrgencyClass,
    classify_demand,
    demand_class_id,
    derive_demand,
    urgency_for_window,
    window_seconds,
    withdraw_demand,
)


ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"

WALLET = "value/funding-source/wallet-7"
BANK = "value/funding-source/bank-7"
ENDPOINT = "endpoint/merchant-42"


def prov(issuer: str = "principal/merchant-ops-7", source: str = "dogfood/work-008") -> Provenance:
    return Provenance(
        issuer=issuer,
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/dogfood-008",),
    )


def policy_spec() -> PolicySpec:
    return PolicySpec(
        objectives=(
            OptimizationObjective.COST,
            OptimizationObjective.RELIABILITY,
            OptimizationObjective.TIME,
            OptimizationObjective.PRIVACY,
        ),
        allow_split=True,
        allow_asset_substitution=True,
        allow_route_substitution=True,
    )


def policy() -> FulfillmentPolicy:
    return FulfillmentPolicy.build(
        object_id="intent/policy/merchant-001",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=policy_spec(),
        provenance=prov(source="intent/fulfillment-policy"),
        correlation_id="corr/merchant-checkout-42",
    )


def slack_spec() -> SlackSpec:
    return SlackSpec(
        amount_min=Amount(125000, 2, "asset/USD"),
        amount_max=Amount(130000, 2, "asset/USD"),
        earliest_completion="2026-09-03T00:00:00Z",
        latest_completion="2026-09-03T12:00:00Z",
        max_payment_count=2,
        substitute_assets=("asset/USDC",),
    )


def slack() -> EconomicSlack:
    return EconomicSlack.build(
        object_id="intent/slack/merchant-001",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=slack_spec(),
        provenance=prov(source="intent/economic-slack"),
        correlation_id="corr/merchant-checkout-42",
    )


def intent_spec() -> IntentSpec:
    return IntentSpec(
        destination_id=ENDPOINT,
        amount=Amount(125000, 2, "asset/USD"),
        deadline="2026-09-03T12:00:00Z",
        funding=FundingBinding.build([
            FundingSourceRef(WALLET, Amount(125000, 2, "asset/USD")),
            FundingSourceRef(BANK),
        ]),
        policy_id="intent/policy/merchant-001",
        slack_id="intent/slack/merchant-001",
    )


def intent() -> Intent:
    return Intent.build(
        object_id="intent/pay-2026-0007",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=intent_spec(),
        provenance=prov(source="intent/merchant-checkout"),
        correlation_id="corr/merchant-checkout-42",
    )


def authorized_intent() -> Intent:
    return intent().authorize(
        provenance=prov(source="intent/authorize-command"),
        causation_id="command/authorize-0007",
    )


def demand() -> Demand:
    return derive_demand(
        authorized_intent(),
        slack=slack(),
        policy=policy(),
        provenance=prov(source="intent/demand-derivation"),
    )


def demand_class() -> DemandClass:
    return classify_demand(
        demand(),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(source="intent/demand-classification"),
    )


def parse(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def resealed(owner, *, state=None, object_type=None, protocol_version=None):
    """Forge a validly re-sealed composite with an altered envelope.

    Integrity hashes are tamper evidence, not signatures: an attacker who can
    recompute hashes can produce well-sealed objects. The domain must
    therefore also fail closed on vocabulary and contract violations, which
    is exactly what this helper probes.
    """
    source = owner.to_dict()
    envelope = owner.envelope
    forged = ObjectEnvelope(
        object_id=envelope.object_id,
        object_type=object_type if object_type is not None else envelope.object_type,
        object_version=envelope.object_version,
        environment_id=envelope.environment_id,
        domain_id=envelope.domain_id,
        schema_version=envelope.schema_version,
        protocol_version=protocol_version if protocol_version is not None else envelope.protocol_version,
        state=state if state is not None else envelope.state,
        provenance=envelope.provenance,
        causation_id=envelope.causation_id,
        correlation_id=envelope.correlation_id,
        previous_version=envelope.previous_version,
    ).with_integrity_hash()
    payload = source["payload"]
    return {
        "envelope": forged.to_dict(),
        "payload": payload,
        "integrity_hash": canonical_sha256({"envelope": forged.to_dict(), "payload": payload}),
    }


class AmountTests(unittest.TestCase):
    """The canonical amount declaration (integer value + scale + asset)."""

    def test_amount_declares_the_canonical_scaled_integer_domain(self) -> None:
        amount = Amount(125000, 2, "asset/USD")
        self.assertEqual(
            amount.to_dict(), {"value": 125000, "scale": 2, "asset": "asset/USD"}
        )
        for bad in (
            {"value": -1, "scale": 2, "asset": "asset/USD"},
            {"value": True, "scale": 2, "asset": "asset/USD"},
            {"value": 1.5, "scale": 2, "asset": "asset/USD"},
            {"value": 1, "scale": -1, "asset": "asset/USD"},
            {"value": 1, "scale": 19, "asset": "asset/USD"},
            {"value": 1, "scale": 2, "asset": ""},
            {"value": 1, "scale": 2, "asset": "asset/USD extra"},
        ):
            with self.assertRaises(CoreValidationError):
                Amount(**bad)

    def test_amount_round_trip_is_lossless(self) -> None:
        amount = Amount(125000, 2, "asset/USD")
        self.assertEqual(Amount.from_dict(amount.to_dict()), amount)
        with self.assertRaises(CoreValidationError):
            Amount.from_dict({"value": 125000, "scale": 2})
        with self.assertRaises(CoreValidationError):
            Amount.from_dict({"value": 125000, "scale": 2, "asset": "asset/USD", "extra": 1})

    def test_amount_is_deterministic_and_byte_stable(self) -> None:
        first = Amount(125000, 2, "asset/USD")
        second = Amount(125000, 2, "asset/USD")
        self.assertEqual(first, second)
        self.assertEqual(canonical_json(first.to_dict()), canonical_json(second.to_dict()))

    def test_amount_is_a_declaration_without_arithmetic(self) -> None:
        # Monetary arithmetic (scaling, rounding, FX) is owned by src/money
        # (WORK-006); the intent domain only declares amounts.
        for operator in ("__add__", "__sub__", "__mul__", "__floordiv__", "__truediv__"):
            self.assertFalse(hasattr(Amount, operator), operator)


class FundingBindingTests(unittest.TestCase):
    """Intent-side funding binding over opaque funding source references."""

    def test_funding_binding_orders_and_deduplicates_sources(self) -> None:
        wallet = FundingSourceRef(WALLET, Amount(125000, 2, "asset/USD"))
        bank = FundingSourceRef(BANK)
        binding = FundingBinding.build([wallet, bank])
        self.assertEqual(binding.sources, (wallet, bank))
        with self.assertRaises(CoreValidationError):
            FundingBinding.build([wallet, wallet])
        with self.assertRaises(CoreValidationError):
            FundingBinding.build([])
        with self.assertRaises(CoreValidationError):
            FundingSourceRef("invalid funding id")

    def test_funding_binding_normalizes_and_freezes_sources(self) -> None:
        wallet = FundingSourceRef(WALLET)
        source_list = [wallet]
        binding = FundingBinding.build(source_list)
        self.assertIsInstance(binding.sources, tuple)
        source_list.append(FundingSourceRef(BANK))
        self.assertEqual(binding.sources, (wallet,))
        with self.assertRaises(CoreValidationError):
            FundingBinding(sources=[wallet])
        with self.assertRaises(CoreValidationError):
            FundingBinding(sources=(FundingSourceRef(WALLET), "not-a-ref"))

    def test_funding_binding_round_trips_losslessly(self) -> None:
        binding = FundingBinding.build([
            FundingSourceRef(WALLET, Amount(125000, 2, "asset/USD")),
            FundingSourceRef(BANK),
        ])
        decoded = FundingBinding.from_dict(binding.to_dict())
        self.assertEqual(decoded, binding)
        self.assertEqual(decoded.sources[0].cap, Amount(125000, 2, "asset/USD"))
        self.assertIsNone(decoded.sources[1].cap)


class FulfillmentPolicyTests(unittest.TestCase):
    """Fulfillment policy: objective ranking and hard substitution constraints."""

    def test_objectives_form_a_closed_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            PolicySpec.build(objectives=("SPEED",), allow_split=True,
                             allow_asset_substitution=False, allow_route_substitution=False)
        value = policy_spec().to_dict()
        value["objectives"] = ["SPEED"]
        with self.assertRaises(CoreValidationError):
            PolicySpec.from_dict(value)

    def test_objectives_are_a_strict_non_empty_ranking(self) -> None:
        every = tuple(OptimizationObjective)
        spec = PolicySpec.build(objectives=every, allow_split=False,
                                allow_asset_substitution=False, allow_route_substitution=False)
        self.assertEqual(spec.objectives, every)
        with self.assertRaises(CoreValidationError):
            PolicySpec.build(objectives=(OptimizationObjective.COST, OptimizationObjective.COST),
                             allow_split=False, allow_asset_substitution=False,
                             allow_route_substitution=False)
        with self.assertRaises(CoreValidationError):
            PolicySpec.build(objectives=(), allow_split=False,
                             allow_asset_substitution=False, allow_route_substitution=False)
        with self.assertRaises(CoreValidationError):
            PolicySpec(objectives=(OptimizationObjective.COST,), allow_split="yes",
                       allow_asset_substitution=False, allow_route_substitution=False)

    def test_policy_lifecycle_versions_and_retires(self) -> None:
        active = policy()
        self.assertEqual(active.state, PolicyState.ACTIVE)
        self.assertEqual(active.envelope.object_version, 1)
        retired = active.retire(provenance=prov(), causation_id="command/retire-policy-1")
        self.assertEqual(retired.state, PolicyState.RETIRED)
        self.assertEqual(retired.envelope.object_version, 2)
        self.assertEqual(retired.envelope.previous_version, 1)
        with self.assertRaises(CoreValidationError):
            retired.retire(provenance=prov())
        with self.assertRaises(CoreValidationError):
            retired.amend(provenance=prov(), allow_split=False)

    def test_policy_amend_preserves_identity_and_reseals(self) -> None:
        original = policy()
        amended = original.amend(
            provenance=prov(),
            causation_id="command/amend-policy-1",
            allow_split=False,
            objectives=(OptimizationObjective.TIME, OptimizationObjective.COST),
        )
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertFalse(amended.spec.allow_split)
        self.assertEqual(original.envelope.object_version, 1)
        for field in ("object_id", "object_type", "environment_id", "domain_id",
                      "schema_version", "protocol_version"):
            self.assertEqual(getattr(amended.envelope, field), getattr(original.envelope, field))
        self.assertNotEqual(amended.integrity_hash, original.integrity_hash)
        self.assertEqual(FulfillmentPolicy.from_json(amended.to_json()), amended)
        with self.assertRaises(CoreValidationError):
            original.amend(provenance=prov(), allow_flavor="fast")

    def test_policy_serialization_is_lossless_and_byte_stable(self) -> None:
        value = policy()
        encoded = value.to_json()
        self.assertEqual(FulfillmentPolicy.from_json(encoded), value)
        self.assertEqual(FulfillmentPolicy.from_json(encoded).to_json(), encoded)
        twin = policy()
        self.assertEqual(twin, value)
        self.assertEqual(twin.to_json(), encoded)

    def test_policy_fail_closed_on_tampering_and_unknown_contracts(self) -> None:
        encoded = policy().to_json()
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_json(encoded.replace('"allow_split":true', '"allow_split":false'))
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_json(encoded.replace('"state":"ACTIVE"', '"state":"TAMPERED"'))
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_json(slack().to_json())
        forged = resealed(policy(), state="MYSTERY")
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_dict(forged)
        forged = resealed(policy(), protocol_version="v0.2")
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_dict(forged)
        value = policy().to_dict()
        value["surprise"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            FulfillmentPolicy.from_dict(value)


class EconomicSlackTests(unittest.TestCase):
    """Economic slack: the permitted flexibility around the requested outcome."""

    def test_slack_amount_window_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            SlackSpec(amount_min=Amount(130000, 2, "asset/USD"),
                      amount_max=Amount(125000, 2, "asset/USD"),
                      earliest_completion="2026-09-03T00:00:00Z",
                      latest_completion="2026-09-03T12:00:00Z", max_payment_count=2)
        with self.assertRaises(CoreValidationError):
            SlackSpec(amount_min=Amount(125000, 2, "asset/USD"),
                      amount_max=Amount(130000, 2, "asset/EUR"),
                      earliest_completion="2026-09-03T00:00:00Z",
                      latest_completion="2026-09-03T12:00:00Z", max_payment_count=2)
        with self.assertRaises(CoreValidationError):
            SlackSpec(amount_min=Amount(125000, 2, "asset/USD"),
                      amount_max=Amount(130000, 4, "asset/USD"),
                      earliest_completion="2026-09-03T00:00:00Z",
                      latest_completion="2026-09-03T12:00:00Z", max_payment_count=2)

    def test_slack_completion_window_validation(self) -> None:
        for earliest, latest in (
            ("2026-09-03T12:00:00Z", "2026-09-03T00:00:00Z"),
            ("2026-09-03T00:00:00", "2026-09-03T12:00:00Z"),
            ("not-a-timestamp", "2026-09-03T12:00:00Z"),
        ):
            with self.assertRaises(CoreValidationError):
                SlackSpec(amount_min=Amount(125000, 2, "asset/USD"),
                          amount_max=Amount(130000, 2, "asset/USD"),
                          earliest_completion=earliest, latest_completion=latest,
                          max_payment_count=2)

    def test_slack_payment_count_and_substitution_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            slack_spec().with_changes({"max_payment_count": 0})
        with self.assertRaises(CoreValidationError):
            slack_spec().with_changes({"substitute_assets": ("asset/USDC", "asset/USDC")})
        with self.assertRaises(CoreValidationError):
            slack_spec().with_changes({"substitute_assets": ("asset/USD",)})
        with self.assertRaises(CoreValidationError):
            slack_spec().with_changes({"substitute_assets": ("bad asset",)})
        with self.assertRaises(CoreValidationError):
            slack_spec().with_changes({"max_payment_count": True})

    def test_slack_serialization_is_lossless_and_byte_stable(self) -> None:
        value = slack()
        encoded = value.to_json()
        self.assertEqual(EconomicSlack.from_json(encoded), value)
        self.assertEqual(EconomicSlack.from_json(encoded).to_json(), encoded)
        self.assertEqual(EconomicSlack.from_dict(value.to_dict()), value)

    def test_slack_fail_closed_on_tampering_and_unknown_contracts(self) -> None:
        encoded = slack().to_json()
        with self.assertRaises(CoreValidationError):
            EconomicSlack.from_json(encoded.replace('"value":130000', '"value":990000'))
        with self.assertRaises(CoreValidationError):
            EconomicSlack.from_json(encoded.replace('"state":"ACTIVE"', '"state":"TAMPERED"'))
        with self.assertRaises(CoreValidationError):
            EconomicSlack.from_json(policy().to_json())
        forged = resealed(slack(), state="MYSTERY")
        with self.assertRaises(CoreValidationError):
            EconomicSlack.from_dict(forged)

    def test_slack_amend_and_retire(self) -> None:
        original = slack()
        amended = original.amend(
            provenance=prov(),
            causation_id="command/amend-slack-1",
            substitute_assets=("asset/USDC", "asset/EURC"),
        )
        self.assertEqual(amended.spec.substitute_assets, ("asset/USDC", "asset/EURC"))
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(original.envelope.object_version, 1)
        retired = amended.retire(provenance=prov())
        self.assertEqual(retired.state, SlackState.RETIRED)
        with self.assertRaises(CoreValidationError):
            retired.amend(provenance=prov())


class IntentSpecTests(unittest.TestCase):
    """The requested outcome declaration carried by an intent."""

    def test_intent_spec_validates_references(self) -> None:
        for changes in (
            {"destination_id": ""},
            {"destination_id": "bad endpoint"},
            {"policy_id": "bad policy"},
            {"slack_id": "bad slack"},
            {"deadline": "2026-09-03T12:00:00"},
            {"deadline": "tomorrow"},
        ):
            with self.assertRaises(CoreValidationError):
                intent_spec().with_changes(changes)

    def test_intent_spec_requires_a_positive_outcome(self) -> None:
        with self.assertRaises(CoreValidationError):
            intent_spec().with_changes({"amount": Amount(0, 2, "asset/USD")})

    def test_intent_spec_funding_cap_coherence(self) -> None:
        with self.assertRaises(CoreValidationError):
            intent_spec().with_changes({"funding": FundingBinding.build([
                FundingSourceRef(WALLET, Amount(125000, 2, "asset/EUR")),
            ])})
        with self.assertRaises(CoreValidationError):
            intent_spec().with_changes({"funding": FundingBinding.build([
                FundingSourceRef(WALLET, Amount(125000, 4, "asset/USD")),
            ])})

    def test_intent_spec_round_trips_losslessly(self) -> None:
        spec = intent_spec()
        self.assertEqual(IntentSpec.from_dict(spec.to_dict()), spec)


class IntentLifecycleTests(unittest.TestCase):
    """Intent state machine: Create/Authorize/Reject/Amend/Cancel/Suspend/Resume."""

    def test_create_seals_a_draft_intent(self) -> None:
        value = intent()
        self.assertEqual(value.state, IntentState.DRAFT)
        self.assertEqual(value.envelope.object_type, INTENT_OBJECT_TYPE)
        self.assertEqual(value.envelope.protocol_version, INTENT_PROTOCOL_VERSION)
        self.assertEqual(value.envelope.schema_version, INTENT_SCHEMA_VERSION)
        self.assertIsNotNone(value.envelope.integrity_hash)
        self.assertIsNotNone(value.integrity_hash)
        self.assertEqual(Intent.from_json(value.to_json()), value)

    def test_authorize_transition(self) -> None:
        authorized = authorized_intent()
        self.assertEqual(authorized.state, IntentState.AUTHORIZED)
        self.assertEqual(authorized.envelope.object_version, 2)
        self.assertEqual(authorized.envelope.previous_version, 1)
        self.assertEqual(authorized.envelope.provenance.issuer, "principal/merchant-ops-7")
        self.assertEqual(authorized.envelope.causation_id, "command/authorize-0007")
        self.assertEqual(Intent.from_json(authorized.to_json()), authorized)

    def test_reject_is_terminal(self) -> None:
        rejected = intent().reject(provenance=prov(), causation_id="command/reject-0007")
        self.assertEqual(rejected.state, IntentState.REJECTED)
        for command in (
            lambda: rejected.authorize(provenance=prov()),
            lambda: rejected.reject(provenance=prov()),
            lambda: rejected.suspend(provenance=prov()),
            lambda: rejected.resume(provenance=prov()),
            lambda: rejected.cancel(provenance=prov()),
            lambda: rejected.amend(provenance=prov()),
        ):
            with self.assertRaises(CoreValidationError):
                command()

    def test_cancel_is_allowed_from_draft_authorized_and_suspended(self) -> None:
        for source in (intent(), authorized_intent(),
                       authorized_intent().suspend(provenance=prov())):
            cancelled = source.cancel(provenance=prov(), causation_id="command/cancel-0007")
            self.assertEqual(cancelled.state, IntentState.CANCELLED)
            with self.assertRaises(CoreValidationError):
                cancelled.cancel(provenance=prov())

    def test_suspend_and_resume_round_trip_states(self) -> None:
        suspended = authorized_intent().suspend(provenance=prov(), causation_id="command/suspend-0007")
        self.assertEqual(suspended.state, IntentState.SUSPENDED)
        self.assertEqual(suspended.envelope.object_version, 3)
        resumed = suspended.resume(provenance=prov(), causation_id="command/resume-0007")
        self.assertEqual(resumed.state, IntentState.AUTHORIZED)
        self.assertEqual(resumed.envelope.object_version, 4)

    def test_invalid_transitions_fail_closed(self) -> None:
        authorized = authorized_intent()
        with self.assertRaises(CoreValidationError):
            authorized.authorize(provenance=prov())
        with self.assertRaises(CoreValidationError):
            authorized.reject(provenance=prov())
        with self.assertRaises(CoreValidationError):
            authorized.resume(provenance=prov())
        with self.assertRaises(CoreValidationError):
            intent().suspend(provenance=prov())
        with self.assertRaises(CoreValidationError):
            intent().resume(provenance=prov())
        with self.assertRaises(CoreValidationError):
            authorized.cancel(provenance=prov()).amend(provenance=prov())

    def test_amend_versions_the_intent_and_preserves_identity(self) -> None:
        original = authorized_intent()
        amended = original.amend(
            provenance=prov(),
            causation_id="command/amend-0007",
            amount=Amount(126000, 2, "asset/USD"),
            destination_id="endpoint/merchant-43",
        )
        self.assertEqual(amended.spec.amount, Amount(126000, 2, "asset/USD"))
        self.assertEqual(amended.spec.destination_id, "endpoint/merchant-43")
        self.assertEqual(amended.envelope.object_version, 3)
        self.assertEqual(amended.envelope.previous_version, 2)
        self.assertEqual(original.spec.amount, Amount(125000, 2, "asset/USD"))
        for field in ("object_id", "object_type", "environment_id", "domain_id",
                      "schema_version", "protocol_version"):
            self.assertEqual(getattr(amended.envelope, field), getattr(original.envelope, field))
        self.assertEqual(Intent.from_json(amended.to_json()), amended)

    def test_intent_state_and_type_vocabularies_are_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            Intent.from_dict(resealed(intent(), state="MYSTERY"))
        with self.assertRaises(CoreValidationError):
            Intent.from_dict(resealed(intent(), object_type="intent/other"))
        with self.assertRaises(CoreValidationError):
            Intent.from_dict(resealed(intent(), protocol_version="v0.9"))
        with self.assertRaises(CoreValidationError):
            Intent.from_json(policy().to_json())


class DemandDerivationTests(unittest.TestCase):
    """Demand is derived from an authorized intent, its policy and its slack."""

    def test_derivation_is_deterministic(self) -> None:
        first = demand()
        second = derive_demand(
            authorized_intent(), slack=slack(), policy=policy(),
            provenance=prov(source="intent/demand-derivation"),
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_derivation_propagates_constraints(self) -> None:
        derived = demand()
        self.assertEqual(derived.state, DemandState.OPEN)
        self.assertEqual(derived.object_id, "intent/pay-2026-0007/demand")
        self.assertEqual(derived.envelope.causation_id, "intent/pay-2026-0007")
        self.assertEqual(derived.envelope.correlation_id, "corr/merchant-checkout-42")
        spec = derived.spec
        self.assertEqual(spec.intent_id, "intent/pay-2026-0007")
        self.assertEqual(spec.intent_version, 2)
        self.assertEqual(spec.destination_id, ENDPOINT)
        self.assertEqual(spec.asset, "asset/USD")
        self.assertEqual(spec.amount_min, 125000)
        self.assertEqual(spec.amount_max, 130000)
        self.assertEqual(spec.amount_scale, 2)
        self.assertEqual(spec.earliest_completion, "2026-09-03T00:00:00Z")
        self.assertEqual(spec.latest_completion, "2026-09-03T12:00:00Z")
        self.assertTrue(spec.allow_split)
        self.assertEqual(spec.max_payment_count, 2)
        self.assertEqual(spec.substitute_assets, ("asset/USDC",))
        self.assertEqual(spec.demand_class_id, "intent/demand-class/asset/USD/DEADLINE/SPLIT")

    def test_derivation_requires_an_authorized_intent(self) -> None:
        for source in (
            intent(),
            authorized_intent().suspend(provenance=prov()),
            intent().reject(provenance=prov()),
            authorized_intent().cancel(provenance=prov()),
        ):
            with self.assertRaises(CoreValidationError) as ctx:
                derive_demand(source, slack=slack(), policy=policy(), provenance=prov())
            self.assertIn("authorized", str(ctx.exception))

    def test_derivation_requires_the_referenced_policy_and_slack(self) -> None:
        other_policy = FulfillmentPolicy.build(
            object_id="intent/policy/other-001", environment_id=ENV, domain_id=DOMAIN,
            spec=policy_spec(), provenance=prov(),
        )
        other_slack = EconomicSlack.build(
            object_id="intent/slack/other-001", environment_id=ENV, domain_id=DOMAIN,
            spec=slack_spec(), provenance=prov(),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            derive_demand(authorized_intent(), slack=slack(), policy=other_policy, provenance=prov())
        self.assertIn("intent/policy/other-001", str(ctx.exception))
        with self.assertRaises(CoreValidationError) as ctx:
            derive_demand(authorized_intent(), slack=other_slack, policy=policy(), provenance=prov())
        self.assertIn("intent/slack/other-001", str(ctx.exception))

    def test_derivation_requires_active_policy_and_slack(self) -> None:
        retired_policy = policy().retire(provenance=prov())
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=slack(), policy=retired_policy, provenance=prov())
        retired_slack = slack().retire(provenance=prov())
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=retired_slack, policy=policy(), provenance=prov())

    def test_window_must_bracket_the_intent_amount(self) -> None:
        narrow = slack_spec().with_changes({
            "amount_min": Amount(100000, 2, "asset/USD"),
            "amount_max": Amount(124000, 2, "asset/USD"),
        })
        low_slack = EconomicSlack.build(object_id="intent/slack/merchant-001", environment_id=ENV,
                                        domain_id=DOMAIN, spec=narrow, provenance=prov())
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=low_slack, policy=policy(), provenance=prov())
        shifted = slack_spec().with_changes({"amount_min": Amount(126000, 2, "asset/USD")})
        high_slack = EconomicSlack.build(object_id="intent/slack/merchant-001", environment_id=ENV,
                                         domain_id=DOMAIN, spec=shifted, provenance=prov())
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=high_slack, policy=policy(), provenance=prov())

    def test_slack_must_not_relax_the_deadline(self) -> None:
        late = slack_spec().with_changes({
            "latest_completion": "2026-09-03T18:00:00Z",
            "earliest_completion": "2026-09-03T06:00:00Z",
        })
        late_slack = EconomicSlack.build(object_id="intent/slack/merchant-001", environment_id=ENV,
                                         domain_id=DOMAIN, spec=late, provenance=prov())
        with self.assertRaises(CoreValidationError) as ctx:
            derive_demand(authorized_intent(), slack=late_slack, policy=policy(), provenance=prov())
        self.assertIn("deadline", str(ctx.exception))

    def test_policy_slack_coherence_is_enforced(self) -> None:
        no_split = policy_spec().with_changes({"allow_split": False})
        strict_policy = FulfillmentPolicy.build(
            object_id="intent/policy/merchant-001", environment_id=ENV, domain_id=DOMAIN,
            spec=no_split, provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=slack(), policy=strict_policy, provenance=prov())
        no_substitute = policy_spec().with_changes({"allow_asset_substitution": False})
        fixed_policy = FulfillmentPolicy.build(
            object_id="intent/policy/merchant-001", environment_id=ENV, domain_id=DOMAIN,
            spec=no_substitute, provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            derive_demand(authorized_intent(), slack=slack(), policy=fixed_policy, provenance=prov())

    def test_withdraw_only_from_open(self) -> None:
        derived = demand()
        withdrawn = withdraw_demand(derived, provenance=prov(), causation_id="command/withdraw-0007")
        self.assertEqual(withdrawn.state, DemandState.WITHDRAWN)
        self.assertEqual(withdrawn.envelope.object_version, 2)
        self.assertEqual(withdrawn.spec, derived.spec)
        with self.assertRaises(CoreValidationError):
            withdraw_demand(withdrawn, provenance=prov())

    def test_rederivation_versions_the_demand(self) -> None:
        derived = demand()
        amended_intent = authorized_intent().amend(
            provenance=prov(), causation_id="command/amend-0007",
            amount=Amount(126000, 2, "asset/USD"),
        )
        rederived = derive_demand(
            amended_intent, slack=slack(), policy=policy(), provenance=prov(),
            previous=derived,
        )
        self.assertEqual(rederived.envelope.object_version, 2)
        self.assertEqual(rederived.state, DemandState.OPEN)
        self.assertEqual(rederived.spec.intent_version, 3)
        self.assertEqual(Demand.from_json(rederived.to_json()), rederived)

        other = derive_demand(
            _other_authorized_intent(), slack=slack(), policy=policy(), provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            derive_demand(amended_intent, slack=slack(), policy=policy(), provenance=prov(),
                          previous=other)
        withdrawn = withdraw_demand(derived, provenance=prov())
        with self.assertRaises(CoreValidationError):
            derive_demand(amended_intent, slack=slack(), policy=policy(), provenance=prov(),
                          previous=withdrawn)

    def test_demand_spec_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            Demand.from_dict(resealed(demand(), state="MYSTERY"))
        with self.assertRaises(CoreValidationError):
            Demand.from_json(policy().to_json())
        with self.assertRaises(CoreValidationError):
            DemandSpec(
                intent_id="intent/pay-2026-0007", intent_version=2, destination_id=ENDPOINT,
                asset="asset/USD", amount_min=125000, amount_max=130000, amount_scale=2,
                earliest_completion="2026-09-03T00:00:00Z",
                latest_completion="2026-09-03T12:00:00Z",
                allow_split=False, max_payment_count=2,
                substitute_assets=(), demand_class_id="intent/demand-class/asset/USD/DEADLINE/SINGLE",
            )


def _other_authorized_intent() -> Intent:
    return Intent.build(
        object_id="intent/pay-2026-0099",
        environment_id=ENV,
        domain_id=DOMAIN,
        spec=intent_spec(),
        provenance=prov(source="intent/other-checkout"),
    ).authorize(provenance=prov())


class DemandClassTests(unittest.TestCase):
    """Demand classes: deterministic DERIVED classification of demand."""

    def test_urgency_bands_are_deterministic(self) -> None:
        self.assertEqual(window_seconds("2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z"), 0)
        self.assertEqual(
            urgency_for_window("2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z"),
            UrgencyClass.IMMEDIATE,
        )
        self.assertEqual(
            urgency_for_window("2026-09-03T00:00:00Z", "2026-09-03T00:30:00Z"),
            UrgencyClass.IMMEDIATE,
        )
        self.assertEqual(
            urgency_for_window("2026-09-03T00:00:00Z", "2026-09-03T01:00:01Z"),
            UrgencyClass.DEADLINE,
        )
        self.assertEqual(
            urgency_for_window("2026-09-03T00:00:00Z", "2026-09-03T12:00:00Z"),
            UrgencyClass.DEADLINE,
        )
        self.assertEqual(
            urgency_for_window("2026-09-02T00:00:00Z", "2026-09-03T00:00:01Z"),
            UrgencyClass.FLEXIBLE,
        )
        with self.assertRaises(CoreValidationError):
            window_seconds("2026-09-03T12:00:00Z", "2026-09-03T00:00:00Z")

    def test_demand_class_id_is_canonical(self) -> None:
        self.assertEqual(
            demand_class_id("asset/USD", UrgencyClass.DEADLINE, DemandShape.SPLIT),
            "intent/demand-class/asset/USD/DEADLINE/SPLIT",
        )
        with self.assertRaises(CoreValidationError):
            demand_class_id("asset USD", UrgencyClass.DEADLINE, DemandShape.SPLIT)
        with self.assertRaises(CoreValidationError):
            demand_class_id("asset/USD", "SOMEDAY", DemandShape.SPLIT)
        with self.assertRaises(CoreValidationError):
            demand_class_id("asset/USD", UrgencyClass.DEADLINE, "MULTI")

    def test_classify_demand_is_deterministic_and_consistent(self) -> None:
        derived = demand()
        first = classify_demand(derived, environment_id=ENV, domain_id=DOMAIN, provenance=prov())
        second = classify_demand(derived, environment_id=ENV, domain_id=DOMAIN, provenance=prov())
        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.object_id, derived.spec.demand_class_id)
        self.assertEqual(first.envelope.object_id, first.object_id)
        self.assertEqual(first.spec.asset, "asset/USD")
        self.assertEqual(first.spec.urgency, UrgencyClass.DEADLINE)
        self.assertEqual(first.spec.shape, DemandShape.SPLIT)

    def test_demand_class_round_trip_is_byte_stable(self) -> None:
        value = demand_class()
        encoded = value.to_json()
        self.assertEqual(DemandClass.from_json(encoded), value)
        self.assertEqual(DemandClass.from_json(encoded).to_json(), encoded)

    def test_demand_class_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            DemandClassSpec(asset="asset/USD", urgency="SOMEDAY", shape=DemandShape.SINGLE,
                            class_id="intent/demand-class/asset/USD/IMMEDIATE/SINGLE")
        with self.assertRaises(CoreValidationError):
            DemandClassSpec(asset="asset/USD", urgency=UrgencyClass.IMMEDIATE, shape=DemandShape.SINGLE,
                            class_id="intent/demand-class/asset/USD/DEADLINE/SINGLE")
        with self.assertRaises(CoreValidationError):
            DemandClass.from_dict(resealed(demand_class(), state="MYSTERY"))


class TransformationCompletenessTests(unittest.TestCase):
    """No semantic loss across representation boundaries (byte-stable)."""

    def test_all_durable_objects_round_trip_losslessly(self) -> None:
        authorized = authorized_intent()
        derived = demand()
        for value in (policy(), slack(), intent(), authorized, derived, demand_class()):
            with self.subTest(value=value.object_id):
                self.assertEqual(type(value).from_json(value.to_json()), value)

    def test_round_trips_are_byte_stable(self) -> None:
        for value in (policy(), slack(), intent(), authorized_intent(), demand(), demand_class()):
            with self.subTest(value=value.object_id):
                encoded = value.to_json()
                self.assertEqual(type(value).from_json(encoded).to_json(), encoded)

    def test_canonical_encoding_is_compact_and_sorted(self) -> None:
        encoded = demand().to_json()
        self.assertNotIn(": ", encoded)
        self.assertNotIn(", ", encoded)
        self.assertTrue(encoded.startswith('{"envelope":'))
        self.assertIn('"integrity_hash"', encoded)

    def test_demand_constraints_survive_serialization(self) -> None:
        source_intent = authorized_intent()
        source_demand = demand()
        decoded_intent = Intent.from_json(source_intent.to_json())
        decoded_demand = Demand.from_json(source_demand.to_json())
        self.assertEqual(decoded_intent, source_intent)
        self.assertEqual(decoded_demand, source_demand)
        spec = decoded_demand.spec
        self.assertTrue(spec.amount_min <= decoded_intent.spec.amount.value <= spec.amount_max)
        self.assertLessEqual(parse(spec.latest_completion), parse(decoded_intent.spec.deadline))
        self.assertGreaterEqual(parse(spec.latest_completion), parse(spec.earliest_completion))
        self.assertEqual(
            tuple(ref.source_id for ref in decoded_intent.spec.funding.sources),
            (WALLET, BANK),
        )
        self.assertEqual(decoded_intent.spec.funding.sources[0].cap,
                         Amount(125000, 2, "asset/USD"))
        self.assertEqual(decoded_intent.spec.policy_id, "intent/policy/merchant-001")
        self.assertEqual(decoded_intent.spec.slack_id, "intent/slack/merchant-001")
        self.assertEqual(spec.demand_class_id, "intent/demand-class/asset/USD/DEADLINE/SPLIT")
        self.assertEqual(decoded_demand.to_json(), source_demand.to_json())

    def test_duplicate_json_keys_are_rejected(self) -> None:
        encoded = demand().to_json()
        duplicated = encoded.replace(
            '"asset":"asset/USD"', '"asset":"asset/USD","asset":"asset/EUR"'
        )
        with self.assertRaises(CoreValidationError):
            Demand.from_json(duplicated)


class IntegrityAndImmutabilityTests(unittest.TestCase):
    """Domain seal: tampered, spliced, forged and unsealed objects fail closed."""

    def test_unsealed_envelope_is_rejected(self) -> None:
        source = demand()
        envelope = source.envelope
        unsealed = ObjectEnvelope(
            object_id=envelope.object_id,
            object_type=envelope.object_type,
            object_version=envelope.object_version,
            environment_id=envelope.environment_id,
            domain_id=envelope.domain_id,
            schema_version=envelope.schema_version,
            protocol_version=envelope.protocol_version,
            state=envelope.state,
            provenance=envelope.provenance,
            causation_id=envelope.causation_id,
            correlation_id=envelope.correlation_id,
            previous_version=envelope.previous_version,
        )
        value = {
            "envelope": unsealed.to_dict(),
            "payload": source.to_dict()["payload"],
            "integrity_hash": source.integrity_hash,
        }
        with self.assertRaises(CoreValidationError):
            Demand.from_dict(value)

    def test_tampered_envelope_is_rejected(self) -> None:
        encoded = demand().to_json()
        for tampered in (
            encoded.replace('"state":"OPEN"', '"state":"CLOSED"'),
            encoded.replace('"issuer":"principal/merchant-ops-7"', '"issuer":"principal/attacker"'),
        ):
            with self.assertRaises(CoreValidationError):
                Demand.from_json(tampered)

    def test_tampered_payload_is_rejected(self) -> None:
        encoded = demand().to_json()
        tampered = encoded.replace('"amount_max":130000', '"amount_max":990000')
        with self.assertRaises(CoreValidationError):
            Demand.from_json(tampered)
        tampered_intent = intent().to_json().replace('"value":125000', '"value":999000')
        with self.assertRaises(CoreValidationError):
            Intent.from_json(tampered_intent)

    def test_spliced_composite_is_rejected(self) -> None:
        first = demand()
        second = derive_demand(
            _other_authorized_intent(), slack=slack(), policy=policy(), provenance=prov(),
        )
        spliced = {
            "envelope": first.envelope.to_dict(),
            "payload": second.to_dict()["payload"],
            "integrity_hash": second.integrity_hash,
        }
        with self.assertRaises(CoreValidationError):
            Demand.from_dict(spliced)

    def test_forged_digest_and_unknown_fields_are_rejected(self) -> None:
        value = demand().to_dict()
        value["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            Demand.from_dict(value)
        value = demand().to_dict()
        value["surprise"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            Demand.from_dict(value)

    def test_identity_is_frozen_across_versions(self) -> None:
        original = authorized_intent()
        advanced = original.amend(provenance=prov(), amount=Amount(127000, 2, "asset/USD"))
        for field in ("object_id", "object_type", "environment_id", "domain_id",
                      "schema_version", "protocol_version"):
            self.assertEqual(getattr(advanced.envelope, field), getattr(original.envelope, field))
        with self.assertRaises(CoreValidationError):
            original.envelope.next_version(object_id="intent/other")
        with self.assertRaises(CoreValidationError):
            original.envelope.next_version(object_type="payswap/other/v1")


class IntentGraphDogfoodingTests(unittest.TestCase):
    """DOGFOOD-008: real product intent to derived demand with constraints
    preserved through serialization, over the supported product path
    (Intent.authorize -> derive_demand -> classify_demand -> ObjectGraph).

    The endpoint envelope mirrors the representative intent-graph fixture
    established by src/core/test_core.py (intent envelope + endpoint envelope
    + IS_ENTITLED_TO); the endpoint object authority itself is WORK-007.
    """

    def _endpoint_envelope(self) -> ObjectEnvelope:
        return ObjectEnvelope(
            object_id=ENDPOINT,
            object_type="payswap/endpoint/v1",
            object_version=1,
            environment_id=ENV,
            domain_id=DOMAIN,
            schema_version=1,
            protocol_version="v0.1",
            state="ACTIVE",
            provenance=Provenance(
                issuer="principal/merchant-42",
                source="interop/endpoint-registry",
                recorded_at=STAMP,
            ),
            correlation_id="corr/merchant-checkout-42",
        ).with_integrity_hash()

    def test_dogfood_008_merchant_outcome_to_demand_graph(self) -> None:
        policy_object = policy()
        slack_object = slack()
        authorized = authorized_intent()
        derived = derive_demand(
            authorized, slack=slack_object, policy=policy_object,
            provenance=prov(source="intent/demand-derivation"),
        )
        klass = classify_demand(
            derived, environment_id=ENV, domain_id=DOMAIN,
            provenance=prov(source="intent/demand-classification"),
        )
        endpoint = self._endpoint_envelope()
        relationships = (
            Relationship.build(
                RelationshipType.IS_ENTITLED_TO,
                authorized.object_id,
                endpoint.object_id,
                attributes={"priority": 1, "tags": ("settlement", "instant")},
            ),
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                authorized.object_id,
                policy_object.object_id,
                attributes={"role": "fulfillment_policy"},
            ),
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                authorized.object_id,
                slack_object.object_id,
                attributes={"role": "economic_slack"},
            ),
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                derived.object_id,
                authorized.object_id,
                attributes={"role": "source_of_truth"},
            ),
            Relationship.build(
                RelationshipType.DEPENDS_ON,
                derived.object_id,
                klass.object_id,
                attributes={"role": "classification"},
            ),
        )
        graph = ObjectGraph.build(
            [
                authorized.envelope,
                policy_object.envelope,
                slack_object.envelope,
                derived.envelope,
                klass.envelope,
                endpoint,
            ],
            relationships,
        )
        encoded = graph.to_json()
        decoded = ObjectGraph.from_json(encoded)
        self.assertEqual(decoded, graph)
        self.assertEqual(decoded.to_json(), encoded)
        self.assertEqual(decoded.objects[0].state, "AUTHORIZED")
        self.assertEqual(decoded.objects[3].causation_id, authorized.object_id)
        for tampered in (
            encoded.replace('"state":"AUTHORIZED"', '"state":"SETTLED"'),
            encoded.replace('"issuer":"principal/merchant-ops-7"', '"issuer":"principal/attacker"'),
        ):
            with self.assertRaises(CoreValidationError):
                ObjectGraph.from_json(tampered)

    def test_dogfood_008_constraints_preserved_and_lifecycle_continues(self) -> None:
        authorized = authorized_intent()
        derived = demand()
        klass = demand_class()

        decoded_intent = Intent.from_json(authorized.to_json())
        decoded_demand = Demand.from_json(derived.to_json())
        decoded_class = DemandClass.from_json(klass.to_json())
        self.assertEqual((decoded_intent, decoded_demand, decoded_class),
                         (authorized, derived, klass))

        # Constraint preservation after serialization.
        self.assertTrue(decoded_demand.spec.amount_min
                         <= decoded_intent.spec.amount.value
                         <= decoded_demand.spec.amount_max)
        self.assertLessEqual(parse(decoded_demand.spec.latest_completion),
                             parse(decoded_intent.spec.deadline))
        self.assertEqual(classify_demand(decoded_demand, environment_id=ENV, domain_id=DOMAIN,
                                          provenance=prov()).object_id,
                         decoded_class.object_id)

        # The lifecycle continues from deserialized objects, deterministically.
        cancelled = decoded_intent.cancel(
            provenance=prov(source="intent/cancel-command"),
            causation_id="command/cancel-0007",
        )
        withdrawn = withdraw_demand(
            decoded_demand,
            provenance=prov(source="intent/withdraw-command"),
            causation_id="command/withdraw-0007",
        )
        self.assertEqual(cancelled.state, IntentState.CANCELLED)
        self.assertEqual(withdrawn.state, DemandState.WITHDRAWN)
        self.assertEqual(Intent.from_json(cancelled.to_json()), cancelled)
        self.assertEqual(Demand.from_json(withdrawn.to_json()), withdrawn)
        with self.assertRaises(CoreValidationError):
            derive_demand(cancelled, slack=slack(), policy=policy(), provenance=prov())


if __name__ == "__main__":
    unittest.main()
