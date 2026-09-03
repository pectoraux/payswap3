from __future__ import annotations

from dataclasses import replace

import pytest

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.transition import ExpectedVersion, Outcome, RejectionReason
from src.value import Amount

from .contracts import CHECKOUT_OBJECT_TYPE, PROMISE_OBJECT_TYPE, CheckoutState, PromiseState
from .dogfooding import NOW, run_dogfood
from .engine import MerchantEngine
from .records import Checkout, CheckoutSpec, SettlementPromise, SettlementPromiseSpec
from .seal import decode_json, to_json


def amount(value: int) -> Amount:
    return Amount(value=value, scale=2, asset="USD")


def spec() -> CheckoutSpec:
    return CheckoutSpec("checkout/1", "acme", "customer/1", "intent/1", amount(5000), "2026-01-01T01:00:00+00:00")


def engine() -> MerchantEngine:
    return MerchantEngine(environment_id="sandbox", domain_id="merchant-domain", actor="principal/acme")


def create(e: MerchantEngine) -> None:
    result = e.submit(e.command(command_id="create", command_type="merchant/checkout.create", payload=spec().to_dict(), target_refs=("checkout/1",), requested_at=NOW))
    assert result.outcome is Outcome.ACCEPTED


def test_checkout_is_typed_versioned_and_sealed() -> None:
    checkout = Checkout.create(spec=spec(), environment_id="sandbox", domain_id="merchant-domain", provenance=Provenance("principal/acme", "test", NOW))
    assert checkout.envelope.object_type == CHECKOUT_OBJECT_TYPE
    assert checkout.envelope.object_version == 1
    raw = to_json(checkout.envelope, checkout.spec, checkout.integrity_hash)
    envelope, payload, digest = decode_json(raw, object_type=CHECKOUT_OBJECT_TYPE, state_type=CheckoutState)
    assert envelope == checkout.envelope
    assert payload == checkout.spec.to_dict()
    assert digest == checkout.integrity_hash


def test_create_accept_promise_and_refund_route_use_kernel() -> None:
    e = engine(); create(e)
    accepted = e.submit(e.command(command_id="accept", command_type="merchant/checkout.accept", payload={"checkout_id":"checkout/1","merchant_id":"acme","accepted_at":NOW}, target_refs=("checkout/1","checkout/1/acceptance"), expected_versions=(ExpectedVersion("checkout/1",1),), requested_at=NOW))
    assert accepted.outcome is Outcome.ACCEPTED
    promised = e.submit(e.command(command_id="promise", command_type="merchant/checkout.promise", payload={"checkout_id":"checkout/1","promise":{"promise_id":"promise/1","checkout_id":"checkout/1","settlement_id":"settlement/1","merchant_id":"acme","amount":amount(5000).to_dict(),"credit_limit":amount(6000).to_dict(),"expires_at":"2026-01-01T02:00:00+00:00"}}, target_refs=("checkout/1","promise/1"), expected_versions=(ExpectedVersion("checkout/1",2),), requested_at=NOW))
    assert promised.outcome is Outcome.ACCEPTED
    route = e.submit(e.command(command_id="refund", command_type="merchant/checkout.refund-route", payload={"checkout_id":"checkout/1","route_id":"refund/1","settlement_id":"settlement/1"}, target_refs=("refund/1",), requested_at=NOW))
    assert route.outcome is Outcome.ACCEPTED
    assert e.records["checkout/1"].envelope.state == "PROMISED"
    assert isinstance(e.records["promise/1"], SettlementPromise)
    assert e.records["promise/1"].spec.credit_limit.value == 6000


def test_duplicate_command_does_not_reemit_event() -> None:
    e = engine(); create(e)
    command = e.command(command_id="same", command_type="merchant/checkout.accept", payload={"checkout_id":"checkout/1","merchant_id":"acme","accepted_at":NOW}, target_refs=("checkout/1","checkout/1/acceptance"), expected_versions=(ExpectedVersion("checkout/1",1),), requested_at=NOW)
    first = e.submit(command); second = e.submit(command)
    assert first.outcome is Outcome.ACCEPTED
    assert second.outcome is Outcome.DUPLICATE
    assert len(e.kernel.journal) == 2


def test_wrong_merchant_cannot_accept() -> None:
    e = engine(); create(e)
    with pytest.raises(CoreValidationError, match="merchant does not own checkout"):
        e.submit(e.command(command_id="bad", command_type="merchant/checkout.accept", payload={"checkout_id":"checkout/1","merchant_id":"other","accepted_at":NOW}, target_refs=("checkout/1","checkout/1/acceptance"), expected_versions=(ExpectedVersion("checkout/1",1),), requested_at=NOW))


def test_credit_limit_is_fail_closed() -> None:
    with pytest.raises(CoreValidationError, match="credit limit exceeded"):
        SettlementPromiseSpec("promise/1","checkout/1","settlement/1","acme",amount(7000),amount(6000),"2026-01-01T02:00:00+00:00")


def test_promise_seal_round_trip() -> None:
    e = engine(); create(e)
    e.submit(e.command(command_id="accept", command_type="merchant/checkout.accept", payload={"checkout_id":"checkout/1","merchant_id":"acme","accepted_at":NOW}, target_refs=("checkout/1","checkout/1/acceptance"), expected_versions=(ExpectedVersion("checkout/1",1),), requested_at=NOW))
    result = e.submit(e.command(command_id="promise", command_type="merchant/checkout.promise", payload={"checkout_id":"checkout/1","promise":{"promise_id":"promise/1","checkout_id":"checkout/1","settlement_id":"settlement/1","merchant_id":"acme","amount":amount(5000).to_dict(),"credit_limit":amount(6000).to_dict(),"expires_at":"2026-01-01T02:00:00+00:00"}}, target_refs=("checkout/1","promise/1"), expected_versions=(ExpectedVersion("checkout/1",2),), requested_at=NOW))
    assert result.outcome is Outcome.ACCEPTED
    promise = e.records["promise/1"]
    envelope, payload, digest = decode_json(to_json(promise.envelope, promise.spec, promise.integrity_hash), object_type=PROMISE_OBJECT_TYPE, state_type=PromiseState)
    assert envelope == promise.envelope
    assert payload == promise.spec.to_dict()
    assert digest == promise.integrity_hash


def test_no_second_settlement_authority_is_exposed() -> None:
    e = engine()
    assert not hasattr(e, "settle")
    assert not hasattr(e, "post")
    assert not hasattr(e, "finalize")


def test_domain_binding_is_structural() -> None:
    e = engine()
    command = e.command(command_id="create", command_type="merchant/checkout.create", payload=spec().to_dict(), target_refs=("checkout/1",), requested_at=NOW)
    foreign = replace(command, domain_id="foreign")
    result = e.submit(foreign)
    assert result.outcome is Outcome.REJECTED
    assert result.reason is RejectionReason.DOMAIN_MISMATCH


def test_dogfood_is_twenty_for_twenty() -> None:
    first = run_dogfood(); second = run_dogfood()
    assert first == second
    assert first["passed"] == first["total"] == 20
