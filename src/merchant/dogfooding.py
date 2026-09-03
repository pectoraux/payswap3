from __future__ import annotations

from src.transition import ExpectedVersion, Outcome
from src.value import Amount

from .engine import MerchantEngine
from .records import Checkout, SettlementPromise

NOW = "2026-01-01T00:00:00+00:00"


def run_dogfood() -> dict[str, object]:
    engine = MerchantEngine(environment_id="sandbox", domain_id="merchant-domain", actor="principal/acme")
    amount = Amount(value=5000, scale=2, asset="USD")
    create = engine.submit(engine.command(command_id="c1", command_type="merchant/checkout.create", payload={"checkout_id":"checkout/demo-1","merchant_id":"acme","customer_id":"customer/1","intent_id":"intent/demo-1","amount":amount.to_dict(),"expires_at":"2026-01-01T01:00:00+00:00"}, target_refs=("checkout/demo-1",), requested_at=NOW))
    accepted = engine.submit(engine.command(command_id="c2", command_type="merchant/checkout.accept", payload={"checkout_id":"checkout/demo-1","merchant_id":"acme","accepted_at":NOW}, target_refs=("checkout/demo-1","checkout/demo-1/acceptance"), expected_versions=(ExpectedVersion("checkout/demo-1",1),), requested_at=NOW))
    promise_payload={"checkout_id":"checkout/demo-1","promise":{"promise_id":"promise/demo-1","checkout_id":"checkout/demo-1","settlement_id":"settlement/demo-1","merchant_id":"acme","amount":amount.to_dict(),"credit_limit":Amount(value=6000,scale=2,asset="USD").to_dict(),"expires_at":"2026-01-01T02:00:00+00:00"}}
    promised = engine.submit(engine.command(command_id="c3", command_type="merchant/checkout.promise", payload=promise_payload, target_refs=("checkout/demo-1","promise/demo-1"), expected_versions=(ExpectedVersion("checkout/demo-1",2),), requested_at=NOW))
    route = engine.submit(engine.command(command_id="c4", command_type="merchant/checkout.refund-route", payload={"checkout_id":"checkout/demo-1","route_id":"refund-route/demo-1","settlement_id":"settlement/demo-1"}, target_refs=("refund-route/demo-1",), requested_at=NOW))
    replay = engine.submit(engine.command(command_id="c3", command_type="merchant/checkout.promise", payload=promise_payload, target_refs=("checkout/demo-1","promise/demo-1"), expected_versions=(ExpectedVersion("checkout/demo-1",2),), requested_at=NOW))
    try:
        engine.submit(engine.command(command_id="c5", command_type="merchant/checkout.promise", payload={"checkout_id":"checkout/demo-1","promise":{"promise_id":"promise/too-large","checkout_id":"checkout/demo-1","settlement_id":"settlement/demo-1","merchant_id":"acme","amount":Amount(value=7000,scale=2,asset="USD").to_dict(),"credit_limit":Amount(value=6000,scale=2,asset="USD").to_dict(),"expires_at":"2026-01-01T02:00:00+00:00"}}, target_refs=("checkout/demo-1","promise/too-large"), expected_versions=(ExpectedVersion("checkout/demo-1",3),), requested_at=NOW))
        oversized_rejected = False
    except Exception:
        oversized_rejected = True
    checks = [
        create.outcome is Outcome.ACCEPTED,
        accepted.outcome is Outcome.ACCEPTED,
        promised.outcome is Outcome.ACCEPTED,
        route.outcome is Outcome.ACCEPTED,
        replay.outcome is Outcome.DUPLICATE,
        oversized_rejected,
        isinstance(engine.records["checkout/demo-1"], Checkout),
        isinstance(engine.records["promise/demo-1"], SettlementPromise),
        engine.records["promise/demo-1"].spec.credit_limit.value == 6000,
        engine.records["checkout/demo-1"].envelope.state == "PROMISED",
        engine.records["refund-route/demo-1"].settlement_id == "settlement/demo-1",
        len(engine.kernel.journal) == 4,
        engine.kernel.journal[0].event.event_type == "intent/merchant-checkout-created",
        engine.kernel.journal[-1].event.event_type == "intent/merchant-refund-route-recorded",
        len({entry.event.event_id for entry in engine.kernel.journal}) == 4,
        all(entry.event.environment_id == "sandbox" for entry in engine.kernel.journal),
        all(entry.event.domain_id == "merchant-domain" for entry in engine.kernel.journal),
        all(record.envelope.integrity_hash for record in engine.records.values()),
        engine.records["promise/demo-1"].envelope.object_version == 1,
        engine.records["checkout/demo-1"].envelope.object_version == 3,
    ]
    return {"checks": [bool(x) for x in checks], "passed": sum(bool(x) for x in checks), "total": len(checks)}
