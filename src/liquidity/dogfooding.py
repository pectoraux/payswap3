"""DOGFOOD-011: corridor liquidity bootstrap, credit availability and
exposure limit breach.

The dogfooding/conformance contract of WORK-011: drive one deterministic
fixture through the three user/execution-facing surfaces of this package —

(a) corridor liquidity bootstrap: bounded offers with capability
    references, availability windows, amendment, suspension and a
    concentration check over the bootstrapped capacity;
(b) credit availability changes: a facility drawn, repaid, restructured
    with outstanding exposure and drawn again, tracking the exact
    remaining capacity at every step;
(c) exposure limit breach: two facilities each drawn within their own
    limits whose aggregate exceeds the control-side exposure limit
    (BREACH detected by the assessment), plus the fail-closed
    control-side draw gate.

The harness consumes only the public boundary, uses explicit ``as_of``
instants and provenance everywhere (never a clock read or an entropy
source), and is fully deterministic: two clean-process runs produce
byte-identical output and the same SHA-256 transcript digest. All
amounts are exact minor units (scale 2) of the corridor source currency.
"""

from __future__ import annotations

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money import Amount, Currency

from . import (
    Corridor,
    amend_liquidity_offer,
    assess_exposure,
    create_credit_exposure,
    create_credit_offer,
    create_liquidity_offer,
    credit_available_capacity,
    draw_against_exposure,
    draw_credit,
    evaluate_concentration,
    liquidity_offer_available_at,
    repay_credit,
    restructure_credit,
    suspend_liquidity_offer,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"

ASSET_USD = "asset/USD"
ASSET_EUR = "asset/EUR"
CORRIDOR = Corridor(ASSET_USD, ASSET_EUR)
REVERSE_CORRIDOR = Corridor(ASSET_EUR, ASSET_USD)

USD = Currency(code="USD", scale=2)
EUR = Currency(code="EUR", scale=2)

BOOT_AT = "2026-09-03T00:30:00Z"
CREDIT_DRAW_AT = "2026-09-03T01:00:00Z"
CREDIT_REPAY_AT = "2026-09-04T01:00:00Z"
CREDIT_RESTRUCTURE_AT = "2026-09-04T02:00:00Z"
CREDIT_DRAW2_AT = "2026-09-04T03:00:00Z"
EXPOSURE_AT = "2026-09-05T00:00:00Z"

OFFER_WINDOW = ("2026-09-03T00:00:00Z", "2026-09-10T00:00:00Z")
FACILITY_WINDOW = ("2026-09-03T00:00:00Z", "2026-09-20T00:00:00Z")
EXPOSURE_WINDOW = ("2026-09-03T00:00:00Z", "2026-09-30T00:00:00Z")


def usd(value: int) -> Amount:
    return Amount(currency=USD, value=value, scale=2)


def prov(source: str) -> Provenance:
    return Provenance(
        issuer="principal/liquidity-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-011-dogfooding",),
    )


def _bootstrap_lines() -> list[str]:
    """(a) Corridor liquidity bootstrap with a concentration check."""
    offers = [
        create_liquidity_offer(
            offer_id="liquidity/offer/alpha",
            provider="provider/alpha",
            provider_capability_id="capability/capability/alpha",
            beneficiary="principal/beneficiary-7",
            corridor=CORRIDOR,
            capacity=usd(1_500_000),
            available_from=OFFER_WINDOW[0],
            available_until=OFFER_WINDOW[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("liquidity/bootstrap"),
        ),
        create_liquidity_offer(
            offer_id="liquidity/offer/beta",
            provider="provider/beta",
            provider_capability_id="capability/capability/beta",
            beneficiary="principal/beneficiary-7",
            corridor=CORRIDOR,
            capacity=usd(600_000),
            available_from=OFFER_WINDOW[0],
            available_until=OFFER_WINDOW[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("liquidity/bootstrap"),
        ),
        create_liquidity_offer(
            offer_id="liquidity/offer/standby",
            provider="provider/gamma",
            provider_capability_id="capability/capability/gamma",
            corridor=REVERSE_CORRIDOR,
            capacity=Amount(currency=EUR, value=400_000, scale=2),
            available_from=OFFER_WINDOW[0],
            available_until=OFFER_WINDOW[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("liquidity/bootstrap"),
        ),
    ]
    offers[0] = amend_liquidity_offer(
        offers[0], provenance=prov("liquidity/bootstrap-amend"), capacity=usd(1_200_000)
    )
    offers[1] = suspend_liquidity_offer(
        offers[1], provenance=prov("liquidity/bootstrap-suspend")
    )

    lines = ["phase=bootstrap", f"as_of={BOOT_AT}"]
    for offer in offers:
        lines.append(
            "bootstrap.offer={offer} provider={provider} corridor={corridor} "
            "capacity={capacity} state={state} available={available}".format(
                offer=offer.envelope.object_id,
                provider=offer.spec.provider,
                corridor=offer.spec.corridor.corridor_id,
                capacity=offer.spec.capacity.value,
                state=offer.state.value,
                available=liquidity_offer_available_at(offer, BOOT_AT),
            )
        )
    report = evaluate_concentration(liquidity_offers=offers)
    lines.append(f"bootstrap.concentration_entries={len(report.entries)}")
    lines.append(f"bootstrap.concentration_breaches={len(report.breaches)}")
    if report.breaches:
        breach = report.breaches[0]
        lines.append(
            "bootstrap.concentration_breach=kind={kind} group={group} share_bps={share}".format(
                kind=breach.kind.value,
                group=":".join(breach.group),
                share=breach.share_bps,
            )
        )
    return lines


def _credit_lines() -> list[str]:
    """(b) Credit availability changes on one facility."""
    facility = create_credit_offer(
        offer_id="liquidity/credit/facility-1",
        provider="provider/alpha",
        provider_capability_id="capability/capability/alpha",
        counterparty="principal/cpty-7",
        corridor=CORRIDOR,
        limit=usd(100_000),
        utilization_from=FACILITY_WINDOW[0],
        utilization_until=FACILITY_WINDOW[1],
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("liquidity/credit-create"),
    )
    lines = [
        "phase=credit",
        f"as_of={CREDIT_DRAW_AT}",
        "credit.facility=liquidity/credit/facility-1",
        f"credit.limit={facility.spec.limit.value}",
    ]
    drawn = draw_credit(
        facility, usd(40_000), as_of=CREDIT_DRAW_AT,
        provenance=prov("liquidity/credit-draw"),
    )
    lines.append(
        f"credit.draw=40000 utilized={drawn.spec.utilized.value} "
        f"available={credit_available_capacity(drawn).value}"
    )
    repaid = repay_credit(
        drawn, usd(10_000), as_of=CREDIT_REPAY_AT,
        provenance=prov("liquidity/credit-repay"),
    )
    lines.append(
        f"credit.repay=10000 utilized={repaid.spec.utilized.value} "
        f"available={credit_available_capacity(repaid).value}"
    )
    restructured = restructure_credit(
        repaid,
        provenance=prov("liquidity/credit-restructure"),
        limit=usd(120_000),
    )
    lines.append(
        f"as_of={CREDIT_RESTRUCTURE_AT} credit.restructure_limit=120000 "
        f"available={credit_available_capacity(restructured).value}"
    )
    redrawn = draw_credit(
        restructured, usd(50_000), as_of=CREDIT_DRAW2_AT,
        provenance=prov("liquidity/credit-draw-2"),
    )
    lines.append(
        f"credit.draw=50000 utilized={redrawn.spec.utilized.value} "
        f"available={credit_available_capacity(redrawn).value}"
    )
    return lines


def _exposure_lines() -> list[str]:
    """(c) Exposure limit breach: aggregate breach plus fail-closed gate."""
    facilities = []
    for offer_id, provider, capability in (
        ("liquidity/credit/exposure-f1", "provider/alpha", "capability/capability/alpha"),
        ("liquidity/credit/exposure-f2", "provider/beta", "capability/capability/beta"),
    ):
        facility = create_credit_offer(
            offer_id=offer_id,
            provider=provider,
            provider_capability_id=capability,
            counterparty="principal/cpty-9",
            corridor=CORRIDOR,
            limit=usd(50_000),
            utilization_from=FACILITY_WINDOW[0],
            utilization_until=FACILITY_WINDOW[1],
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("liquidity/exposure-facility"),
        )
        facilities.append(
            draw_credit(
                facility, usd(40_000), as_of=EXPOSURE_AT,
                provenance=prov("liquidity/exposure-facility-draw"),
            )
        )
    # A second, smaller counterparty keeps the concentration measurement
    # non-degenerate.
    neighbour = create_credit_offer(
        offer_id="liquidity/credit/exposure-f3",
        provider="provider/gamma",
        provider_capability_id="capability/capability/gamma",
        counterparty="principal/cpty-8",
        corridor=CORRIDOR,
        limit=usd(20_000),
        utilization_from=FACILITY_WINDOW[0],
        utilization_until=FACILITY_WINDOW[1],
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("liquidity/exposure-facility"),
    )
    facilities.append(
        draw_credit(
            neighbour, usd(20_000), as_of=EXPOSURE_AT,
            provenance=prov("liquidity/exposure-facility-draw"),
        )
    )

    exposure = create_credit_exposure(
        exposure_id="liquidity/exposure/cpty-9",
        counterparty="principal/cpty-9",
        corridor=CORRIDOR,
        limit=usd(75_000),
        valid_from=EXPOSURE_WINDOW[0],
        valid_until=EXPOSURE_WINDOW[1],
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("liquidity/exposure-create"),
    )
    assessment = assess_exposure([exposure], facilities)
    lines = ["phase=exposure", f"as_of={EXPOSURE_AT}"]
    for check in assessment.checks:
        lines.append(
            "exposure.check={exposure} corridor={corridor} limit={limit} "
            "drawn={drawn} status={status}".format(
                exposure=check.exposure_id,
                corridor=check.corridor.corridor_id,
                limit=check.limit.value,
                drawn=check.drawn.value,
                status=check.status.value,
            )
        )
    lines.append(f"exposure.breach_count={len(assessment.breaches)}")
    report = evaluate_concentration(credit_offers=facilities)
    lines.append(f"exposure.counterparty_concentration_breaches={len(report.breaches)}")

    # The control-side draw gate fails closed on the same limit.
    try:
        draw_against_exposure(
            exposure, usd(80_000), as_of=EXPOSURE_AT,
            provenance=prov("liquidity/exposure-gate"),
        )
    except CoreValidationError:
        lines.append(
            f"exposure.gate=REJECTED draw=80000 limit={exposure.spec.limit.value}"
        )
    else:
        raise AssertionError("DOGFOOD-011: exposure draw gate must fail closed")
    return lines


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-011 transcript and its digest."""
    lines = [
        "DOGFOOD-011: corridor liquidity bootstrap, credit availability and exposure breach",
        f"environment={ENV}",
        f"domain={DOMAIN}",
    ]
    lines.extend(_bootstrap_lines())
    lines.extend(_credit_lines())
    lines.extend(_exposure_lines())
    lines.append("classification: DOGFOOD-011: PASS")
    transcript = "\n".join(lines)
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> str:
    """Run DOGFOOD-011, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
