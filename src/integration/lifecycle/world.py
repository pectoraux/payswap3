"""The deterministic declared world of the IG-002 composed scenarios.

Every input the fulfillment lifecycle consumes is built here through the
merged sibling domains' public APIs — nothing is stubbed, no wall clock,
no entropy, no generated identifiers. The builder mirrors the compiler
domain's own dogfooding discipline (WORK-013) and adds exactly what the
execution stretch of the lifecycle needs:

* a real AUTHORIZED :class:`~src.intent.Intent`, an ACTIVE
  :class:`~src.intent.FulfillmentPolicy` and an ACTIVE
  :class:`~src.intent.EconomicSlack` (the compiler's public input
  contract);
* real per-hop :class:`~src.compiler.RouteHopOffer` projections of the
  (capability, standing offer, firm quote, liquidity offer, HELD
  reservation, compliance assessment) tuple — the reservation is
  additionally strengthened through the reservation domain's public
  ``Hold`` command so the execution hold gate is backed by a real HELD
  encumbrance reference;
* a real safety-domain fraud decision (verdict ``ALLOW``) for the
  execution plan authorization gate, keyed per hop;
* the canonical payment-leg declaration (payer/payee/asset/amount) the
  gate records as execution effect-result detail — the exact shape the
  clearing domain derives obligation facts from;
* a typed effect-authorization declaration (the simulation domain's
  contract re-exported by the execution domain) covering the payment
  submission effect type over the declared window.

Two runs with the same declared parameters build byte-identical worlds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json
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
from src.liquidity.offers import (
    create_liquidity_offer as create_capacity_offer,
)
from src.market import create_liquidity_offer, create_quote
from src.money import FxRate, get_currency
from src.reservation import Amount as ReservationAmount
from src.reservation import (
    create_reservation,
    hold_reservation,
)
from src.safety import (
    ComplianceConstraint,
    ConstraintOutcome,
    ConstraintPrecedence,
    FraudDecisionState,
    create_fraud_decision,
    record_compliance_result,
    request_compliance_assessment,
)

from .contracts import GATE_PROVENANCE_SOURCE, PAYMENT_SUBMIT_EFFECT_TYPE


@dataclass(frozen=True)
class LifecycleWorld:
    """One declared world: everything the composed lifecycle consumes.

    ``intent``/``policy``/``slack`` are real intent-domain durable
    objects; ``hops`` are real compiler-domain input projections;
    ``reservations`` maps reservation ids to the HELD records backing the
    execution hold gates; ``fraud_gates``/``compliance_gates`` map hop
    ids to the execution-domain gate declarations derived from real
    safety-domain records; ``payment_legs`` maps hop ids to the canonical
    payment-leg detail recorded as execution effect-result evidence;
    ``authorization`` is the typed effect-authorization declaration.
    """

    environment_id: str
    domain_id: str
    payer: str
    payee: str
    currency: str
    amount_minor: int
    destination: str
    as_of: str
    jurisdiction: str
    minimum_authority_tier: str
    intent: Intent
    policy: FulfillmentPolicy
    slack: EconomicSlack
    hops: tuple[Any, ...]
    reservations: Mapping[str, Any]
    fraud_gates: Mapping[str, Mapping[str, Any]]
    compliance_gates: Mapping[str, Mapping[str, Any]]
    payment_legs: Mapping[str, Mapping[str, Any]]
    authorization: Mapping[str, Any]

    def hold_gate_for(self, reservation_id: str) -> dict[str, Any]:
        reservation = self.reservations.get(reservation_id)
        if reservation is None:
            raise CoreValidationError(
                f"the world declares no HELD reservation {reservation_id!r}"
            )
        return {
            "reservation_id": reservation_id,
            "state": reservation.state.value,
            "object_version": reservation.envelope.object_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "payer": self.payer,
            "payee": self.payee,
            "currency": self.currency,
            "amount_minor": self.amount_minor,
            "destination": self.destination,
            "as_of": self.as_of,
            "jurisdiction": self.jurisdiction,
            "minimum_authority_tier": self.minimum_authority_tier,
            "intent": self.intent.to_dict(),
            "policy": self.policy.to_dict(),
            "slack": self.slack.to_dict(),
            "hops": [hop.to_dict() for hop in self.hops],
            "reservations": {
                reservation_id: reservation.to_dict()
                for reservation_id, reservation in self.reservations.items()
            },
            "fraud_gates": dict(self.fraud_gates),
            "compliance_gates": dict(self.compliance_gates),
            "payment_legs": {
                hop_id: dict(leg) for hop_id, leg in self.payment_legs.items()
            },
            "authorization": dict(self.authorization),
        }

    def canonical(self) -> str:
        return canonical_json(self.to_dict())


#: Deterministic world instants (declared data; never a clock read).
WORLD_STAMP = "2026-09-04T00:00:00Z"
WORLD_AS_OF = "2026-09-04T00:05:00Z"
WORLD_OPENS = "2026-09-04T00:00:00Z"
WORLD_CLOSES = "2026-09-04T06:00:00Z"
WORLD_DEADLINE = "2026-09-04T12:00:00Z"
WORLD_EARLIEST_COMPLETION = "2026-09-04T00:06:00Z"
WORLD_LATEST_COMPLETION = "2026-09-04T06:00:00Z"
WORLD_VERIFIED_UNTIL = "2027-01-01T00:00:00Z"

#: The canonical two-hop offer set: a cheap direct corridor and an
#: expensive alternate the compiler must rank below it under COST.
CANONICAL_HOPS = (
    {
        "slug": "d1-usd-direct",
        "provider": "provider/direct-us",
        "price_bps": 50,
        "flat_fee": 30,
        "reliability_bps": 9950,
        "latency_seconds": 120,
    },
    {
        "slug": "d2-usd-alternate",
        "provider": "provider/alt-us",
        "price_bps": 300,
        "flat_fee": 50,
        "reliability_bps": 9900,
        "latency_seconds": 90,
    },
)


def _provenance(issuer: str) -> Provenance:
    return Provenance(
        issuer=issuer,
        source=GATE_PROVENANCE_SOURCE,
        recorded_at=WORLD_STAMP,
    )


def _verification(slug: str) -> VerificationMetadata:
    return VerificationMetadata(
        method=VerificationMethod.CERTIFICATION,
        verifier="capability/verifier-ig002",
        result=VerificationResult.PASSED,
        verified_at=WORLD_STAMP,
        valid_until=WORLD_VERIFIED_UNTIL,
        evidence_refs=(f"evidence/ig002-cap-cert-{slug}",),
    )


def _satisfied_constraint(slug: str) -> ComplianceConstraint:
    return ComplianceConstraint(
        constraint_id=f"compliance/ig002-con-kyc-{slug}",
        requirement="screening:kyc",
        precedence=ConstraintPrecedence.LEGAL,
        outcome=ConstraintOutcome.SATISFIED,
        version=1,
        effective_from="2026-01-01T00:00:00Z",
        effective_until="2027-01-01T00:00:00Z",
        evidence_refs=(f"evidence/ig002-kyc-{slug}",),
    )


def _hop(
    world: dict[str, Any],
    hop: Mapping[str, Any],
) -> dict[str, Any]:
    """Build ONE routable hop plus its execution-side records."""
    from src.compiler import RouteHopOffer

    slug = hop["slug"]
    currency = world["currency"]
    asset = f"asset/{currency}"
    tag = world["tag"]
    environment_id = world["environment_id"]
    domain_id = world["domain_id"]
    amount_minor = world["amount_minor"]
    capacity = amount_minor * 4
    window = OperatingWindow(opens_at=WORLD_OPENS, closes_at=WORLD_CLOSES)

    capability = register_capability(
        object_id=f"capability/ig002-{tag}-{slug}",
        provider_id=f"capability/provider-{slug.rpartition('/')[2]}",
        kind=CapabilityKind.PAYMENT_EXECUTION,
        description=f"payment execution corridor {asset}->{asset}",
        authority_tier=AuthorityTier.R3,
        jurisdictions=("US",),
        protocol_versions=("v0.1",),
        simulation_support=True,
        production_support=True,
        operating_windows=(window,),
        environment_id=environment_id,
        domain_id=domain_id,
        issuer="principal/treasury",
        source=GATE_PROVENANCE_SOURCE,
        recorded_at=WORLD_STAMP,
    )
    capability = apply_verification(capability, _verification(slug))
    capability = activate_capability(capability, as_of=WORLD_AS_OF)

    market_offer = create_liquidity_offer(
        offer_id=f"market/ig002-{tag}-{slug}",
        provider=hop["provider"],
        asset=asset,
        amount_min=1,
        amount_max=capacity,
        scale=2,
        price_bps=hop["price_bps"],
        flat_fee=hop["flat_fee"],
        available_from=WORLD_OPENS,
        available_until=WORLD_CLOSES,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=_provenance("principal/treasury"),
        capability_id=capability.envelope.object_id,
    )
    quote = create_quote(
        quote_id=f"market/ig002-{tag}-{slug}-quote",
        demand_id=f"intent/ig002-demand-{tag}",
        maker=hop["provider"],
        asset=asset,
        scale=2,
        amount_min=1,
        amount_max=capacity,
        price_bps=hop["price_bps"],
        flat_fee=hop["flat_fee"],
        valid_from=WORLD_OPENS,
        valid_until=WORLD_CLOSES,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=_provenance("principal/treasury"),
        offer=market_offer,
    )
    corridor = Corridor(source_asset=asset, target_asset=asset)
    liquidity = create_capacity_offer(
        offer_id=f"liquidity/ig002-{tag}-{slug}",
        provider=hop["provider"],
        provider_capability_id=capability.envelope.object_id,
        beneficiary=world["payer"],
        corridor=corridor,
        capacity=_money_amount(currency, capacity),
        available_from=WORLD_OPENS,
        available_until=WORLD_CLOSES,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=_provenance("principal/treasury"),
    )
    reservation = create_reservation(
        reservation_id=f"reservation/ig002-{tag}-{slug}",
        resource_key=f"corridor:{asset}:{asset}:{hop['provider']}",
        provider=hop["provider"],
        beneficiary=world["payer"],
        asset=asset,
        amount=ReservationAmount(value=capacity, scale=2, asset=asset),
        window=window,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=_provenance("principal/treasury"),
    )
    reservation = hold_reservation(
        reservation,
        as_of=WORLD_AS_OF,
        hold_ref=f"value/hold/ig002-{tag}-{slug}",
        provenance=_provenance("principal/treasury"),
    )

    compliance_provenance = Provenance(
        issuer="principal/compliance-desk",
        source=GATE_PROVENANCE_SOURCE,
        recorded_at=WORLD_STAMP,
        evidence_refs=(f"evidence/ig002-kyc-{slug}",),
    )
    assessment = request_compliance_assessment(
        assessment_id=f"safety/ig002-{tag}-{slug}",
        subject_id=world["payer"],
        jurisdiction="US",
        constraints=(_satisfied_constraint(slug),),
        as_of=WORLD_STAMP,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=compliance_provenance,
    )
    assessment = record_compliance_result(
        assessment, as_of=WORLD_AS_OF, provenance=compliance_provenance
    )
    fraud_decision = create_fraud_decision(
        decision_id=f"safety/ig002-{tag}-{slug}-fraud",
        subject_id=world["payer"],
        assessment_ref=assessment.envelope.object_id,
        state=FraudDecisionState.ALLOW,
        as_of=WORLD_AS_OF,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=Provenance(
            issuer="principal/fraud-desk",
            source=GATE_PROVENANCE_SOURCE,
            recorded_at=WORLD_AS_OF,
            evidence_refs=(f"evidence/ig002-fraud-{slug}",),
        ),
    )

    offer = RouteHopOffer(
        hop_id=f"hop/ig002-{tag}-{slug}",
        environment_id=environment_id,
        domain_id=domain_id,
        provider=hop["provider"],
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
        fraud_decision_state=fraud_decision.state.value,
        corridor=corridor,
        fx_rate=None,
        source_scale=2,
        target_scale=2,
        amount_min=market_offer.spec.amount_min,
        amount_max=market_offer.spec.amount_max,
        capacity=liquidity.spec.capacity.value,
        price_bps=quote.spec.price_bps,
        flat_fee=quote.spec.flat_fee,
        reliability_bps=hop["reliability_bps"],
        latency_seconds=hop["latency_seconds"],
        window_opens_at=capability.operating_windows[0].opens_at,
        window_closes_at=capability.operating_windows[0].closes_at,
        quote_valid_from=quote.spec.valid_from,
        quote_valid_until=quote.spec.valid_until,
    )
    return {
        "offer": offer,
        "reservation": reservation,
        "fraud_gate": {
            "decision_id": fraud_decision.envelope.object_id,
            "verdict": fraud_decision.state.value,
            "object_version": fraud_decision.envelope.object_version,
        },
        "compliance_gate": {
            "assessment_id": assessment.envelope.object_id,
            "verdict": assessment.spec.result.verdict.value,
            "object_version": assessment.envelope.object_version,
        },
        "payment_leg": {
            "payer": world["payer"],
            "payee": world["payee"],
            "asset": currency,
            "amount": {
                "value": world["amount_minor"],
                "scale": 2,
                "asset": currency,
            },
        },
    }


def _money_amount(currency: str, value: int):
    from src.money import Amount as MoneyAmount

    return MoneyAmount(currency=get_currency(currency), value=value, scale=2)


def build_declared_world(
    *,
    environment_id: str,
    domain_id: str,
    tag: str,
    payer: str,
    payee: str,
    amount_minor: int,
    currency: str = "USD",
    hops: tuple[Mapping[str, Any], ...] = CANONICAL_HOPS,
    destination: str | None = None,
    as_of: str = WORLD_AS_OF,
    jurisdiction: str = "US",
    minimum_authority_tier: str = "R3",
    authorization_authorizer: str = "principal/ig002-ops",
) -> LifecycleWorld:
    """Build one deterministic declared world from real sibling records.

    The same declared parameters always build a byte-identical world
    (same identifiers, same instants, same amounts).
    """
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool):
        raise CoreValidationError("amount_minor must be an integer")
    if amount_minor < 1:
        raise CoreValidationError("amount_minor must be positive")
    if not hops:
        raise CoreValidationError("the world requires at least one hop")
    world_data = {
        "tag": tag,
        "environment_id": environment_id,
        "domain_id": domain_id,
        "payer": payer,
        "payee": payee,
        "currency": currency,
        "amount_minor": amount_minor,
    }

    funding = FundingBinding.build(
        (
            FundingSourceRef(
                source_id=f"value/funding/wallet-{tag}",
                cap=IntentAmount(value=amount_minor * 2, scale=2, asset=f"asset/{currency}"),
            ),
        )
    )
    intent_spec = IntentSpec(
        destination_id=payee,
        amount=IntentAmount(value=amount_minor, scale=2, asset=f"asset/{currency}"),
        deadline=WORLD_DEADLINE,
        funding=funding,
        policy_id=f"intent/ig002-policy-{tag}",
        slack_id=f"intent/ig002-slack-{tag}",
    )
    intent = Intent.build(
        object_id=f"intent/ig002-{tag}",
        environment_id=environment_id,
        domain_id=domain_id,
        spec=intent_spec,
        provenance=_provenance(payer),
    )
    intent = intent.authorize(provenance=_provenance(payer))

    policy_spec = PolicySpec.build(
        objectives=(OptimizationObjective.COST,),
        allow_split=False,
        allow_asset_substitution=False,
        allow_route_substitution=False,
    )
    policy = FulfillmentPolicy.build(
        object_id=f"intent/ig002-policy-{tag}",
        environment_id=environment_id,
        domain_id=domain_id,
        spec=policy_spec,
        provenance=_provenance(payer),
    )
    slack_spec = SlackSpec(
        amount_min=IntentAmount(
            value=max(1, amount_minor - 100), scale=2, asset=f"asset/{currency}"
        ),
        amount_max=IntentAmount(
            value=amount_minor + 100, scale=2, asset=f"asset/{currency}"
        ),
        earliest_completion=WORLD_EARLIEST_COMPLETION,
        latest_completion=WORLD_LATEST_COMPLETION,
        max_payment_count=1,
        substitute_assets=(),
    )
    slack = EconomicSlack.build(
        object_id=f"intent/ig002-slack-{tag}",
        environment_id=environment_id,
        domain_id=domain_id,
        spec=slack_spec,
        provenance=_provenance(payer),
    )

    built_hops = tuple(_hop(world_data, hop) for hop in hops)
    return LifecycleWorld(
        environment_id=environment_id,
        domain_id=domain_id,
        payer=payer,
        payee=payee,
        currency=currency,
        amount_minor=amount_minor,
        destination=destination if destination is not None else f"alias/{tag}-payee",
        as_of=as_of,
        jurisdiction=jurisdiction,
        minimum_authority_tier=minimum_authority_tier,
        intent=intent,
        policy=policy,
        slack=slack,
        hops=tuple(entry["offer"] for entry in built_hops),
        reservations={
            entry["offer"].reservation_id: entry["reservation"]
            for entry in built_hops
        },
        fraud_gates={
            entry["offer"].hop_id: entry["fraud_gate"] for entry in built_hops
        },
        compliance_gates={
            entry["offer"].hop_id: entry["compliance_gate"] for entry in built_hops
        },
        payment_legs={
            entry["offer"].hop_id: entry["payment_leg"] for entry in built_hops
        },
        authorization={
            "authorizer": authorization_authorizer,
            "authority_class": "A2",
            "authorized_types": [PAYMENT_SUBMIT_EFFECT_TYPE],
            "valid_from": WORLD_OPENS,
            "valid_until": WORLD_CLOSES,
        },
    )
