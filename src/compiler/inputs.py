"""Typed, versioned compiler inputs: route hop offers and compile requests.

The compiler consumes the merged sibling domains (WORK-006 money,
WORK-008 intent, WORK-009 capability, WORK-010 market, WORK-011
liquidity, WORK-012 reservation, WORK-017 safety) through their public
contracts ONLY, as declared input data:

- a :class:`RouteHopOffer` is one routable edge: the projection of one
  real (liquidity offer, firm quote, capability, reservation, compliance
  assessment, optional fraud decision) tuple into the data the routing
  engine needs. Every closed vocabulary (capability state, reservation
  state, compliance verdict, fraud decision state, authority tier) is
  the OWNING sibling domain's enum, parsed fail-closed here — the
  compiler never redefines a sibling vocabulary;
- a :class:`CompilationRequest` is the compile-time context (explicit
  ``as_of`` instant, required jurisdiction, minimum authority tier);
- a :class:`CompilationInput` bundles one request with the intent, the
  fulfillment policy, the economic slack (all real intent-domain durable
  objects, re-verified through their own trusted deserialization) and
  the hop offers.

All three are canonical-JSON serializable value objects with
byte-stable round-trips. They are inputs, not authorities: the compiler
derives nothing from them beyond deterministic arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.capability import AuthorityTier, CapabilityState
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical
from src.intent import EconomicSlack, FulfillmentPolicy, Intent
from src.liquidity import Corridor
from src.market import MAX_PRICE_BPS, MIN_PRICE_BPS
from src.money import FxRate
from src.reservation import ReservationState
from src.safety import ComplianceVerdict, FraudDecisionState

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    require_utc_window,
    strict_fields,
)
from .contracts import (
    BPS_DENOMINATOR,
    COMPILATION_INPUT_TYPE,
    COMPILATION_REQUEST_TYPE,
    ROUTE_HOP_OFFER_TYPE,
)

_HOP_OFFER_FIELDS = frozenset(
    {
        "type",
        "hop_id",
        "environment_id",
        "domain_id",
        "provider",
        "capability_id",
        "capability_state",
        "capability_protocol_version",
        "authority_tier",
        "jurisdictions",
        "offer_id",
        "quote_id",
        "reservation_id",
        "reservation_state",
        "reservation_opens_at",
        "reservation_closes_at",
        "compliance_assessment_id",
        "compliance_verdict",
        "fraud_decision_state",
        "corridor",
        "fx_rate",
        "source_scale",
        "target_scale",
        "amount_min",
        "amount_max",
        "capacity",
        "price_bps",
        "flat_fee",
        "reliability_bps",
        "latency_seconds",
        "window_opens_at",
        "window_closes_at",
        "quote_valid_from",
        "quote_valid_until",
    }
)

_REQUEST_FIELDS = frozenset(
    {
        "type",
        "environment_id",
        "domain_id",
        "as_of",
        "required_jurisdiction",
        "minimum_authority_tier",
    }
)

_INPUT_FIELDS = frozenset(
    {
        "type",
        "request",
        "intent",
        "policy",
        "slack",
        "hop_offers",
    }
)


def _require_jurisdictions(name: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    if not value:
        raise CoreValidationError(f"{name} must not be empty")
    items = [require_identifier(f"{name} entry", item) for item in value]
    if len(set(items)) != len(items):
        raise CoreValidationError(f"{name} must not repeat a jurisdiction")
    return tuple(items)


@dataclass(frozen=True, slots=True)
class RouteHopOffer:
    """One routable hop declared from real sibling-domain data.

    Consistency rules (fail closed at construction):

    - ``fx_rate`` is ``None`` only for a same-asset passthrough corridor
      (``source_asset == target_asset``) whose scales match;
    - with an FX rate, the corridor assets must be exactly
      ``asset/<source currency>`` and ``asset/<target currency>`` and the
      scales must be the money authority's canonical scales (the same
      rule the liquidity domain enforces for capacity);
    - ``price_bps`` respects the market domain's frozen price band;
    - ``reliability_bps`` is a declared basis-point score on the closed
      1..10000 scale (declared data with provenance, never a guess);
    - all closed vocabularies parse through the owning sibling enums.
    """

    hop_id: str
    environment_id: str
    domain_id: str
    provider: str
    capability_id: str
    capability_state: str
    capability_protocol_version: str
    authority_tier: str
    jurisdictions: tuple[str, ...]
    offer_id: str
    quote_id: str
    reservation_id: str
    reservation_state: str
    reservation_opens_at: str
    reservation_closes_at: str
    compliance_assessment_id: str
    compliance_verdict: str
    fraud_decision_state: str | None
    corridor: Corridor
    fx_rate: FxRate | None
    source_scale: int
    target_scale: int
    amount_min: int
    amount_max: int
    capacity: int
    price_bps: int
    flat_fee: int
    reliability_bps: int
    latency_seconds: int
    window_opens_at: str
    window_closes_at: str
    quote_valid_from: str
    quote_valid_until: str

    def __post_init__(self) -> None:
        require_identifier("hop.hop_id", self.hop_id)
        require_identifier("hop.environment_id", self.environment_id)
        require_identifier("hop.domain_id", self.domain_id)
        require_identifier("hop.provider", self.provider)
        require_identifier("hop.capability_id", self.capability_id)
        parse_enum("hop capability_state", CapabilityState, self.capability_state)
        require_text("hop.capability_protocol_version", self.capability_protocol_version)
        parse_enum("hop authority_tier", AuthorityTier, self.authority_tier)
        _require_jurisdictions("hop.jurisdictions", self.jurisdictions)
        require_identifier("hop.offer_id", self.offer_id)
        require_identifier("hop.quote_id", self.quote_id)
        require_identifier("hop.reservation_id", self.reservation_id)
        parse_enum("hop reservation_state", ReservationState, self.reservation_state)
        require_utc_timestamp("hop.reservation_opens_at", self.reservation_opens_at)
        require_utc_timestamp("hop.reservation_closes_at", self.reservation_closes_at)
        require_utc_window(
            "hop.reservation", self.reservation_opens_at, self.reservation_closes_at
        )
        require_identifier(
            "hop.compliance_assessment_id", self.compliance_assessment_id
        )
        parse_enum("hop compliance_verdict", ComplianceVerdict, self.compliance_verdict)
        if self.fraud_decision_state is not None:
            parse_enum(
                "hop fraud_decision_state",
                FraudDecisionState,
                self.fraud_decision_state,
            )
        if not isinstance(self.corridor, Corridor):
            raise CoreValidationError("hop.corridor must be a Corridor")
        if not isinstance(self.fx_rate, FxRate) and self.fx_rate is not None:
            raise CoreValidationError("hop.fx_rate must be an FxRate or None")
        require_int("hop.source_scale", self.source_scale, minimum=0, maximum=18)
        require_int("hop.target_scale", self.target_scale, minimum=0, maximum=18)
        self._require_corridor_consistency()
        require_int("hop.amount_min", self.amount_min, minimum=1)
        require_int("hop.amount_max", self.amount_max, minimum=1)
        if self.amount_max < self.amount_min:
            raise CoreValidationError("hop.amount_max must not be below amount_min")
        require_int("hop.capacity", self.capacity, minimum=1)
        require_int(
            "hop.price_bps", self.price_bps, minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS
        )
        require_int("hop.flat_fee", self.flat_fee, minimum=0)
        require_int(
            "hop.reliability_bps",
            self.reliability_bps,
            minimum=1,
            maximum=BPS_DENOMINATOR,
        )
        require_int("hop.latency_seconds", self.latency_seconds, minimum=0)
        require_utc_timestamp("hop.window_opens_at", self.window_opens_at)
        require_utc_timestamp("hop.window_closes_at", self.window_closes_at)
        require_utc_window("hop.window", self.window_opens_at, self.window_closes_at)
        require_utc_timestamp("hop.quote_valid_from", self.quote_valid_from)
        require_utc_timestamp("hop.quote_valid_until", self.quote_valid_until)
        require_utc_window(
            "hop.quote_validity", self.quote_valid_from, self.quote_valid_until
        )

    def _require_corridor_consistency(self) -> None:
        if self.fx_rate is None:
            if self.corridor.source_asset != self.corridor.target_asset:
                raise CoreValidationError(
                    "a hop without an fx_rate must be a same-asset passthrough "
                    f"corridor; got {self.corridor.corridor_id}"
                )
            if self.source_scale != self.target_scale:
                raise CoreValidationError(
                    "a same-asset passthrough hop must declare matching scales; "
                    f"got {self.source_scale} vs {self.target_scale}"
                )
            return
        expected_source = f"asset/{self.fx_rate.source.code}"
        expected_target = f"asset/{self.fx_rate.target.code}"
        if self.corridor.source_asset != expected_source:
            raise CoreValidationError(
                f"hop corridor source asset must be {expected_source!r} for the "
                f"declared fx rate; got {self.corridor.source_asset!r}"
            )
        if self.corridor.target_asset != expected_target:
            raise CoreValidationError(
                f"hop corridor target asset must be {expected_target!r} for the "
                f"declared fx rate; got {self.corridor.target_asset!r}"
            )
        if self.source_scale != self.fx_rate.source.scale:
            raise CoreValidationError(
                "hop source_scale must be the money authority's canonical scale "
                f"{self.fx_rate.source.scale} for {self.fx_rate.source.code}"
            )
        if self.target_scale != self.fx_rate.target.scale:
            raise CoreValidationError(
                "hop target_scale must be the money authority's canonical scale "
                f"{self.fx_rate.target.scale} for {self.fx_rate.target.code}"
            )

    @property
    def source_asset(self) -> str:
        return self.corridor.source_asset

    @property
    def target_asset(self) -> str:
        return self.corridor.target_asset

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": ROUTE_HOP_OFFER_TYPE,
            "hop_id": self.hop_id,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "provider": self.provider,
            "capability_id": self.capability_id,
            "capability_state": self.capability_state,
            "capability_protocol_version": self.capability_protocol_version,
            "authority_tier": self.authority_tier,
            "jurisdictions": list(self.jurisdictions),
            "offer_id": self.offer_id,
            "quote_id": self.quote_id,
            "reservation_id": self.reservation_id,
            "reservation_state": self.reservation_state,
            "reservation_opens_at": self.reservation_opens_at,
            "reservation_closes_at": self.reservation_closes_at,
            "compliance_assessment_id": self.compliance_assessment_id,
            "compliance_verdict": self.compliance_verdict,
            "fraud_decision_state": self.fraud_decision_state,
            "corridor": self.corridor.to_dict(),
            "fx_rate": None if self.fx_rate is None else self.fx_rate.to_dict(),
            "source_scale": self.source_scale,
            "target_scale": self.target_scale,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "capacity": self.capacity,
            "price_bps": self.price_bps,
            "flat_fee": self.flat_fee,
            "reliability_bps": self.reliability_bps,
            "latency_seconds": self.latency_seconds,
            "window_opens_at": self.window_opens_at,
            "window_closes_at": self.window_closes_at,
            "quote_valid_from": self.quote_valid_from,
            "quote_valid_until": self.quote_valid_until,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RouteHopOffer":
        strict_fields("route hop offer", value, _HOP_OFFER_FIELDS)
        if value["type"] != ROUTE_HOP_OFFER_TYPE:
            raise CoreValidationError(
                f"route hop offer type must be {ROUTE_HOP_OFFER_TYPE!r}; "
                f"got {value['type']!r}"
            )
        jurisdictions = value["jurisdictions"]
        if not isinstance(jurisdictions, list):
            raise CoreValidationError("hop.jurisdictions must deserialize from an array")
        fx_rate = value["fx_rate"]
        if fx_rate is not None:
            fx_rate = FxRate.from_dict(fx_rate)
        return cls(
            hop_id=value["hop_id"],
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            provider=value["provider"],
            capability_id=value["capability_id"],
            capability_state=value["capability_state"],
            capability_protocol_version=value["capability_protocol_version"],
            authority_tier=value["authority_tier"],
            jurisdictions=tuple(jurisdictions),
            offer_id=value["offer_id"],
            quote_id=value["quote_id"],
            reservation_id=value["reservation_id"],
            reservation_state=value["reservation_state"],
            reservation_opens_at=value["reservation_opens_at"],
            reservation_closes_at=value["reservation_closes_at"],
            compliance_assessment_id=value["compliance_assessment_id"],
            compliance_verdict=value["compliance_verdict"],
            fraud_decision_state=value["fraud_decision_state"],
            corridor=Corridor.from_dict(value["corridor"]),
            fx_rate=fx_rate,
            source_scale=value["source_scale"],
            target_scale=value["target_scale"],
            amount_min=value["amount_min"],
            amount_max=value["amount_max"],
            capacity=value["capacity"],
            price_bps=value["price_bps"],
            flat_fee=value["flat_fee"],
            reliability_bps=value["reliability_bps"],
            latency_seconds=value["latency_seconds"],
            window_opens_at=value["window_opens_at"],
            window_closes_at=value["window_closes_at"],
            quote_valid_from=value["quote_valid_from"],
            quote_valid_until=value["quote_valid_until"],
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "RouteHopOffer":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("route hop offer JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class CompilationRequest:
    """Compile-time context: explicit instant, jurisdiction and authority floor."""

    environment_id: str
    domain_id: str
    as_of: str
    required_jurisdiction: str
    minimum_authority_tier: str

    def __post_init__(self) -> None:
        require_identifier("request.environment_id", self.environment_id)
        require_identifier("request.domain_id", self.domain_id)
        require_utc_timestamp("request.as_of", self.as_of)
        require_identifier("request.required_jurisdiction", self.required_jurisdiction)
        parse_enum(
            "request minimum_authority_tier", AuthorityTier, self.minimum_authority_tier
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": COMPILATION_REQUEST_TYPE,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "as_of": self.as_of,
            "required_jurisdiction": self.required_jurisdiction,
            "minimum_authority_tier": self.minimum_authority_tier,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CompilationRequest":
        strict_fields("compilation request", value, _REQUEST_FIELDS)
        if value["type"] != COMPILATION_REQUEST_TYPE:
            raise CoreValidationError(
                f"compilation request type must be {COMPILATION_REQUEST_TYPE!r}; "
                f"got {value['type']!r}"
            )
        return cls(
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            as_of=value["as_of"],
            required_jurisdiction=value["required_jurisdiction"],
            minimum_authority_tier=value["minimum_authority_tier"],
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "CompilationRequest":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("compilation request JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class CompilationInput:
    """The full, typed input set of one compilation.

    The bundle embeds the real intent-domain durable objects and the hop
    offers; deserialization runs every embedded object through its own
    trusted path (envelope integrity + domain seal), so a tampered input
    fails closed here, before any routing decision is made.
    """

    request: CompilationRequest
    intent: Intent
    policy: FulfillmentPolicy
    slack: EconomicSlack
    hop_offers: tuple[RouteHopOffer, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, CompilationRequest):
            raise CoreValidationError("input.request must be a CompilationRequest")
        if not isinstance(self.intent, Intent):
            raise CoreValidationError("input.intent must be an Intent")
        if not isinstance(self.policy, FulfillmentPolicy):
            raise CoreValidationError("input.policy must be a FulfillmentPolicy")
        if not isinstance(self.slack, EconomicSlack):
            raise CoreValidationError("input.slack must be an EconomicSlack")
        if not isinstance(self.hop_offers, tuple):
            raise CoreValidationError("input.hop_offers must be a tuple")
        hop_ids = [offer.hop_id for offer in self.hop_offers]
        if len(set(hop_ids)) != len(hop_ids):
            raise CoreValidationError("input.hop_offers must not repeat a hop_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": COMPILATION_INPUT_TYPE,
            "request": self.request.to_dict(),
            "intent": self.intent.to_dict(),
            "policy": self.policy.to_dict(),
            "slack": self.slack.to_dict(),
            "hop_offers": [offer.to_dict() for offer in self.hop_offers],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CompilationInput":
        strict_fields("compilation input", value, _INPUT_FIELDS)
        if value["type"] != COMPILATION_INPUT_TYPE:
            raise CoreValidationError(
                f"compilation input type must be {COMPILATION_INPUT_TYPE!r}; "
                f"got {value['type']!r}"
            )
        hop_offers = value["hop_offers"]
        if not isinstance(hop_offers, list):
            raise CoreValidationError("input.hop_offers must deserialize from an array")
        return cls(
            request=CompilationRequest.from_dict(value["request"]),
            intent=Intent.from_dict(value["intent"]),
            policy=FulfillmentPolicy.from_dict(value["policy"]),
            slack=EconomicSlack.from_dict(value["slack"]),
            hop_offers=tuple(RouteHopOffer.from_dict(offer) for offer in hop_offers),
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "CompilationInput":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("compilation input JSON must decode to an object")
        return cls.from_dict(decoded)
