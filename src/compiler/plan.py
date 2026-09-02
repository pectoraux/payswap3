"""The durable, versioned fulfillment plan and its sealed lifecycle.

``FulfillmentPlan`` is the compiler's only protocol-visible durable
object: the registry-listed ``payswap/fulfillment-plan/v1`` envelope
plus a sealed payload (:class:`FulfillmentPlanSpec`). The spec carries
the full routing decision with provenance:

- the payment shape (per payment: route hops with exact inputs,
  outputs, FX rates, explicit rounding residuals, fees, latencies);
- exact totals (cost in the intent asset, delivered amount, completion
  instant, reliability, capital-time, liquidity utilization, risk and
  privacy exposure);
- the hard-gate report (routes considered, rejections per gate in
  precedence order, shapes evaluated/rejected/feasible);
- the objective order that ranked the candidates and the runner-up
  digests (constitution invariant 13: material decisions preserve
  provenance);
- ``plan_digest``: the canonical SHA-256 over the semantic projection —
  two compilations of the same input produce the same digest, which is
  the deterministic semantic-equivalence proof.

Lifecycle (the frozen ``Fulfillment: Compile/Recompile/Accept/Reject/
Invalidate`` family): ``COMPILED → ACCEPTED | REJECTED | INVALIDATED``
and ``COMPILED → COMPILED`` via recompile; ``ACCEPTED → INVALIDATED``.
Accepting a plan hands it to the execution domain — it never executes
anything, never posts to a ledger and never grants authority (the
compiler proposes; constitution invariants 3, 14, 18).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256

from ._validation import (
    require_digest,
    require_identifier,
    require_int,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    FULFILLMENT_PLAN_OBJECT_TYPE,
    FULFILLMENT_PLAN_SPEC_TYPE,
    PLAN_TRANSITIONS,
    PlanState,
    RUNNER_UP_DIGEST_COUNT,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_HOP_PLAN_FIELDS = frozenset(
    {
        "hop_id",
        "provider",
        "capability_id",
        "offer_id",
        "quote_id",
        "reservation_id",
        "compliance_assessment_id",
        "source_asset",
        "target_asset",
        "source_scale",
        "target_scale",
        "input_value",
        "output_value",
        "fx_source_currency",
        "fx_target_currency",
        "fx_numerator",
        "fx_denominator",
        "fx_rounding_mode",
        "residual_numerator",
        "residual_denominator",
        "fee_value",
        "price_bps",
        "flat_fee",
        "reliability_bps",
        "latency_seconds",
    }
)

_PAYMENT_PLAN_FIELDS = frozenset(
    {"payment_index", "route_hops", "source_value", "delivered_value"}
)

_PLAN_SPEC_FIELDS = frozenset(
    {
        "type",
        "intent_id",
        "policy_id",
        "slack_id",
        "destination_id",
        "as_of",
        "environment_id",
        "domain_id",
        "intent_amount",
        "payments",
        "totals",
        "gate_report",
        "objective_order",
        "runner_up_digests",
        "plan_digest",
    }
)

_TOTALS_FIELDS = frozenset(
    {
        "total_cost_value",
        "total_source_value",
        "total_delivered_value",
        "amount_distance",
        "completion_epoch",
        "completion",
        "total_latency_seconds",
        "hop_count",
        "payment_count",
        "reliability_numerator",
        "reliability_denominator",
        "capital_time",
        "liquidity_numerator",
        "liquidity_denominator",
        "risk_penalty",
        "privacy_exposure",
    }
)

_GATE_REPORT_FIELDS = frozenset(
    {
        "routes_considered",
        "routes_rejected_per_gate",
        "shapes_evaluated",
        "shapes_rejected_accounting",
        "shapes_feasible",
    }
)


def _require_hop_plan_ints(value: Mapping[str, Any]) -> None:
    require_int("hop_plan.input_value", value["input_value"], minimum=0)
    require_int("hop_plan.output_value", value["output_value"], minimum=0)
    require_int("hop_plan.residual_numerator", value["residual_numerator"])
    require_int(
        "hop_plan.residual_denominator", value["residual_denominator"], minimum=1
    )
    require_int("hop_plan.fee_value", value["fee_value"], minimum=0)
    require_int("hop_plan.price_bps", value["price_bps"], minimum=1, maximum=10000)
    require_int("hop_plan.flat_fee", value["flat_fee"], minimum=0)
    require_int("hop_plan.reliability_bps", value["reliability_bps"], minimum=1,
                maximum=10000)
    require_int("hop_plan.latency_seconds", value["latency_seconds"], minimum=0)
    for name in ("fx_numerator", "fx_denominator"):
        if value[name] is not None:
            require_int(f"hop_plan.{name}", value[name], minimum=1)


@dataclass(frozen=True, slots=True)
class HopPlanSpec:
    """One planned hop: identity, exact amounts, FX and fee records."""

    hop_id: str
    provider: str
    capability_id: str
    offer_id: str
    quote_id: str
    reservation_id: str
    compliance_assessment_id: str
    source_asset: str
    target_asset: str
    source_scale: int
    target_scale: int
    input_value: int
    output_value: int
    fx_source_currency: str | None
    fx_target_currency: str | None
    fx_numerator: int | None
    fx_denominator: int | None
    fx_rounding_mode: str | None
    residual_numerator: int
    residual_denominator: int
    fee_value: int
    price_bps: int
    flat_fee: int
    reliability_bps: int
    latency_seconds: int

    def __post_init__(self) -> None:
        for name in (
            "hop_id",
            "provider",
            "capability_id",
            "offer_id",
            "quote_id",
            "reservation_id",
            "compliance_assessment_id",
            "source_asset",
            "target_asset",
        ):
            require_identifier(f"hop_plan.{name}", getattr(self, name))
        require_int("hop_plan.source_scale", self.source_scale, minimum=0, maximum=18)
        require_int("hop_plan.target_scale", self.target_scale, minimum=0, maximum=18)
        require_int("hop_plan.input_value", self.input_value, minimum=0)
        require_int("hop_plan.output_value", self.output_value, minimum=0)
        for name in ("fx_source_currency", "fx_target_currency", "fx_rounding_mode"):
            if getattr(self, name) is not None:
                require_identifier(f"hop_plan.{name}", getattr(self, name))
        if self.fx_numerator is None or self.fx_denominator is None:
            if self.fx_numerator is not None or self.fx_denominator is not None:
                raise CoreValidationError(
                    "hop_plan fx numerator and denominator must be present together"
                )
            if self.fx_source_currency is not None or self.fx_target_currency is not None:
                raise CoreValidationError(
                    "hop_plan fx currencies must be None for a passthrough hop"
                )
        else:
            require_int("hop_plan.fx_numerator", self.fx_numerator, minimum=1)
            require_int("hop_plan.fx_denominator", self.fx_denominator, minimum=1)
            require_identifier(
                "hop_plan.fx_source_currency", self.fx_source_currency or ""
            )
            require_identifier(
                "hop_plan.fx_target_currency", self.fx_target_currency or ""
            )
            require_identifier(
                "hop_plan.fx_rounding_mode", self.fx_rounding_mode or ""
            )
        require_int("hop_plan.residual_numerator", self.residual_numerator)
        require_int(
            "hop_plan.residual_denominator", self.residual_denominator, minimum=1
        )
        require_int("hop_plan.fee_value", self.fee_value, minimum=0)
        require_int("hop_plan.price_bps", self.price_bps, minimum=1, maximum=10000)
        require_int("hop_plan.flat_fee", self.flat_fee, minimum=0)
        require_int(
            "hop_plan.reliability_bps", self.reliability_bps, minimum=1, maximum=10000
        )
        require_int("hop_plan.latency_seconds", self.latency_seconds, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop_id": self.hop_id,
            "provider": self.provider,
            "capability_id": self.capability_id,
            "offer_id": self.offer_id,
            "quote_id": self.quote_id,
            "reservation_id": self.reservation_id,
            "compliance_assessment_id": self.compliance_assessment_id,
            "source_asset": self.source_asset,
            "target_asset": self.target_asset,
            "source_scale": self.source_scale,
            "target_scale": self.target_scale,
            "input_value": self.input_value,
            "output_value": self.output_value,
            "fx_source_currency": self.fx_source_currency,
            "fx_target_currency": self.fx_target_currency,
            "fx_numerator": self.fx_numerator,
            "fx_denominator": self.fx_denominator,
            "fx_rounding_mode": self.fx_rounding_mode,
            "residual_numerator": self.residual_numerator,
            "residual_denominator": self.residual_denominator,
            "fee_value": self.fee_value,
            "price_bps": self.price_bps,
            "flat_fee": self.flat_fee,
            "reliability_bps": self.reliability_bps,
            "latency_seconds": self.latency_seconds,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HopPlanSpec":
        strict_fields("hop plan", value, _HOP_PLAN_FIELDS)
        _require_hop_plan_ints(value)
        return cls(**{field: value[field] for field in _HOP_PLAN_FIELDS})


@dataclass(frozen=True, slots=True)
class PaymentPlanSpec:
    """One planned payment: its route hops, source and delivered amounts."""

    payment_index: int
    route_hops: tuple[HopPlanSpec, ...]
    source_value: int
    delivered_value: int

    def __post_init__(self) -> None:
        require_int("payment_plan.payment_index", self.payment_index, minimum=1)
        if not isinstance(self.route_hops, tuple) or not self.route_hops:
            raise CoreValidationError("payment_plan.route_hops must be a non-empty tuple")
        for hop in self.route_hops:
            if not isinstance(hop, HopPlanSpec):
                raise CoreValidationError(
                    "payment_plan.route_hops entries must be HopPlanSpec"
                )
        require_int("payment_plan.source_value", self.source_value, minimum=1)
        require_int("payment_plan.delivered_value", self.delivered_value, minimum=0)
        hop_ids = [hop.hop_id for hop in self.route_hops]
        if len(set(hop_ids)) != len(hop_ids):
            raise CoreValidationError("payment_plan.route_hops must not repeat a hop")

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_index": self.payment_index,
            "route_hops": [hop.to_dict() for hop in self.route_hops],
            "source_value": self.source_value,
            "delivered_value": self.delivered_value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PaymentPlanSpec":
        strict_fields("payment plan", value, _PAYMENT_PLAN_FIELDS)
        route_hops = value["route_hops"]
        if not isinstance(route_hops, list):
            raise CoreValidationError(
                "payment_plan.route_hops must deserialize from an array"
            )
        return cls(
            payment_index=value["payment_index"],
            route_hops=tuple(HopPlanSpec.from_dict(hop) for hop in route_hops),
            source_value=value["source_value"],
            delivered_value=value["delivered_value"],
        )


def _validate_totals(value: Mapping[str, Any]) -> None:
    strict_fields("plan totals", value, _TOTALS_FIELDS)
    for field in (
        "total_cost_value",
        "total_source_value",
        "total_delivered_value",
        "amount_distance",
        "completion_epoch",
        "total_latency_seconds",
        "hop_count",
        "payment_count",
        "reliability_numerator",
        "reliability_denominator",
        "capital_time",
        "liquidity_numerator",
        "liquidity_denominator",
        "risk_penalty",
        "privacy_exposure",
    ):
        require_int(f"totals.{field}", value[field], minimum=0)
    require_int(
        "totals.reliability_denominator", value["reliability_denominator"], minimum=1
    )
    require_int(
        "totals.liquidity_denominator", value["liquidity_denominator"], minimum=1
    )
    require_int("totals.payment_count", value["payment_count"], minimum=1)
    require_int("totals.hop_count", value["hop_count"], minimum=1)
    require_utc_timestamp("totals.completion", value["completion"])


def _validate_gate_report(value: Mapping[str, Any]) -> None:
    strict_fields("gate report", value, _GATE_REPORT_FIELDS)
    require_int("gate_report.routes_considered", value["routes_considered"], minimum=0)
    require_int("gate_report.shapes_evaluated", value["shapes_evaluated"], minimum=0)
    require_int(
        "gate_report.shapes_rejected_accounting",
        value["shapes_rejected_accounting"],
        minimum=0,
    )
    require_int("gate_report.shapes_feasible", value["shapes_feasible"], minimum=0)
    rejections = value["routes_rejected_per_gate"]
    if not isinstance(rejections, Mapping):
        raise CoreValidationError("gate_report.routes_rejected_per_gate must be an object")
    for gate, count in rejections.items():
        if gate not in {
            "compliance",
            "authority",
            "settlement",
            "safety",
            "accounting",
        }:
            raise CoreValidationError(f"gate_report names unknown gate {gate!r}")
        require_int(f"gate_report.rejections[{gate}]", count, minimum=0)


@dataclass(frozen=True, slots=True)
class FulfillmentPlanSpec:
    """The sealed payload of a fulfillment plan: the full decision record."""

    intent_id: str
    policy_id: str
    slack_id: str
    destination_id: str
    as_of: str
    environment_id: str
    domain_id: str
    intent_amount: dict[str, Any]
    payments: tuple[PaymentPlanSpec, ...]
    totals: dict[str, Any]
    gate_report: dict[str, Any]
    objective_order: tuple[str, ...]
    runner_up_digests: tuple[str, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        for name in (
            "intent_id",
            "policy_id",
            "slack_id",
            "destination_id",
            "environment_id",
            "domain_id",
        ):
            require_identifier(f"plan.{name}", getattr(self, name))
        require_utc_timestamp("plan.as_of", self.as_of)
        if not isinstance(self.intent_amount, Mapping) or set(self.intent_amount) != {
            "value",
            "scale",
            "asset",
        }:
            raise CoreValidationError(
                "plan.intent_amount must be {value, scale, asset}"
            )
        require_int(
            "plan.intent_amount.value", self.intent_amount["value"], minimum=1
        )
        require_int(
            "plan.intent_amount.scale", self.intent_amount["scale"], minimum=0,
            maximum=18,
        )
        require_identifier("plan.intent_amount.asset", self.intent_amount["asset"])
        if not isinstance(self.payments, tuple) or not self.payments:
            raise CoreValidationError("plan.payments must be a non-empty tuple")
        for payment in self.payments:
            if not isinstance(payment, PaymentPlanSpec):
                raise CoreValidationError("plan.payments entries must be PaymentPlanSpec")
        indices = [payment.payment_index for payment in self.payments]
        if indices != list(range(1, len(indices) + 1)):
            raise CoreValidationError("plan.payments must be indexed 1..N in order")
        if not isinstance(self.totals, Mapping):
            raise CoreValidationError("plan.totals must be an object")
        _validate_totals(self.totals)
        if not isinstance(self.gate_report, Mapping):
            raise CoreValidationError("plan.gate_report must be an object")
        _validate_gate_report(self.gate_report)
        if not isinstance(self.objective_order, tuple) or not self.objective_order:
            raise CoreValidationError("plan.objective_order must be a non-empty tuple")
        for objective in self.objective_order:
            require_identifier("plan.objective_order entry", objective)
        if not isinstance(self.runner_up_digests, tuple):
            raise CoreValidationError("plan.runner_up_digests must be a tuple")
        for digest in self.runner_up_digests:
            require_digest("plan.runner_up_digest", digest)
        if len(self.runner_up_digests) > RUNNER_UP_DIGEST_COUNT:
            raise CoreValidationError(
                f"plan.runner_up_digests is bounded by {RUNNER_UP_DIGEST_COUNT}"
            )
        require_digest("plan.plan_digest", self.plan_digest)

    def semantic_projection(self) -> dict[str, Any]:
        """The digest projection: everything the plan MEANS, nothing about
        which envelope version carries it."""
        return {
            "intent_id": self.intent_id,
            "destination_id": self.destination_id,
            "as_of": self.as_of,
            "payments": [payment.to_dict() for payment in self.payments],
            "totals": dict(self.totals),
            "gate_report": {
                **self.gate_report,
                "routes_rejected_per_gate": dict(
                    self.gate_report["routes_rejected_per_gate"]
                ),
            },
            "objective_order": list(self.objective_order),
            "runner_up_digests": list(self.runner_up_digests),
        }

    def recompute_plan_digest(self) -> str:
        return canonical_sha256(self.semantic_projection())

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": FULFILLMENT_PLAN_SPEC_TYPE,
            "intent_id": self.intent_id,
            "policy_id": self.policy_id,
            "slack_id": self.slack_id,
            "destination_id": self.destination_id,
            "as_of": self.as_of,
            "environment_id": self.environment_id,
            "domain_id": self.domain_id,
            "intent_amount": dict(self.intent_amount),
            "payments": [payment.to_dict() for payment in self.payments],
            "totals": dict(self.totals),
            "gate_report": {
                **self.gate_report,
                "routes_rejected_per_gate": dict(
                    self.gate_report["routes_rejected_per_gate"]
                ),
            },
            "objective_order": list(self.objective_order),
            "runner_up_digests": list(self.runner_up_digests),
            "plan_digest": self.plan_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FulfillmentPlanSpec":
        strict_fields("fulfillment plan spec", value, _PLAN_SPEC_FIELDS)
        if value["type"] != FULFILLMENT_PLAN_SPEC_TYPE:
            raise CoreValidationError(
                f"fulfillment plan spec type must be {FULFILLMENT_PLAN_SPEC_TYPE!r}; "
                f"got {value['type']!r}"
            )
        payments = value["payments"]
        if not isinstance(payments, list):
            raise CoreValidationError("plan.payments must deserialize from an array")
        objective_order = value["objective_order"]
        if not isinstance(objective_order, list):
            raise CoreValidationError(
                "plan.objective_order must deserialize from an array"
            )
        runner_up_digests = value["runner_up_digests"]
        if not isinstance(runner_up_digests, list):
            raise CoreValidationError(
                "plan.runner_up_digests must deserialize from an array"
            )
        spec = cls(
            intent_id=value["intent_id"],
            policy_id=value["policy_id"],
            slack_id=value["slack_id"],
            destination_id=value["destination_id"],
            as_of=value["as_of"],
            environment_id=value["environment_id"],
            domain_id=value["domain_id"],
            intent_amount=dict(value["intent_amount"]),
            payments=tuple(PaymentPlanSpec.from_dict(payment) for payment in payments),
            totals=dict(value["totals"]),
            gate_report={
                **value["gate_report"],
                "routes_rejected_per_gate": dict(
                    value["gate_report"]["routes_rejected_per_gate"]
                ),
            },
            objective_order=tuple(objective_order),
            runner_up_digests=tuple(runner_up_digests),
            plan_digest=value["plan_digest"],
        )
        # Fail closed on self-inconsistent specs: the recorded digest must
        # commit to the payload's own semantic projection, so a tampered
        # spec fails deserialization even when the composite seal is not
        # available to check yet (defense in depth alongside the seal).
        if spec.plan_digest != spec.recompute_plan_digest():
            raise CoreValidationError(
                "fulfillment plan spec digest does not commit to its own semantic "
                "projection; the payload is tampered or truncated"
            )
        return spec

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "FulfillmentPlanSpec":
        from src.core.serialization import loads_canonical

        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("plan spec JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class FulfillmentPlan:
    """Durable, versioned fulfillment plan (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: FulfillmentPlanSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FULFILLMENT_PLAN_OBJECT_TYPE
    STATE_TYPE = PlanState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("plan envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, FulfillmentPlanSpec):
            raise CoreValidationError("plan spec must be a FulfillmentPlanSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != FULFILLMENT_PLAN_OBJECT_TYPE:
            raise CoreValidationError(
                f"plan object_type must be {FULFILLMENT_PLAN_OBJECT_TYPE!r}"
            )
        try:
            PlanState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown fulfillment plan state: {self.envelope.state!r}"
            ) from exc
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @classmethod
    def build(
        cls,
        *,
        object_id: str,
        environment_id: str,
        domain_id: str,
        spec: FulfillmentPlanSpec,
        provenance: Provenance,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> "FulfillmentPlan":
        if not isinstance(spec, FulfillmentPlanSpec):
            raise CoreValidationError("plan spec must be a FulfillmentPlanSpec")
        envelope = build_domain_envelope(
            object_id=object_id,
            object_type=FULFILLMENT_PLAN_OBJECT_TYPE,
            state=PlanState.COMPILED.value,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        return cls(
            envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> PlanState:
        return PlanState(self.envelope.state)

    def _command(
        self,
        name: str,
        *,
        provenance: Provenance,
        spec: FulfillmentPlanSpec | None = None,
    ) -> "FulfillmentPlan":
        current = self.state
        transitions = PLAN_TRANSITIONS[name]
        if current not in transitions:
            raise CoreValidationError(
                f"fulfillment plan command {name!r} is not allowed from state "
                f"{current.value}"
            )
        next_spec = self.spec if spec is None else spec
        envelope = advance_envelope(
            self.envelope,
            state=transitions[current].value,
            provenance=provenance,
        )
        return type(self)(
            envelope=envelope,
            spec=next_spec,
            integrity_hash=seal_composite(envelope, next_spec),
        )

    def accept(self, *, provenance: Provenance) -> "FulfillmentPlan":
        return self._command("accept", provenance=provenance)

    def reject(self, *, provenance: Provenance) -> "FulfillmentPlan":
        return self._command("reject", provenance=provenance)

    def invalidate(self, *, provenance: Provenance) -> "FulfillmentPlan":
        return self._command("invalidate", provenance=provenance)

    def recompile(
        self, *, spec: FulfillmentPlanSpec, provenance: Provenance
    ) -> "FulfillmentPlan":
        if not isinstance(spec, FulfillmentPlanSpec):
            raise CoreValidationError("recompile requires a FulfillmentPlanSpec")
        return self._command("recompile", provenance=provenance, spec=spec)

    @classmethod
    def advance_version(
        cls,
        envelope: ObjectEnvelope,
        spec: FulfillmentPlanSpec,
        *,
        command: str,
        provenance: Provenance,
    ) -> "FulfillmentPlan":
        """Advance the kernel-store envelope under one lifecycle command.

        Validates the transition from the envelope's current state, then
        produces the next sealed version. Used by the kernel handlers
        (which hold the store envelope, not a domain object).
        """
        try:
            current = PlanState(envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown fulfillment plan state: {envelope.state!r}"
            ) from exc
        transitions = PLAN_TRANSITIONS[command]
        if current not in transitions:
            raise CoreValidationError(
                f"fulfillment plan command {command!r} is not allowed from state "
                f"{current.value}"
            )
        next_envelope = advance_envelope(
            envelope,
            state=transitions[current].value,
            provenance=provenance,
        )
        return cls(
            envelope=next_envelope,
            spec=spec,
            integrity_hash=seal_composite(next_envelope, spec),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FulfillmentPlan":
        envelope, payload = decode_composite(
            value,
            expected_object_type=FULFILLMENT_PLAN_OBJECT_TYPE,
            state_type=PlanState,
        )
        spec = FulfillmentPlanSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "FulfillmentPlan":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=FULFILLMENT_PLAN_OBJECT_TYPE,
            state_type=PlanState,
        )
        spec = FulfillmentPlanSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)
