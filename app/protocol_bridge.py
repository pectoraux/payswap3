from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

from src.core import Provenance
from src.execution import ExecutionStepSpec, make_plan_record, make_step_record, step_object_id
from src.intent import (
    Amount,
    EconomicSlack,
    FulfillmentPolicy,
    FundingBinding,
    FundingSourceRef,
    Intent,
    IntentSpec,
    OptimizationObjective,
    PolicySpec,
    SlackSpec,
)


POLICY_OBJECTIVES = {
    "balanced": (
        OptimizationObjective.RELIABILITY,
        OptimizationObjective.TIME,
        OptimizationObjective.COST,
        OptimizationObjective.RISK,
        OptimizationObjective.ROUTE,
    ),
    "fast": (
        OptimizationObjective.TIME,
        OptimizationObjective.RELIABILITY,
        OptimizationObjective.COST,
        OptimizationObjective.ROUTE,
        OptimizationObjective.RISK,
    ),
    "conservative": (
        OptimizationObjective.RELIABILITY,
        OptimizationObjective.RISK,
        OptimizationObjective.COST,
        OptimizationObjective.TIME,
        OptimizationObjective.ROUTE,
    ),
    "resilient": (
        OptimizationObjective.RELIABILITY,
        OptimizationObjective.RISK,
        OptimizationObjective.TIME,
        OptimizationObjective.COST,
        OptimizationObjective.ROUTE,
    ),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_amount(value: str, asset: str) -> Amount:
    text = value.strip()
    try:
        decimal_value = Decimal(text)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("The selected workflow contains an invalid amount.") from exc
    if not decimal_value.is_finite() or decimal_value <= 0:
        raise ValueError("The selected workflow contains an invalid amount.")
    scale = max(0, -decimal_value.as_tuple().exponent)
    if scale > 18:
        raise ValueError("Amount precision exceeds the protocol limit.")
    integer_value = int(decimal_value * (10 ** scale))
    if integer_value < 1:
        raise ValueError("The selected workflow contains an invalid amount.")
    return Amount(value=integer_value, scale=scale, asset=asset.upper())


def _require_utc_timestamp(value: str) -> str:
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Choose a valid deadline.") from exc
    # HTML datetime-local values are intentionally timezone-naive. The form
    # labels them as UTC, so normalize a naive value as UTC at the product edge.
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _provenance(*, username: str, recorded_at: str, source: str = "product-workflow") -> Provenance:
    return Provenance(
        issuer=username,
        source=source,
        recorded_at=recorded_at,
        evidence_refs=(),
    )


def build_protocol_binding(*, task_id: int, owner_id: int, username: str, kind: str, payload: dict[str, Any], selected_option: str) -> dict[str, Any]:
    """Translate a product decision into governed protocol declarations."""
    objectives = POLICY_OBJECTIVES.get(selected_option)
    if objectives is None:
        raise ValueError("Choose a supported workflow option before binding it.")

    amount = _parse_amount(payload["amount"], payload["asset"])
    deadline = _require_utc_timestamp(payload["deadline"])
    recorded_at = _utc_now()
    if datetime.fromisoformat(deadline.replace("Z", "+00:00")) <= datetime.fromisoformat(recorded_at.replace("Z", "+00:00")):
        raise ValueError("The protocol draft cannot use a deadline that has already passed.")

    object_base = f"product-task-{task_id}"
    correlation_id = f"product-task:{task_id}"
    policy = FulfillmentPolicy.build(
        object_id=f"{object_base}-policy",
        environment_id="sandbox",
        domain_id="product",
        spec=PolicySpec.build(
            objectives=objectives,
            allow_split=False,
            allow_asset_substitution=False,
            allow_route_substitution=True,
        ),
        provenance=_provenance(username=username, recorded_at=recorded_at),
        correlation_id=correlation_id,
        causation_id=f"task:{task_id}:decision",
    )
    slack = EconomicSlack.build(
        object_id=f"{object_base}-slack",
        environment_id="sandbox",
        domain_id="product",
        spec=SlackSpec(
            amount_min=amount,
            amount_max=amount,
            earliest_completion=recorded_at,
            latest_completion=deadline,
            max_payment_count=1,
            substitute_assets=(),
        ),
        provenance=_provenance(username=username, recorded_at=recorded_at),
        correlation_id=correlation_id,
        causation_id=f"task:{task_id}:decision",
    )
    intent = Intent.build(
        object_id=f"{object_base}-intent",
        environment_id="sandbox",
        domain_id="product",
        spec=IntentSpec(
            destination_id=f"product-destination:{task_id}",
            amount=amount,
            deadline=deadline,
            funding=FundingBinding.build(
                [FundingSourceRef(source_id=f"product:user:{owner_id}:default", cap=amount)]
            ),
            policy_id=policy.object_id,
            slack_id=slack.object_id,
        ),
        provenance=_provenance(username=username, recorded_at=recorded_at),
        correlation_id=correlation_id,
        causation_id=f"task:{task_id}:decision",
    )
    return {
        "intent_id": intent.object_id,
        "policy_id": policy.object_id,
        "slack_id": slack.object_id,
        "destination_reference": intent.spec.destination_id,
        "state": intent.state.value,
        "environment": "sandbox",
        "created_at": recorded_at,
        "correlation_id": correlation_id,
        "authorization": "NOT_AUTHORIZED",
        "execution": "NOT_REQUESTED",
        "settlement": "NOT_CLAIMED",
        "objects": {
            "intent": intent.to_dict(),
            "policy": policy.to_dict(),
            "slack": slack.to_dict(),
        },
        "binding_id": str(uuid4()),
    }


def build_execution_handoff(*, task_id: int, username: str, binding: dict[str, Any], selected_option: str) -> dict[str, Any]:
    """Prepare a sealed execution plan without authorizing or starting it."""
    if binding.get("state") != "DRAFT":
        raise ValueError("Only a draft protocol intent can enter the execution handoff.")
    intent_id = binding.get("intent_id")
    if not isinstance(intent_id, str) or not intent_id:
        raise ValueError("The protocol draft is missing its intent reference.")
    recorded_at = _utc_now()
    correlation_id = binding.get("correlation_id") or f"product-task:{task_id}"
    plan_id = f"product-task-{task_id}-execution"
    step_id = step_object_id(plan_id, 1)
    provenance = _provenance(username=username, recorded_at=recorded_at, source="product-execution-handoff")
    plan = make_plan_record(
        plan_id=plan_id,
        source_ref=intent_id,
        summary=f"Execution handoff for product workflow option {selected_option}",
        environment_id="sandbox",
        domain_id="product",
        provenance=provenance,
        causation_id=f"task:{task_id}:execution-handoff",
        correlation_id=correlation_id,
    )
    step = make_step_record(
        step_spec=ExecutionStepSpec(
            step_id=step_id,
            plan_id=plan_id,
            position=1,
            adapter_id="pending-adapter",
            effect_type="payment/transfer",
            payload={
                "product_task_id": task_id,
                "intent_id": intent_id,
                "destination_reference": binding.get("destination_reference"),
                "selected_option": selected_option,
            },
            reservation_ref=f"pending-reservation:{intent_id}",
            max_attempts=1,
        ),
        environment_id="sandbox",
        domain_id="product",
        provenance=provenance,
        causation_id=f"task:{task_id}:execution-handoff",
        correlation_id=correlation_id,
    )
    return {
        "execution_plan_id": plan.object_id,
        "execution_step_id": step.object_id,
        "state": plan.state.value,
        "step_state": step.state.value,
        "environment": "sandbox",
        "created_at": recorded_at,
        "correlation_id": correlation_id,
        "source_intent_id": intent_id,
        "authorization": "NOT_AUTHORIZED",
        "execution": "NOT_STARTED",
        "adapter_resolution": "PENDING",
        "reservation": "PENDING",
        "plan": plan.to_dict(),
        "step": step.to_dict(),
    }
