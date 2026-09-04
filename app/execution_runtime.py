from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from src.execution import ExecutionEngine
from src.execution.dogfooding import (
    SANDBOX_ADAPTER_ID,
    SandboxRail,
    make_sandbox_binding,
)
from src.simulation.effects import EffectAuthorization
from src.intent import Intent


SANDBOX_FRAUD_GATE = {
    "decision_id": "safety/product-sandbox-fraud",
    "verdict": "ALLOW",
    "object_version": 1,
}
SANDBOX_COMPLIANCE_GATE = {
    "assessment_id": "safety/product-sandbox-compliance",
    "verdict": "SATISFIED",
    "object_version": 1,
}
SANDBOX_HOLD = {
    "reservation_id": "reservation/product-sandbox-hold",
    "state": "HELD",
    "object_version": 1,
}


def execution_mode() -> str:
    return os.getenv("PAYSWAP_EXECUTION_MODE", "unconfigured").strip().lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sandbox_authorization() -> EffectAuthorization:
    return EffectAuthorization(
        authorizer="principal/product-sandbox-execution",
        authority_class="A2",
        authorized_types=frozenset({"payment/submit"}),
        valid_from="2000-01-01T00:00:00Z",
        valid_until="2999-12-31T23:59:59Z",
    )


def execute_sandbox(*, task_id: int, binding: dict[str, Any]) -> dict[str, Any]:
    """Run a product-bound protocol draft through the real execution kernel.

    This is intentionally available only in ``PAYSWAP_EXECUTION_MODE=sandbox``.
    The sandbox rail is the repository's deterministic test-side adapter: it
    exercises the public execution engine and its authority/idempotency gates
    without moving real funds. Production execution must supply a configured
    real adapter outside the product shell.
    """
    if execution_mode() != "sandbox":
        raise ValueError("The governed execution service is not configured for this environment.")
    if binding.get("state") != "DRAFT":
        raise ValueError("Only a DRAFT protocol intent can be executed from this workflow.")

    intent = Intent.from_dict(binding["objects"]["intent"])
    amount = intent.spec.amount
    destination = binding.get("destination_reference")
    if not isinstance(destination, str) or not destination:
        raise ValueError("The protocol draft is missing its destination reference.")

    plan_id = f"product-task-{task_id}-sandbox-execution"
    step_id = f"{plan_id}/step/1"
    rail = SandboxRail()
    engine = ExecutionEngine(
        environment_id="sandbox",
        domain_id="product",
        bindings={SANDBOX_ADAPTER_ID: make_sandbox_binding(rail)},
    )
    now = _now()

    engine.create_plan(
        command_id=f"product-task-{task_id}-execution-create",
        requested_at=now,
        plan_id=plan_id,
        source_ref=intent.object_id,
        summary=f"Sandbox execution for product task {task_id}",
        steps=[
            {
                "step_id": step_id,
                "adapter_id": SANDBOX_ADAPTER_ID,
                "effect_type": "payment/submit",
                "payload": {
                    "currency": amount.asset,
                    "amount_value": amount.value,
                    "amount_scale": amount.scale,
                    "destination": f"alias/{destination}",
                    "product_task_id": task_id,
                },
                "reservation_ref": SANDBOX_HOLD["reservation_id"],
                "max_attempts": 1,
            }
        ],
    )
    engine.authorize_plan(
        command_id=f"product-task-{task_id}-execution-authorize",
        requested_at=now,
        plan_id=plan_id,
        authority_class="A2",
        fraud_decision=SANDBOX_FRAUD_GATE,
        compliance_assessment=SANDBOX_COMPLIANCE_GATE,
        mandate_ref=f"sandbox-mandate:task:{task_id}",
    )
    engine.start_plan(
        command_id=f"product-task-{task_id}-execution-start",
        requested_at=now,
        plan_id=plan_id,
    )

    request_key = f"product-task-{task_id}-sandbox-payment"
    authorization = _sandbox_authorization()
    engine.request_effect(
        command_id=f"product-task-{task_id}-effect-request",
        requested_at=now,
        step_id=step_id,
        idempotency_key=request_key,
        authorization=authorization,
        hold=SANDBOX_HOLD,
    )
    submission = engine.submit_step(
        command_id=f"product-task-{task_id}-effect-submit",
        requested_at=now,
        step_id=step_id,
    )
    if submission.outcome.value != "accepted":
        raise ValueError(f"Sandbox execution did not accept the effect: {submission.outcome.value}.")

    native_reference = engine.step(step_id).spec.payload.get("native_reference")
    # The rail's deterministic reference is derived from the request key.
    native_reference = native_reference or f"sandbox/{request_key}"
    engine.acknowledge_step(
        command_id=f"product-task-{task_id}-effect-acknowledge",
        requested_at=now,
        step_id=step_id,
        native_reference=native_reference,
    )
    engine.record_effect_result(
        command_id=f"product-task-{task_id}-effect-result",
        requested_at=now,
        step_id=step_id,
        outcome="SUCCEEDED",
        native_reference=native_reference,
        observed_at=now,
    )
    engine.complete_step(
        command_id=f"product-task-{task_id}-effect-complete",
        requested_at=now,
        step_id=step_id,
    )

    return {
        "execution_mode": "sandbox",
        "environment": "sandbox",
        "adapter_id": SANDBOX_ADAPTER_ID,
        "execution_plan_id": plan_id,
        "execution_step_id": step_id,
        "plan_state": engine.plan(plan_id).state.value,
        "step_state": engine.step(step_id).state.value,
        "execution": "COMPLETED",
        "authorization": "AUTHORIZED_SANDBOX",
        "reservation": "HELD_SANDBOX",
        "effect": "SUCCEEDED_SANDBOX",
        "settlement": "NOT_CLAIMED",
        "finality": "NOT_CLAIMED",
        "native_reference": native_reference,
        "executed_at": now,
    }
