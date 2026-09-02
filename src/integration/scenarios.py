"""Deterministic scenario drivers for the IG-001 composition gate.

The canonical payment scenario is the Work Order's mandated experiment
shape: a full simulated ledger/intent trace — an authorized economic
intent (protocol ``Intent: Create/Authorize`` family), reserved through a
REAL hold with its encumbrance posting, fulfilled through REAL fixed-point
FX conversion with an explicit residual and a weighted residual
allocation, posted as balanced double-entry FX/FEE legs, and certified by
a REAL reconciliation that seals the journal.

Every identifier, amount and timestamp is declared data; nothing reads a
clock or an entropy source, so two runs of the same scenario are
byte-identical.
"""

from __future__ import annotations

from typing import Any

from src.transition import Command, ExpectedVersion

from .contracts import (
    GATE_JOURNAL_ID,
    INTENT_AUTHORIZE_COMMAND,
    INTENT_CREATE_COMMAND,
    PAYEE_ACCOUNT,
    PAYER_ACCOUNT,
    SAVINGS_ACCOUNT,
    SETTLEMENT_RECONCILE_COMMAND,
    SETTLEMENT_SUBMIT_COMMAND,
    SOURCE_ASSET_CODE,
    TARGET_ASSET_CODE,
)

#: Default environment and domain of the canonical scenario fixtures.
DEFAULT_GATE_ENVIRONMENT = "env/ig001-gate"
DEFAULT_GATE_DOMAIN = "domain/ig001"

#: Canonical scenario amounts (minor units, exact integers).
DEFAULT_SOURCE_MINOR = 1250050
DEFAULT_FEE_MINOR = 3125
DEFAULT_RATE_NUMERATOR = 91
DEFAULT_RATE_DENOMINATOR = 100
DEFAULT_ALLOCATION_WEIGHTS = (2, 1)
DEFAULT_INITIAL_DEPOSIT_MINOR = DEFAULT_SOURCE_MINOR + DEFAULT_FEE_MINOR

#: Canonical actors of the scenario.
DEFAULT_ACTOR = "principal/customer-7"
DEFAULT_OPS_ACTOR = "principal/treasury-ops"


def _stamp(index: int, step: int) -> str:
    """Deterministic explicit timestamp for scenario step ``step``."""
    total_minutes = 4 * index + step
    day = 2 + total_minutes // 1440
    remainder = total_minutes % 1440
    return f"2026-09-{day:02d}T{remainder // 60:02d}:{remainder % 60:02d}:00Z"


def payment_scenario_commands(
    *,
    tag: str = "ig1",
    index: int = 0,
    source_minor: int = DEFAULT_SOURCE_MINOR,
    fee_minor: int = DEFAULT_FEE_MINOR,
    rate_numerator: int = DEFAULT_RATE_NUMERATOR,
    rate_denominator: int = DEFAULT_RATE_DENOMINATOR,
    weights: tuple[int, ...] = DEFAULT_ALLOCATION_WEIGHTS,
    source_asset: str = SOURCE_ASSET_CODE,
    target_asset: str = TARGET_ASSET_CODE,
    actor: str = DEFAULT_ACTOR,
    ops_actor: str = DEFAULT_OPS_ACTOR,
    environment_id: str = DEFAULT_GATE_ENVIRONMENT,
    domain_id: str = DEFAULT_GATE_DOMAIN,
) -> tuple[Command, ...]:
    """Build the four canonical commands of one payment scenario."""
    intent_ref = f"intent/{tag}"
    settlement_ref = f"settlement/{tag}"
    hold_ref = f"value/hold/{tag}"
    correlation = f"corr/{tag}"
    create = Command.build(
        command_id=f"cmd/{tag}/create",
        command_type=INTENT_CREATE_COMMAND,
        actor=actor,
        target_refs=(intent_ref,),
        payload={
            "originator": "principal/customer-7",
            "beneficiary": "principal/merchant-7",
            "source_asset": source_asset,
            "source_amount": source_minor,
            "target_asset": target_asset,
        },
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=(ExpectedVersion(object_ref=intent_ref, object_version=0),),
        idempotency_key=f"key/{tag}/create",
        nonce=f"nonce-{tag}-0",
        requested_at=_stamp(index, 0),
        correlation_id=correlation,
    )
    authorize = Command.build(
        command_id=f"cmd/{tag}/authorize",
        command_type=INTENT_AUTHORIZE_COMMAND,
        actor=actor,
        target_refs=(intent_ref,),
        payload={
            "source_asset": source_asset,
            "source_amount": source_minor,
            "account_id": PAYER_ACCOUNT,
        },
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=(ExpectedVersion(object_ref=intent_ref, object_version=1),),
        idempotency_key=f"key/{tag}/authorize",
        nonce=f"nonce-{tag}-1",
        requested_at=_stamp(index, 1),
        correlation_id=correlation,
    )
    settle = Command.build(
        command_id=f"cmd/{tag}/settle",
        command_type=SETTLEMENT_SUBMIT_COMMAND,
        actor=actor,
        target_refs=(intent_ref, settlement_ref),
        payload={
            "hold_id": hold_ref,
            "fx_rate": {"numerator": rate_numerator, "denominator": rate_denominator},
            "rounding_mode": "HALF_EVEN",
            "fee_minor": fee_minor,
            "allocation_weights": list(weights),
            "target_asset": target_asset,
            "payout_accounts": [PAYEE_ACCOUNT, SAVINGS_ACCOUNT],
        },
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=(
            ExpectedVersion(object_ref=intent_ref, object_version=2),
            ExpectedVersion(object_ref=settlement_ref, object_version=0),
        ),
        idempotency_key=f"key/{tag}/settle",
        nonce=f"nonce-{tag}-2",
        requested_at=_stamp(index, 2),
        correlation_id=correlation,
    )
    reconcile = Command.build(
        command_id=f"cmd/{tag}/reconcile",
        command_type=SETTLEMENT_RECONCILE_COMMAND,
        actor=ops_actor,
        target_refs=(settlement_ref,),
        payload={"journal_id": GATE_JOURNAL_ID},
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=(ExpectedVersion(object_ref=settlement_ref, object_version=1),),
        idempotency_key=f"key/{tag}/reconcile",
        nonce=f"nonce-{tag}-3",
        requested_at=_stamp(index, 3),
        correlation_id=correlation,
    )
    return (create, authorize, settle, reconcile)


def run_payment_scenario(gate, *, tag: str = "ig1", index: int = 0) -> tuple[Any, ...]:
    """Run the four canonical commands through the gate, in order."""
    commands = payment_scenario_commands(
        tag=tag,
        index=index,
        environment_id=gate.environment_id,
        domain_id=gate.domain_id,
    )
    return tuple(gate.submit(command) for command in commands)


def run_scaled_scenario(gate, *, count: int) -> dict[str, Any]:
    """Run ``count`` payment scenarios, reconciling once at the end.

    One journal is sealed by its first reconciliation, so the scaled run
    executes create/authorize/settle per intent and one final reconcile
    command for the last settlement (the single certification of the
    whole batch — the same discipline a period-close would use).
    """
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError("count must be a positive integer")
    commands_run = 0
    for position in range(count):
        tag = f"s{position:03d}"
        commands = payment_scenario_commands(
            tag=tag,
            index=position,
            environment_id=gate.environment_id,
            domain_id=gate.domain_id,
        )
        # One journal is sealed by its first reconciliation, so only the
        # final intent reconciles (the single certification of the whole
        # batch — the same discipline a period-close would use).
        steps = 4 if position == count - 1 else 3
        for command in commands[:steps]:
            gate.submit(command)
            commands_run += 1
    state = gate.ledger_state()
    return {
        "intents": count,
        "commands": commands_run,
        "journal_entries": len(gate.engine.journal),
        "postings": len(state["postings"]),
        "holds": len(state["holds"]),
        "composed_digest": gate.composed_digest(),
    }
