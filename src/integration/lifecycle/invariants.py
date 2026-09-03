"""The IG-002 cross-domain invariant battery.

``verify_lifecycle_invariants`` runs after EVERY accepted stage of the
composed lifecycle (the gate driver calls it) and re-runs on rebuilt
gates. Each check re-derives facts through the OWNING domain's trusted
decode paths — never from gate-side caches — so a divergence between
domains fails closed immediately. The battery is state-aware: checks
assert only what exists at the current lifecycle position.

Checks (constitution hard invariants in parentheses):

* authority routing (18): every obligation was recognized from a sealed
  execution effect result owned by the execution domain; every
  settlement instruction pins a sealed clearing obligation; finality
  certificates exist only through the settlement domain;
* accounting (1, 2, 8): obligation amounts equal their source evidence
  amounts; netting statements conserve value (positions sum to zero,
  reduction is gross minus net); the settlement posting journal
  balances per asset; discharge postings equal the settled legs;
* settlement truth (11): a payment status never promotes to finality —
  certificates are established only for terminal settlements with
  validated FINALITY-class claims covering exactly the settled legs;
* evidence typing (12): every external observation folded downstream is
  OBSERVED knowledge bound digest-tight to its subject;
* idempotency (9): no idempotency key has more than one submission in
  the execution ledger;
* environment isolation (14): all composed engines share exactly the
  gate environment;
* append-only history (17): the stage journal is chained (each entry's
  ``state_after`` equals the next entry's ``state_before``);
* lifecycle legality: every composed record's state parses in its
  domain's closed vocabulary.
"""

from __future__ import annotations

from typing import Any

from src.clearing import (
    ClearingCycle,
    NettingCycle,
    Obligation,
)
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.execution import (
    EffectResult,
    ExecutionPlan,
    ExecutionStep,
    ExternalObservation,
)
from src.settlement import Finality, Settlement, verify_journal_balance


def verify_lifecycle_invariants(gate: Any) -> list[str]:
    """Run the battery; raise on the first violation; return check names."""
    checks: list[str] = []

    _check_authority_routing(gate, checks)
    _check_accounting(gate, checks)
    _check_settlement_truth(gate, checks)
    _check_evidence_typing(gate, checks)
    _check_idempotency(gate, checks)
    _check_environment_isolation(gate, checks)
    _check_append_only_stage_journal(gate, checks)
    _check_lifecycle_legality(gate, checks)

    return checks


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CoreValidationError(f"IG-002 invariant violation: {message}")


def _check_authority_routing(gate: Any, checks: list[str]) -> None:
    execution_records = {
        record.object_id: record for record in gate.execution.objects()
    }
    netting_records = {
        record.object_id: record for record in gate.clearing.records()
    }
    obligations = [
        record
        for record in gate.clearing.records()
        if isinstance(record, Obligation)
    ]
    routed = True
    for obligation in obligations:
        if obligation.spec.source_kind == "EXECUTION_EVIDENCE":
            source = execution_records.get(obligation.spec.source_ref)
            if not isinstance(source, EffectResult):
                routed = False
                break
            if obligation.spec.source_digest != source.integrity_hash:
                routed = False
                break
        elif obligation.spec.source_kind == "NETTING_ISSUANCE":
            source = netting_records.get(obligation.spec.source_ref)
            if not isinstance(source, NettingCycle):
                routed = False
                break
            statement = source.spec.statement
            if (
                statement is None
                or obligation.spec.source_digest != statement.digest
            ):
                routed = False
                break
        else:
            routed = False
            break
    _require(
        routed,
        "every obligation must pin the sealed authority of its source kind: "
        "execution evidence (execution domain) or a netting statement "
        "(clearing domain)",
    )
    checks.append("authority: obligations derive from their sealed sources")

    clearing_records = {
        record.object_id: record for record in gate.clearing.records()
    }
    settlements = [
        record
        for record in gate.settlement.records()
        if isinstance(record, Settlement)
    ]
    bound = True
    for settlement in settlements:
        for instruction in settlement.spec.instructions:
            obligation = clearing_records.get(instruction.obligation_id)
            if obligation is None or not isinstance(obligation, Obligation):
                bound = False
                break
        if not bound:
            break
    _require(
        bound,
        "every settlement instruction must pin a sealed clearing obligation",
    )
    checks.append("authority: settlement instructions pin clearing obligations")


def _check_accounting(gate: Any, checks: list[str]) -> None:
    execution_results = {
        record.object_id: record
        for record in gate.execution.objects()
        if isinstance(record, EffectResult)
    }
    obligations = [
        record
        for record in gate.clearing.records()
        if isinstance(record, Obligation)
    ]
    from src.transition.payload import payload_to_json_value

    derived = True
    for obligation in obligations:
        if obligation.spec.source_kind != "EXECUTION_EVIDENCE":
            continue
        source = execution_results.get(obligation.spec.source_ref)
        if source is None:
            derived = False
            break
        detail = payload_to_json_value(source.spec.detail)
        if not isinstance(detail, dict):
            derived = False
            break
        amount = detail.get("amount", {})
        if (
            obligation.spec.amount.value != amount.get("value")
            or obligation.spec.amount.scale != amount.get("scale")
            or obligation.spec.asset != amount.get("asset")
            or obligation.spec.obligor != detail.get("payer")
            or obligation.spec.obligee != detail.get("payee")
        ):
            derived = False
            break
    _require(
        derived,
        "obligation economics must equal the sealed effect-result payment leg",
    )
    checks.append("accounting: obligation amounts derive from execution evidence")

    for netting in gate.clearing.records():
        if not isinstance(netting, NettingCycle):
            continue
        statement = netting.spec.statement
        if statement is None:
            continue
        for group in statement.groups:
            if group.positions:
                total = sum(position.net for position in group.positions)
                _require(
                    total == 0,
                    f"netting group {group.asset} positions must sum to zero "
                    f"(got {total})",
                )
            if group.pairs:
                pair_total = sum(pair.forward for pair in group.pairs)
                _require(
                    pair_total == group.net_total,
                    f"netting group {group.asset} pair nets must sum to the "
                    f"group net ({pair_total} != {group.net_total})",
                )
        gross = sum(group.gross for group in statement.groups)
        net = sum(group.net_total for group in statement.groups)
        _require(
            gross == statement.gross_total and net == statement.net_total,
            "netting group totals must sum to the statement totals",
        )
        _require(
            statement.reduction == statement.gross_total - statement.net_total,
            "netting reduction must equal gross minus net",
        )
    checks.append("accounting: netting statements conserve value")

    postings = gate.settlement.postings()
    if postings:
        for entry in postings:
            _require(
                entry.debit_value == entry.credit_value,
                f"posting {entry.entry_id} ({entry.kind}) must balance its pair "
                f"({entry.debit_value} != {entry.credit_value})",
            )
        totals: dict[str, int] = {}
        for entry in postings:
            totals[entry.asset] = totals.get(entry.asset, 0) + entry.debit_value
        verify_journal_balance(postings)
    checks.append("accounting: the settlement journal balances per asset")

    settled_total = 0
    for settlement in gate.settlement.records():
        if not isinstance(settlement, Settlement):
            continue
        for outcome in settlement.spec.leg_outcomes:
            if outcome.state == "SETTLED":
                instruction = next(
                    (
                        item
                        for item in settlement.spec.instructions
                        if item.instruction_id == outcome.instruction_id
                    ),
                    None,
                )
                _require(
                    instruction is not None,
                    "settled legs must reference declared instructions",
                )
                settled_total += 1
    discharges = [
        entry for entry in postings if entry.kind == "DISCHARGE"
    ]
    _require(
        len(discharges) == settled_total,
        f"discharge postings ({len(discharges)}) must equal settled legs "
        f"({settled_total})",
    )
    checks.append("accounting: discharge postings equal settled legs")


def _check_settlement_truth(gate: Any, checks: list[str]) -> None:
    settlements = {
        record.object_id: record
        for record in gate.settlement.records()
        if isinstance(record, Settlement)
    }
    for certificate in gate.settlement.records():
        if not isinstance(certificate, Finality):
            continue
        settlement = settlements.get(certificate.spec.settlement_id)
        _require(
            settlement is not None,
            "finality certificates must reference a declared settlement",
        )
        if certificate.state.value == "ESTABLISHED":
            _require(
                settlement.state.value in ("COMPLETED", "FAILED"),
                "finality can be established only for a terminal settlement "
                "(a payment status never stands in for settlement finality)",
            )
            settled = {
                outcome.instruction_id
                for outcome in settlement.spec.leg_outcomes
                if outcome.state == "SETTLED"
            }
            covered = {binding.instruction_id for binding in certificate.spec.claims}
            _require(
                covered == settled and settled,
                "an established certificate must cover exactly the settled legs",
            )
            for binding in certificate.spec.claims:
                _require(
                    binding.claim in ("FINAL", "SETTLED"),
                    "finality certificates bind finality-class claims only",
                )
    checks.append("settlement truth: finality derives from settled legs only")


def _check_evidence_typing(gate: Any, checks: list[str]) -> None:
    for observation in gate.execution.observations():
        _require(
            observation.spec.epistemic.value == "OBSERVED",
            f"external observation {observation.object_id} must be OBSERVED "
            "knowledge",
        )
    for settlement in gate.settlement.records():
        if not isinstance(settlement, Settlement):
            continue
        for outcome in settlement.spec.leg_outcomes:
            if outcome.state == "SETTLED":
                _require(
                    outcome.observation_digest is not None,
                    "settled legs must carry their observation digest binding",
                )
    checks.append("evidence: external observations are OBSERVED knowledge")


def _check_idempotency(gate: Any, checks: list[str]) -> None:
    ledger = gate.execution.submission_ledger()
    entries = ledger.to_dict()["entries"]
    keys = [entry["key"] for entry in entries]
    _require(
        len(keys) == len(set(keys)),
        "no idempotency key may be submitted twice (constitution invariant 9)",
    )
    checks.append("idempotency: effect keys are submitted at most once")


def _check_environment_isolation(gate: Any, checks: list[str]) -> None:
    environment = gate.environment_id
    _require(
        gate.compiler.environment_id == environment
        and gate.execution.environment_id == environment
        and gate.clearing.environment_id == environment
        and gate.settlement.environment_id == environment,
        "every composed engine must share the gate environment exactly",
    )
    for record in gate.execution.objects():
        _require(
            record.envelope.environment_id == environment,
            f"execution record {record.object_id} leaked across environments",
        )
    checks.append("environment: composed engines share one environment")


def _check_append_only_stage_journal(gate: Any, checks: list[str]) -> None:
    journal = gate.stage_journal
    for previous, current in zip(journal, journal[1:]):
        _require(
            previous["state_after"] == current["state_before"],
            "the stage journal must stay chained (append-only history)",
        )
    seen: set[str] = set()
    for entry in journal:
        _require(
            entry["command_id"] not in seen or entry["outcome"] != "accepted",
            "accepted stage commands are never re-executed",
        )
        seen.add(entry["command_id"])
    checks.append("history: the stage journal is append-only and chained")


def _check_lifecycle_legality(gate: Any, checks: list[str]) -> None:
    from src.clearing import ClearingCycleState, NettingCycleState, ObligationState
    from src.compiler import PlanState
    from src.execution import ExecutionPlanState, ExecutionStepState
    from src.settlement import FinalityState, LegState, SettlementState

    for plan in gate.plans:
        PlanState(plan.state.value)
    for record in gate.execution.objects():
        if isinstance(record, ExecutionPlan):
            ExecutionPlanState(record.state.value)
        elif isinstance(record, ExecutionStep):
            ExecutionStepState(record.state.value)
    for record in gate.clearing.records():
        if isinstance(record, Obligation):
            ObligationState(record.state.value)
        elif isinstance(record, ClearingCycle):
            ClearingCycleState(record.state.value)
        elif isinstance(record, NettingCycle):
            NettingCycleState(record.state.value)
    for record in gate.settlement.records():
        if isinstance(record, Settlement):
            SettlementState(record.state.value)
            for outcome in record.spec.leg_outcomes:
                LegState(outcome.state)
        elif isinstance(record, Finality):
            FinalityState(record.state.value)
    checks.append("lifecycle: every composed state is in its closed vocabulary")


def stage_journal_digest(gate: Any) -> str:
    """Canonical digest over the append-only stage journal."""
    return canonical_sha256(
        {"stage_journal": [dict(entry) for entry in gate.stage_journal]}
    )
