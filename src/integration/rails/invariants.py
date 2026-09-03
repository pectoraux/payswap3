"""The IG-005 invariant battery.

The battery runs the merged WORK-027 lifecycle invariant battery
(authority routing, accounting, settlement truth, evidence typing,
idempotency, environment isolation, append-only stage journal,
lifecycle legality) on BOTH composed worlds — every deep cross-domain
invariant is verified per world by the merged authority — and adds
the IG-005-owned checks:

* per world: domain isolation (each world's engines carry only their
  own domain binding), rail classification honesty (the declared class
  matches the bound rail's observable nature, already enforced at
  construction and re-asserted here), and the finality discipline
  (a finality certificate exists only bound to a completed settlement
  — provider payment success alone never manufactures one);
* cross-rail (when the verdict claims EQUIVALENT): the idempotency
  key sets, failure classes, outcome classes, declared economics
  (amount value and scale), stage sequences, native-reference
  presence and posting structure of the two worlds are equal.

The first violation fails closed with its own dimension's message.
"""

from __future__ import annotations

from typing import Any

from src.clearing import Obligation
from src.core.errors import CoreValidationError
from src.integration.lifecycle import verify_lifecycle_invariants
from src.settlement import Finality, Settlement

from .harness import ExternalRailSandboxGate
from .worlds import RailWorld


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CoreValidationError(f"IG-005 invariant violation: {message}")


def verify_rails_invariants(
    gate: ExternalRailSandboxGate, *, cross_rail: bool = True
) -> list[str]:
    """Run the battery; raise on the first violation; return check names.

    The per-world structural checks always run: a divergence verdict
    never excuses an internally broken world. The cross-rail equality
    checks run when ``cross_rail`` is true — the comparison verdict
    runs them for the EQUIVALENT case and reports the classified
    differences themselves for the DIVERGENCE case.
    """
    checks: list[str] = []
    _check_merged_lifecycle_battery(gate, checks)
    _check_domain_isolation(gate, checks)
    _check_rail_classification_honesty(gate, checks)
    _check_finality_discipline(gate, checks)
    if cross_rail:
        _check_idempotency(gate, checks)
        _check_failure_class(gate, checks)
        _check_outcome_class(gate, checks)
        _check_declared_economics(gate, checks)
        _check_stage_sequences(gate, checks)
        _check_native_reference_presence(gate, checks)
        _check_posting_structure(gate, checks)
    return checks


def _check_merged_lifecycle_battery(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Re-run the merged WORK-027 battery on both worlds."""
    for world in gate.worlds:
        lifecycle_gate = (
            gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
        )
        merged = verify_lifecycle_invariants(lifecycle_gate)
        checks.append(f"merged-ig002-battery:{world.name}:{len(merged)}")


def _check_domain_isolation(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Each world's engines carry only their own domain binding."""
    for world in gate.worlds:
        lifecycle_gate = (
            gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
        )
        for engine_domain in (
            lifecycle_gate.compiler.domain_id
            if hasattr(lifecycle_gate, "compiler")
            else None,
            lifecycle_gate.execution.domain_id,
            lifecycle_gate.clearing.domain_id,
            lifecycle_gate.settlement.domain_id,
        ):
            if engine_domain is None:
                continue
            _require(
                engine_domain.startswith(world.domain_id + "/")
                or engine_domain == world.domain_id,
                f"engine domain {engine_domain!r} escapes world domain "
                f"{world.domain_id!r}",
            )
        for record in lifecycle_gate.execution.objects():
            environment_id = getattr(record, "environment_id", None)
            _require(
                environment_id in (None, world.environment_id),
                f"execution record {record.object_id} carries foreign "
                f"environment {environment_id!r}",
            )
        for record in lifecycle_gate.clearing.records():
            environment_id = getattr(record, "environment_id", None)
            _require(
                environment_id in (None, world.environment_id),
                f"clearing record {record.object_id} carries foreign "
                f"environment {environment_id!r}",
            )
        for record in lifecycle_gate.settlement.records():
            environment_id = getattr(record, "environment_id", None)
            _require(
                environment_id in (None, world.environment_id),
                f"settlement record {record.object_id} carries foreign "
                f"environment {environment_id!r}",
            )
        checks.append(f"domain-isolation:{world.name}")


def _check_rail_classification_honesty(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """The declared rail classifications match the bound rails' nature."""
    from src.integration.lifecycle.dogfooding import LocalDeterministicRail

    for world in gate.worlds:
        if world.rail_class.value == "LOCAL_DETERMINISTIC_SANDBOX":
            _require(
                isinstance(world.rail, LocalDeterministicRail),
                f"world {world.name} declares LOCAL_DETERMINISTIC_SANDBOX "
                "but binds a non-local rail",
            )
        else:
            _require(
                not isinstance(world.rail, LocalDeterministicRail),
                f"world {world.name} declares REAL_PROVIDER_SANDBOX but "
                "binds the local deterministic rail",
            )
        checks.append(f"rail-classification:{world.name}")


def _check_finality_discipline(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Finality certificates exist only over completed settlements.

    A provider payment status alone never manufactures finality: the
    settlement domain's own certificate validation (digest-bound
    FINALITY-kind claims over settled legs of a terminal settlement)
    is the only establishment path, and the merged battery already
    proves it per world. This check re-asserts the observable facts:
    every finality record is ESTABLISHED and its settlement is
    COMPLETED.
    """
    for world in gate.worlds:
        lifecycle_gate = (
            gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
        )
        settlements = {
            record.object_id: record
            for record in lifecycle_gate.settlement.records()
            if isinstance(record, Settlement)
        }
        for record in lifecycle_gate.settlement.records():
            if not isinstance(record, Finality):
                continue
            settlement = settlements.get(record.spec.settlement_id)
            _require(
                settlement is not None,
                f"finality {record.object_id} binds an unknown settlement",
            )
            _require(
                settlement.state.value == "COMPLETED",
                f"finality {record.object_id} binds a settlement in state "
                f"{settlement.state.value!r}",
            )
            _require(
                record.state.value == "ESTABLISHED",
                f"finality {record.object_id} is {record.state.value!r}",
            )
        checks.append(f"finality-discipline:{world.name}")


def _ledger_keys(gate: ExternalRailSandboxGate, world: RailWorld) -> set[str]:
    lifecycle_gate = (
        gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
    )
    ledger = lifecycle_gate.execution.submission_ledger()
    entries = ledger.to_dict().get("entries", [])
    keys = {entry["key"] for entry in entries}
    _require(
        len(keys) == len(entries),
        "the submission ledger carries duplicate idempotency keys",
    )
    return keys


def _latest_attempt(gate: ExternalRailSandboxGate, world: RailWorld) -> Any:
    lifecycle_gate = (
        gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
    )
    attempts = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionAttempt"
    ]
    return attempts[-1] if attempts else None


def _latest_step(gate: ExternalRailSandboxGate, world: RailWorld) -> Any:
    lifecycle_gate = (
        gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
    )
    steps = [
        record
        for record in lifecycle_gate.execution.objects()
        if record.__class__.__name__ == "ExecutionStep"
    ]
    return steps[-1] if steps else None


def _leg_amounts(gate: ExternalRailSandboxGate, world: RailWorld) -> list[int]:
    lifecycle_gate = (
        gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
    )
    return [
        record.spec.amount
        for record in lifecycle_gate.clearing.records()
        if isinstance(record, Obligation)
    ]


def _check_idempotency(gate: ExternalRailSandboxGate, checks: list[str]) -> None:
    """Both worlds' submission ledgers carry the same key set."""
    keys_a = _ledger_keys(gate, gate.rail_a_world)
    keys_b = _ledger_keys(gate, gate.rail_b_world)
    _require(
        keys_a == keys_b,
        f"idempotency key sets diverge: {sorted(keys_a ^ keys_b)}",
    )
    checks.append("cross-rail-idempotency")


def _check_failure_class(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Both worlds' latest submission classifications agree."""
    attempt_a = _latest_attempt(gate, gate.rail_a_world)
    attempt_b = _latest_attempt(gate, gate.rail_b_world)
    _require(
        attempt_a is not None and attempt_b is not None,
        "both worlds must have attempted at least one submission",
    )
    _require(
        attempt_a.spec.status.value == attempt_b.spec.status.value,
        f"failure classes diverge: {attempt_a.spec.status.value} vs "
        f"{attempt_b.spec.status.value}",
    )
    checks.append("cross-rail-failure-class")


def _check_outcome_class(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Both worlds' latest step states agree."""
    step_a = _latest_step(gate, gate.rail_a_world)
    step_b = _latest_step(gate, gate.rail_b_world)
    _require(
        step_a is not None and step_b is not None,
        "both worlds must carry at least one execution step",
    )
    _require(
        step_a.state.value == step_b.state.value,
        f"outcome classes diverge: {step_a.state.value} vs "
        f"{step_b.state.value}",
    )
    checks.append("cross-rail-outcome-class")


def _check_declared_economics(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Both worlds' obligation economics are identical (value, scale)."""
    amounts_a = sorted(_leg_amounts(gate, gate.rail_a_world))
    amounts_b = sorted(_leg_amounts(gate, gate.rail_b_world))
    _require(
        amounts_a == amounts_b,
        f"declared economics diverge: {amounts_a} vs {amounts_b}",
    )
    checks.append("cross-rail-declared-economics")


def _check_stage_sequences(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Both worlds' stage sequences (the semantic tuples) are identical."""
    stages_a = [
        (entry["stage"], entry["domain"], entry["command_id"], entry["outcome"])
        for entry in gate.rail_a_gate.stage_journal
    ]
    stages_b = [
        (entry["stage"], entry["domain"], entry["command_id"], entry["outcome"])
        for entry in gate.rail_b_gate.stage_journal
    ]
    _require(
        stages_a == stages_b,
        "the stage sequences diverge between the two rail worlds",
    )
    checks.append("cross-rail-stage-sequences")


def _check_native_reference_presence(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """An accepted submission carries the rail's native reference."""
    for world in gate.worlds:
        lifecycle_gate = (
            gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
        )
        attempts = [
            record
            for record in lifecycle_gate.execution.objects()
            if record.__class__.__name__ == "ExecutionAttempt"
        ]
        accepted = [
            attempt
            for attempt in attempts
            if attempt.spec.status.value == "ACCEPTED"
        ]
        for attempt in accepted:
            reference = attempt.spec.native_reference
            _require(
                isinstance(reference, str) and reference.strip(),
                f"an ACCEPTED submission of {world.name} carries no native "
                "reference",
            )
            _require(
                world.native_reference_pattern.match(reference) is not None,
                f"native reference {reference!r} of {world.name} escapes "
                "the world's declared reference shape",
            )
        checks.append(f"native-reference-presence:{world.name}")


def _check_posting_structure(
    gate: ExternalRailSandboxGate, checks: list[str]
) -> None:
    """Both worlds' discharge postings count identically."""
    counts: list[int] = []
    for world in gate.worlds:
        lifecycle_gate = (
            gate.rail_a_gate if world is gate.rail_a_world else gate.rail_b_gate
        )
        counts.append(
            len(
                [
                    entry
                    for entry in lifecycle_gate.settlement.postings()
                    if entry.kind == "DISCHARGE"
                ]
            )
        )
    _require(
        counts[0] == counts[1],
        f"discharge postings diverge: {counts[0]} vs {counts[1]}",
    )
    checks.append("cross-rail-posting-structure")


__all__ = [
    "verify_rails_invariants",
]
