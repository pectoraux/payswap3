"""Deterministic journal-driven replay of the IG-005 rail worlds.

``rebuild_rails_gate`` rebuilds BOTH composed rail worlds from their
journal snapshots alone — no rail port is ever called during a rebuild
(the IG-002 rebuild contract reconstructs the execution submission
ledger from the journal) — and ``assert_rails_replay_equivalence``
then proves the gate-level equivalence:

* each world satisfies the merged IG-002 replay contract (identical
  plans, engines, submission ledger and semantic state per world);
* both rebuilt worlds project the identical normalized semantic
  projections as the originals;
* the rebuilt pair re-compares to the identical equivalence verdict.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.integration.lifecycle import (
    assert_replay_equivalence as lifecycle_replay_equivalence,
)
from src.integration.lifecycle import rebuild_lifecycle_gate

from .harness import ExternalRailSandboxGate
from .projection import semantic_projection, semantic_projection_digest


def rebuild_rails_gate(gate: ExternalRailSandboxGate) -> ExternalRailSandboxGate:
    """Rebuild both worlds of one rail gate from their snapshots."""
    world_a = gate.rail_a_world
    world_b = gate.rail_b_world
    rebuilt_a = rebuild_lifecycle_gate(
        gate.rail_a_gate.snapshot(),
        bindings={world_a.adapter_id: world_a.binding},
    )
    rebuilt_b = rebuild_lifecycle_gate(
        gate.rail_b_gate.snapshot(),
        bindings={world_b.adapter_id: world_b.binding},
    )
    rebuilt = ExternalRailSandboxGate(
        (world_a, world_b), gate_id=gate.gate_id
    )
    # Swap in the journal-rebuilt lifecycle gates (the IG-002 rebuild
    # convention: the composed engines are replaced by their
    # journal-only rebuilds inside the same gate wrapper).
    rebuilt._gate_a = rebuilt_a  # noqa: SLF001
    rebuilt._gate_b = rebuilt_b  # noqa: SLF001
    return rebuilt


def assert_rails_replay_equivalence(
    original: ExternalRailSandboxGate, rebuilt: ExternalRailSandboxGate
) -> None:
    """Prove the rebuild: per-world equivalence AND cross-rail identity."""
    lifecycle_replay_equivalence(original.rail_a_gate, rebuilt.rail_a_gate)
    lifecycle_replay_equivalence(original.rail_b_gate, rebuilt.rail_b_gate)
    for original_gate, rebuilt_gate, world in (
        (original.rail_a_gate, rebuilt.rail_a_gate, original.rail_a_world),
        (original.rail_b_gate, rebuilt.rail_b_gate, original.rail_b_world),
    ):
        original_projection = semantic_projection(original_gate, world)
        rebuilt_projection = semantic_projection(rebuilt_gate, world)
        if semantic_projection_digest(original_projection) != (
            semantic_projection_digest(rebuilt_projection)
        ):
            raise CoreValidationError(
                f"the rebuilt {world.name} world's semantic projection "
                "diverges from the original (replay determinism broke)"
            )
    differences = rebuilt.compare_projections()
    if differences:
        raise CoreValidationError(
            "the rebuilt worlds diverge semantically after replay "
            f"({len(differences)} classified differences)"
        )


__all__ = [
    "assert_rails_replay_equivalence",
    "rebuild_rails_gate",
]
