"""Deterministic journal-driven replay of the IG-003 parity worlds.

``rebuild_parity_gate`` rebuilds BOTH composed environments from their
journal snapshots alone — no rail port is ever called during a rebuild
(the IG-002 rebuild contract reconstructs the execution submission
ledger from the journal) — and ``assert_replay_equivalence`` then
proves the parity-level equivalence:

* each world satisfies the merged IG-002 replay contract (identical
  plans, engines, submission ledger and semantic state per world);
* both rebuilt worlds project the identical normalized semantic
  projections as the originals;
* the rebuilt pair re-compares to the identical verdict.
"""

from __future__ import annotations

from src.integration.lifecycle import (
    assert_replay_equivalence as lifecycle_replay_equivalence,
)
from src.integration.lifecycle import rebuild_lifecycle_gate

from .harness import SimulationParityGate
from .projection import semantic_projection, semantic_projection_digest


def rebuild_parity_gate(gate: SimulationParityGate) -> SimulationParityGate:
    """Rebuild both worlds of one parity gate from their snapshots."""
    simulation_world = gate.simulation_world
    production_world = gate.production_world
    rebuilt_simulation = rebuild_lifecycle_gate(
        gate.simulation_gate.snapshot(),
        bindings={simulation_world.adapter_id: simulation_world.binding},
    )
    rebuilt_production = rebuild_lifecycle_gate(
        gate.production_gate.snapshot(),
        bindings={production_world.adapter_id: production_world.binding},
    )
    rebuilt = SimulationParityGate(
        pair=(simulation_world, production_world),
        gate_id=gate.gate_id,
    )
    # Swap in the journal-rebuilt lifecycle gates (the IG-002 rebuild
    # convention: the composed engines are replaced by their
    # journal-only rebuilds inside the same gate wrapper).
    rebuilt._simulation_gate = rebuilt_simulation  # noqa: SLF001
    rebuilt._production_gate = rebuilt_production  # noqa: SLF001
    return rebuilt


def assert_replay_equivalence(
    original: SimulationParityGate, rebuilt: SimulationParityGate
) -> None:
    """Prove the rebuild: per-world equivalence AND parity identity."""
    lifecycle_replay_equivalence(
        original.simulation_gate, rebuilt.simulation_gate
    )
    lifecycle_replay_equivalence(
        original.production_gate, rebuilt.production_gate
    )
    for role, world in (
        ("simulation", original.simulation_world),
        ("production", original.production_world),
    ):
        original_gate = getattr(original, f"{role}_gate")
        rebuilt_gate = getattr(rebuilt, f"{role}_gate")
        original_projection = semantic_projection(original_gate, world)
        rebuilt_projection = semantic_projection(rebuilt_gate, world)
        if semantic_projection_digest(original_projection) != (
            semantic_projection_digest(rebuilt_projection)
        ):
            from src.core.errors import CoreValidationError

            raise CoreValidationError(
                f"the rebuilt {role} world's semantic projection diverges "
                "from the original (replay determinism broke)"
            )
    differences = rebuilt.compare_projections()
    if differences:
        from src.core.errors import CoreValidationError

        raise CoreValidationError(
            "the rebuilt worlds diverge semantically after replay "
            f"({len(differences)} classified differences)"
        )
