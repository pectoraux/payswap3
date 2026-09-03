"""Deterministic replay/rebuild of the IG-004 composed economic state.

``rebuild_economic_gate`` rebuilds the WHOLE composed economics — the
merchant demand record, the REAL extension lifecycle (register →
sandbox-certify → review → publish → install → treat), the REAL agent
surface (model registration, bounded mandate, hypothetical context,
proposals), the simulation-first mediation and the sealed contribution
measurement — from the recorded snapshot alone, in FRESH worlds:

1. a fresh ``EconomicIntegrationGate`` is constructed over fresh
   engines (no live engine state is ever reused: the rebuild is a true
   cold restart of the composed domains);
2. the declared canonical scenario is re-driven stage by stage in
   lockstep on both worlds; every domain command must be re-ACCEPTED
   with the recorded deterministic command ids and declared instants
   (no clock read, no entropy — the scenario is pure declared data);
3. the rebuilt stage journal must reproduce the recorded journal
   entry-for-entry (stage, domain, command id, requested instant,
   outcome and the chained ``state_before``/``state_after`` composed
   digests) and the rebuilt per-world composed state digests must equal
   the snapshot's recorded digests — a tampered or fabricated journal
   fails closed;
4. the rebuilt gate must re-seal an ``ECONOMIC_PARITY`` verdict.

``assert_replay_equivalence`` then proves the rebuild SEMANTICALLY:
identical identity, identical journals, identical composed digests,
identical canonical economic projections (merchant record, extension
records, agent records, contribution, stage tuples), the full
invariant battery re-verified on the rebuilt gate (a tampered rebuild
such as a missing contribution measurement fails closed), and the
re-sealed parity verdict digests byte-identical to the original's.
"""

from __future__ import annotations

from typing import Any

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.integration.economics.contracts import (
    ECONOMICS_API_VERSION,
    ECONOMICS_GATE_ID,
    ECONOMICS_SCHEMA_VERSION,
    validate_economics_gate_id,
)
from src.integration.economics.harness import EconomicIntegrationGate, assert_economic_parity
from src.integration.economics.invariants import verify_economic_invariants
from src.integration.economics.projection import economic_state, normalize_economic_state
from src.integration.economics.worlds import EconomicWorld

#: The journal fields that must reproduce exactly on a rebuild (the
#: semantic stage record; the state digests are checked separately as
#: the chaining witness).
_JOURNAL_SEMANTIC_FIELDS = (
    "stage",
    "role",
    "domain",
    "command_id",
    "requested_at",
    "outcome",
)


def rebuild_economic_gate(gate: EconomicIntegrationGate) -> EconomicIntegrationGate:
    """Rebuild the composed economic gate from the recorded snapshot.

    The rebuild is a cold restart: fresh engines, fresh worlds, the
    declared scenario re-driven deterministically. It fails closed on
    any journal mismatch, digest mismatch or re-sealed divergence.
    """
    if not isinstance(gate, EconomicIntegrationGate):
        raise CoreValidationError("rebuild requires an EconomicIntegrationGate")
    snapshot = gate.snapshot()
    gate_id = validate_economics_gate_id(snapshot["gate_id"])

    rebuilt = EconomicIntegrationGate(gate_id=gate_id, actor=gate.actor)
    verdict = rebuilt.run_canonical_scenario()
    assert_economic_parity(verdict)

    recorded_journal = [dict(entry) for entry in snapshot["stage_journal"]]
    rebuilt_journal = [dict(entry) for entry in rebuilt.stage_journal]
    if len(recorded_journal) != len(rebuilt_journal):
        raise CoreValidationError(
            f"the rebuild produced {len(rebuilt_journal)} stage journal "
            f"entries but the snapshot records {len(recorded_journal)}"
        )
    for recorded, fresh in zip(recorded_journal, rebuilt_journal):
        for field in _JOURNAL_SEMANTIC_FIELDS:
            if recorded[field] != fresh[field]:
                raise CoreValidationError(
                    f"stage journal entry diverges on rebuild at stage "
                    f"{recorded['stage']!r} field {field!r}: "
                    f"{recorded[field]!r} != {fresh[field]!r}"
                )
        if recorded["state_before"] != fresh["state_before"] or (
            recorded["state_after"] != fresh["state_after"]
        ):
            raise CoreValidationError(
                f"stage journal state digests diverge on rebuild at stage "
                f"{recorded['stage']!r}: the composed state is not a pure "
                "function of the accepted command history"
            )

    for role, world in (("simulation", rebuilt.simulation_world), (
        "production",
        rebuilt.production_world,
    )):
        recorded_digest = snapshot[role]["composed_state_digest"]
        fresh_digest = rebuilt.composed_state_digest(world)
        if fresh_digest != recorded_digest:
            raise CoreValidationError(
                f"the rebuilt {role} composed state digest "
                f"{fresh_digest} does not reproduce the recorded "
                f"{recorded_digest}"
            )
    return rebuilt


def assert_replay_equivalence(
    gate: EconomicIntegrationGate, rebuilt: EconomicIntegrationGate
) -> EconomicIntegrationGate:
    """Fail closed unless the rebuilt gate is semantically the original."""
    if not isinstance(gate, EconomicIntegrationGate) or not isinstance(
        rebuilt, EconomicIntegrationGate
    ):
        raise CoreValidationError(
            "replay equivalence compares EconomicIntegrationGate instances"
        )
    if rebuilt.gate_id != gate.gate_id or rebuilt.gate_id != ECONOMICS_GATE_ID:
        raise CoreValidationError("the rebuilt gate identity diverges")
    if rebuilt.api_version != gate.api_version or (
        rebuilt.api_version != ECONOMICS_API_VERSION
    ):
        raise CoreValidationError("the rebuilt gate api version diverges")
    if rebuilt.schema_version != gate.schema_version or (
        rebuilt.schema_version != ECONOMICS_SCHEMA_VERSION
    ):
        raise CoreValidationError("the rebuilt gate schema version diverges")
    if rebuilt.actor != gate.actor:
        raise CoreValidationError("the rebuilt gate actor diverges")

    recorded = [dict(entry) for entry in gate.stage_journal]
    fresh = [dict(entry) for entry in rebuilt.stage_journal]
    if recorded != fresh:
        raise CoreValidationError(
            "the rebuilt stage journal is not entry-for-entry identical to "
            "the recorded journal"
        )

    for original_world, rebuilt_world in zip(gate.worlds, rebuilt.worlds):
        if not isinstance(rebuilt_world, EconomicWorld) or (
            rebuilt_world.environment_id != original_world.environment_id
        ):
            raise CoreValidationError(
                "the rebuilt worlds do not reproduce the declared "
                "environment bindings"
            )
        original_state = economic_state(original_world)
        rebuilt_state = economic_state(rebuilt_world)
        if canonical_sha256(original_state) != canonical_sha256(rebuilt_state):
            raise CoreValidationError(
                f"the rebuilt semantic economic projection of environment "
                f"{rebuilt_world.environment_id!r} is not the recorded one"
            )
        original_normalized = normalize_economic_state(
            original_state, original_world
        )
        rebuilt_normalized = normalize_economic_state(rebuilt_state, rebuilt_world)
        if canonical_sha256(original_normalized) != canonical_sha256(
            rebuilt_normalized
        ):
            raise CoreValidationError(
                "the rebuilt normalized economic projection diverges"
            )

    # The invariant battery re-verified on the CURRENT rebuilt state:
    # a tampered rebuild (e.g. a missing contribution measurement) fails
    # closed here even though the recorded digests still match.
    verify_economic_invariants(rebuilt, cross_world=True)

    original_verdict = gate.parity_verdict()
    rebuilt_verdict = rebuilt.parity_verdict()
    if original_verdict.verdict != rebuilt_verdict.verdict:
        raise CoreValidationError(
            "the re-sealed parity verdict diverges from the recorded one"
        )
    for field in (
        "simulation_digest",
        "production_digest",
        "normalization_digest",
    ):
        if getattr(original_verdict, field) != getattr(rebuilt_verdict, field):
            raise CoreValidationError(
                f"the re-sealed parity verdict {field} diverges"
            )
    return rebuilt


def replay_report(gate: EconomicIntegrationGate) -> dict[str, Any]:
    """The deterministic replay report (audit helper, read-only)."""
    rebuilt = rebuild_economic_gate(gate)
    assert_replay_equivalence(gate, rebuilt)
    return {
        "gate_id": gate.gate_id,
        "stage_journal_entries": len(gate.stage_journal),
        "simulation_state_digest": gate.composed_state_digest(
            gate.simulation_world
        ),
        "production_state_digest": gate.composed_state_digest(
            gate.production_world
        ),
        "rebuild_reproduces_journal": True,
        "rebuild_reproduces_projections": True,
    }
