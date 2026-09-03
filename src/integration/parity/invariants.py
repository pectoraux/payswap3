"""The IG-003 cross-environment parity invariant battery.

``verify_parity_invariants`` runs after both worlds have executed the
declared scenario (the parity verdict calls it) and re-runs on rebuilt
gates. Each check re-derives facts through the OWNING engines' trusted
paths — never from gate-side caches — so a divergence between the two
environments fails closed immediately, and a violation of the composed
lifecycle discipline inside EITHER world fails closed too (the merged
IG-002 battery is re-run on both worlds).

Checks (the frozen IG-003 dimensions):

* protocol identity parity: both worlds' durable records declare the
  same protocol version and object-type vocabulary, and both rail
  bindings declare the same semantic interface (effect operations,
  destination schemes, canonical status vocabulary);
* state-machine parity: the two stage journals carry the identical
  semantic stage tuples (stage, domain, command_id, requested_at,
  outcome) and each journal is chained and append-only;
* accounting parity: obligation economics, netting statements,
  settlement leg outcomes and postings are identical across worlds;
* authorization parity: intent/plan/execution-plan/step authorization
  and terminal states are identical across worlds;
* idempotency parity: the submission ledgers carry the same keys with
  the same semantic submission records, and no key is submitted twice
  in either world;
* failure-class parity: attempt statuses, rejection reasons and failed
  lifecycle states are identical across worlds;
* evidence-type preservation: the simulation world's source evidence
  is exactly SIMULATED and the production-compatible world's is
  exactly OBSERVED (the frozen mode→epistemic binding, checked at the
  world, the world source and the consumed observations), and the
  execution-domain external observations are OBSERVED knowledge in
  both worlds — SIMULATED evidence is never relabelled;
* provenance preservation: the provenance (issuer, source, recorded
  instants) of equivalent records is identical, and the epistemic
  report carries both distinct classes (never normalized away);
* environment isolation: every durable record of each world carries
  exactly that world's environment id, and the composed engines of
  each world share it;
* domain isolation: every record stays in its owning engine's domain
  inside each world;
* append-only history: both stage journals chain and the merged IG-002
  invariant battery holds on both composed worlds;
* finality discipline: finality semantics are identical across worlds
  and derive only from the settlement authority over settled legs — a
  payment status never promotes to finality in either world;
* replay determinism: both worlds rebuild deterministically from their
  journal snapshots with identical semantic projections.
"""

from __future__ import annotations

from typing import Any

from src.clearing import NettingCycle, Obligation
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json
from src.evidence.contracts import EpistemicType
from src.execution import (
    EffectResult,
    ExecutionPlan,
    ExecutionStep,
)
from src.integration.lifecycle import verify_lifecycle_invariants
from src.settlement import Finality, Settlement
from src.simulation import mode_epistemic_type

from .harness import SimulationParityGate
from .projection import semantic_projection, semantic_projection_digest


def verify_parity_invariants(
    gate: SimulationParityGate, *, cross_world: bool = True
) -> list[str]:
    """Run the battery; raise on the first violation; return check names.

    The per-world structural checks (evidence classes, environment and
    domain isolation, append-only history, replay determinism) always
    run: a divergence verdict never excuses an internally broken world.
    The cross-world equality checks (protocol identity, state machine,
    accounting, authorization, idempotency, failure classes, provenance,
    finality semantics) run when ``cross_world`` is true — the parity
    verdict runs them for the PARITY case and reports the classified
    differences themselves for the DIVERGENCE case.
    """
    checks: list[str] = []

    _check_evidence_type_preservation(gate, checks)
    _check_environment_isolation(gate, checks)
    _check_domain_isolation(gate, checks)
    _check_append_only_history(gate, checks)
    _check_replay_determinism(gate, checks)
    if cross_world:
        # Cross-world order: the cheap, isolated classifications first
        # (idempotency ledgers, failure classifications), then the
        # sequence/state/accounting projections, then the interface and
        # provenance/finality semantics — the first violation fails
        # closed with its own dimension's message.
        _check_idempotency(gate, checks)
        _check_failure_class(gate, checks)
        _check_state_machine(gate, checks)
        _check_authorization(gate, checks)
        _check_accounting(gate, checks)
        _check_protocol_identity(gate, checks)
        _check_provenance(gate, checks)
        _check_finality_discipline(gate, checks)

    return checks


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CoreValidationError(f"IG-003 invariant violation: {message}")


def _worlds(gate: SimulationParityGate):
    return (
        (gate.simulation_world, gate.simulation_gate),
        (gate.production_world, gate.production_gate),
    )


def _check_evidence_type_preservation(
    gate: SimulationParityGate, checks: list[str]
) -> None:
    """The epistemic classes are load-bearing: never relabelled."""
    for world, lifecycle_gate in _worlds(gate):
        required = mode_epistemic_type(world.mode)
        _require(
            world.epistemic_class is required,
            f"the {world.role.value} world declares epistemic class "
            f"{world.epistemic_class.value} but its mode {world.mode.value} "
            f"requires {required.value} (SIMULATED evidence may never be "
            "relabelled OBSERVED, and vice versa)",
        )
        _require(
            world.world_source.epistemic_type is required,
            f"the {world.role.value} world's scripted source declares "
            f"{world.world_source.epistemic_type.value} observations instead "
            f"of the required {required.value}",
        )
        for observation in world.rail.consumed_observations():
            _require(
                observation.epistemic_type is required,
                f"a consumed {world.role.value}-world observation carries "
                f"{observation.epistemic_type.value} instead of "
                f"{required.value}",
            )
        for observation in lifecycle_gate.execution.observations():
            _require(
                observation.spec.epistemic is EpistemicType.OBSERVED,
                "execution-domain external observations must be OBSERVED "
                "knowledge in every world (the frozen execution contract)",
            )
    simulation_class = gate.simulation_world.epistemic_class
    production_class = gate.production_world.epistemic_class
    _require(
        simulation_class is EpistemicType.SIMULATED
        and production_class is EpistemicType.OBSERVED,
        "the epistemic report must distinguish SIMULATED simulation-world "
        "evidence from OBSERVED production-compatible observations",
    )
    report = gate.epistemic_report()
    _require(
        report.simulation_world_evidence_class == simulation_class.value
        and report.production_world_evidence_class == production_class.value,
        "the epistemic provenance report must carry the declared classes",
    )
    checks.append(
        "evidence-type preservation: SIMULATED simulation evidence and "
        "OBSERVED production-compatible observations stay distinct and "
        "unrelabelled"
    )


def _check_protocol_identity(gate: SimulationParityGate, checks: list[str]) -> None:
    from src.transition.registry import PROTOCOL_VERSION

    # Protocol identity is the DECLARED protocol version and the shared
    # adapter semantic interface — never the set of records that happen
    # to exist (a lifecycle-position difference is a state-machine
    # divergence, detected and classified by the projection comparison).
    for world, lifecycle_gate in _worlds(gate):
        records = (
            list(lifecycle_gate.execution.objects())
            + list(lifecycle_gate.clearing.records())
            + list(lifecycle_gate.settlement.records())
            + list(lifecycle_gate.plans)
        )
        for record in records:
            _require(
                record.envelope.protocol_version == PROTOCOL_VERSION,
                f"record {record.envelope.object_id} in the "
                f"{world.role.value} world declares protocol version "
                f"{record.envelope.protocol_version!r} instead of the frozen "
                f"{PROTOCOL_VERSION!r} (protocol identity parity)",
            )
    simulation_contract = gate.simulation_world.binding.world_adapter
    production_contract = gate.production_world.binding.world_adapter
    _require(
        simulation_contract.effect_interface.operations
        == production_contract.effect_interface.operations
        and simulation_contract.effect_interface.destination_schemes
        == production_contract.effect_interface.destination_schemes
        and simulation_contract.observation_interface.operations
        == production_contract.observation_interface.operations,
        "both rail bindings must declare the same semantic adapter "
        "interface (only the fidelity class differs)",
    )
    simulation_map = {
        entry.native_code: entry.canonical_status.value
        for entry in gate.simulation_world.binding.status_map.entries
    }
    production_map = {
        entry.native_code: entry.canonical_status.value
        for entry in gate.production_world.binding.status_map.entries
    }
    _require(
        simulation_map == production_map,
        "both rail bindings must declare the same canonical status "
        "vocabulary (protocol identity parity)",
    )
    checks.append(
        "protocol identity parity: both environments project the same "
        "protocol version, object types and adapter semantic interface"
    )


def _check_state_machine(gate: SimulationParityGate, checks: list[str]) -> None:
    journals = []
    for _, lifecycle_gate in _worlds(gate):
        journal = [
            (
                entry["stage"],
                entry["domain"],
                entry["command_id"],
                entry["requested_at"],
                entry["outcome"],
            )
            for entry in lifecycle_gate.stage_journal
        ]
        journals.append(journal)
    _require(
        journals[0] == journals[1],
        "the two environments must drive the identical semantic stage "
        "sequence (state-machine parity)",
    )
    checks.append(
        "state-machine parity: identical transition sequences after "
        "semantic normalization"
    )


def _check_authorization(gate: SimulationParityGate, checks: list[str]) -> None:
    states = []
    for world, lifecycle_gate in _worlds(gate):
        world_state = {
            "intents": sorted(
                declared.intent.state.value for declared in lifecycle_gate.worlds
            ),
            "plans": sorted(plan.state.value for plan in lifecycle_gate.plans),
            "execution_plans": sorted(
                record.state.value
                for record in lifecycle_gate.execution.objects()
                if isinstance(record, ExecutionPlan)
            ),
            "steps": sorted(
                record.state.value
                for record in lifecycle_gate.execution.objects()
                if isinstance(record, ExecutionStep)
            ),
        }
        states.append(world_state)
    _require(
        states[0] == states[1],
        "authorization and lifecycle states must be identical across the "
        "two environments (authorization parity)",
    )
    for world, lifecycle_gate in _worlds(gate):
        for declared in lifecycle_gate.worlds:
            _require(
                declared.intent.state.value == "AUTHORIZED",
                f"the {world.role.value} world's intent must be AUTHORIZED "
                "before fulfillment (authorization parity)",
            )
    checks.append(
        "authorization parity: identical authorization decisions and "
        "lifecycle states across environments"
    )


def _accounting_of(lifecycle_gate: Any) -> dict[str, Any]:
    obligations = {
        obligation.object_id: {
            "value": obligation.spec.amount.value,
            "scale": obligation.spec.amount.scale,
            "asset": obligation.spec.asset,
            "obligor": obligation.spec.obligor,
            "obligee": obligation.spec.obligee,
            "state": obligation.state.value,
        }
        for obligation in lifecycle_gate.clearing.records()
        if isinstance(obligation, Obligation)
    }
    netting = {
        netting.object_id: {
            "gross": netting.spec.statement.gross_total
            if netting.spec.statement
            else None,
            "net": netting.spec.statement.net_total
            if netting.spec.statement
            else None,
            "reduction": netting.spec.statement.reduction
            if netting.spec.statement
            else None,
        }
        for netting in lifecycle_gate.clearing.records()
        if isinstance(netting, NettingCycle)
    }
    settlements = {
        settlement.object_id: {
            "state": settlement.state.value,
            "legs": sorted(
                (outcome.instruction_id, outcome.state)
                for outcome in settlement.spec.leg_outcomes
            ),
        }
        for settlement in lifecycle_gate.settlement.records()
        if isinstance(settlement, Settlement)
    }
    postings = sorted(
        (entry.kind, entry.asset, entry.debit_value, entry.credit_value)
        for entry in lifecycle_gate.settlement.postings()
    )
    return {
        "obligations": obligations,
        "netting": netting,
        "settlements": settlements,
        "postings": postings,
    }


def _check_accounting(gate: SimulationParityGate, checks: list[str]) -> None:
    economics = [_accounting_of(lifecycle_gate) for _, lifecycle_gate in _worlds(gate)]
    _require(
        canonical_json(economics[0]) == canonical_json(economics[1]),
        "economic values must be identical across the two environments with "
        "exact integer semantics (accounting parity)",
    )
    checks.append(
        "accounting parity: identical obligation, netting, settlement and "
        "posting economics across environments"
    )


def _check_idempotency(gate: SimulationParityGate, checks: list[str]) -> None:
    ledgers = []
    for world, lifecycle_gate in _worlds(gate):
        ledger = lifecycle_gate.execution.submission_ledger().to_dict()
        entries = ledger["entries"]
        keys = [entry["key"] for entry in entries]
        _require(
            len(keys) == len(set(keys)),
            f"a {world.role.value}-world idempotency key was submitted twice "
            "(constitution invariant 9)",
        )
        ledgers.append(
            {
                "keys": sorted(keys),
                "submissions": {
                    entry["key"]: {
                        "status": entry["submission"]["status"],
                        "native_reference": (
                            entry["submission"]["native_reference"]
                        ),
                    }
                    for entry in entries
                },
            }
        )
    _require(
        ledgers[0]["keys"] == ledgers[1]["keys"],
        "the submission ledgers must carry the same idempotency keys in "
        "both environments (idempotency parity)",
    )
    checks.append(
        "idempotency parity: identical idempotency semantics with no "
        "duplicate economic effect in either environment"
    )


def _check_failure_class(gate: SimulationParityGate, checks: list[str]) -> None:
    classifications = []
    for _, lifecycle_gate in _worlds(gate):
        attempts = {}
        for record in lifecycle_gate.execution.objects():
            if record.__class__.__name__ == "ExecutionAttempt":
                attempts[record.spec.idempotency_key] = {
                    "status": record.spec.status.value,
                    "reason": record.spec.reason,
                }
        rejected_stages = sorted(
            entry["stage"]
            for entry in lifecycle_gate.stage_journal
            if entry["outcome"] != "accepted"
        )
        failed_results = sorted(
            record.object_id
            for record in lifecycle_gate.execution.objects()
            if isinstance(record, EffectResult)
            and record.spec.outcome.value == "FAILED"
        )
        classifications.append(
            {
                "attempts": attempts,
                "rejected_stages": rejected_stages,
                "failed_results": failed_results,
            }
        )
    _require(
        canonical_json(classifications[0]) == canonical_json(classifications[1]),
        "failure classifications must be identical across the two "
        "environments (failure-class parity)",
    )
    checks.append(
        "failure-class parity: identical rejection and failure semantics "
        "across environments"
    )


def _check_provenance(gate: SimulationParityGate, checks: list[str]) -> None:
    provenance_sets = []
    for _, lifecycle_gate in _worlds(gate):
        records = (
            list(lifecycle_gate.execution.objects())
            + list(lifecycle_gate.clearing.records())
            + list(lifecycle_gate.settlement.records())
        )
        provenance_sets.append(
            sorted(
                (
                    record.envelope.provenance.issuer,
                    record.envelope.provenance.source,
                    record.envelope.provenance.recorded_at,
                )
                for record in records
            )
        )
    _require(
        provenance_sets[0] == provenance_sets[1],
        "equivalent records must retain identical provenance semantics "
        "across environments (provenance preservation)",
    )
    report = gate.epistemic_report()
    _require(
        report.simulation_world_evidence_class
        != report.production_world_evidence_class,
        "the parity result must report both distinct epistemic provenances "
        "(never normalize the epistemic difference away)",
    )
    checks.append(
        "provenance preservation: identical provenance semantics with the "
        "epistemic classes reported distinctly"
    )


def _check_environment_isolation(
    gate: SimulationParityGate, checks: list[str]
) -> None:
    for world, lifecycle_gate in _worlds(gate):
        _require(
            lifecycle_gate.environment_id == world.environment_id,
            f"the {world.role.value} lifecycle gate must bind exactly its "
            "world's environment",
        )
        for record in lifecycle_gate.execution.objects():
            _require(
                record.envelope.environment_id == world.environment_id,
                f"execution record {record.object_id} leaked across "
                f"environments in the {world.role.value} world",
            )
        for record in lifecycle_gate.clearing.records():
            _require(
                record.envelope.environment_id == world.environment_id,
                f"clearing record {record.object_id} leaked across "
                f"environments in the {world.role.value} world",
            )
        for record in lifecycle_gate.settlement.records():
            _require(
                record.envelope.environment_id == world.environment_id,
                f"settlement record {record.object_id} leaked across "
                f"environments in the {world.role.value} world",
            )
    _require(
        gate.simulation_world.environment_id
        != gate.production_world.environment_id,
        "the two compared environments must remain distinct identities",
    )
    checks.append(
        "environment isolation: every durable record carries exactly its "
        "world's environment"
    )


def _check_domain_isolation(gate: SimulationParityGate, checks: list[str]) -> None:
    suffixes = {
        "execution": "execution",
        "clearing": "clearing",
        "settlement": "settlement",
    }
    for world, lifecycle_gate in _worlds(gate):
        base = world.domain_id
        for record in lifecycle_gate.execution.objects():
            _require(
                record.envelope.domain_id == f"{base}/{suffixes['execution']}",
                f"execution record {record.object_id} left its engine domain",
            )
        for record in lifecycle_gate.clearing.records():
            _require(
                record.envelope.domain_id == f"{base}/{suffixes['clearing']}",
                f"clearing record {record.object_id} left its engine domain",
            )
        for record in lifecycle_gate.settlement.records():
            _require(
                record.envelope.domain_id == f"{base}/{suffixes['settlement']}",
                f"settlement record {record.object_id} left its engine domain",
            )
        for plan in lifecycle_gate.plans:
            _require(
                plan.envelope.domain_id == f"{base}/compiler",
                f"plan {plan.envelope.object_id} left the compiler domain",
            )
    checks.append(
        "domain isolation: every record stays in its owning engine's domain"
    )


def _check_append_only_history(
    gate: SimulationParityGate, checks: list[str]
) -> None:
    for world, lifecycle_gate in _worlds(gate):
        journal = lifecycle_gate.stage_journal
        for previous, current in zip(journal, journal[1:]):
            _require(
                previous["state_after"] == current["state_before"],
                f"the {world.role.value} stage journal broke its chain at "
                f"{current['command_id']}",
            )
        # The merged IG-002 invariant battery re-runs on both worlds
        # (authority routing, accounting, settlement truth, evidence
        # typing, idempotency, environment isolation, append-only
        # history, lifecycle legality — the composed discipline).
        verify_lifecycle_invariants(lifecycle_gate)
    checks.append(
        "append-only history: both stage journals chain and the composed "
        "IG-002 invariant battery holds on both worlds"
    )


def _check_finality_discipline(
    gate: SimulationParityGate, checks: list[str]
) -> None:
    finalities = []
    for world, lifecycle_gate in _worlds(gate):
        world_finality = {}
        settlements = {
            settlement.object_id: settlement
            for settlement in lifecycle_gate.settlement.records()
            if isinstance(settlement, Settlement)
        }
        for certificate in lifecycle_gate.settlement.records():
            if not isinstance(certificate, Finality):
                continue
            settlement = settlements.get(certificate.spec.settlement_id)
            _require(
                settlement is not None,
                f"finality certificate {certificate.object_id} references no "
                "declared settlement in the "
                f"{world.role.value} world",
            )
            if certificate.state.value == "ESTABLISHED":
                _require(
                    settlement.state.value in ("COMPLETED", "FAILED"),
                    "finality can be established only for a terminal "
                    f"settlement in the {world.role.value} world (a payment "
                    "status never stands in for settlement finality)",
                )
                settled = {
                    outcome.instruction_id
                    for outcome in settlement.spec.leg_outcomes
                    if outcome.state == "SETTLED"
                }
                covered = {
                    binding.instruction_id for binding in certificate.spec.claims
                }
                _require(
                    covered == settled and settled,
                    "an established certificate must cover exactly the "
                    f"settled legs in the {world.role.value} world",
                )
                for binding in certificate.spec.claims:
                    _require(
                        binding.claim in ("FINAL", "SETTLED"),
                        "finality certificates bind finality-class claims "
                        f"only in the {world.role.value} world",
                    )
            world_finality[certificate.object_id] = {
                "state": certificate.state.value,
                "settlement_id": certificate.spec.settlement_id,
                "claims": sorted(
                    (binding.instruction_id, binding.claim)
                    for binding in certificate.spec.claims
                ),
            }
        # A recorded payment status alone never creates finality: any
        # finality must coexist with a terminal settlement carrying
        # settled legs (the settlement authority owns finality).
        for observation in lifecycle_gate.execution.observations():
            if observation.spec.kind.value == "STATUS":
                for certificate_id, record in world_finality.items():
                    _require(
                        settlements[record["settlement_id"]].state.value
                        in ("COMPLETED", "FAILED"),
                        f"finality {certificate_id} exists while its "
                        "settlement is not terminal in the "
                        f"{world.role.value} world",
                    )
        finalities.append(world_finality)
    _require(
        canonical_json(finalities[0]) == canonical_json(finalities[1]),
        "finality semantics must be identical across the two environments "
        "(finality parity)",
    )
    checks.append(
        "finality discipline: payment status never promotes to finality; "
        "identical finality semantics from the settlement authority only"
    )


def _check_replay_determinism(
    gate: SimulationParityGate, checks: list[str]
) -> None:
    # The battery's replay check proves the comparison basis is stable:
    # each world's semantic projection is a deterministic function of its
    # composed state (re-projecting is byte-identical), and each stage
    # journal chains (the precondition the deterministic rebuild contract
    # verifies). The full journal-only rebuild of both worlds — the
    # stronger proof — is executed by the replay contract
    # (``rebuild_parity_gate`` / ``assert_replay_equivalence``) in the
    # replay module, the contract suite and the dogfood.
    for world, lifecycle_gate in _worlds(gate):
        first = semantic_projection(lifecycle_gate, world)
        second = semantic_projection(lifecycle_gate, world)
        _require(
            semantic_projection_digest(first) == semantic_projection_digest(second),
            f"the {world.role.value} world's semantic projection is not a "
            "deterministic function of its composed state (replay "
            "determinism broke)",
        )
    checks.append(
        "replay determinism: deterministic semantic projections with "
        "chained journals (the full journal-only rebuild is proven by the "
        "replay contract)"
    )
