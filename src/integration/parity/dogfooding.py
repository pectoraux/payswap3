"""DOGFOOD-028 — the simulation parity integration gate conformance.

This module is a clearly-marked TEST-SIDE ARTIFACT, not part of the
authoritative package surface. It executes the dogfooding contract of
WORK-028 — *the same state/observations replayed through the simulation
and the production-compatible harness* — by driving the five required
parity scenarios (canonical success, rejection, idempotency, recovery,
finality discipline) through fresh environment pairs and reporting the
typed parity verdicts:

* the shared declared input digest (identical for both environments);
* the simulation and production-compatible result digests (raw,
  environment-bound) and the normalized semantic projection digests
  (identical exactly when parity holds);
* the semantic normalization digest (the frozen rule registry);
* the parity verdict per scenario;
* the epistemic provenance distinction: SIMULATED simulation-world
  evidence vs OBSERVED production-compatible observations.

SECURITY (non-negotiable): the dogfood is fully deterministic and
local — no external provider is contacted, no credentials exist in
this path, no authorization headers or raw provider responses can
appear. The transcript contains only canonical digests, declared
identifiers and semantic facts.
"""

from __future__ import annotations

import sys

from src.core.serialization import canonical_sha256

if __package__ in (None, ""):  # pragma: no cover - direct script execution
    import pathlib

    _REPOSITORY_ROOT = str(pathlib.Path(__file__).resolve().parents[3])
    if _REPOSITORY_ROOT not in sys.path:
        sys.path.insert(0, _REPOSITORY_ROOT)
    __package__ = "src.integration.parity"  # noqa: A001

from . import (
    DeclaredRailScript,
    NORMALIZATION_DIGEST,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    SIMULATION_ENVIRONMENT_ID,
    SimulationParityGate,
    build_environment_pair,
    run_parity_scenario,
    run_scenario_e_finality_discipline,
)

_PAYER = "principal/payer-ig003"
_PAYEE = "principal/merchant-42"
_AMOUNT = 10000


def _scripts(
    key: str,
    *,
    submission: str = "accept",
    query: str = "succeeded",
    native_status: str | None = "STLD",
    finality_claim: str | None = "FINAL",
) -> tuple[DeclaredRailScript, ...]:
    return (
        DeclaredRailScript(
            idempotency_key=key,
            submission=submission,
            query=query,
            native_status=native_status,
            finality_claim=finality_claim,
        ),
    )


def build_transcript() -> tuple[str, str]:
    """Execute the deterministic DOGFOOD-028 conformance transcript."""
    lines: list[str] = [
        "DOGFOOD-028: simulation parity integration gate (IG-003) — the same "
        "state and observations replayed through the simulation and the "
        "production-compatible harness",
        "work_order=WORK-028",
        "architecture=v0.1 (frozen)",
        "gate=IG-003",
        f"simulation_environment={SIMULATION_ENVIRONMENT_ID} "
        "(sandbox class; SIMULATION-fidelity rail; WORK-019 scripted world of "
        "SIMULATED observations)",
        f"production_compatible_environment={PRODUCTION_COMPATIBLE_ENVIRONMENT_ID} "
        "(production class; PRODUCTION-fidelity rail through the same typed "
        "ports; WORK-019 scripted world of OBSERVED observations)",
        "shared_domain=domain/ig003-parity (one domain, two environments)",
        f"semantic_normalization_digest={NORMALIZATION_DIGEST}",
    ]
    checks: list[bool] = []

    # -- scenario A: canonical success --------------------------------------
    scenario_a = run_parity_scenario(
        SimulationParityGate(
            pair=build_environment_pair(scripts=_scripts("ig003-pay-1"))
        ),
        tag="pay-1",
        scripts=_scripts("ig003-pay-1"),
        payer=_PAYER,
        payee=_PAYEE,
        amount_minor=_AMOUNT,
    )
    verdict = scenario_a.verdict
    lines.append(
        "scenario=A-canonical-success: the same declared lifecycle input "
        "(100.00 USD) through both environments to an ESTABLISHED finality "
        "certificate and a RESOLVED obligation"
    )
    lines.append(
        f"shared_input_digest={verdict.shared_input_digest} (identical for "
        "both environments)"
    )
    lines.append(
        f"simulation_result_digest={verdict.simulation.raw_state_digest} "
        "(raw, environment-bound)"
    )
    lines.append(
        f"production_compatible_result_digest={verdict.production.raw_state_digest} "
        "(raw, environment-bound)"
    )
    lines.append(
        "simulation_semantic_projection_digest="
        f"{verdict.simulation.semantic_projection_digest}"
    )
    lines.append(
        "production_compatible_semantic_projection_digest="
        f"{verdict.production.semantic_projection_digest}"
    )
    lines.append(
        "semantic_projection_digests_equal="
        f"{verdict.simulation.semantic_projection_digest == verdict.production.semantic_projection_digest}"
    )
    lines.append(f"parity_verdict={verdict.verdict}")
    lines.append(
        "economic_outcome: 10000 minor units conserved identically through "
        "execution evidence, obligation, discharge posting and finality "
        "certificate in both environments"
    )
    checks.append(verdict.verdict == "PARITY")
    checks.append(
        verdict.simulation.semantic_projection_digest
        == verdict.production.semantic_projection_digest
    )
    checks.append(
        verdict.simulation.raw_state_digest != verdict.production.raw_state_digest
    )
    checks.append(
        scenario_a.facts["simulation"]["finality_state"] == "ESTABLISHED"
        and scenario_a.facts["production"]["finality_state"] == "ESTABLISHED"
    )
    economics = scenario_a.facts["shared"]["economics"]
    checks.append(economics["obligation_amount_minor"] == 10000)
    checks.append(economics["settled_legs"] == 1)
    checks.append(economics["posting_count"] == 1)

    # -- scenario B: rejection ----------------------------------------------
    scenario_b = run_parity_scenario(
        SimulationParityGate(
            pair=build_environment_pair(
                scripts=_scripts(
                    "ig003-reject-1",
                    submission="reject",
                    query="failed",
                    native_status="RJCT",
                    finality_claim=None,
                )
            )
        ),
        tag="reject-1",
        scripts=_scripts(
            "ig003-reject-1",
            submission="reject",
            query="failed",
            native_status="RJCT",
            finality_claim=None,
        ),
        payer=_PAYER,
        payee=_PAYEE,
        amount_minor=_AMOUNT,
        mode="rejection",
    )
    lines.append(
        "scenario=B-rejection: the rail definitively rejects the effect in "
        "both environments — the step fails, the recognition probe fails "
        "closed, no obligation, no economics, no finality"
    )
    lines.append(f"parity_verdict={scenario_b.verdict.verdict}")
    for world in ("simulation", "production"):
        facts = scenario_b.facts[world]
        lines.append(
            f"{world}_rejection: step_state={facts['step_state']} "
            f"submission_status={facts['submission_status']} "
            f"obligations={len(facts['obligation_states'])} "
            f"finality={facts['finality_state']}"
        )
        checks.append(facts["step_state"] == "FAILED")
        checks.append(facts["obligation_states"] == [])
        checks.append(facts["finality_state"] is None)
    checks.append(scenario_b.verdict.verdict == "PARITY")
    checks.append(
        scenario_b.facts["shared"]["recognition_probe_rejected"] is True
    )

    # -- scenario C: idempotency ---------------------------------------------
    scenario_c = run_parity_scenario(
        SimulationParityGate(
            pair=build_environment_pair(scripts=_scripts("ig003-idem-1"))
        ),
        tag="idem-1",
        scripts=_scripts("ig003-idem-1"),
        payer=_PAYER,
        payee=_PAYEE,
        amount_minor=_AMOUNT,
    )
    idempotency = scenario_c.facts["shared"]["idempotency"]
    lines.append(
        "scenario=C-idempotency: the same idempotency key re-driven in both "
        "environments converges without a second rail-side effect or "
        "economic effect"
    )
    for world in ("simulation", "production"):
        probe = idempotency[world]
        lines.append(
            f"{world}_idempotency: re_drive_outcome={probe['re_drive_outcome']} "
            f"re_request_rejected={probe['re_request_rejected']} "
            f"port_calls={probe['port_calls_before']}->{probe['port_calls_after']} "
            f"ledger_keys={probe['ledger_keys']}"
        )
        checks.append(probe["re_drive_outcome"] == "rejected")
        checks.append(probe["port_calls_before"] == 1)
        checks.append(probe["port_calls_after"] == 1)
        checks.append(probe["ledger_keys"] == ["ig003-idem-1"])
    checks.append(scenario_c.verdict.verdict == "PARITY")

    # -- scenario D: recovery -------------------------------------------------
    scenario_d = run_parity_scenario(
        SimulationParityGate(
            pair=build_environment_pair(
                scripts=(
                    DeclaredRailScript(
                        idempotency_key="ig003-recover-1",
                        submission="unknown",
                        query="not-found",
                        native_status=None,
                        finality_claim=None,
                    ),
                    DeclaredRailScript(
                        idempotency_key="ig003-recover-1-retry",
                        submission="accept",
                        query="succeeded",
                        native_status="STLD",
                        finality_claim="FINAL",
                    ),
                )
            )
        ),
        tag="recover-1",
        scripts=(
            DeclaredRailScript(
                idempotency_key="ig003-recover-1",
                submission="unknown",
                query="not-found",
                native_status=None,
                finality_claim=None,
            ),
            DeclaredRailScript(
                idempotency_key="ig003-recover-1-retry",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        ),
        payer=_PAYER,
        payee=_PAYEE,
        amount_minor=_AMOUNT,
        mode="recovery",
    )
    lines.append(
        "scenario=D-recovery: UNKNOWN submission -> reconciliation NOT_FOUND "
        "(retry-safe) -> the same step re-armed under a fresh key -> "
        "SUCCEEDED -> finality, identically in both environments"
    )
    for world in ("simulation", "production"):
        facts = scenario_d.facts[world]
        lines.append(
            f"{world}_recovery: first_submission_state="
            f"{facts['first_submission_state']} reconciliation_outcome="
            f"{facts['reconciliation_outcome']} "
            f"idempotency_keys={facts['idempotency_keys']} "
            f"finality={facts['finality_state']}"
        )
        checks.append(facts["first_submission_state"] == "UNKNOWN")
        checks.append(facts["reconciliation_outcome"] == "NOT_FOUND")
        checks.append(facts["finality_state"] == "ESTABLISHED")
    checks.append(scenario_d.verdict.verdict == "PARITY")

    # -- scenario E: finality discipline --------------------------------------
    scenario_e = run_scenario_e_finality_discipline(
        SimulationParityGate(
            pair=build_environment_pair(scripts=_scripts("ig003-final-1"))
        ),
        payer=_PAYER,
        payee=_PAYEE,
        amount_minor=_AMOUNT,
    )
    lines.append(
        "scenario=E-finality-discipline: at the payment-status checkpoint "
        "(the rail already reported its settled status) NO finality exists "
        "in either environment; finality arrives only after the settlement "
        "chain, from the settlement authority"
    )
    pre_status = scenario_e.facts["shared"]["pre_status"]
    for world in ("simulation", "production"):
        pre = pre_status[world]
        lines.append(
            f"{world}_pre_status: status_recorded={pre['status_recorded']} "
            f"finality_records={pre['finality_records']} "
            f"settled_legs={pre['settled_legs']}"
        )
        checks.append(pre["status_recorded"] is True)
        checks.append(pre["finality_records"] == 0)
        checks.append(pre["settled_legs"] == 0)
    for world in ("simulation", "production"):
        facts = scenario_e.facts[world]
        checks.append(facts["finality_state"] == "ESTABLISHED")
        checks.append(facts["finality_authority"] == "settlement")
    checks.append(scenario_e.verdict.verdict == "PARITY")
    checks.append(
        pre_status["simulation"]["semantic_projection_digest"]
        == pre_status["production"]["semantic_projection_digest"]
    )
    lines.append(f"parity_verdict={scenario_e.verdict.verdict}")

    # -- the epistemic provenance distinction ---------------------------------
    epistemic = scenario_a.verdict.epistemic
    lines.append(
        "epistemic_provenance: simulation_world_evidence_class="
        f"{epistemic.simulation_world_evidence_class} (SIMULATED — the "
        "simulation world consumes WORK-019 SIMULATED observations) while "
        "production_world_evidence_class="
        f"{epistemic.production_world_evidence_class} (OBSERVED — the "
        "production-compatible world consumes OBSERVED observations); "
        "execution-domain external observations are "
        f"{epistemic.execution_observation_class} in both worlds (the frozen "
        "execution contract); the classes are preserved and reported, never "
        "normalized away or relabelled"
    )
    checks.append(epistemic.simulation_world_evidence_class == "SIMULATED")
    checks.append(epistemic.production_world_evidence_class == "OBSERVED")

    invariant_checks = scenario_a.verdict.invariant_checks
    lines.append(
        f"parity_invariant_checks={len(invariant_checks)}/13 dimensions "
        "(protocol identity, state machine, accounting, authorization, "
        "idempotency, failure class, evidence type, provenance, environment "
        "isolation, domain isolation, append-only history, finality "
        "discipline, replay determinism)"
    )
    checks.append(len(invariant_checks) == 13)

    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    passed = all(checks)
    lines.append(
        "classification: DOGFOOD-028: PASS"
        if passed
        else "classification: DOGFOOD-028: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


if __name__ == "__main__":
    text, digest = build_transcript()
    print(text, end="")
    print(f"transcript_sha256={digest}")
