"""DOGFOOD-029 — real extension + real agent proposal on merchant demand.

The conformance experiment required by ``spec/work-orders/WORK-029.md``:
a REAL extension (the in-repo deterministic route-advisor handler)
loaded through the merged WORK-020 extension runtime, a REAL agent
proposal (the frozen R2 PROPOSE tier, backed by registered models and
a bounded mandate) through the merged WORK-021 agents surface, on a
REAL merchant demand scenario (the merged WORK-025 checkout record
boundary), decided by the simulation-first mediation, with:

* the economic contribution proven end-to-end (counterfactual
  baseline, treatment evidence, exact integer revenue share, conserved
  attribution, and cross-currency conservation through the merged
  money FX authority);
* authority containment demonstrated by the negative probe battery
  (tier escalation, forbidden permissions, undeclared resources,
  execute-tier proposals, production agent contexts, model outputs
  masquerading as observations, self-mediation, foreign domains —
  every probe rejected with the composed state unchanged);
* semantic parity of the SAME declared composition across the
  simulation and production-compatible environments, classified by
  the merged IG-003 diff authority;
* deterministic replay/rebuild of the whole composed economics.

The transcript is pure declared data (fixed logical instants, no clock
reads, no entropy): two runs are byte-identical and the digest is the
canonical SHA-256 of the transcript text.
"""

from __future__ import annotations

from src.core.serialization import canonical_sha256

from src.integration.economics.contracts import (
    AGENT_PRINCIPAL,
    CONTRIBUTION_ID,
    DECISION_ID,
    DEMAND_ARTIFACT_ID,
    DEMAND_ASSET,
    DEMAND_SCALE,
    DEMAND_VOLUME_MINOR,
    EXTENSION_ID,
    EXTENSIONS_DOMAIN_ID,
    INSTANCE_ID,
    MANDATE_ID,
    MEDIATION_ID,
    MERCHANT_CHECKOUT_ID,
    MERCHANT_DOMAIN_ID,
    PROPOSAL_ALPHA_ID,
    PROPOSAL_BRAVO_ID,
    TREATMENT_INVOCATION_ID,
)
from src.integration.economics.replay import rebuild_economic_gate, assert_replay_equivalence
from src.integration.economics.scenarios import (
    run_containment_battery,
    run_contribution_integrity_scenario,
    run_economic_scenario,
)


def build_dogfood_transcript() -> tuple[str, str]:
    """Execute the deterministic DOGFOOD-029 conformance experiment."""
    lines: list[str] = [
        "DOGFOOD-029: real extension + real agent proposal on merchant demand",
        "work_order=WORK-029",
        "architecture=v0.1 (frozen)",
        "gate=IG-004 (extension/agent economic integration; required inputs "
        "WORK-020, WORK-021, WORK-028, all complete and merged on main)",
        "composed_surfaces=src.extensions + src.agents + src.merchant + "
        "src.simulation + src.integration.parity (public boundaries only)",
        "environment=env/sandbox-ig004-economics + "
        "env/production-ig004-economics (one domain binding, two "
        "environment bindings; isolated in-memory kernels)",
    ]
    checks: list[bool] = []

    # -- the canonical scenario: composition + simulation-first + parity ----
    gate, verdict = run_economic_scenario()
    simulation = gate.simulation_world
    checkout = simulation.checkout
    assert checkout is not None
    lines.append(
        f"merchant: checkout={MERCHANT_CHECKOUT_ID} "
        f"domain={MERCHANT_DOMAIN_ID} volume={DEMAND_VOLUME_MINOR} minor "
        f"units of {DEMAND_ASSET} (scale {DEMAND_SCALE}) sealed through the "
        "merchant record boundary; demand artifact "
        f"{DEMAND_ARTIFACT_ID} derived for the extension market"
    )
    checks.append(checkout.spec.checkout_id == MERCHANT_CHECKOUT_ID)
    manifest = simulation.runtime.manifest(EXTENSION_ID)
    instance = simulation.runtime.instance(INSTANCE_ID)
    lines.append(
        f"extension: real provider {EXTENSION_ID} code_hash={manifest.code_hash} "
        f"lifecycle={manifest.state.value} installed as "
        f"{INSTANCE_ID} state={instance.state.value} with a "
        "covering capability grant; treatment invocation "
        f"{TREATMENT_INVOCATION_ID} recorded as candidate artifacts"
    )
    checks.append(manifest.state.value == "PUBLISHED")
    checks.append(instance.state.value == "ACTIVE")
    proposals = simulation.proposals
    lines.append(
        f"agent: principal={AGENT_PRINCIPAL} (frozen R2 PROPOSE tier) "
        f"mandate={MANDATE_ID} context="
        f"{simulation.context.context_id if simulation.context else None} "
        f"hypothetical_world_only; proposals={sorted(proposals)} "
        "backed by registered models through the agents surface"
    )
    checks.append(sorted(proposals) == [PROPOSAL_ALPHA_ID, PROPOSAL_BRAVO_ID])
    decision = simulation.decision
    assert decision is not None
    lines.append(
        f"mediation: session={MEDIATION_ID} decision={DECISION_ID} "
        f"simulated_candidates={len(decision.spec.candidates)} "
        "simulation-first (every candidate simulated in a SIMULATION-mode "
        "world before the deterministic policy selects); decision carries "
        "no execution authority"
    )
    checks.append(len(decision.spec.candidates) == len(proposals))
    contribution = simulation.contribution
    assert contribution is not None
    earnings = contribution.earnings.amount_minor
    residual = contribution.incremental - earnings
    lines.append(
        f"contribution: {CONTRIBUTION_ID} baseline(counterfactual)="
        f"{contribution.baseline.value} treatment(simulated evidence "
        f"{TREATMENT_INVOCATION_ID})={contribution.treatment.value} "
        f"incremental={contribution.incremental} verified="
        f"{contribution.verified} earnings={earnings} (exact integer "
        f"revenue share, {contribution.pricing.share_bps} bps) residual="
        f"{residual}; attribution conserved: "
        f"{earnings} + {residual} == {contribution.incremental}"
    )
    checks.append(
        contribution.verified
        and earnings + residual == contribution.incremental
        and residual >= 0
    )
    lines.append(
        f"parity: verdict={verdict.verdict} classified_differences="
        f"{len(verdict.differences)} simulation_digest="
        f"{verdict.simulation_digest[:16]}… production_digest="
        f"{verdict.production_digest[:16]}… (IG-003 diff authority)"
    )
    checks.append(verdict.verdict == "ECONOMIC_PARITY" and not verdict.differences)
    lines.append(f"stage_journal_entries={len(gate.stage_journal)}")

    # -- economic contribution integrity (conservation, no free earnings) --
    integrity = run_contribution_integrity_scenario()
    lines.append(
        f"contribution integrity: unverified treatment earnings="
        f"{integrity['unverified_earnings_minor']} (activity volume never "
        f"earns); shadow activity earnings delta="
        f"{integrity['shadow_earnings_delta_minor']} applied delta="
        f"{integrity['shadow_applied_delta']} (shadow adds nothing)"
    )
    checks.append(integrity["unverified_earnings_minor"] == 0)
    checks.append(
        integrity["shadow_earnings_delta_minor"] == 0
        and integrity["shadow_applied_delta"] == 0
    )
    lines.append(
        f"fx conservation: {integrity['fx_source_minor']} USD -> "
        f"{integrity['fx_target_minor']} GHS at "
        f"{integrity['fx_rate']['rate_numerator']}/"
        f"{integrity['fx_rate']['rate_denominator']} "
        f"residual={integrity['fx_residual_numerator']}/"
        f"{integrity['fx_residual_denominator']}; value conserved="
        f"{integrity['fx_conservation']} through the merged money FX authority"
    )
    checks.append(integrity["fx_conservation"])

    # -- authority containment: the negative probe battery ------------------
    battery = run_containment_battery()
    contained = sum(1 for result in battery if result.contained)
    unchanged = sum(1 for result in battery if result.state_unchanged)
    for result in battery:
        lines.append(
            f"containment probe {result.probe_id}: contained="
            f"{result.contained} state_unchanged={result.state_unchanged}"
        )
    lines.append(
        f"containment battery: {contained}/{len(battery)} probes contained, "
        f"{unchanged}/{len(battery)} with the composed state unchanged "
        "(attempted authority bypass rejected fail-closed)"
    )
    checks.append(contained == len(battery) and unchanged == len(battery))

    # -- deterministic replay/rebuild ----------------------------------------
    rebuilt = rebuild_economic_gate(gate)
    assert_replay_equivalence(gate, rebuilt)
    lines.append(
        "replay: cold rebuild of the composed economics reproduces the "
        f"stage journal ({len(rebuilt.stage_journal)} entries), the composed "
        "state digests, the normalized projections and the re-sealed parity "
        "verdict byte-identically"
    )
    checks.append(
        [dict(entry) for entry in rebuilt.stage_journal]
        == [dict(entry) for entry in gate.stage_journal]
    )

    passed = all(checks)
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    lines.append(
        "classification: DOGFOOD-029: PASS" if passed else "DOGFOOD-029: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest
