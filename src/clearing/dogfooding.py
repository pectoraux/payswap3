"""DOGFOOD-015 — the Work Order's mandated dogfooding experiment.

**Reciprocal cross-border demand through clearing, proving gross-to-net
capital reduction.**

Scenario (every instant is declared data; the module is deterministic
and runnable as ``python3 -m src.clearing.dogfooding``):

* Four payout operators run reciprocal cross-border payment corridors:
  ``principal/accra-payout`` (Ghana), ``principal/nyc-payout`` (US),
  ``principal/lon-payout`` (UK) and ``principal/tema-payout`` (Ghana,
  regional). Inter-participant corridor obligations settle in the
  corridor settlement asset: the transatlantic pool settles in USD
  (``value/asset/usd-clearing``), the regional pool settles in GHS
  (``value/asset/ghs-clearing``).
* Clearing cycle C1 recognizes the transatlantic pool's reciprocal
  demand: US→Ghana remittances (NYC owes ACCRA USD), Ghana→US
  remittances (ACCRA owes NYC USD), UK→US and US→UK remittances, and
  Ghana↔UK remittances — plus the regional GHS reciprocal pair
  ACCRA↔TEMA. Every obligation is recognized from a sealed
  ``SUCCEEDED`` execution effect result (built through the execution
  domain's public factory) and derived by the engine — never trusted
  from the command payload.
* Bilateral netting cycle N1 offsets the reciprocal pairs per asset and
  values the statement in USD through the money domain's exact FX
  authority (declared GHS→USD rate, explicit FLOOR rounding).
* Clearing cycle C2 recognizes the regional GHS reciprocal triangle
  (ACCRA↔TEMA↔ACCRA-2/TEMA? — ACCRA, TEMA and NYC's regional leg), and
  multilateral netting cycle N2 reclassifies it into per participant
  net funding positions with the conservation proof.
* The experiment proves: per-asset gross→net reduction, multilateral
  position conservation, common-unit capital reduction, digest-bound
  resolutions, journal-only rebuild equivalence and snapshot
  round-trip stability.

This module is a TEST-SIDE ARTIFACT of the clearing domain (the
sibling convention): it is not imported by the authoritative package
surface and contributes no domain semantics.
"""

from __future__ import annotations

import sys
from typing import Any

from src.core.envelope import Provenance
from src.core.serialization import canonical_json
from src.execution.contracts import EffectOutcome
from src.execution.effects import EffectResultSpec, make_result_record

from .engine import ClearingEngine

ENVIRONMENT_ID = "env/dogfood-clearing-015"
DOMAIN_ID = "domain/clearing"
EXECUTION_DOMAIN_ID = "domain/execution"

ACCRA = "principal/accra-payout"
NYC = "principal/nyc-payout"
LON = "principal/lon-payout"
TEMA = "principal/tema-payout"

USD = "value/asset/usd-usdclearing"
GHS = "value/asset/ghs-ghsclearing"

#: Declared FX rate for the common-unit valuation (money domain
#: authority: GHS→USD at exactly 1/15, canonical reduced form).
GHS_TO_USD_NUMERATOR = 1
GHS_TO_USD_DENOMINATOR = 15

#: Every instant is declared data (no clock reads anywhere).
T0 = "2026-09-03T08:00:00Z"

#: The transatlantic reciprocal demand: (payer, payee, asset, minor
#: units at scale 2). US→Ghana remittances reimburse ACCRA's local GHS
#: payouts in USD; Ghana→US remittances reimburse NYC's local USD
#: payouts; UK↔US and Ghana↔UK likewise — all USD-settled. The regional
#: reciprocal pair (ACCRA↔TEMA) settles in GHS.
C1_DEMAND = (
    (NYC, ACCRA, USD, 1_200_000),
    (NYC, ACCRA, USD, 750_000),
    (NYC, ACCRA, USD, 550_000),
    (ACCRA, NYC, USD, 300_000),
    (ACCRA, NYC, USD, 200_000),
    (LON, NYC, USD, 400_000),
    (NYC, LON, USD, 550_000),
    (ACCRA, LON, USD, 250_000),
    (LON, ACCRA, USD, 150_000),
    (ACCRA, TEMA, GHS, 400_000),
    (TEMA, ACCRA, GHS, 250_000),
)

#: The regional reciprocal GHS triangle: ACCRA↔TEMA plus NYC's regional
#: leg settling in GHS.
C2_DEMAND = (
    (ACCRA, TEMA, GHS, 400_000),
    (TEMA, ACCRA, GHS, 250_000),
    (TEMA, NYC, GHS, 120_000),
    (NYC, TEMA, GHS, 80_000),
    (NYC, ACCRA, GHS, 60_000),
    (ACCRA, NYC, GHS, 90_000),
)


def _effect_result_for(
    pool: str, index: int, payer: str, payee: str, asset: str, minor: int
) -> dict[str, Any]:
    """Build one sealed SUCCEEDED execution effect result (public path)."""
    request_id = f"plan/dogfood-015-{pool}-{index}/request/1"
    step_id = f"plan/dogfood-015-{pool}-{index}/step-1"
    result_id = f"{request_id}/result"
    spec = EffectResultSpec(
        result_id=result_id,
        request_id=request_id,
        step_id=step_id,
        effect_type="payment/submit",
        outcome=EffectOutcome.SUCCEEDED,
        native_reference=f"rail/ref-dogfood-015-{index}",
        error_code=None,
        observed_at=T0,
        request_digest="f" * 64,
        detail={
            "payer": payer,
            "payee": payee,
            "asset": asset,
            "amount": {"value": minor, "scale": 2, "asset": asset},
        },
    )
    record = make_result_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN_ID,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T0,
        ),
    )
    return record.to_dict()


def _reciprocal_pool(
    engine: ClearingEngine,
    *,
    cycle_id: str,
    command_prefix: str,
    demand: tuple,
    due_from: str,
    due_until: str,
) -> list[str]:
    """Recognize and validate one reciprocal demand pool into the cycle."""
    engine.create_cycle(
        command_id=f"{command_prefix}-cycle",
        requested_at=T0,
        cycle_id=cycle_id,
        opens_at=T0,
        closes_at=due_from,
        description="dogfood reciprocal cross-border pool",
    )
    obligation_ids: list[str] = []
    for index, (payer, payee, asset, minor) in enumerate(demand, start=1):
        effect_result = _effect_result_for(
            command_prefix, index, payer, payee, asset, minor
        )
        engine.recognize_obligation(
            command_id=f"{command_prefix}-recognize-{index}",
            requested_at=T0,
            cycle_id=cycle_id,
            effect_result=effect_result,
            due_from=due_from,
            due_until=due_until,
        )
        obligation_ids.append(
            f"plan/dogfood-015-{command_prefix}-{index}/request/1/result/obligation"
        )
    for index, obligation_id in enumerate(obligation_ids, start=1):
        engine.validate_obligation(
            command_id=f"{command_prefix}-validate-{index}",
            requested_at=T0,
            obligation_id=obligation_id,
        )
    engine.validate_cycle(
        command_id=f"{command_prefix}-cycle-validate",
        requested_at=T0,
        cycle_id=cycle_id,
    )
    engine.finalize_cycle(
        command_id=f"{command_prefix}-cycle-finalize",
        requested_at=T0,
        cycle_id=cycle_id,
    )
    return obligation_ids


def build_transcript() -> dict[str, Any]:
    """Run DOGFOOD-015 and produce the canonical transcript."""
    engine = ClearingEngine(
        environment_id=ENVIRONMENT_ID,
        domain_id=DOMAIN_ID,
    )

    # -- clearing cycle C1: the transatlantic + regional reciprocal pool --
    c1_members = _reciprocal_pool(
        engine,
        cycle_id="clearing/cycle/dogfood-015-c1",
        command_prefix="c1",
        demand=C1_DEMAND,
        due_from="2026-09-03T12:00:00Z",
        due_until="2026-09-04T12:00:00Z",
    )
    c1_statement = engine.cycle("clearing/cycle/dogfood-015-c1").spec.statement
    assert c1_statement is not None

    # -- bilateral netting N1 over C1 (multi-asset, USD-valued) ----------
    engine.create_netting(
        command_id="n1-create",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n1",
        mode="BILATERAL",
        due_from="2026-09-03T12:00:00Z",
        due_until="2026-09-04T12:00:00Z",
    )
    for index, obligation_id in enumerate(c1_members, start=1):
        engine.add_netting_member(
            command_id=f"n1-add-{index}",
            requested_at=T0,
            netting_id="clearing/netting/dogfood-015-n1",
            obligation_id=obligation_id,
        )
    engine.calculate_netting(
        command_id="n1-calculate",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n1",
        valuation={
            "base_currency": "USD",
            "rounding": "FLOOR",
            "asset_currencies": [[USD, "USD"], [GHS, "GHS"]],
            "rates": [
                {
                    "source_currency": "GHS",
                    "source_scale": 2,
                    "target_currency": "USD",
                    "target_scale": 2,
                    "rate_numerator": GHS_TO_USD_NUMERATOR,
                    "rate_denominator": GHS_TO_USD_DENOMINATOR,
                }
            ],
        },
    )
    n1 = engine.netting("clearing/netting/dogfood-015-n1")
    n1_statement = n1.spec.statement
    assert n1_statement is not None
    engine.finalize_netting(
        command_id="n1-finalize",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n1",
    )
    n1_final = engine.netting("clearing/netting/dogfood-015-n1")
    n1_pairs = [
        {
            "obligor": pair.obligor,
            "obligee": pair.obligee,
            "asset": group.asset,
            "forward_minor": pair.forward,
            "issued_obligation_id": pair.issued_obligation_id,
        }
        for group in n1_statement.groups
        for pair in group.pairs
    ]

    # -- clearing cycle C2: the regional reciprocal GHS triangle ---------
    c2_members = _reciprocal_pool(
        engine,
        cycle_id="clearing/cycle/dogfood-015-c2",
        command_prefix="c2",
        demand=C2_DEMAND,
        due_from="2026-09-03T12:00:00Z",
        due_until="2026-09-04T12:00:00Z",
    )

    # -- multilateral netting N2 over C2 -----------------------------------
    engine.create_netting(
        command_id="n2-create",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n2",
        mode="MULTILATERAL",
        due_from="2026-09-03T12:00:00Z",
        due_until="2026-09-04T12:00:00Z",
    )
    for index, obligation_id in enumerate(c2_members, start=1):
        engine.add_netting_member(
            command_id=f"n2-add-{index}",
            requested_at=T0,
            netting_id="clearing/netting/dogfood-015-n2",
            obligation_id=obligation_id,
        )
    engine.calculate_netting(
        command_id="n2-calculate",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n2",
        valuation={
            "base_currency": "USD",
            "rounding": "FLOOR",
            "asset_currencies": [[GHS, "GHS"]],
            "rates": [
                {
                    "source_currency": "GHS",
                    "source_scale": 2,
                    "target_currency": "USD",
                    "target_scale": 2,
                    "rate_numerator": GHS_TO_USD_NUMERATOR,
                    "rate_denominator": GHS_TO_USD_DENOMINATOR,
                }
            ],
        },
    )
    n2 = engine.netting("clearing/netting/dogfood-015-n2")
    n2_statement = n2.spec.statement
    assert n2_statement is not None
    engine.finalize_netting(
        command_id="n2-finalize",
        requested_at=T0,
        netting_id="clearing/netting/dogfood-015-n2",
    )
    n2_final = engine.netting("clearing/netting/dogfood-015-n2")
    n2_positions = [
        {
            "participant": position.participant,
            "net_minor": position.net,
            "asset": group.asset,
        }
        for group in n2_statement.groups
        for position in group.positions
    ]

    # -- transformation completeness ---------------------------------------
    rebuilt = ClearingEngine.rebuild_from_journal(
        environment_id=ENVIRONMENT_ID,
        domain_id=DOMAIN_ID,
        journal=engine.journal,
    )
    live_index = engine.snapshot_state()["index"]
    rebuilt_index = rebuilt.snapshot_state()["index"]
    journal_rebuild_index_match = live_index == rebuilt_index

    snapshot = engine.snapshot_state()
    restored_engine = ClearingEngine(
        environment_id=ENVIRONMENT_ID, domain_id=DOMAIN_ID
    )
    restored_engine.restore_state(snapshot)
    snapshot_round_trip_match = restored_engine.snapshot_state() == snapshot

    # -- gross-to-net capital reduction proof ------------------------------
    c1_gross_usd_minor = sum(
        entry.gross for entry in c1_statement.gross_by_asset if entry.asset == USD
    )
    c1_gross_ghs_minor = sum(
        entry.gross for entry in c1_statement.gross_by_asset if entry.asset == GHS
    )
    n1_group_by_asset = {group.asset: group for group in n1_statement.groups}
    n1_usd_gross = n1_group_by_asset[USD].gross
    n1_usd_net = n1_group_by_asset[USD].net_total
    n1_ghs_gross = n1_group_by_asset[GHS].gross
    n1_ghs_net = n1_group_by_asset[GHS].net_total
    assert n1_statement.valuation is not None
    n1_valuation = n1_statement.valuation

    c2_gross_ghs_minor = sum(
        entry.gross for entry in engine.cycle("clearing/cycle/dogfood-015-c2").spec.statement.gross_by_asset
    )
    n2_group = n2_statement.groups[0]
    n2_ghs_gross = n2_group.gross
    n2_ghs_net = n2_group.net_total
    assert n2_statement.valuation is not None
    n2_valuation = n2_statement.valuation

    total_gross_base = n1_valuation.gross_base + n2_valuation.gross_base
    total_net_base = n1_valuation.net_base + n2_valuation.net_base
    total_reduction_base = total_gross_base - total_net_base

    n1_resolved_members = sum(
        1
        for obligation_id in c1_members
        if engine.obligation(obligation_id).state.value == "RESOLVED"
    )
    n1_issued_ids = [
        pair["issued_obligation_id"]
        for pair in n1_pairs
        if pair["issued_obligation_id"] is not None
    ]
    issued_net_obligations = {
        obligation_id: {
            "state": engine.obligation(obligation_id).state.value,
            "amount_minor": engine.obligation(obligation_id).spec.amount.value,
            "asset": engine.obligation(obligation_id).spec.asset,
            "obligor": engine.obligation(obligation_id).spec.obligor,
            "obligee": engine.obligation(obligation_id).spec.obligee,
            "source_kind": engine.obligation(obligation_id).spec.source_kind,
        }
        for obligation_id in n1_issued_ids
    }
    n2_resolved_members = sum(
        1
        for obligation_id in c2_members
        if engine.obligation(obligation_id).state.value == "RESOLVED"
    )

    checks = {
        "c1_pool_finalized": engine.cycle("clearing/cycle/dogfood-015-c1").state.value
        == "FINALIZED",
        "c1_members_total": len(c1_members) == len(C1_DEMAND),
        "c1_gross_usd_minor": c1_gross_usd_minor == 4_350_000,
        "c1_gross_ghs_minor": c1_gross_ghs_minor == 650_000,
        "n1_statement_digest_bound": all(
            engine.obligation(obligation_id).spec.resolution is not None
            and engine.obligation(obligation_id).spec.resolution.digest
            == n1_statement.digest
            for obligation_id in c1_members
        ),
        "n1_all_members_resolved": n1_resolved_members == len(C1_DEMAND),
        "n1_usd_bilateral_offset": (n1_usd_gross, n1_usd_net) == (4_350_000, 2_250_000),
        "n1_ghs_bilateral_offset": (n1_ghs_gross, n1_ghs_net) == (650_000, 150_000),
        "n1_issued_obligations": len(n1_issued_ids) == 4,
        "n1_issued_net_obligations_recognized": all(
            entry["state"] == "RECOGNIZED"
            and entry["source_kind"] == "NETTING_ISSUANCE"
            for entry in issued_net_obligations.values()
        ),
        "n1_valued_in_usd_base": (
            n1_valuation.gross_base,
            n1_valuation.net_base,
            n1_valuation.reduction_base,
        )
        == (4_350_000 + 43_333, 2_250_000 + 10_000, 2_100_000 + 33_333),
        "c2_pool_finalized": engine.cycle("clearing/cycle/dogfood-015-c2").state.value
        == "FINALIZED",
        "c2_members_total": len(c2_members) == len(C2_DEMAND),
        "c2_gross_ghs_minor": c2_gross_ghs_minor == 1_000_000,
        "n2_multilateral_conservation": sum(position.net for position in n2_group.positions)
        == 0,
        "n2_multilateral_net_funding": (n2_ghs_gross, n2_ghs_net) == (1_000_000, 180_000),
        "n2_positions": [
            (position.participant, position.net)
            for position in n2_group.positions
        ]
        == [(ACCRA, 180_000), (NYC, -70_000), (TEMA, -110_000)],
        "n2_no_issued_obligations": not any(
            pair.issued_obligation_id is not None
            for group in n2_statement.groups
            for pair in group.pairs
        ),
        "n2_all_members_resolved": n2_resolved_members == len(C2_DEMAND),
        "n2_valued_in_usd_base": (
            n2_valuation.gross_base,
            n2_valuation.net_base,
            n2_valuation.reduction_base,
        )
        == (66_666, 12_000, 54_666),
        "gross_to_net_capital_reduction_base": total_reduction_base == 2_187_999
        and total_reduction_base > 0,
        "capital_reduction_ratio_positive": total_net_base < total_gross_base,
        "journal_rebuild_index_match": journal_rebuild_index_match,
        "snapshot_round_trip_match": snapshot_round_trip_match,
        "netting_cycles_finalized": (
            n1_final.state.value == "FINALIZED"
            and n2_final.state.value == "FINALIZED"
        ),
    }

    transcript = {
        "experiment": "DOGFOOD-015",
        "work_order": "WORK-015 — clearing, obligations and netting",
        "environment_id": ENVIRONMENT_ID,
        "domain_id": DOMAIN_ID,
        "participants": [ACCRA, NYC, LON, TEMA],
        "assets": {"usd": USD, "ghs": GHS},
        "c1": {
            "cycle_id": "clearing/cycle/dogfood-015-c1",
            "members": len(C1_DEMAND),
            "gross_by_asset_minor": {
                entry.asset: entry.gross for entry in c1_statement.gross_by_asset
            },
            "gross_by_pair_minor": [
                {
                    "obligor": entry.obligor,
                    "obligee": entry.obligee,
                    "asset": entry.asset,
                    "gross": entry.gross,
                }
                for entry in c1_statement.gross_by_pair
            ],
        },
        "n1_bilateral": {
            "netting_id": "clearing/netting/dogfood-015-n1",
            "mode": "BILATERAL",
            "groups": [
                {
                    "asset": group.asset,
                    "gross_minor": group.gross,
                    "net_minor": group.net_total,
                    "reduction_minor": group.gross - group.net_total,
                }
                for group in n1_statement.groups
            ],
            "pairs": n1_pairs,
            "issued_net_obligations": issued_net_obligations,
            "valuation_usd_base_minor": {
                "gross_base": n1_valuation.gross_base,
                "net_base": n1_valuation.net_base,
                "reduction_base": n1_valuation.reduction_base,
            },
            "statement_digest": n1_statement.digest,
        },
        "n2_multilateral": {
            "netting_id": "clearing/netting/dogfood-015-n2",
            "mode": "MULTILATERAL",
            "groups": [
                {
                    "asset": group.asset,
                    "gross_minor": group.gross,
                    "net_minor": group.net_total,
                    "reduction_minor": group.gross - group.net_total,
                }
                for group in n2_statement.groups
            ],
            "positions": n2_positions,
            "valuation_usd_base_minor": {
                "gross_base": n2_valuation.gross_base,
                "net_base": n2_valuation.net_base,
                "reduction_base": n2_valuation.reduction_base,
            },
            "statement_digest": n2_statement.digest,
        },
        "gross_to_net_capital_reduction": {
            "gross_base_minor": total_gross_base,
            "net_base_minor": total_net_base,
            "reduction_base_minor": total_reduction_base,
            "reduction_ratio_bp": round(total_reduction_base * 10_000 / total_gross_base),
        },
        "transformation_completeness": {
            "journal_entries": len(engine.journal),
            "journal_rebuild_index_match": journal_rebuild_index_match,
            "snapshot_round_trip_match": snapshot_round_trip_match,
        },
        "checks": checks,
        "classification": "PASS" if all(checks.values()) else "FAIL",
    }
    return transcript


def main() -> int:
    transcript = build_transcript()
    print(canonical_json(transcript))
    return 0 if transcript["classification"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
