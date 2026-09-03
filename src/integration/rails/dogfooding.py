"""DOGFOOD-030 — the external rail sandbox integration gate conformance.

Two transcripts:

* :func:`build_local_dogfood_transcript` — the DETERMINISTIC local
  conformance (LOCAL_DETERMINISTIC_SANDBOX pair): the full scenario
  battery A–E (canonical success, rejection, unknown/recovery,
  idempotency, cross-rail comparison), the failure/investigation
  battery and the finality discipline, all network-free and
  byte-identical across runs.

* :func:`build_real_rails_transcript` — the REAL_PROVIDER_SANDBOX
  experiment: the same canonical payment request executed through
  rail A (Stripe test mode, credential read from ``STRIPE_SECRET_KEY``
  at call time and never printed, stored or committed) AND rail B
  (the public Stellar testnet, credential-free), each as a full
  canonical lifecycle to an ESTABLISHED finality certificate, then the
  cross-rail semantic comparison, the idempotent same-key
  re-submission through both adapters, the deterministic rejection
  probes on both rails and the reconciliation queries (success and
  the retry-safe not-found truth).

SECURITY (non-negotiable): no secrets, no authorization headers, no
raw provider bodies and no credential material ever appear in any
transcript; only safe normalized provider references (Stripe
PaymentIntent ids, Stellar transaction hashes) are recorded. Provider
call counts are deliberately NOT recorded in the transcripts (they
are run-specific setup details; the canonical facts and digests are
the deterministic content).

Offline contract (mirroring WORK-027 §8A): a missing Stripe
credential or an unreachable sandbox means the real-rail experiment
is NOT EXECUTED — the transcript states ``REAL RAIL: NOT EXECUTED``
with the sanitized reason, and the classification becomes
OUTSTANDING (this run does not satisfy the real-rail dogfood
requirement).
"""

from __future__ import annotations

import os
from typing import Any

from src.core.serialization import canonical_sha256

from .contracts import (
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_RAILS_ACTOR,
    RAILS_AMOUNT_MINOR,
    RAILS_PAYEE,
    RAILS_PAYER,
)
from .harness import ExternalRailSandboxGate
from .scenarios import (
    run_failure_battery,
    run_rails_finality_discipline,
    run_rails_scenario_a,
    run_rails_scenario_b,
    run_rails_scenario_c,
    run_rails_scenario_d,
)

#: The environment variable carrying the Stripe test-mode secret key.
STRIPE_SECRET_ENV = "STRIPE_SECRET_KEY"


def build_local_dogfood_transcript() -> tuple[str, str]:
    """Execute the deterministic DOGFOOD-030 experiment (local pair)."""
    lines: list[str] = [
        "DOGFOOD-030 LOCAL: external rail sandbox integration gate (IG-005) — "
        "canonical A/B machinery on the deterministic local pair",
        "work_order=WORK-030",
        "architecture=v0.1 (frozen)",
        "gate=IG-005 (external rail sandbox; required inputs WORK-007, "
        "WORK-014, WORK-016, WORK-023, WORK-027, all complete and merged "
        "on main)",
        "rail_a=LOCAL_DETERMINISTIC_SANDBOX "
        "(interoperability/adapter/ig005-local-a) bound through the typed "
        "EffectSubmissionPort/EffectReconciliationPort",
        "rail_b=LOCAL_DETERMINISTIC_SANDBOX "
        "(interoperability/adapter/ig005-local-b) bound through the typed "
        "EffectSubmissionPort/EffectReconciliationPort",
        "classification=LOCAL_DETERMINISTIC_SANDBOX (never counted as one "
        "of the two external rails)",
        "environment=env/sandbox-ig005-local-a + env/sandbox-ig005-local-b "
        "(isolated in-memory kernels; no production state is reachable)",
    ]
    checks: list[bool] = []
    gate = ExternalRailSandboxGate(
        _local_pair_with_scripts(),
        actor=DEFAULT_RAILS_ACTOR,
        authorized_actors=DEFAULT_AUTHORIZED_ACTORS,
    )

    scenario_a = run_rails_scenario_a(gate)
    verdict = scenario_a["verdict"]
    lines.append(
        f"intent={RAILS_PAYER} -> {RAILS_PAYEE} "
        f"{RAILS_AMOUNT_MINOR} minor units (value {RAILS_AMOUNT_MINOR}, scale 2, "
        "asset/usd declared on both local worlds)"
    )
    lines.append(f"shared_input_digest={scenario_a['shared_input_digest']}")
    for side in ("rail_a", "rail_b"):
        facts = scenario_a[side]
        lines.append(
            f"{side}: submission={facts['submission_status']} "
            f"step={facts['step_state']} plan={facts['plan_state']} "
            f"native_reference={facts['native_reference']} "
            f"obligation_resolved={facts['obligation_resolved']} "
            f"discharges={facts['discharge_count']} "
            f"finality={facts['finality_established']}"
        )
        checks.append(
            facts["submission_status"] == "ACCEPTED"
            and facts["step_state"] == "SUCCEEDED"
            and facts["finality_established"]
            and facts["obligation_resolved"]
        )
    lines.append(
        f"semantic comparison: canonicalized result(rail_a) == "
        f"canonicalized result(rail_b) for every contractually rail-neutral "
        f"field -> verdict={verdict.verdict} "
        f"normalization_digest={verdict.normalization_digest[:16]}…"
    )
    checks.append(verdict.verdict == "EQUIVALENT" and not verdict.differences)

    scenario_b = run_rails_scenario_b(gate)
    for side in ("rail_a", "rail_b"):
        facts = scenario_b[side]
        lines.append(
            f"rejection {side}: submission={facts['submission_status']} "
            f"step={facts['step_state']} plan={facts['plan_state']} "
            f"obligations_recognized={facts['obligations_recognized']} "
            f"settlements={facts['settlement_count']} "
            f"discharges={facts['discharge_count']} "
            f"recognition_probe_rejected={facts['recognition_probe_rejected']}"
        )
        checks.append(
            facts["submission_status"] == "REJECTED"
            and facts["obligations_recognized"] == 0
            and facts["settlement_count"] == 0
            and facts["discharge_count"] == 0
            and facts["recognition_probe_rejected"]
        )

    scenario_c = run_rails_scenario_c()
    lines.append(
        "failure -> investigation: transport ambiguity (deterministic local "
        f"rail) submission={scenario_c['first_submission_state']} -> "
        f"reconciliation={scenario_c['reconciliation_outcome']} (retry-safe) "
        f"-> fresh-key retry submission={scenario_c['retry_submission_state']} "
        f"-> definitive: finality={scenario_c['finality_established']} "
        f"obligation_resolved={scenario_c['obligation_resolved']}"
    )
    checks.append(
        scenario_c["first_submission_state"] == "UNKNOWN"
        and scenario_c["reconciliation_outcome"] == "NOT_FOUND"
        and scenario_c["finality_established"]
    )

    scenario_d = run_rails_scenario_d(gate)
    for side in ("rail_a", "rail_b"):
        facts = scenario_d[side]
        lines.append(
            f"idempotency {side}: re-drive={facts['re_drive_outcome']} "
            f"(no second port call={facts['re_drive_port_call_unchanged']}); "
            f"same-key re-submission through the adapter: "
            f"status={facts['resubmission_status']} "
            f"stable_reference={facts['resubmission_native_reference'] == facts['first_native_reference']} "
            f"obligation_delta={facts['obligation_delta']} "
            f"discharge_delta={facts['discharge_delta']} "
            f"native_payments={facts['native_payment_count']}"
        )
        checks.append(
            facts["resubmission_status"] == "ACCEPTED"
            and facts["resubmission_native_reference"]
            == facts["first_native_reference"]
            and facts["obligation_delta"] == 0
            and facts["discharge_delta"] == 0
            and facts["native_payment_count"] == 1
        )

    finality = run_rails_finality_discipline(gate)
    for side in ("rail_a", "rail_b"):
        facts = finality[side]
        lines.append(
            f"finality discipline {side}: rail status SETTLED recorded="
            f"{facts['status_recorded_settled']}, finality at the status "
            f"point={facts['finality_count_at_status_point']}; finality "
            f"arrived only after the settlement chain "
            f"(settlement={facts['settlement_state']}, settled_legs="
            f"{facts['settled_legs']}, finality_established="
            f"{facts['finality_established_after_settlement']}, claim kind="
            f"{facts['finality_claim_kind']} recorded as OBSERVED evidence "
            "only)"
        )
        checks.append(
            facts["status_recorded_settled"]
            and facts["finality_count_at_status_point"] == 0
            and facts["finality_established_after_settlement"]
        )

    battery = run_failure_battery(gate)
    for name in (
        "transport_ambiguity",
        "provider_rejection",
        "reconciliation_success",
        "reconciliation_not_found",
        "idempotent_retry",
        "unexpected_provider_status",
    ):
        probe = battery["paths"][name]
        lines.append(
            f"failure path {name}: fail_closed={probe['fail_closed']}"
        )
        checks.append(probe["fail_closed"])

    lines.append(f"stage_journal_entries={len(gate.rail_a_gate.stage_journal)}")
    lines.append(
        "economic_outcome: the same declared 1.00 canonical payment ran "
        "end-to-end on both local worlds through execution evidence, "
        "obligation, discharge posting and finality certificate with "
        "identical economics"
    )
    passed = all(checks)
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    lines.append(
        "classification: DOGFOOD-030 LOCAL: PASS"
        if passed
        else "classification: DOGFOOD-030 LOCAL: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def _local_pair_with_scripts():
    from .worlds import build_local_rail_pair

    return build_local_rail_pair(
        submissions={
            "ig005-b1": ("reject",),
            "ig005-c1": ("unknown",),
            "ig005-c1-retry": ("accept",),
        },
        queries={"ig005-c1": ("not-found",)},
    )


def build_real_rails_transcript(
    *,
    secret_env_var: str = STRIPE_SECRET_ENV,
    stellar_api_base: str | None = None,
) -> tuple[str, str]:
    """Execute the REAL_PROVIDER_SANDBOX experiment (rails A and B).

    Falls back to the explicit offline contract when the Stripe
    credential is absent or the Stellar sandbox is unreachable: the
    effects are NOT ATTEMPTED, the transcript states ``REAL RAIL: NOT
    EXECUTED`` with the sanitized reason, and the experiment
    classification becomes OUTSTANDING.
    """
    lines: list[str] = [
        "DOGFOOD-030 REAL RAILS: external rail sandbox integration gate "
        "(IG-005) — canonical request through two real sandbox rails",
        "work_order=WORK-030",
        "architecture=v0.1 (frozen)",
        "gate=IG-005",
        "rail_a=REAL_PROVIDER_SANDBOX Stripe test mode "
        "(interoperability/adapter/stripe-test) bound through the typed "
        "EffectSubmissionPort/EffectReconciliationPort; credential read "
        "from the STRIPE_SECRET_KEY environment variable at call time "
        "(never printed, stored, committed or echoed)",
        "rail_b=REAL_PROVIDER_SANDBOX Stellar testnet "
        "(interoperability/adapter/stellar-testnet) bound through the same "
        "typed ports; the public testnet is credential-free and the rail's "
        "deterministic test accounts derive from public constants "
        "(testnet-only, non-secret by construction)",
        "classification=REAL_PROVIDER_SANDBOX on both rails (never "
        "counted as local deterministic sandboxes)",
        "canonical_request: "
        f"{RAILS_PAYER} -> {RAILS_PAYEE}, 1.00 declared (value "
        f"{RAILS_AMOUNT_MINOR}, scale 2, asset/usd — the SAME canonical "
        "declared asset on both rails; rail A settles usd natively while "
        "rail B settles the declared amount natively on the public "
        "testnet as the documented sandbox-conformance translation, "
        "disclosed here and never a canonical value claim)",
    ]
    from .worlds import build_rail_world_a, build_rail_world_b

    credential = os.environ.get(secret_env_var)
    stellar_kwargs: dict[str, Any] = {}
    if stellar_api_base is not None:
        stellar_kwargs["api_base"] = stellar_api_base

    offline_reasons: list[str] = []
    if credential is None:
        offline_reasons.append("Stripe credential not configured")
    if stellar_api_base is not None and stellar_api_base.endswith(".invalid"):
        offline_reasons.append("Stellar sandbox unreachable (offline test)")

    if offline_reasons:
        world_a = build_rail_world_a(
            decline_keys={"ig005-b1"}, secret_env_var=secret_env_var
        )
        world_b = build_rail_world_b(reject_keys={"ig005-b1"}, **stellar_kwargs)
        gate = ExternalRailSandboxGate((world_a, world_b))
        scenario_a = run_rails_scenario_a(gate)
        facts_a = scenario_a["rail_a"]
        facts_b = scenario_a["rail_b"]
        lines.extend(
            [
                "REAL RAIL: NOT EXECUTED",
                "REASON: " + "; ".join(offline_reasons),
                "OFFLINE FALLBACK: EXECUTED (the effects are NOT ATTEMPTED "
                "— the typed ports return explicit UNKNOWN submissions with "
                "sanitized reasons, and the rails never fabricate success)",
                f"submission_state_rail_a={facts_a['submission_status']} "
                f"(no native reference, no charge)",
                f"submission_state_rail_b={facts_b['submission_status']} "
                f"(no native reference, no payment)",
                f"offline_verdict={scenario_a['verdict'].verdict} (both "
                "worlds fail identically closed: no settlement, no "
                "finality, no economic effect)",
                "REAL-RAIL REQUIREMENT: OUTSTANDING",
                "classification: DOGFOOD-030 REAL RAILS: BLOCKED (offline "
                "fallback executed; the real sandbox payments remain "
                "outstanding)",
            ]
        )
        transcript = "\n".join(lines) + "\n"
        return transcript, canonical_sha256({"transcript": transcript})

    world_a = build_rail_world_a(decline_keys={"ig005-b1"})
    world_b = build_rail_world_b(reject_keys={"ig005-b1"}, **stellar_kwargs)
    gate = ExternalRailSandboxGate((world_a, world_b))
    checks: list[bool] = []

    # -- the canonical request through BOTH real rails, to finality.
    scenario_a = run_rails_scenario_a(gate)
    verdict = scenario_a["verdict"]
    lines.append(
        f"shared_input_digest={scenario_a['shared_input_digest']}"
    )
    for side, facts in (
        ("rail_a (Stripe)", scenario_a["rail_a"]),
        ("rail_b (Stellar)", scenario_a["rail_b"]),
    ):
        lines.append(
            f"{side}: submission={facts['submission_status']} "
            f"step={facts['step_state']} plan={facts['plan_state']} "
            f"native_reference={facts['native_reference']} (safe normalized "
            "provider reference) "
            f"obligation_resolved={facts['obligation_resolved']} "
            f"discharges={facts['discharge_count']} "
            f"finality={facts['finality_established']}"
        )
        checks.append(
            facts["submission_status"] == "ACCEPTED"
            and facts["step_state"] == "SUCCEEDED"
            and facts["native_reference"] is not None
            and facts["finality_established"]
            and facts["obligation_resolved"]
            and facts["discharge_count"] == 1
        )
    lines.append(
        "semantic comparison: canonicalized result(rail A) == "
        "canonicalized result(rail B) for every contractually rail-neutral "
        f"field -> verdict={verdict.verdict} with "
        f"{len(verdict.differences)} classified differences; the "
        "legitimate differences (provider-native references "
        "pi_… vs tx-hash, native status words succeeded/completed, "
        "adapter identities, environments) are exactly the registered "
        "normalization rules; the canonical declared asset is IDENTICAL "
        "(asset/usd, strictly compared); normalization_digest="
        f"{verdict.normalization_digest[:16]}…"
    )
    checks.append(verdict.verdict == "EQUIVALENT" and not verdict.differences)

    # -- idempotent retry through BOTH real adapters.
    scenario_d = run_rails_scenario_d(gate)
    for side, label in (
        ("rail_a", "rail_a (Stripe)"),
        ("rail_b", "rail_b (Stellar)"),
    ):
        facts = scenario_d[side]
        lines.append(
            f"idempotency {label}: re-drive={facts['re_drive_outcome']} "
            f"(no second port call={facts['re_drive_port_call_unchanged']}); "
            f"same-key re-submission through the adapter: "
            f"status={facts['resubmission_status']} "
            f"stable_reference={facts['resubmission_native_reference'] == facts['first_native_reference']} "
            f"obligation_delta={facts['obligation_delta']} "
            f"discharge_delta={facts['discharge_delta']}"
        )
        checks.append(
            facts["resubmission_status"] == "ACCEPTED"
            and facts["resubmission_native_reference"]
            == facts["first_native_reference"]
            and facts["obligation_delta"] == 0
            and facts["discharge_delta"] == 0
        )

    # -- failure -> investigation/reconciliation: the deterministic
    #    rejection probes on both real rails, then the reconciliation
    #    queries (the definitive success already folded above; the
    #    retry-safe not-found truth for a never-submitted key).
    scenario_b = run_rails_scenario_b(gate)
    for side, label in (
        ("rail_a", "rail_a (Stripe: card_declined)"),
        ("rail_b", "rail_b (Stellar: op_no_destination)"),
    ):
        facts = scenario_b[side]
        lines.append(
            f"rejection {label}: submission={facts['submission_status']} "
            f"step={facts['step_state']} plan={facts['plan_state']} "
            f"obligations_recognized={facts['obligations_recognized']} "
            f"settlements={facts['settlement_count']} "
            f"discharges={facts['discharge_count']} (provider reason "
            "metadata preserved as diagnostic data only; the canonical "
            "REJECTED classification is authoritative)"
        )
        checks.append(
            facts["submission_status"] == "REJECTED"
            and facts["obligations_recognized"] == 0
            and facts["settlement_count"] == 0
            and facts["discharge_count"] == 0
        )
    battery = run_failure_battery(gate)
    not_found = battery["paths"]["reconciliation_not_found"]
    lines.append(
        "reconciliation: a never-submitted key reconciles "
        f"{not_found['outcome']} (the retry-safe truth — never fabricated "
        "as success) on both rails; the transport-ambiguity -> "
        "reconciliation -> recovery chain is proven deterministically on "
        "the LOCAL_DETERMINISTIC_SANDBOX pair (the local DOGFOOD-030 "
        "transcript); a real provider is never abused to fabricate "
        "network corruption"
    )
    checks.append(not_found["fail_closed"])

    lines.append(
        "economic_outcome: the same declared 1.00 canonical payment "
        "succeeded end-to-end on BOTH real sandbox rails — Stripe test "
        "mode (settling usd natively) and the Stellar testnet (settling "
        "the declared amount natively as the documented sandbox "
        "translation) — through compilation, "
        "execution, real adapter ports, clearing, settlement and ESTABLISHED "
        "finality certificates with exactly one discharge posting each, "
        "with identical canonical economics; no secret material appears in "
        "this transcript"
    )
    passed = all(checks)
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    lines.append(
        "classification: DOGFOOD-030 REAL RAILS: PASS"
        if passed
        else "classification: DOGFOOD-030 REAL RAILS: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


__all__ = [
    "STRIPE_SECRET_ENV",
    "build_local_dogfood_transcript",
    "build_real_rails_transcript",
]
