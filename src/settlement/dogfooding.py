"""DOGFOOD-016 — sandbox settlement with unknown, failure, reversal and
finality evidence paths (WORK-016 dogfooding contract).

This module is a clearly-marked TEST-SIDE artifact (sandbox world
state): it drives the real :class:`~src.clearing.ClearingEngine` and
the real :class:`~src.settlement.SettlementEngine` over the merged
public contracts, with rail evidence synthesized as sealed
execution-domain records (``EffectResult`` / ``ExternalObservation``).
It moves no real funds and claims no real finality.

Scenario (reciprocal corridor, all instants declared):

1. clearing recognizes three obligations from sealed SUCCEEDED
   execution effect results (alpha→beta, beta→alpha, gamma→alpha),
   validates and marks them due, then closes the cycle;
2. the settlement engine creates one settlement batch over the three
   DUE obligations, authorizes and submits it inside its window;
3. reconciliation folds the rail evidence: one leg settles, one leg
   reports UNKNOWN (explicit suspense posting), one leg FAILS;
4. clearing resolves the settled obligation with the settlement's
   discharge evidence (digest-bound, kind ``DISCHARGE_EVIDENCE``);
5. a late SUCCEEDED observation resolves the suspense leg: the
   suspense pair is released (exact compensation) and the leg
   discharges, completing the settlement; clearing resolves it too;
6. finality: two FINAL claims validate into the certificate and it is
   established for the completed settlement;
7. a REVOKED claim withdraws the certificate; the reversal case
   (digest-bound to the revoked certificate) executes the explicit
   compensation posting for one discharge;
8. a refund case compiles a linked refund settlement (reversed leg),
   which settles through the normal lifecycle with REFUND postings,
   and the case executes against it;
9. the posting journal is verified balanced per asset, and the whole
   domain state (records + postings) is rebuilt from the journal alone
   and restored from a snapshot, byte-identically.

Two negative probes pin the no-false-finality boundary: a payment
status can never validate into a finality certificate, and a SIMULATED
observation can never fold a leg.
"""

from __future__ import annotations

import sys
from typing import Any

from src.clearing import ClearingEngine
from src.clearing.contracts import ClearingCycleState, ObligationState, ResolutionKind
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256
from src.evidence.contracts import EpistemicType
from src.execution.contracts import EffectOutcome, FinalityClaim, ObservationKind
from src.execution.effects import (
    EffectResultSpec,
    ExternalObservationSpec,
    make_observation_record,
    make_result_record,
)
from src.core.envelope import Provenance

from .contracts import FinalityState, LegState, PostingKind, RecourseCaseState, SettlementState
from .engine import SettlementEngine

ENVIRONMENT_ID = "env/dogfood-016"
CLEARING_DOMAIN_ID = "clearing/dogfood-016"
SETTLEMENT_DOMAIN_ID = "settlement/dogfood-016"
EXECUTION_DOMAIN_ID = "execution/dogfood-016"

T0 = "2026-01-05T09:00:00Z"
T1 = "2026-01-05T09:30:00Z"
T2 = "2026-01-05T10:00:00Z"
T3 = "2026-01-05T11:00:00Z"
T4 = "2026-01-05T12:00:00Z"
T5 = "2026-01-05T13:00:00Z"
T6 = "2026-01-05T14:00:00Z"
T7 = "2026-01-05T15:00:00Z"
T8 = "2026-01-05T16:00:00Z"
T9 = "2026-01-05T17:00:00Z"
T10 = "2026-01-05T18:00:00Z"
T11 = "2026-01-05T19:00:00Z"
T12 = "2026-01-05T20:00:00Z"
T13 = "2026-01-05T21:00:00Z"
T14 = "2026-01-05T22:00:00Z"

SUBMIT_BY = "2026-01-05T20:00:00Z"
SETTLE_BY = "2026-01-06T09:00:00Z"
REFUND_SUBMIT_BY = "2026-01-06T06:00:00Z"
REFUND_SETTLE_BY = "2026-01-07T09:00:00Z"

CYCLE_ID = "clearing/dogfood-016/cycle-1"
SETTLEMENT_ID = "settlement/dogfood-016/batch-1"
FINALITY_ID = "settlement/dogfood-016/finality-1"
REVERSAL_CASE_ID = "settlement/dogfood-016/reversal-1"
REFUND_CASE_ID = "settlement/dogfood-016/refund-1"
REFUND_SETTLEMENT_ID = "settlement/dogfood-016/refund-1/refund"

ALPHA = "psp/alpha"
BETA = "psp/beta"
GAMMA = "psp/gamma"
ASSET = "GHS"

RAIL = "adapter/sandbox-rail"


def _effect_result_for(index: int, payer: str, payee: str, minor: int) -> dict[str, Any]:
    """Build one sealed SUCCEEDED execution effect result (public path)."""
    request_id = f"plan/dogfood-016-1/request/{index}"
    step_id = f"plan/dogfood-016-1/step-{index}"
    result_id = f"{request_id}/result"
    spec = EffectResultSpec(
        result_id=result_id,
        request_id=request_id,
        step_id=step_id,
        effect_type="payment/submit",
        outcome=EffectOutcome.SUCCEEDED,
        native_reference=f"rail/ref-dogfood-016-{index}",
        error_code=None,
        observed_at=T0,
        request_digest="f" * 64,
        detail={
            "payer": payer,
            "payee": payee,
            "asset": ASSET,
            "amount": {"value": minor, "scale": 2, "asset": ASSET},
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


def _status_observation(
    index: int,
    subject_ref: str,
    subject_digest: str,
    canonical_status: str,
    observed_at: str,
    subject_request_digest: str | None = None,
) -> dict[str, Any]:
    """Build one sealed rail STATUS observation (public path).

    ``subject_request_digest`` overrides the digest binding for the
    splice probe (the observation then fails the settlement's
    digest-binding gate).
    """
    observation_id = f"execution/dogfood-016/observation-{index}"
    spec = ExternalObservationSpec(
        observation_id=observation_id,
        kind=ObservationKind.STATUS,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=observed_at,
        content={
            "native_code": f"rail/code-016-{index}",
            "canonical_status": canonical_status,
        },
        subject_request_digest=(
            subject_digest
            if subject_request_digest is None
            else subject_request_digest
        ),
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN_ID,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=observed_at,
        ),
    )
    return record.to_dict()


def _finality_observation(
    index: int,
    subject_ref: str,
    subject_digest: str,
    claim: FinalityClaim,
    observed_at: str,
) -> dict[str, Any]:
    """Build one sealed rail FINALITY observation (public path)."""
    observation_id = f"execution/dogfood-016/finality-observation-{index}"
    spec = ExternalObservationSpec(
        observation_id=observation_id,
        kind=ObservationKind.FINALITY,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=observed_at,
        content={
            "claim": claim.value,
            "native_reference": f"rail/finality-016-{index}",
        },
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN_ID,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=observed_at,
        ),
    )
    return record.to_dict()


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "pass": bool(passed), "detail": detail})


def _negative_probe(checks: list[dict[str, Any]], name: str, action) -> None:
    try:
        action()
    except CoreValidationError as exc:
        _check(checks, name, True, f"rejected: {exc}")
        return
    _check(checks, name, False, "probe unexpectedly accepted")


def build_transcript() -> dict[str, Any]:
    """Drive the full sandbox scenario and build the byte-stable transcript."""
    checks: list[dict[str, Any]] = []
    clearing = ClearingEngine(
        environment_id=ENVIRONMENT_ID,
        domain_id=CLEARING_DOMAIN_ID,
    )
    engine = SettlementEngine(
        environment_id=ENVIRONMENT_ID,
        domain_id=SETTLEMENT_DOMAIN_ID,
    )

    # -- 1. clearing recognizes, validates and marks three obligations due --
    clearing.create_cycle(
        command_id="cmd-016-001",
        requested_at=T0,
        cycle_id=CYCLE_ID,
        opens_at=T0,
        closes_at=T2,
        description="dogfood-016 recognition window",
    )
    legs = (
        (ALPHA, BETA, 120000, "cmd-016-010", "cmd-016-013"),
        (BETA, ALPHA, 80000, "cmd-016-011", "cmd-016-014"),
        (GAMMA, ALPHA, 50000, "cmd-016-012", "cmd-016-015"),
    )
    obligation_ids: list[str] = []
    for index, (payer, payee, minor, recognize_id, _) in enumerate(legs, start=1):
        clearing.recognize_obligation(
            command_id=recognize_id,
            requested_at=T1,
            cycle_id=CYCLE_ID,
            effect_result=_effect_result_for(index, payer, payee, minor),
            due_from=T2,
            due_until=SETTLE_BY,
        )
    for record in clearing.records():
        from src.clearing import Obligation  # local import keeps module import flat

        if isinstance(record, Obligation):
            obligation_ids.append(record.object_id)
    obligation_ids.sort()
    for position, obligation_id in enumerate(obligation_ids):
        clearing.validate_obligation(
            command_id=f"cmd-016-02{position}",
            requested_at=T2,
            obligation_id=obligation_id,
        )
    for position, obligation_id in enumerate(obligation_ids):
        clearing.mark_due_obligation(
            command_id=f"cmd-016-03{position}",
            requested_at=T2,
            obligation_id=obligation_id,
        )
    clearing.validate_cycle(command_id="cmd-016-040", requested_at=T2, cycle_id=CYCLE_ID)
    clearing.finalize_cycle(command_id="cmd-016-041", requested_at=T2, cycle_id=CYCLE_ID)
    _check(
        checks,
        "clearing cycle closed with three DUE obligations",
        clearing.cycle(CYCLE_ID).state is ClearingCycleState.FINALIZED
        and len(obligation_ids) == 3
        and all(
            clearing.obligation(obligation_id).state is ObligationState.DUE
            for obligation_id in obligation_ids
        ),
        f"cycle={clearing.cycle(CYCLE_ID).state.value}, obligations={obligation_ids}",
    )

    # -- 2. settlement batch over the three DUE obligations --
    obligations = [clearing.obligation(obligation_id).to_dict() for obligation_id in obligation_ids]
    engine.create_settlement(
        command_id="cmd-016-100",
        requested_at=T2,
        settlement_id=SETTLEMENT_ID,
        obligations=obligations,
        submit_by=SUBMIT_BY,
        settle_by=SETTLE_BY,
    )
    settlement = engine.settlement(SETTLEMENT_ID)
    instruction_by_obligation = {
        instruction.obligation_id: instruction
        for instruction in settlement.spec.instructions
    }
    leg_of = {
        obligation_id: instruction_by_obligation[obligation_id].instruction_id
        for obligation_id in obligation_ids
    }
    leg_alpha_beta = leg_of[obligation_ids[0]]
    leg_beta_alpha = leg_of[obligation_ids[1]]
    leg_gamma_alpha = leg_of[obligation_ids[2]]
    engine.authorize_settlement(
        command_id="cmd-016-101", requested_at=T2, settlement_id=SETTLEMENT_ID
    )
    engine.submit_settlement(
        command_id="cmd-016-102", requested_at=T2, settlement_id=SETTLEMENT_ID
    )
    settlement = engine.settlement(SETTLEMENT_ID)
    digests = {
        instruction.instruction_id: instruction.instruction_digest()
        for instruction in settlement.spec.instructions
    }
    _check(
        checks,
        "settlement batch created, authorized and submitted in window",
        settlement.state is SettlementState.SUBMITTED
        and len(settlement.spec.instructions) == 3
        and settlement.spec.submitted_at == T2,
        f"state={settlement.state.value}, legs={sorted(digests)}",
    )

    # -- 3. first reconciliation: settled / unknown / failed legs --
    engine.reconcile_settlement(
        command_id="cmd-016-103",
        requested_at=T3,
        settlement_id=SETTLEMENT_ID,
        as_of=T3,
        observations=[
            _status_observation(
                1,
                leg_alpha_beta,
                digests[leg_alpha_beta],
                "SETTLED",
                T3,
            ),
            _status_observation(
                2,
                leg_beta_alpha,
                digests[leg_beta_alpha],
                "UNKNOWN",
                T3,
            ),
            _status_observation(
                3,
                leg_gamma_alpha,
                digests[leg_gamma_alpha],
                "FAILED",
                T3,
            ),
        ],
    )
    settlement = engine.settlement(SETTLEMENT_ID)
    outcomes = {
        outcome.instruction_id: LegState(outcome.state)
        for outcome in settlement.spec.leg_outcomes
    }
    postings = engine.postings()
    suspense_entries = [
        entry for entry in postings if entry.kind == PostingKind.SUSPENSE.value
    ]
    discharge_entries = [
        entry for entry in postings if entry.kind == PostingKind.DISCHARGE.value
    ]
    _check(
        checks,
        "reconciliation folds settled/unknown/failed legs explicitly",
        outcomes[leg_alpha_beta] is LegState.SETTLED
        and outcomes[leg_beta_alpha] is LegState.UNKNOWN
        and outcomes[leg_gamma_alpha] is LegState.FAILED,
        f"legs={{{leg_alpha_beta}: SETTLED, {leg_beta_alpha}: UNKNOWN, "
        f"{leg_gamma_alpha}: FAILED}}",
    )
    _check(
        checks,
        "unknown leg posts exactly one controlled suspense pair",
        len(suspense_entries) == 1
        and suspense_entries[0].instruction_ref == leg_beta_alpha
        and suspense_entries[0].debit_account == f"suspense-in-transit/{BETA}"
        and suspense_entries[0].credit_account == f"suspense-exception/{ALPHA}"
        and suspense_entries[0].debit_value == 80000,
        f"suspense={suspense_entries[0].to_dict() if suspense_entries else None}",
    )
    _check(
        checks,
        "settled leg posts its discharge pair; failed leg posts nothing",
        len(discharge_entries) == 1
        and discharge_entries[0].instruction_ref == leg_alpha_beta
        and discharge_entries[0].debit_account == f"obligation-liability/{ALPHA}"
        and discharge_entries[0].credit_account == f"settled-claim/{BETA}"
        and discharge_entries[0].debit_value == 120000
        and all(
            entry.instruction_ref != leg_gamma_alpha for entry in postings
        ),
        f"discharge={discharge_entries[0].to_dict() if discharge_entries else None}",
    )
    _check(
        checks,
        "settlement stays SUBMITTED while a leg is unknown (no silent classification)",
        settlement.state is SettlementState.SUBMITTED,
        f"state={settlement.state.value}",
    )

    # -- 4. clearing resolves the settled obligation with discharge evidence --
    evidence = {
        binding["obligation_id"]: binding
        for binding in engine.discharge_evidence(SETTLEMENT_ID)
    }
    settled_obligation = _obligation_for_leg(
        obligation_ids, leg_alpha_beta, evidence
    )
    clearing.resolve_obligation(
        command_id="cmd-016-110",
        requested_at=T3,
        obligation_id=settled_obligation,
        evidence_ref=evidence[settled_obligation]["evidence_ref"],
        evidence_digest=evidence[settled_obligation]["evidence_digest"],
        reason="sandbox settlement discharge",
    )
    resolved_record = clearing.obligation(settled_obligation)
    _check(
        checks,
        "clearing resolves the settled obligation with digest-bound discharge evidence",
        resolved_record.state is ObligationState.RESOLVED
        and resolved_record.spec.resolution.kind
        == ResolutionKind.DISCHARGE_EVIDENCE.value
        and resolved_record.spec.resolution.digest
        == evidence[settled_obligation]["evidence_digest"],
        f"resolution={resolved_record.spec.resolution.to_dict()}",
    )

    # -- 5. late SUCCEEDED observation resolves the suspense leg --
    engine.reconcile_settlement(
        command_id="cmd-016-104",
        requested_at=T4,
        settlement_id=SETTLEMENT_ID,
        as_of=T4,
        observations=[
            _status_observation(
                4,
                leg_beta_alpha,
                digests[leg_beta_alpha],
                "SETTLED",
                T4,
            )
        ],
    )
    settlement = engine.settlement(SETTLEMENT_ID)
    postings = engine.postings()
    releases = [
        entry for entry in postings if entry.kind == PostingKind.SUSPENSE_RELEASE.value
    ]
    discharge_entries = [
        entry for entry in postings if entry.kind == PostingKind.DISCHARGE.value
    ]
    _check(
        checks,
        "late success releases suspense (exact compensation) and discharges",
        settlement.state is SettlementState.FAILED
        and len(releases) == 1
        and releases[0].instruction_ref == leg_beta_alpha
        and releases[0].debit_account == f"suspense-exception/{ALPHA}"
        and releases[0].credit_account == f"suspense-in-transit/{BETA}"
        and releases[0].debit_value == 80000
        and len(discharge_entries) == 2,
        f"release={releases[0].to_dict() if releases else None}, "
        f"state={settlement.state.value}",
    )
    evidence = {
        binding["obligation_id"]: binding
        for binding in engine.discharge_evidence(SETTLEMENT_ID)
    }
    late_settled_obligation = _obligation_for_leg(
        obligation_ids, leg_beta_alpha, evidence
    )
    clearing.resolve_obligation(
        command_id="cmd-016-111",
        requested_at=T4,
        obligation_id=late_settled_obligation,
        evidence_ref=evidence[late_settled_obligation]["evidence_ref"],
        evidence_digest=evidence[late_settled_obligation]["evidence_digest"],
        reason="sandbox settlement discharge (late resolution)",
    )
    failed_obligation_id = next(
        obligation_id
        for obligation_id in obligation_ids
        if obligation_id not in (settled_obligation, late_settled_obligation)
    )
    _check(
        checks,
        "failed leg's obligation stays DUE (failure never discharges)",
        clearing.obligation(failed_obligation_id).state is ObligationState.DUE,
        f"obligation={failed_obligation_id}, "
        f"state={clearing.obligation(failed_obligation_id).state.value}",
    )

    # -- negative probes: the no-false-finality and splice boundaries --
    _negative_probe(
        checks,
        "a payment status can never validate into a finality certificate",
        lambda: engine.validate_finality_claim(
            command_id="cmd-016-neg-1",
            requested_at=T5,
            finality_id="settlement/dogfood-016/finality-neg",
            settlement_id=SETTLEMENT_ID,
            observation=_status_observation(
                90,
                leg_alpha_beta,
                digests[leg_alpha_beta],
                "SETTLED",
                T5,
            ),
        ),
    )
    _negative_probe(
        checks,
        "a rail observation spliced onto another leg fails closed",
        lambda: engine.reconcile_settlement(
            command_id="cmd-016-neg-2",
            requested_at=T5,
            settlement_id=SETTLEMENT_ID,
            as_of=T5,
            observations=[
                _status_observation(
                    91,
                    leg_alpha_beta,
                    digests[leg_alpha_beta],
                    "SETTLED",
                    T5,
                    subject_request_digest=digests[leg_gamma_alpha],
                )
            ],
        ),
    )

    # -- 6. finality: validate FINAL claims and establish --
    engine.validate_finality_claim(
        command_id="cmd-016-120",
        requested_at=T5,
        finality_id=FINALITY_ID,
        settlement_id=SETTLEMENT_ID,
        observation=_finality_observation(
            1, leg_alpha_beta, digests[leg_alpha_beta], FinalityClaim.FINAL, T5
        ),
    )
    engine.validate_finality_claim(
        command_id="cmd-016-121",
        requested_at=T5,
        finality_id=FINALITY_ID,
        settlement_id=SETTLEMENT_ID,
        observation=_finality_observation(
            2, leg_beta_alpha, digests[leg_beta_alpha], FinalityClaim.FINAL, T5
        ),
    )
    certificate = engine.finality(FINALITY_ID)
    _check(
        checks,
        "finality claims validate digest-bound to the settled legs",
        certificate.state is FinalityState.PENDING
        and len(certificate.spec.claims) == 2
        and all(
            binding.claim == FinalityClaim.FINAL.value
            for binding in certificate.spec.claims
        ),
        f"claims={[binding.to_dict() for binding in certificate.spec.claims]}",
    )
    engine.establish_finality(
        command_id="cmd-016-122", requested_at=T6, finality_id=FINALITY_ID
    )
    certificate = engine.finality(FINALITY_ID)
    _check(
        checks,
        "finality established only for the terminal settlement with full coverage",
        certificate.state is FinalityState.ESTABLISHED
        and certificate.spec.established_at == T6,
        f"state={certificate.state.value}, "
        f"settlement={certificate.spec.settlement_id}",
    )

    # -- 7. revocation and the reversal boundary --
    revoked_claim_observation = _finality_observation(
        3, leg_beta_alpha, digests[leg_beta_alpha], FinalityClaim.REVOKED, T7
    )
    engine.revoke_finality_claim(
        command_id="cmd-016-130",
        requested_at=T7,
        finality_id=FINALITY_ID,
        evidence_ref=revoked_claim_observation["envelope"]["object_id"],
        evidence_digest=revoked_claim_observation["integrity_hash"],
        reason="rail withdrew the finality claim for the late-resolved leg",
    )
    certificate = engine.finality(FINALITY_ID)
    _check(
        checks,
        "revoked claim withdraws the certificate (terminal, append-only)",
        certificate.state is FinalityState.REVOKED
        and certificate.spec.revocation is not None,
        f"state={certificate.state.value}, "
        f"revocation={certificate.spec.revocation.to_dict()}",
    )
    engine.request_reversal(
        command_id="cmd-016-131",
        requested_at=T8,
        case_id=REVERSAL_CASE_ID,
        settlement_id=SETTLEMENT_ID,
        instruction_ids=[leg_beta_alpha],
        evidence_ref=FINALITY_ID,
        evidence_digest=certificate.integrity_hash,
        epistemic_type=EpistemicType.OBSERVED.value,
        reason="discharge must be compensated after finality withdrawal",
    )
    engine.approve_reversal(
        command_id="cmd-016-132", requested_at=T8, case_id=REVERSAL_CASE_ID
    )
    engine.execute_reversal(
        command_id="cmd-016-133", requested_at=T8, case_id=REVERSAL_CASE_ID
    )
    reversal_case = engine.recourse_case(REVERSAL_CASE_ID)
    postings = engine.postings()
    reversal_entries = [
        entry for entry in postings if entry.kind == PostingKind.REVERSAL.value
    ]
    original_discharge = next(
        entry
        for entry in postings
        if entry.kind == PostingKind.DISCHARGE.value
        and entry.instruction_ref == leg_beta_alpha
    )
    reversal = reversal_entries[0] if reversal_entries else None
    _check(
        checks,
        "reversal executes the explicit compensation posting",
        reversal_case.state is RecourseCaseState.EXECUTED
        and reversal is not None
        and reversal.instruction_ref == leg_beta_alpha
        and reversal.debit_value == original_discharge.debit_value
        and reversal.debit_account == original_discharge.credit_account
        and reversal.credit_account == "reversal-adjustment/psp/beta",
        f"reversal={reversal.to_dict() if reversal else None}",
    )
    _check(
        checks,
        "the original discharge posting is untouched (append-only journal)",
        original_discharge.debit_account == f"obligation-liability/{BETA}"
        and original_discharge.credit_account == f"settled-claim/{ALPHA}"
        and original_discharge.debit_value == 80000,
        f"original={original_discharge.to_dict()}",
    )

    # -- 8. the refund boundary: linked new economic transaction --
    engine.request_refund(
        command_id="cmd-016-140",
        requested_at=T9,
        case_id=REFUND_CASE_ID,
        settlement_id=SETTLEMENT_ID,
        instruction_ids=[leg_alpha_beta],
        evidence_ref="evidence/dogfood-016-refund-request",
        evidence_digest=canonical_sha256({"refund": "alpha customer return"}),
        epistemic_type=EpistemicType.OBSERVED.value,
        reason="customer requested return of the alpha->beta payout",
    )
    engine.approve_refund(
        command_id="cmd-016-141", requested_at=T9, case_id=REFUND_CASE_ID
    )
    engine.compile_refund(
        command_id="cmd-016-142",
        requested_at=T10,
        case_id=REFUND_CASE_ID,
        submit_by=REFUND_SUBMIT_BY,
        settle_by=REFUND_SETTLE_BY,
    )
    refund_settlement = engine.settlement(REFUND_SETTLEMENT_ID)
    refund_instruction = refund_settlement.spec.instructions[0]
    original_instruction = next(
        instruction
        for instruction in settlement.spec.instructions
        if instruction.instruction_id == leg_alpha_beta
    )
    _check(
        checks,
        "refund compiles a linked settlement with the reversed leg",
        refund_settlement.state is SettlementState.DRAFT
        and refund_settlement.spec.linked_ref == SETTLEMENT_ID
        and refund_instruction.obligor == original_instruction.obligee
        and refund_instruction.obligee == original_instruction.obligor
        and refund_instruction.amount == original_instruction.amount,
        f"refund_leg={refund_instruction.to_dict()}",
    )
    engine.authorize_settlement(
        command_id="cmd-016-143", requested_at=T10, settlement_id=REFUND_SETTLEMENT_ID
    )
    engine.submit_settlement(
        command_id="cmd-016-144", requested_at=T10, settlement_id=REFUND_SETTLEMENT_ID
    )
    refund_digests = {
        instruction.instruction_id: instruction.instruction_digest()
        for instruction in refund_settlement.spec.instructions
    }
    engine.reconcile_settlement(
        command_id="cmd-016-145",
        requested_at=T11,
        settlement_id=REFUND_SETTLEMENT_ID,
        as_of=T11,
        observations=[
            _status_observation(
                5,
                refund_instruction.instruction_id,
                refund_digests[refund_instruction.instruction_id],
                "SETTLED",
                T11,
            )
        ],
    )
    refund_settlement = engine.settlement(REFUND_SETTLEMENT_ID)
    engine.execute_refund(
        command_id="cmd-016-146",
        requested_at=T12,
        case_id=REFUND_CASE_ID,
        settlement_id=REFUND_SETTLEMENT_ID,
    )
    refund_case = engine.recourse_case(REFUND_CASE_ID)
    postings = engine.postings()
    refund_entries = [
        entry for entry in postings if entry.kind == PostingKind.REFUND.value
    ]
    _check(
        checks,
        "refund settlement completes and the case executes against its postings",
        refund_settlement.state is SettlementState.COMPLETED
        and refund_case.state is RecourseCaseState.EXECUTED
        and len(refund_entries) == 1
        and refund_entries[0].instruction_ref == refund_instruction.instruction_id
        and refund_entries[0].debit_account == f"settled-claim/{BETA}"
        and refund_entries[0].credit_account == f"refund-disbursed/{ALPHA}"
        and refund_entries[0].debit_value == 120000
        and refund_case.spec.execution.posting_refs
        == (refund_entries[0].entry_id,),
        f"refund_posting={refund_entries[0].to_dict() if refund_entries else None}",
    )

    # -- 9. journal integrity, rebuild and restore --
    postings = engine.postings()
    totals: dict[str, int] = {}
    for entry in postings:
        totals[entry.asset] = totals.get(entry.asset, 0) + entry.debit_value
    balanced = all(
        sum(entry.debit_value for entry in postings if entry.asset == asset)
        == sum(entry.credit_value for entry in postings if entry.asset == asset)
        for asset in totals
    )
    _check(
        checks,
        "posting journal balances per asset (double-entry integrity)",
        balanced and totals == {ASSET: 560000},
        f"totals={totals}, entries={len(postings)}",
    )
    postings_digest = engine.postings_digest()
    index_digest = canonical_sha256(
        {"records": [record.to_dict() for record in engine.records()]}
    )
    rebuilt = SettlementEngine.rebuild_from_journal(
        environment_id=ENVIRONMENT_ID,
        domain_id=SETTLEMENT_DOMAIN_ID,
        journal=engine.journal,
    )
    _check(
        checks,
        "journal-only rebuild reproduces records and postings byte-identically",
        canonical_sha256(
            {"records": [record.to_dict() for record in rebuilt.records()]}
        )
        == index_digest
        and rebuilt.postings_digest() == postings_digest,
        f"index_digest={index_digest}, postings_digest={postings_digest}",
    )
    snapshot = engine.snapshot_state()
    restored = SettlementEngine(
        environment_id=ENVIRONMENT_ID,
        domain_id=SETTLEMENT_DOMAIN_ID,
    )
    restored.restore_state(snapshot)
    _check(
        checks,
        "snapshot restore round-trips records and postings byte-identically",
        canonical_sha256(
            {"records": [record.to_dict() for record in restored.records()]}
        )
        == index_digest
        and restored.postings_digest() == postings_digest,
        "snapshot round-trip",
    )
    final_settlement = engine.settlement(SETTLEMENT_ID)
    _check(
        checks,
        "terminal state stays append-only (failed batch stays failed)",
        final_settlement.state is SettlementState.FAILED
        and restored.settlement(SETTLEMENT_ID).state is SettlementState.FAILED
        and restored.settlement(REFUND_SETTLEMENT_ID).state
        is SettlementState.COMPLETED,
        f"state={final_settlement.state.value}",
    )

    classification = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "experiment": "DOGFOOD-016",
        "contract": "complete a sandbox settlement, with unknown/failure/reversal "
        "and finality evidence paths",
        "environment_id": ENVIRONMENT_ID,
        "domain_id": SETTLEMENT_DOMAIN_ID,
        "base_timestamp": T0,
        "facts": {
            "obligations": obligation_ids,
            "settlement": SETTLEMENT_ID,
            "finality_certificate": FINALITY_ID,
            "reversal_case": REVERSAL_CASE_ID,
            "refund_case": REFUND_CASE_ID,
            "refund_settlement": REFUND_SETTLEMENT_ID,
            "settlement_state": engine.settlement(SETTLEMENT_ID).state.value,
            "finality_state": engine.finality(FINALITY_ID).state.value,
            "reversal_state": engine.recourse_case(REVERSAL_CASE_ID).state.value,
            "refund_state": engine.recourse_case(REFUND_CASE_ID).state.value,
            "posting_entries": len(engine.postings()),
            "postings_digest": postings_digest,
            "index_digest": index_digest,
            "journal_entries": len(engine.journal),
            "clearing_resolved": sorted(
                [
                    settled_obligation,
                    late_settled_obligation,
                ]
            ),
            "clearing_still_due": [failed_obligation_id],
        },
        "checks": checks,
        "classification": classification,
    }


def _obligation_for_leg(
    obligation_ids: list[str], leg_ref: str, evidence: dict[str, dict[str, str]]
) -> str:
    """Find which settled obligation a leg refers to (via evidence refs)."""
    for obligation_id in obligation_ids:
        binding = evidence.get(obligation_id)
        if binding is not None and binding["evidence_ref"] == leg_ref:
            return obligation_id
    raise CoreValidationError(f"no obligation bound to leg {leg_ref!r}")


def main() -> int:
    transcript = build_transcript()
    print(canonical_json(transcript))
    return 0 if transcript["classification"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
