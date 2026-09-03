"""DOGFOOD-022: real-path data-governance experiment (deterministic).

Exercises the two Work-Order-mandated scenarios end to end through the
REAL supported product path — the kernel-bound
:class:`~src.data.engine.DataGovernanceEngine` over the real trust
registry (WORK-004) and the real evidence archive (WORK-018):

(a) a user dispute: the case is opened with a typed claim, investigated
    with archived evidence, decided as an approved refund, the refund
    package compiled, the execution outcome recorded with an explicit
    external reference, and the case closed;

(b) a selective-disclosure proof over an isolated dataset: a disclosure
    request is assessed against the declared policy, the proof discloses
    only policy-permitted fields while carrying commitments for every
    field and record, verification proves the disclosed subset matches
    the policy and the committed data — and a tampered dataset fails
    closed.

Every instant is fixed declared ``as_of`` data; the transcript contains
no wall-clock reads, no entropy and no environment-dependent values, so
two clean processes produce byte-identical output.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.evidence import EpistemicType, EvidenceArchive, ScaledValue, submit_evidence
from src.trust import TrustRegistry

from .cases import Claim, ClaimType, DecisionKind, ExecutionRecord, Investigation, RecourseDecision, RefundPackage
from .contracts import DataClass, DisclosurePurpose
from .disclosure import DisclosureRequest
from .engine import DataGovernanceEngine
from .policy import DataPolicySpec, FieldRule, PurposeGrant, RetentionRule
from .selective import IsolatedDataset, dataset_record, commit_dataset
from .retention import LegalHold

ENV = "env/dogfood-022"
DOMAIN = "domain/data"
SOURCE = "data-governance"

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T06:00:00Z"
T2 = "2026-09-02T12:00:00Z"
T3 = "2026-09-02T18:00:00Z"
T4 = "2026-09-03T00:00:00Z"
T5 = "2026-09-04T00:00:00Z"

OPERATOR = "trust/principal/dogfood-operator"
USER = "trust/principal/dogfood-user"
INVESTIGATOR = "trust/principal/dogfood-investigator"
DECIDER = "trust/principal/dogfood-decider"

SUBJECT = "account/wallet-dogfood"
EVIDENCE_TXN = "evidence/evidence/ev-dogfood-txn"
EVIDENCE_COMPLAINT = "evidence/evidence/ev-dogfood-complaint"

POLICY_ID = "data-policy/dogfood-retail"
CLAIM_AMOUNT = ScaledValue(value=125000, scale=2, unit="asset/USD")


def _prov(evidence_refs: tuple[str, ...] = ()):
    from src.core.envelope import Provenance

    return Provenance(
        issuer=OPERATOR, source=SOURCE, recorded_at=T1, evidence_refs=evidence_refs
    )


def _build_trust_registry() -> TrustRegistry:
    registry = TrustRegistry(environment_id=ENV)
    for principal_id, display_name in (
        (OPERATOR, "Dogfood Data Operator"),
        (USER, "Dogfood User"),
        (INVESTIGATOR, "Dogfood Investigator"),
        (DECIDER, "Dogfood Recourse Decider"),
    ):
        registry.create_principal(
            principal_id=principal_id, display_name=display_name, as_of=T0
        )
    return registry


def _build_evidence_archive() -> EvidenceArchive:
    archive = EvidenceArchive()
    archive.append(
        submit_evidence(
            evidence_id=EVIDENCE_TXN,
            epistemic_type=EpistemicType.OBSERVED,
            subject_ref=SUBJECT,
            observed_at=T1,
            valid_from=T1,
            valid_until=T4,
            value=ScaledValue(value=125000, scale=2, unit="asset/USD"),
            environment_id=ENV,
            domain_id="domain/evidence",
            provenance=_prov(),
        )
    )
    archive.append(
        submit_evidence(
            evidence_id=EVIDENCE_COMPLAINT,
            epistemic_type=EpistemicType.OBSERVED,
            subject_ref=SUBJECT,
            observed_at=T2,
            valid_from=T2,
            valid_until=T4,
            value=ScaledValue(value=1, scale=0, unit="complaint"),
            environment_id=ENV,
            domain_id="domain/evidence",
            provenance=_prov(),
        )
    )
    return archive


def _policy_spec() -> DataPolicySpec:
    return DataPolicySpec(
        policy_id=POLICY_ID,
        declared_by=OPERATOR,
        declared_at=T0,
        effective_from=T1,
        valid_until=T5,
        legal_basis_ref="legal-basis/dogfood-consent",
        purpose_grants=(
            PurposeGrant(
                purpose=DisclosurePurpose.DISPUTE,
                allowed_classes=(DataClass.PUBLIC, DataClass.RESTRICTED),
            ),
            PurposeGrant(
                purpose=DisclosurePurpose.COMPLIANCE,
                allowed_classes=(
                    DataClass.PUBLIC,
                    DataClass.RESTRICTED,
                    DataClass.CONFIDENTIAL,
                ),
            ),
        ),
        field_rules=(
            FieldRule(field_name="account_id", data_class=DataClass.PUBLIC),
            FieldRule(field_name="txn_count", data_class=DataClass.PUBLIC),
            FieldRule(field_name="email", data_class=DataClass.RESTRICTED),
            FieldRule(field_name="country", data_class=DataClass.RESTRICTED),
            FieldRule(field_name="full_name", data_class=DataClass.CONFIDENTIAL),
            FieldRule(field_name="balance", data_class=DataClass.CONFIDENTIAL),
        ),
        retention_rules=(
            RetentionRule(data_class=DataClass.PUBLIC, retain_seconds=3600),
            RetentionRule(data_class=DataClass.RESTRICTED, retain_seconds=86400),
            RetentionRule(data_class=DataClass.CONFIDENTIAL, retain_seconds=604800),
        ),
    )


def _dataset() -> IsolatedDataset:
    return IsolatedDataset(
        dataset_id="dataset/dogfood-customers",
        records=(
            dataset_record(
                "customer-001",
                {
                    "account_id": "acct-001",
                    "txn_count": 42,
                    "email": "user1@example.test",
                    "country": "DE",
                    "full_name": "Ada Example",
                    "balance": 125000,
                },
            ),
            dataset_record(
                "customer-002",
                {
                    "account_id": "acct-002",
                    "txn_count": 7,
                    "email": "user2@example.test",
                    "country": "FR",
                    "full_name": "Bob Example",
                    "balance": 9900,
                },
            ),
        ),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CoreValidationError(f"DOGFOOD-022 check failed: {message}")


def run_experiment() -> str:
    """Run the deterministic DOGFOOD-022 experiment; return the transcript."""
    lines: list[str] = []
    checks = 0

    engine = DataGovernanceEngine(
        environment_id=ENV,
        operator=OPERATOR,
        trust_registry=_build_trust_registry(),
        evidence_archive=_build_evidence_archive(),
    )
    lines.append(
        "DOGFOOD-022: data governance, privacy and recourse — real supported path"
    )
    lines.append(
        "binding: WORK-022, architecture v0.1, module src.data, "
        "kernel src.transition, trust src.trust, evidence src.evidence"
    )
    lines.append(
        f"environment: {ENV}; participants: 4 ACTIVE trust principals; "
        "archived evidence records: 2"
    )

    # -- declared policy --------------------------------------------------
    declared = engine.declare_policy(spec=_policy_spec())
    active = engine.activate_policy(policy_id=POLICY_ID, as_of=T1)
    checks += 1
    _require(active.state.value == "ACTIVE", "policy must be ACTIVE after activation")
    lines.append(
        f"declared data policy {POLICY_ID}: state ACTIVE, version "
        f"{active.envelope.object_version}, window "
        f"[{active.spec.effective_from}, {active.spec.valid_until})"
    )

    # -- (a) user dispute case -------------------------------------------
    lines.append("--- user dispute case (recourse through the real kernel) ---")
    claim = Claim(
        claim_id="claim-001",
        claimant=USER,
        claim_type=ClaimType.UNAUTHORIZED_TRANSACTION,
        subject_ref=SUBJECT,
        description="Transaction tx-9001 was not authorized by the account holder.",
        asserted_at=T2,
        amount=CLAIM_AMOUNT,
        evidence_refs=(EVIDENCE_COMPLAINT,),
    )
    case = engine.open_case(
        case_id="data-case/dispute-001",
        subject_ref=SUBJECT,
        opened_by=OPERATOR,
        opened_at=T2,
        claims=(claim,),
    )
    checks += 1
    _require(case.state.value == "OPEN", "case must open in state OPEN")
    lines.append(
        f"dispute case opened {case.case_id}: state OPEN, version "
        f"{case.envelope.object_version}, claims {len(case.claims)} "
        f"({case.claims[0].claim_type.value}, {case.claims[0].amount.value}"
        f"e{case.claims[0].amount.scale} {case.claims[0].amount.unit})"
    )

    investigated = engine.investigate(
        case_id="data-case/dispute-001",
        investigation=Investigation(
            investigator=INVESTIGATOR,
            investigated_at=T3,
            findings="No authorization record exists for tx-9001; complaint matches evidence.",
            evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
        ),
    )
    checks += 1
    _require(
        investigated.state.value == "INVESTIGATED"
        and investigated.investigation.evidence_refs
        == (EVIDENCE_TXN, EVIDENCE_COMPLAINT),
        "investigation must attach resolvable archived evidence",
    )
    lines.append(
        f"investigation recorded by {INVESTIGATOR}: state INVESTIGATED, "
        f"{len(investigated.investigation.evidence_refs)} archived evidence references"
    )

    decided = engine.decide(
        case_id="data-case/dispute-001",
        decision=RecourseDecision(
            decision_id="decision-001",
            kind=DecisionKind.APPROVE_REFUND,
            decided_by=DECIDER,
            decided_at=T3,
            rationale="Unauthorized transaction confirmed; refund approved.",
            evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
            amount=CLAIM_AMOUNT,
        ),
    )
    checks += 1
    _require(decided.state.value == "DECIDED", "case must be DECIDED after the decision")
    lines.append(
        f"recourse decision recorded: {decided.decision.kind.value} "
        f"{decided.decision.amount.value}e{decided.decision.amount.scale} "
        f"{decided.decision.amount.unit} by {DECIDER}, state DECIDED"
    )

    compiled = engine.compile_refund(
        case_id="data-case/dispute-001",
        package=RefundPackage(
            package_id="refund-package/001",
            compiled_by=OPERATOR,
            compiled_at=T3,
            amount=CLAIM_AMOUNT,
            target_ref=SUBJECT,
            execution_domain="domain/settlement",
            evidence_refs=(EVIDENCE_TXN,),
        ),
    )
    checks += 1
    _require(
        compiled.refund_package.package_id == "refund-package/001"
        and compiled.refund_package.amount == CLAIM_AMOUNT,
        "the compiled refund package must match the approved decision exactly",
    )
    lines.append(
        f"refund package compiled: {compiled.refund_package.package_id} "
        f"-> {compiled.refund_package.execution_domain} (recorded reference; "
        "actual financial execution belongs to other domains)"
    )

    executed = engine.execute_refund(
        case_id="data-case/dispute-001",
        execution=ExecutionRecord(
            executed_by=OPERATOR,
            executed_at=T4,
            execution_ref="ledger/refund/tx-9001-r1",
        ),
    )
    checks += 1
    _require(
        executed.state.value == "EXECUTED"
        and executed.execution.execution_ref == "ledger/refund/tx-9001-r1",
        "the recorded execution must carry the explicit external reference",
    )
    lines.append(
        f"refund execution recorded: {executed.execution.execution_ref}, "
        f"state EXECUTED at {executed.execution.executed_at}"
    )

    closed = engine.close_case(
        case_id="data-case/dispute-001",
        closed_at=T5,
        close_reason="Refund executed and confirmed.",
    )
    checks += 1
    _require(closed.state.value == "CLOSED", "the dispute case must close")
    lines.append(
        f"dispute case closed at {closed.closed_at}: state CLOSED, version "
        f"{closed.envelope.object_version}, reason {closed.payload.close_reason!r}"
    )

    # -- (b) selective disclosure over an isolated dataset ----------------
    lines.append("--- selective disclosure over an isolated dataset ---")
    dataset = _dataset()
    commitment = commit_dataset(dataset)
    checks += 1
    _require(
        len(commitment.records) == 2
        and len(commitment.records[0].field_commitments) == 6,
        "the dataset commitment must cover every record and field",
    )
    lines.append(
        f"isolated dataset committed: {len(commitment.records)} records x "
        f"{len(commitment.records[0].field_commitments)} fields, root "
        f"{commitment.root[:16]}…"
    )

    request = DisclosureRequest(
        requester=USER,
        subject_ref=SUBJECT,
        purpose=DisclosurePurpose.DISPUTE,
        requested_fields=("account_id", "email", "balance"),
        requested_at=T2,
    )
    assessment = engine.get_assessment(
        engine.request_disclosure(
            disclosure_id="data-disclosure/dogfood-001", request=request
        ).disclosure_id
    )
    checks += 1
    _require(
        assessment.verdict.value == "PARTIALLY_PERMITTED"
        and assessment.permitted_fields == ("account_id", "email")
        and assessment.denied_fields == ("balance",),
        "the privacy assessment must split fields exactly per the declared policy",
    )
    lines.append(
        f"disclosure request assessed at {assessment.as_of}: verdict "
        f"{assessment.verdict.value}, permitted {list(assessment.permitted_fields)}, "
        f"denied {list(assessment.denied_fields)}"
    )

    proof = engine.produce_proof(
        proof_id="data-proof/dogfood-001",
        dataset=dataset,
        commitment=commitment,
        request=request,
        policy_id=POLICY_ID,
        as_of=T2,
    )
    proof_json = proof.to_json()
    checks += 1
    _require(
        set(dict(proof.disclosed_records[0].disclosed_fields)) == {"account_id", "email"}
        and set(proof.disclosed_records[0].withheld_fields)
        == {"balance", "country", "full_name", "txn_count"},
        "the proof must disclose only policy-permitted fields",
    )
    lines.append(
        "selective disclosure proof produced: disclosed {account_id, email}, "
        "withheld {balance, country, full_name, txn_count} (commitments only)"
    )

    from .selective import verify_disclosure_proof

    verify_disclosure_proof(
        proof, policy=engine.get(POLICY_ID), as_of=T2, expected_root=commitment.root
    )
    checks += 1
    lines.append(
        "proof verified against the declared policy and the trusted dataset root: OK"
    )

    checks += 1
    _require(
        "Ada Example" not in proof_json
        and "Bob Example" not in proof_json
        and "user1@example.test" in proof_json,
        "withheld CONFIDENTIAL values must never appear in the proof",
    )
    lines.append(
        "leakage gate: withheld values absent from the serialized proof while "
        "permitted values present: OK"
    )

    tampered = IsolatedDataset(
        dataset_id=dataset.dataset_id,
        records=(
            dataset_record(
                "customer-001",
                {**dict(dataset.records[0].fields), "balance": 999999},
            ),
            dataset.records[1],
        ),
    )
    tamper_rejected = False
    try:
        engine.produce_proof(
            proof_id="data-proof/dogfood-tamper",
            dataset=tampered,
            commitment=commitment,
            request=request,
            policy_id=POLICY_ID,
            as_of=T3,
        )
    except CoreValidationError:
        tamper_rejected = True
    checks += 1
    _require(tamper_rejected, "a tampered dataset must fail closed at proof production")
    lines.append(
        "tampered dataset (customer-001 balance changed): proof production "
        "REJECTED — fail closed on commitment mismatch"
    )

    # -- retention bookkeeping on the same subject -------------------------
    retention = engine.record_retention(
        retention_id="data-retention/dogfood-001",
        subject_ref=SUBJECT,
        data_class=DataClass.RESTRICTED,
        collected_at=T1,
        policy_id=POLICY_ID,
    )
    held = engine.declare_retention_hold(
        retention_id="data-retention/dogfood-001",
        hold=LegalHold(
            hold_id="legal-hold/dogfood-1",
            declared_by=DECIDER,
            declared_at=T2,
            basis_ref="legal-basis/dogfood-litigation",
            case_ref="data-case/dispute-001",
        ),
    )
    checks += 1
    _require(
        held.legal_hold is not None
        and held.state.value == "ACTIVE"
        and held.payload.retain_until == "2026-09-03T06:00:00Z",
        "retention horizon must follow the declared policy and the hold must suspend expiry",
    )
    lines.append(
        f"retention recorded for {SUBJECT}: class RESTRICTED, retain_until "
        f"{held.payload.retain_until}, legal hold {held.legal_hold.hold_id} "
        "suspends expiry (append-only bookkeeping; no deletion exists)"
    )

    # -- kernel discipline -------------------------------------------------
    journal = engine.journal
    checks += 1
    _require(
        len(journal) > 0
        and all(entry.event.event_type.startswith("governance/") for entry in journal),
        "every accepted transition must emit a governance-namespace event",
    )
    lines.append(
        f"kernel discipline: {len(journal)} journal entries, all governance/* "
        f"events, logical time {journal[-1].event.logical_time}"
    )

    digest = engine.state_digest()
    checks += 1
    _require(len(digest) == 64, "the engine state digest must be a SHA-256 hex digest")
    lines.append(f"engine state digest: {digest}")

    lines.append(f"checks: {checks}/{checks} PASS")
    lines.append("classification: PASS")
    lines.append("DOGFOOD-022: PASS")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual invocation helper
    import sys

    sys.stdout.write(run_experiment())
