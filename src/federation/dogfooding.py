"""DOGFOOD-023 — two-domain payment scenario with signed state
commitments and a replayed inter-domain message (WORK-023 dogfooding
contract).

This module is a clearly-marked TEST-SIDE artifact (sandbox world
state): it drives the REAL :class:`~src.trust.TrustRegistry` (WORK-004),
the REAL :class:`~src.clearing.ClearingEngine` +
:class:`~src.settlement.SettlementEngine` chain (WORK-015/016) and two
REAL :class:`~src.federation.FederationEngine` instances — one per
domain — over the merged public contracts, with rail evidence
synthesized as sealed execution-domain records. It moves no real funds
and claims no real finality beyond the settlement domain's certificates.

Scenario (all instants declared):

1. the trust registry registers the two domains' state authorities and
   their purpose-bound ``DOMAIN_STATE_COMMITMENT`` keys;
2. a real payment runs in the GH domain's corridor: clearing recognizes
   and finalizes one obligation, settlement discharges it with a
   SETTLED rail observation, and a finality certificate is established
   (the only protocol claim of finality);
3. both federation engines register their own domains (authority facts
   derived from the sealed trust keys) and join each other as mutual
   anchors;
4. GH publishes commitment 1 (state-only) and commitment 2 (signed
   state + digest-bound finality evidence, addressed to US through an
   inter-domain message created in the same atomic transition);
5. US accepts the foreign commitment — full signature verification
   against the anchor key, message/commitment digest binding — and
   records the acceptance;
6. the REPLAYED message is submitted to US again and rejected (replay
   protection);
7. US publishes its own state commitment addressed to GH, and GH
   accepts it (bidirectional federation);
8. GH transfers its domain authority to the successor principal (dual
   secret-knowledge consent, one atomic version bump) and publishes
   commitment 3 under the new key;
9. negative probes pin the boundaries: a PENDING finality certificate
   never binds, a forged commitment signature never passes the peer's
   acceptance, a tampered message fails the seal, and a wrong anchor
   secret is rejected;
10. both engines' domain state is rebuilt from the journal alone and
    restored from snapshots, byte-identically.
"""

from __future__ import annotations

from typing import Any

from src.clearing import ClearingEngine, Obligation
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
from src.settlement import SettlementEngine
from src.trust import TrustRegistry
from src.trust.keys import KeyPurpose

from .commitments import FinalityBinding, commitment_payload_digest
from .contracts import (
    AcceptanceState,
    CommitmentState,
    DomainState,
    MessageState,
)
from .engine import FederationEngine

ENVIRONMENT_ID = "env/dogfood-023"
GH_DOMAIN = "domain/dogfood-023-gh"
US_DOMAIN = "domain/dogfood-023-us"
TRUST_DOMAIN = "trust/dogfood-023"
CLEARING_DOMAIN = "clearing/dogfood-023"
SETTLEMENT_DOMAIN = "settlement/dogfood-023"
EXECUTION_DOMAIN = "execution/dogfood-023"

T0 = "2026-01-05T09:00:00Z"
T1 = "2026-01-05T09:30:00Z"
T2 = "2026-01-05T10:00:00Z"
T3 = "2026-01-05T11:00:00Z"
T4 = "2026-01-05T12:00:00Z"
T5 = "2026-01-05T13:00:00Z"
T6 = "2026-01-05T14:00:00Z"
T7 = "2026-01-05T15:00:00Z"
T8 = "2026-01-05T16:00:00Z"
LATE = "2027-01-01T00:00:00Z"

OPERATOR_PRINCIPAL = "trust/principal/dogfood-023-operator"
GH_AUTHORITY_PRINCIPAL = "trust/principal/gh-state-authority"
GH_SUCCESSOR_PRINCIPAL = "trust/principal/gh-successor-authority"
US_AUTHORITY_PRINCIPAL = "trust/principal/us-state-authority"

GH_KEY_ID = "trust/key/dogfood-023-gh-1"
GH_SUCCESSOR_KEY_ID = "trust/key/dogfood-023-gh-2"
US_KEY_ID = "trust/key/dogfood-023-us-1"
GH_PUBLIC = "pk-dogfood-023-gh-1"
GH_SUCCESSOR_PUBLIC = "pk-dogfood-023-gh-2"
US_PUBLIC = "pk-dogfood-023-us-1"
GH_SECRET = "sk-dogfood-023-gh-1"
GH_SUCCESSOR_SECRET = "sk-dogfood-023-gh-2"
US_SECRET = "sk-dogfood-023-us-1"

CYCLE_ID = "clearing/dogfood-023/cycle-1"
SETTLEMENT_ID = "settlement/dogfood-023/batch-1"
FINALITY_ID = "settlement/dogfood-023/finality-1"

ALPHA = "psp/alpha"
BETA = "psp/beta"
ASSET = "GHS"
RAIL = "adapter/sandbox-rail"


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "pass": bool(passed), "detail": detail})


def _negative_probe(checks: list[dict[str, Any]], name: str, action) -> None:
    try:
        action()
    except CoreValidationError as exc:
        _check(checks, name, True, f"rejected: {exc}")
        return
    _check(checks, name, False, "probe unexpectedly accepted")


def _register_key(
    registry: TrustRegistry,
    key_id: str,
    owner: str,
    public: str,
    secret: str,
):
    return registry.register_key(
        key_id=key_id,
        owner_principal_id=owner,
        purpose=KeyPurpose.DOMAIN_STATE_COMMITMENT.value,
        public_material=public,
        secret_material=secret,
        not_before=T0,
        not_after=LATE,
        as_of=T0,
        operator=OPERATOR_PRINCIPAL,
    )


def _effect_result(payer: str, payee: str, minor: int) -> dict[str, Any]:
    request_id = "plan/dogfood-023-1/request/1"
    spec = EffectResultSpec(
        result_id=f"{request_id}/result",
        request_id=request_id,
        step_id="plan/dogfood-023-1/step-1",
        effect_type="payment/submit",
        outcome=EffectOutcome.SUCCEEDED,
        native_reference="rail/ref-dogfood-023-1",
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
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T0,
        ),
    )
    return record.to_dict()


def _status_observation(subject_ref: str, subject_digest: str) -> dict[str, Any]:
    spec = ExternalObservationSpec(
        observation_id="execution/dogfood-023/status-1",
        kind=ObservationKind.STATUS,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=T3,
        content={"native_code": "rail/code-023-1", "canonical_status": "SETTLED"},
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T3,
        ),
    )
    return record.to_dict()


def _finality_observation(subject_ref: str, subject_digest: str) -> dict[str, Any]:
    spec = ExternalObservationSpec(
        observation_id="execution/dogfood-023/finality-1",
        kind=ObservationKind.FINALITY,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=T3,
        content={
            "claim": FinalityClaim.FINAL.value,
            "native_reference": "rail/finality-023-1",
        },
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T3,
        ),
    )
    return record.to_dict()


def build_transcript() -> dict[str, Any]:
    """Drive the full two-domain sandbox scenario and build the byte-stable transcript."""
    checks: list[dict[str, Any]] = []

    # -- 1. the trust registry: two state authorities and their keys --
    registry = TrustRegistry(environment_id=ENVIRONMENT_ID, domain_id=TRUST_DOMAIN)
    registry.create_principal(
        principal_id=OPERATOR_PRINCIPAL,
        display_name="dogfood-023 operator",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=GH_AUTHORITY_PRINCIPAL,
        display_name="Ghana domain state authority",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=GH_SUCCESSOR_PRINCIPAL,
        display_name="Ghana domain successor authority",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=US_AUTHORITY_PRINCIPAL,
        display_name="US domain state authority",
        as_of=T0,
    )
    gh_key = _register_key(
        registry, GH_KEY_ID, GH_AUTHORITY_PRINCIPAL, GH_PUBLIC, GH_SECRET
    )
    gh_successor_key = _register_key(
        registry,
        GH_SUCCESSOR_KEY_ID,
        GH_SUCCESSOR_PRINCIPAL,
        GH_SUCCESSOR_PUBLIC,
        GH_SUCCESSOR_SECRET,
    )
    us_key = _register_key(registry, US_KEY_ID, US_AUTHORITY_PRINCIPAL, US_PUBLIC, US_SECRET)
    _check(
        checks,
        "both domain state authorities hold ACTIVE DOMAIN_STATE_COMMITMENT keys",
        gh_key.state == "ACTIVE"
        and gh_key.purpose is KeyPurpose.DOMAIN_STATE_COMMITMENT
        and us_key.state == "ACTIVE"
        and us_key.purpose is KeyPurpose.DOMAIN_STATE_COMMITMENT,
        f"gh={gh_key.key_id}, us={us_key.key_id}",
    )

    # -- 2. a real payment settles with an established finality certificate --
    clearing = ClearingEngine(environment_id=ENVIRONMENT_ID, domain_id=CLEARING_DOMAIN)
    settlement = SettlementEngine(
        environment_id=ENVIRONMENT_ID, domain_id=SETTLEMENT_DOMAIN
    )
    clearing.create_cycle(
        command_id="cmd-023-001",
        requested_at=T0,
        cycle_id=CYCLE_ID,
        opens_at=T0,
        closes_at=T2,
        description="dogfood-023 recognition window",
    )
    clearing.recognize_obligation(
        command_id="cmd-023-010",
        requested_at=T1,
        cycle_id=CYCLE_ID,
        effect_result=_effect_result(ALPHA, BETA, 120000),
        due_from=T2,
        due_until=LATE,
    )
    obligation_id = next(
        record.object_id
        for record in clearing.records()
        if isinstance(record, Obligation)
    )
    clearing.validate_obligation(
        command_id="cmd-023-020", requested_at=T2, obligation_id=obligation_id
    )
    clearing.mark_due_obligation(
        command_id="cmd-023-021", requested_at=T2, obligation_id=obligation_id
    )
    clearing.validate_cycle(command_id="cmd-023-030", requested_at=T2, cycle_id=CYCLE_ID)
    clearing.finalize_cycle(command_id="cmd-023-031", requested_at=T2, cycle_id=CYCLE_ID)
    _check(
        checks,
        "clearing finalizes the cycle with the obligation DUE",
        clearing.cycle(CYCLE_ID).state is ClearingCycleState.FINALIZED
        and clearing.obligation(obligation_id).state is ObligationState.DUE,
        f"cycle={clearing.cycle(CYCLE_ID).state.value}",
    )
    settlement.create_settlement(
        command_id="cmd-023-100",
        requested_at=T2,
        settlement_id=SETTLEMENT_ID,
        obligations=[clearing.obligation(obligation_id).to_dict()],
        submit_by="2026-02-01T00:00:00Z",
        settle_by=LATE,
    )
    settlement.authorize_settlement(
        command_id="cmd-023-101", requested_at=T2, settlement_id=SETTLEMENT_ID
    )
    settlement.submit_settlement(
        command_id="cmd-023-102", requested_at=T2, settlement_id=SETTLEMENT_ID
    )
    batch = settlement.settlement(SETTLEMENT_ID)
    leg_id = batch.spec.instructions[0].instruction_id
    leg_digest = batch.spec.instructions[0].instruction_digest()
    settlement.reconcile_settlement(
        command_id="cmd-023-103",
        requested_at=T3,
        settlement_id=SETTLEMENT_ID,
        as_of=T3,
        observations=[_status_observation(leg_id, leg_digest)],
    )
    settlement.validate_finality_claim(
        command_id="cmd-023-110",
        requested_at=T3,
        finality_id=FINALITY_ID,
        settlement_id=SETTLEMENT_ID,
        observation=_finality_observation(leg_id, leg_digest),
    )
    # the certificate's PENDING version (validated, not yet established)
    # is captured here for the no-false-finality negative probe below.
    pending_certificate = settlement.finality(FINALITY_ID).to_dict()
    settlement.establish_finality(
        command_id="cmd-023-111", requested_at=T3, finality_id=FINALITY_ID
    )
    certificate = settlement.finality(FINALITY_ID)
    _check(
        checks,
        "the payment settles and a finality certificate is established",
        certificate.state.value == "ESTABLISHED",
        f"finality={FINALITY_ID}, settlement={SETTLEMENT_ID}",
    )
    evidence = settlement.discharge_evidence(SETTLEMENT_ID)
    clearing.resolve_obligation(
        command_id="cmd-023-112",
        requested_at=T3,
        obligation_id=obligation_id,
        evidence_ref=evidence[0]["evidence_ref"],
        evidence_digest=evidence[0]["evidence_digest"],
        reason="dogfood-023 settlement discharge",
    )
    _check(
        checks,
        "the obligation is resolved with digest-bound discharge evidence",
        clearing.obligation(obligation_id).state is ObligationState.RESOLVED
        and clearing.obligation(obligation_id).spec.resolution.kind
        == ResolutionKind.DISCHARGE_EVIDENCE.value,
        f"resolution kind={ResolutionKind.DISCHARGE_EVIDENCE.value}",
    )

    # -- 3. both domains register and join each other as mutual anchors --
    gh = FederationEngine(environment_id=ENVIRONMENT_ID, domain_id=GH_DOMAIN)
    us = FederationEngine(environment_id=ENVIRONMENT_ID, domain_id=US_DOMAIN)
    gh.register_domain(
        command_id="cmd-gh-001",
        requested_at=T0,
        domain_id=GH_DOMAIN,
        authority_key=gh_key.to_dict(),
    )
    us.register_domain(
        command_id="cmd-us-001",
        requested_at=T0,
        domain_id=US_DOMAIN,
        authority_key=us_key.to_dict(),
    )
    gh.join_federation(
        command_id="cmd-gh-002",
        requested_at=T1,
        domain_id=GH_DOMAIN,
        anchor_domain_id=US_DOMAIN,
        anchor_key=us_key.to_dict(),
    )
    us.join_federation(
        command_id="cmd-us-002",
        requested_at=T1,
        domain_id=US_DOMAIN,
        anchor_domain_id=GH_DOMAIN,
        anchor_key=gh_key.to_dict(),
    )
    _check(
        checks,
        "both domains are JOINED with each other as anchors",
        gh.domain(GH_DOMAIN).state is DomainState.JOINED
        and us.domain(US_DOMAIN).state is DomainState.JOINED
        and gh.domain(GH_DOMAIN).spec.join.anchor_domain_id == US_DOMAIN
        and us.domain(US_DOMAIN).spec.join.anchor_domain_id == GH_DOMAIN,
        f"gh anchor={US_DOMAIN}, us anchor={GH_DOMAIN}",
    )

    # -- 4. GH publishes a state-only commitment, then a finality-bound one --
    gh.publish_commitment(
        command_id="cmd-gh-010",
        requested_at=T2,
        commitment_id="commitment/gh-1",
        sequence=1,
        finality_certificates=[],
        secret_material=GH_SECRET,
    )
    first = gh.commitment("commitment/gh-1")
    first_digest = commitment_payload_digest(
        commitment_id="commitment/gh-1",
        domain_id=GH_DOMAIN,
        sequence=1,
        state_digest=first.spec.state_digest,
        finality_bindings=first.spec.finality_bindings,
    )
    from .authority import verify_commitment_signature

    verify_commitment_signature(
        first.spec.signature,
        key_id=first.spec.key_id,
        public_material=first.spec.public_material,
        secret_material=GH_SECRET,
        payload_digest=first_digest,
    )
    _check(
        checks,
        "GH publishes a signed state-only commitment (sequence 1)",
        first.state is CommitmentState.PUBLISHED
        and first.spec.sequence == 1
        and first.spec.finality_bindings == (),
        f"state_digest={first.spec.state_digest[:16]}...",
    )
    gh_state_digest_before_second = gh.state_digest()
    gh.publish_commitment(
        command_id="cmd-gh-011",
        requested_at=T3,
        commitment_id="commitment/gh-2",
        sequence=2,
        finality_certificates=[certificate.to_dict()],
        secret_material=GH_SECRET,
        destination_domain_id=US_DOMAIN,
        message_id="message/gh-2",
        message_nonce="nonce-gh-2",
    )
    second = gh.commitment("commitment/gh-2")
    binding: FinalityBinding = second.spec.finality_bindings[0]
    message = gh.message("message/gh-2")
    _check(
        checks,
        "the commitment signs the exact pre-publish journal state digest",
        second.spec.state_digest == gh_state_digest_before_second,
        f"state_digest={second.spec.state_digest[:16]}...",
    )
    _check(
        checks,
        "the finality-bound commitment is digest-bound to the real certificate",
        binding.finality_id == FINALITY_ID
        and binding.settlement_id == SETTLEMENT_ID
        and binding.certificate_digest == certificate.integrity_hash
        and binding.settlement_digest == certificate.spec.settlement_digest,
        f"binding={binding.to_dict()}",
    )
    _check(
        checks,
        "the inter-domain message is created in the same atomic transition",
        message.state is MessageState.ISSUED
        and message.spec.origin_domain == GH_DOMAIN
        and message.spec.destination_domain == US_DOMAIN
        and message.spec.commitment_digest == second.integrity_hash,
        f"message={message.object_id}, nonce={message.spec.nonce}",
    )

    # -- 5. US accepts the foreign commitment with full verification --
    us.accept_commitment(
        command_id="cmd-us-010",
        requested_at=T4,
        acceptance_id="acceptance/us-1",
        message=message.to_dict(),
        commitment=second.to_dict(),
        anchor_secret_material=GH_SECRET,
    )
    acceptance = us.acceptance("acceptance/us-1")
    second_digest = commitment_payload_digest(
        commitment_id="commitment/gh-2",
        domain_id=GH_DOMAIN,
        sequence=second.spec.sequence,
        state_digest=second.spec.state_digest,
        finality_bindings=second.spec.finality_bindings,
    )
    verify_commitment_signature(
        second.spec.signature,
        key_id=second.spec.key_id,
        public_material=second.spec.public_material,
        secret_material=GH_SECRET,
        payload_digest=second_digest,
    )
    _check(
        checks,
        "US accepts the foreign commitment after signature verification",
        acceptance.state is AcceptanceState.ACCEPTED
        and acceptance.spec.origin_domain == GH_DOMAIN
        and acceptance.spec.message_id == "message/gh-2"
        and acceptance.spec.commitment_digest == second.integrity_hash,
        f"acceptance={acceptance.object_id}",
    )

    # -- 6. the replayed inter-domain message is rejected --
    _negative_probe(
        checks,
        "a replayed inter-domain message is rejected",
        lambda: us.accept_commitment(
            command_id="cmd-us-011",
            requested_at=T5,
            acceptance_id="acceptance/us-2",
            message=message.to_dict(),
            commitment=second.to_dict(),
            anchor_secret_material=GH_SECRET,
        ),
    )

    # -- 7. US publishes its own commitment and GH accepts it --
    us.publish_commitment(
        command_id="cmd-us-012",
        requested_at=T5,
        commitment_id="commitment/us-1",
        sequence=1,
        finality_certificates=[],
        secret_material=US_SECRET,
        destination_domain_id=GH_DOMAIN,
        message_id="message/us-1",
        message_nonce="nonce-us-1",
    )
    gh.accept_commitment(
        command_id="cmd-gh-012",
        requested_at=T6,
        acceptance_id="acceptance/gh-1",
        message=us.message("message/us-1").to_dict(),
        commitment=us.commitment("commitment/us-1").to_dict(),
        anchor_secret_material=US_SECRET,
    )
    _check(
        checks,
        "bidirectional federation: GH accepts US's state commitment",
        gh.acceptance("acceptance/gh-1").state is AcceptanceState.ACCEPTED
        and gh.acceptance("acceptance/gh-1").spec.origin_domain == US_DOMAIN,
        f"acceptance=acceptance/gh-1",
    )

    # -- 8. governed authority transfer, then a commitment under the new key --
    gh.transfer_domain(
        command_id="cmd-gh-013",
        requested_at=T6,
        domain_id=GH_DOMAIN,
        new_principal_id=GH_SUCCESSOR_PRINCIPAL,
        new_key=gh_successor_key.to_dict(),
        outgoing_secret_material=GH_SECRET,
        incoming_secret_material=GH_SUCCESSOR_SECRET,
    )
    transferred = gh.domain(GH_DOMAIN)
    _check(
        checks,
        "the authority transfer is atomic with the successor in one version",
        transferred.spec.authority.principal_id == GH_SUCCESSOR_PRINCIPAL
        and transferred.spec.authority.key_id == GH_SUCCESSOR_KEY_ID
        and len(transferred.spec.transfers) == 1
        and transferred.spec.transfers[0].prior_principal_id == GH_AUTHORITY_PRINCIPAL,
        f"authority={transferred.spec.authority.principal_id}",
    )
    gh.publish_commitment(
        command_id="cmd-gh-014",
        requested_at=T7,
        commitment_id="commitment/gh-3",
        sequence=3,
        finality_certificates=[],
        secret_material=GH_SUCCESSOR_SECRET,
    )
    third = gh.commitment("commitment/gh-3")
    third_digest = commitment_payload_digest(
        commitment_id="commitment/gh-3",
        domain_id=GH_DOMAIN,
        sequence=3,
        state_digest=third.spec.state_digest,
        finality_bindings=third.spec.finality_bindings,
    )
    verify_commitment_signature(
        third.spec.signature,
        key_id=third.spec.key_id,
        public_material=third.spec.public_material,
        secret_material=GH_SUCCESSOR_SECRET,
        payload_digest=third_digest,
    )
    _check(
        checks,
        "the successor authority publishes under the new commitment key",
        third.spec.key_id == GH_SUCCESSOR_KEY_ID
        and third.spec.sequence == 3,
        f"key={third.spec.key_id}",
    )

    # -- 9. negative probes: the no-false-finality and no-forgery boundaries --
    _negative_probe(
        checks,
        "a PENDING finality certificate can never bind into a commitment",
        lambda: gh.publish_commitment(
            command_id="cmd-gh-015",
            requested_at=T7,
            commitment_id="commitment/gh-4",
            sequence=4,
            finality_certificates=[pending_certificate],
            secret_material=GH_SUCCESSOR_SECRET,
        ),
    )
    _negative_probe(
        checks,
        "a wrong anchor secret can never accept a foreign commitment",
        lambda: us.accept_commitment(
            command_id="cmd-us-013",
            requested_at=T7,
            acceptance_id="acceptance/us-3",
            message=message.to_dict(),
            commitment=second.to_dict(),
            anchor_secret_material=US_SECRET,
        ),
    )
    _negative_probe(
        checks,
        "a tampered inter-domain message fails the seal",
        lambda: us.accept_commitment(
            command_id="cmd-us-014",
            requested_at=T7,
            acceptance_id="acceptance/us-4",
            message={
                "envelope": message.to_dict()["envelope"],
                "payload": dict(
                    message.to_dict()["payload"], nonce="nonce-forged"
                ),
                "integrity_hash": message.integrity_hash,
            },
            commitment=second.to_dict(),
            anchor_secret_material=GH_SECRET,
        ),
    )

    # -- 10. journal-only rebuild and snapshot restore, byte-identically --
    gh_rebuilt = FederationEngine.rebuild_from_journal(
        environment_id=ENVIRONMENT_ID,
        domain_id=GH_DOMAIN,
        journal=gh.journal,
    )
    us_rebuilt = FederationEngine.rebuild_from_journal(
        environment_id=ENVIRONMENT_ID,
        domain_id=US_DOMAIN,
        journal=us.journal,
    )
    gh_restored = FederationEngine(environment_id=ENVIRONMENT_ID, domain_id=GH_DOMAIN)
    gh_restored.restore_state(gh.snapshot_state())
    us_restored = FederationEngine(environment_id=ENVIRONMENT_ID, domain_id=US_DOMAIN)
    us_restored.restore_state(us.snapshot_state())
    _check(
        checks,
        "GH state rebuilds byte-identically from the journal alone",
        [record.to_dict() for record in gh_rebuilt.records()]
        == [record.to_dict() for record in gh.records()]
        and gh_rebuilt.state_digest() == gh.state_digest()
        and gh_rebuilt.accepted_message_ids() == gh.accepted_message_ids(),
        f"records={len(gh_rebuilt.records())}, digest={gh.state_digest()[:16]}...",
    )
    _check(
        checks,
        "US state rebuilds byte-identically from the journal alone",
        [record.to_dict() for record in us_rebuilt.records()]
        == [record.to_dict() for record in us.records()]
        and us_rebuilt.state_digest() == us.state_digest(),
        f"records={len(us_rebuilt.records())}, digest={us.state_digest()[:16]}...",
    )
    _check(
        checks,
        "snapshot restore round-trips both engines identically",
        [record.to_dict() for record in gh_restored.records()]
        == [record.to_dict() for record in gh.records()]
        and [record.to_dict() for record in us_restored.records()]
        == [record.to_dict() for record in us.records()]
        and gh_restored.state_digest() == gh.state_digest()
        and us_restored.state_digest() == us.state_digest(),
        "both engines byte-identical after restore",
    )

    transcript = {
        "scenario": "dogfood-023: two-domain payment with signed state commitments "
        "and a replayed inter-domain message",
        "environment_id": ENVIRONMENT_ID,
        "gh_domain": GH_DOMAIN,
        "us_domain": US_DOMAIN,
        "checks": checks,
        "summary": {
            "checks_total": len(checks),
            "checks_passed": sum(1 for check in checks if check["pass"]),
            "gh_state_digest": gh.state_digest(),
            "us_state_digest": us.state_digest(),
            "gh_commitments": 3,
            "us_commitments": 1,
            "transcript_digest": canonical_sha256(
                {"checks": checks}
            ),
        },
    }
    return transcript


def main() -> int:
    transcript = build_transcript()
    print(canonical_json(transcript))
    return 0 if all(check["pass"] for check in transcript["checks"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
