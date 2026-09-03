"""Federation domain test suite (WORK-023).

Red-first-authored suite covering the static boundary, contracts and
registry discipline, composite sealing, the authority and commitment
signature scheme, domain lifecycles with every gate, commitment
publication with finality binding, inter-domain messages, commitment
acceptance with replay protection, the kernel binding (idempotency,
authorization, expected versions, environment and domain mismatch),
snapshot / restore / journal-rebuild transformation completeness, and
dogfooding conformance. The suite shares the domain's discipline:
sealed composites only, declared instants, no wall clock, no entropy.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import subprocess
import sys
import unittest

from src.clearing import ClearingEngine, Obligation
from src.core.envelope import Provenance
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
from src.transition import Command, Outcome, RejectionReason
from src.transition.registry import validate_event_type
from src.trust import KeyRecord, TrustRegistry
from src.trust.keys import KeyPurpose, derive_key_verification_digest
from src.value.amount import Amount

import src.federation as federation
from src.federation import (
    ACCEPTANCE_OBJECT_TYPE,
    AuthorityUpdate,
    AcceptanceSpec,
    COMMAND_EVENT_TYPES,
    COMMITMENT_OBJECT_TYPE,
    CommitmentSpec,
    CommitmentState,
    CommitmentAcceptance,
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    DOMAIN_OBJECT_TYPE,
    DOMAIN_TERMINAL_STATES,
    DomainSpec,
    DomainState,
    FEDERATION_API_VERSION,
    FEDERATION_COMMANDS,
    FEDERATION_EVENT_NAMESPACE,
    FEDERATION_PROTOCOL_VERSION,
    FEDERATION_SCHEMA_VERSION,
    FEDERATION_TRANSITIONS,
    FinalityBinding,
    FederationEngine,
    FederationTransition,
    JoinFact,
    MESSAGE_OBJECT_TYPE,
    MessageKind,
    MessageSpec,
    MessageState,
    OBJECT_TYPES,
    NetworkDomain,
    AcceptanceState,
    StateAuthority,
    StateCommitment,
    InterDomainMessage,
    TransferFact,
    advance_domain,
    advance_envelope,
    build_domain_envelope,
    commitment_payload_digest,
    composite_to_dict,
    composite_to_json,
    decode_authority_key,
    make_acceptance_record,
    make_commitment_record,
    make_domain_record,
    make_message_record,
    sign_commitment,
    validate_command,
    verify_commitment_signature,
)

ENV = "env/federation-test"
GH_DOMAIN = "domain/test-gh"
US_DOMAIN = "domain/test-us"
FOREIGN_DOMAIN = "domain/test-foreign"

TRUST_ENV = "env/federation-test"
OPERATOR_PRINCIPAL = "trust/principal/federation-operator"
GH_PRINCIPAL = "trust/principal/gh-authority"
GH_PRINCIPAL_2 = "trust/principal/gh-authority-2"
US_PRINCIPAL = "trust/principal/us-authority"

GH_KEY_ID = "trust/key/gh-commitment-1"
GH_KEY_ID_2 = "trust/key/gh-commitment-2"
GH_KEY_ID_3 = "trust/key/gh-commitment-3"
US_KEY_ID = "trust/key/us-commitment-1"
OTHER_PURPOSE_KEY_ID = "trust/key/gh-authentication-1"

GH_PUBLIC = "pk-gh-commitment-1"
GH_PUBLIC_2 = "pk-gh-commitment-2"
GH_PUBLIC_3 = "pk-gh-commitment-3"
US_PUBLIC = "pk-us-commitment-1"
GH_SECRET = "sk-gh-commitment-1"
GH_SECRET_2 = "sk-gh-commitment-2"
GH_SECRET_3 = "sk-gh-commitment-3"
US_SECRET = "sk-us-commitment-1"

T0 = "2026-01-05T09:00:00Z"
T1 = "2026-01-05T10:00:00Z"
T2 = "2026-01-05T11:00:00Z"
T3 = "2026-01-05T12:00:00Z"
T4 = "2026-01-05T13:00:00Z"
T5 = "2026-01-05T14:00:00Z"
T6 = "2026-01-05T15:00:00Z"
LATE = "2027-01-01T00:00:00Z"

PROVENANCE = Provenance(
    issuer=DEFAULT_ENGINE_ACTOR,
    source="federation/domain",
    recorded_at=T0,
)


# ---------------------------------------------------------------------------
# shared fixtures: trust keys and a real established finality certificate
# ---------------------------------------------------------------------------


def _trust_registry() -> TrustRegistry:
    registry = TrustRegistry(environment_id=TRUST_ENV)
    registry.create_principal(
        principal_id=OPERATOR_PRINCIPAL,
        display_name="federation test operator",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=GH_PRINCIPAL,
        display_name="Ghana domain state authority",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=GH_PRINCIPAL_2,
        display_name="Ghana domain successor authority",
        as_of=T0,
    )
    registry.create_principal(
        principal_id=US_PRINCIPAL,
        display_name="US domain state authority",
        as_of=T0,
    )
    return registry


def _register_commitment_key(
    registry: TrustRegistry,
    key_id: str,
    owner_principal_id: str,
    public_material: str,
    secret_material: str,
):
    return registry.register_key(
        key_id=key_id,
        owner_principal_id=owner_principal_id,
        purpose=KeyPurpose.DOMAIN_STATE_COMMITMENT.value,
        public_material=public_material,
        secret_material=secret_material,
        not_before=T0,
        not_after=LATE,
        as_of=T0,
        operator=OPERATOR_PRINCIPAL,
    )


_TRUST_FIXTURE: dict[str, object] = {}


def _trust_fixtures() -> dict[str, object]:
    if not _TRUST_FIXTURE:
        registry = _trust_registry()
        gh_key = _register_commitment_key(
            registry, GH_KEY_ID, GH_PRINCIPAL, GH_PUBLIC, GH_SECRET
        )
        gh_key_2 = _register_commitment_key(
            registry, GH_KEY_ID_2, GH_PRINCIPAL, GH_PUBLIC_2, GH_SECRET_2
        )
        gh_key_3 = _register_commitment_key(
            registry, GH_KEY_ID_3, GH_PRINCIPAL_2, GH_PUBLIC_3, GH_SECRET_3
        )
        us_key = _register_commitment_key(
            registry, US_KEY_ID, US_PRINCIPAL, US_PUBLIC, US_SECRET
        )
        other_purpose_key = registry.register_key(
            key_id=OTHER_PURPOSE_KEY_ID,
            owner_principal_id=GH_PRINCIPAL,
            purpose=KeyPurpose.AUTHENTICATION.value,
            public_material="pk-gh-auth-1",
            secret_material="sk-gh-auth-1",
            not_before=T0,
            not_after=LATE,
            as_of=T0,
            operator=OPERATOR_PRINCIPAL,
        )
        _TRUST_FIXTURE.update(
            {
                "registry": registry,
                "gh_key": gh_key,
                "gh_key_2": gh_key_2,
                "gh_key_3": gh_key_3,
                "us_key": us_key,
                "other_purpose_key": other_purpose_key,
            }
        )
    return _TRUST_FIXTURE


def _gh_key_composite() -> dict:
    return _trust_fixtures()["gh_key"].to_dict()


def _gh_key_2_composite() -> dict:
    return _trust_fixtures()["gh_key_2"].to_dict()


def _gh_key_3_composite() -> dict:
    return _trust_fixtures()["gh_key_3"].to_dict()


def _us_key_composite() -> dict:
    return _trust_fixtures()["us_key"].to_dict()


def _other_purpose_key_composite() -> dict:
    return _trust_fixtures()["other_purpose_key"].to_dict()


# -- real settlement flow producing a finality certificate composite ---------

_SETTLEMENT_ENV = "env/federation-settlement"
CLEARING_DOMAIN = "clearing/federation-test"
SETTLEMENT_DOMAIN = "settlement/federation-test"
EXECUTION_DOMAIN = "execution/federation-test"

ASSET = "GHS"
ALPHA = "psp/alpha"
BETA = "psp/beta"
RAIL = "adapter/sandbox-rail"


def _effect_result(payer: str, payee: str, minor: int, index: int = 1) -> dict:
    request_id = f"plan/federation-test-{index}/request/1"
    spec = EffectResultSpec(
        result_id=f"{request_id}/result",
        request_id=request_id,
        step_id=f"plan/federation-test-{index}/step-1",
        effect_type="payment/submit",
        outcome=EffectOutcome.SUCCEEDED,
        native_reference=f"rail/ref-federation-test-{index}",
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
        environment_id=_SETTLEMENT_ENV,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T0,
        ),
    )
    return record.to_dict()


def _status_observation(subject_ref: str, subject_digest: str) -> dict:
    spec = ExternalObservationSpec(
        observation_id="execution/federation-test/status-1",
        kind=ObservationKind.STATUS,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=T3,
        content={"native_code": "rail/code-fed-1", "canonical_status": "SETTLED"},
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=_SETTLEMENT_ENV,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T3,
        ),
    )
    return record.to_dict()


def _finality_observation(subject_ref: str, subject_digest: str) -> dict:
    spec = ExternalObservationSpec(
        observation_id="execution/federation-test/finality-1",
        kind=ObservationKind.FINALITY,
        subject_ref=subject_ref,
        adapter_id=RAIL,
        epistemic=EpistemicType.OBSERVED,
        observed_at=T3,
        content={"claim": FinalityClaim.FINAL.value, "native_reference": "rail/finality-federation-1"},
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=_SETTLEMENT_ENV,
        domain_id=EXECUTION_DOMAIN,
        provenance=Provenance(
            issuer="principal/sandbox-rail",
            source="execution/domain",
            recorded_at=T3,
        ),
    )
    return record.to_dict()


_SETTLEMENT_FIXTURE: dict[str, object] = {}


def _settlement_fixture() -> dict[str, object]:
    if not _SETTLEMENT_FIXTURE:
        clearing = ClearingEngine(
            environment_id=_SETTLEMENT_ENV, domain_id=CLEARING_DOMAIN
        )
        settlement = SettlementEngineLite = None  # placeholder removed below
        from src.settlement import SettlementEngine

        engine = SettlementEngine(
            environment_id=_SETTLEMENT_ENV, domain_id=SETTLEMENT_DOMAIN
        )
        clearing.create_cycle(
            command_id="cmd-fed-001",
            requested_at=T0,
            cycle_id="clearing/federation-test/cycle-1",
            opens_at=T0,
            closes_at=T2,
            description="federation test recognition window",
        )
        clearing.recognize_obligation(
            command_id="cmd-fed-010",
            requested_at=T1,
            cycle_id="clearing/federation-test/cycle-1",
            effect_result=_effect_result(ALPHA, BETA, 120000, index=1),
            due_from=T2,
            due_until=LATE,
        )
        clearing.recognize_obligation(
            command_id="cmd-fed-011",
            requested_at=T1,
            cycle_id="clearing/federation-test/cycle-1",
            effect_result=_effect_result(BETA, ALPHA, 80000, index=2),
            due_from=T2,
            due_until=LATE,
        )
        obligation_ids = sorted(
            record.object_id
            for record in clearing.records()
            if isinstance(record, Obligation)
        )
        obligation_id = obligation_ids[0]
        pending_obligation_id = obligation_ids[1]
        for position, oid in enumerate(obligation_ids):
            clearing.validate_obligation(
                command_id=f"cmd-fed-02{position}",
                requested_at=T2,
                obligation_id=oid,
            )
        for position, oid in enumerate(obligation_ids):
            clearing.mark_due_obligation(
                command_id=f"cmd-fed-03{position}",
                requested_at=T2,
                obligation_id=oid,
            )
        clearing.validate_cycle(
            command_id="cmd-fed-030",
            requested_at=T2,
            cycle_id="clearing/federation-test/cycle-1",
        )
        clearing.finalize_cycle(
            command_id="cmd-fed-031",
            requested_at=T2,
            cycle_id="clearing/federation-test/cycle-1",
        )
        settlement_id = "settlement/federation-test/batch-1"
        engine.create_settlement(
            command_id="cmd-fed-100",
            requested_at=T2,
            settlement_id=settlement_id,
            obligations=[clearing.obligation(obligation_id).to_dict()],
            submit_by="2026-02-01T00:00:00Z",
            settle_by=LATE,
        )
        engine.authorize_settlement(
            command_id="cmd-fed-101", requested_at=T2, settlement_id=settlement_id
        )
        engine.submit_settlement(
            command_id="cmd-fed-102", requested_at=T2, settlement_id=settlement_id
        )
        batch = engine.settlement(settlement_id)
        leg_id = batch.spec.instructions[0].instruction_id
        leg_digest = batch.spec.instructions[0].instruction_digest()
        engine.reconcile_settlement(
            command_id="cmd-fed-103",
            requested_at=T3,
            settlement_id=settlement_id,
            as_of=T3,
            observations=[_status_observation(leg_id, leg_digest)],
        )
        finality_id = "settlement/federation-test/finality-1"
        engine.validate_finality_claim(
            command_id="cmd-fed-110",
            requested_at=T3,
            finality_id=finality_id,
            settlement_id=settlement_id,
            observation=_finality_observation(leg_id, leg_digest),
        )
        engine.establish_finality(
            command_id="cmd-fed-111", requested_at=T3, finality_id=finality_id
        )
        pending_id = "settlement/federation-test/finality-pending"
        pending_settlement_id = "settlement/federation-test/batch-2"
        engine.create_settlement(
            command_id="cmd-fed-120",
            requested_at=T2,
            settlement_id=pending_settlement_id,
            obligations=[clearing.obligation(pending_obligation_id).to_dict()],
            submit_by="2026-02-01T00:00:00Z",
            settle_by=LATE,
        )
        engine.authorize_settlement(
            command_id="cmd-fed-121", requested_at=T2, settlement_id=pending_settlement_id
        )
        engine.submit_settlement(
            command_id="cmd-fed-122", requested_at=T2, settlement_id=pending_settlement_id
        )
        pending_batch = engine.settlement(pending_settlement_id)
        pending_leg_id = pending_batch.spec.instructions[0].instruction_id
        pending_leg_digest = pending_batch.spec.instructions[0].instruction_digest()
        engine.reconcile_settlement(
            command_id="cmd-fed-123",
            requested_at=T3,
            settlement_id=pending_settlement_id,
            as_of=T3,
            observations=[_status_observation(pending_leg_id, pending_leg_digest)],
        )
        engine.validate_finality_claim(
            command_id="cmd-fed-112",
            requested_at=T4,
            finality_id=pending_id,
            settlement_id=pending_settlement_id,
            observation=_finality_observation(pending_leg_id, pending_leg_digest),
        )
        _SETTLEMENT_FIXTURE.update(
            {
                "established": engine.finality(finality_id).to_dict(),
                "pending": engine.finality(pending_id).to_dict(),
            }
        )
    return _SETTLEMENT_FIXTURE


def _established_finality_composite() -> dict:
    return _settlement_fixture()["established"]


def _pending_finality_composite() -> dict:
    return _settlement_fixture()["pending"]


# ---------------------------------------------------------------------------
# static boundary
# ---------------------------------------------------------------------------


class TestStaticBoundary(unittest.TestCase):
    def test_public_api_version_and_constants(self) -> None:
        self.assertEqual(FEDERATION_API_VERSION, "v0.1")
        self.assertEqual(FEDERATION_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(FEDERATION_SCHEMA_VERSION, 1)
        self.assertEqual(FEDERATION_EVENT_NAMESPACE, "governance")

    def test_all_is_sorted_unique_and_public(self) -> None:
        exported = federation.__all__
        self.assertEqual(sorted(exported), list(exported))
        self.assertEqual(len(set(exported)), len(exported))
        for name in exported:
            self.assertFalse(name.startswith("_"), name)
            self.assertTrue(hasattr(federation, name), name)

    def test_object_types_are_internal_non_registry(self) -> None:
        self.assertEqual(
            OBJECT_TYPES,
            (
                DOMAIN_OBJECT_TYPE,
                COMMITMENT_OBJECT_TYPE,
                MESSAGE_OBJECT_TYPE,
                ACCEPTANCE_OBJECT_TYPE,
            ),
        )
        for object_type in OBJECT_TYPES:
            self.assertTrue(object_type.startswith("federation/"))
            self.assertFalse(object_type.startswith("payswap/"))

    def test_command_family_is_exactly_the_frozen_seven(self) -> None:
        self.assertEqual(
            set(FEDERATION_COMMANDS),
            {
                "federation/register",
                "federation/join",
                "federation/leave",
                "federation/update-authority",
                "federation/publish-commitment",
                "federation/accept-commitment",
                "federation/transfer-domain",
            },
        )

    def test_every_event_type_uses_the_registered_governance_namespace(self) -> None:
        for command_type, event_type in COMMAND_EVENT_TYPES.items():
            self.assertIn(command_type, FEDERATION_COMMANDS)
            self.assertTrue(event_type.startswith("governance/"))
            self.assertEqual(validate_event_type("event", event_type), event_type)
        self.assertEqual(set(COMMAND_EVENT_TYPES), set(FEDERATION_COMMANDS))

    def test_no_wall_clock_or_entropy_in_domain_sources(self) -> None:
        forbidden = {
            "now",
            "utcnow",
            "today",
            "monotonic",
            "perf_counter",
            "urandom",
            "uuid4",
            "uuid1",
            "randint",
            "random",
            "choice",
            "shuffle",
            "seed",
        }
        for path in sorted(pathlib.Path(__file__).parent.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in forbidden:
                    self.fail(
                        f"{path.name}:{node.lineno} uses forbidden non-determinism "
                        f".{node.attr}"
                    )

    def test_import_closure_in_isolated_subprocess(self) -> None:
        root = str(pathlib.Path(__file__).resolve().parents[2])
        completed = subprocess.run(
            [sys.executable, "-c", "import src.federation, src.federation.dogfooding"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")


# ---------------------------------------------------------------------------
# contracts
# ---------------------------------------------------------------------------


class TestContracts(unittest.TestCase):
    def test_validate_command_accepts_the_frozen_family(self) -> None:
        for command in FEDERATION_COMMANDS:
            self.assertEqual(validate_command(command), command)

    def test_validate_command_rejects_unknown_commands(self) -> None:
        for command in ("", "federation/send", "federation/register/x", "settlement/create"):
            with self.assertRaises(CoreValidationError):
                validate_command(command)

    def test_domain_lifecycle_is_closed(self) -> None:
        self.assertEqual(
            {state.value for state in DomainState},
            {"REGISTERED", "JOINED", "LEFT"},
        )
        self.assertEqual(DOMAIN_TERMINAL_STATES, frozenset({DomainState.LEFT}))
        self.assertEqual(DomainState.parse("JOINED"), DomainState.JOINED)
        with self.assertRaises(CoreValidationError):
            DomainState.parse("SUSPENDED")

    def test_immutable_record_lifecycles_are_single_state(self) -> None:
        self.assertEqual({state.value for state in CommitmentState}, {"PUBLISHED"})
        self.assertEqual({state.value for state in MessageState}, {"ISSUED"})
        self.assertEqual({state.value for state in AcceptanceState}, {"ACCEPTED"})
        self.assertEqual(
            {kind.value for kind in MessageKind},
            {"STATE_COMMITMENT"},
        )

    def test_transition_table_covers_the_frozen_family(self) -> None:
        self.assertEqual(set(FEDERATION_TRANSITIONS), set(FEDERATION_COMMANDS))
        self.assertEqual(FEDERATION_TRANSITIONS["federation/register"], frozenset())
        self.assertEqual(
            FEDERATION_TRANSITIONS["federation/join"],
            frozenset({DomainState.REGISTERED}),
        )
        self.assertEqual(
            FEDERATION_TRANSITIONS["federation/leave"],
            frozenset({DomainState.JOINED}),
        )
        self.assertEqual(
            FEDERATION_TRANSITIONS["federation/update-authority"],
            frozenset({DomainState.REGISTERED, DomainState.JOINED}),
        )
        self.assertEqual(
            FEDERATION_TRANSITIONS["federation/transfer-domain"],
            frozenset({DomainState.REGISTERED, DomainState.JOINED}),
        )


# ---------------------------------------------------------------------------
# seal
# ---------------------------------------------------------------------------


class TestSeal(unittest.TestCase):
    def _envelope(self) -> object:
        return build_domain_envelope(
            object_id="domain/seal-test",
            object_type=DOMAIN_OBJECT_TYPE,
            state=DomainState.REGISTERED.value,
            environment_id=ENV,
            domain_id="domain/seal-test",
            provenance=PROVENANCE,
        )

    def test_build_and_advance_envelope(self) -> None:
        envelope = self._envelope()
        self.assertEqual(envelope.object_version, 1)
        self.assertEqual(envelope.state, DomainState.REGISTERED.value)
        advanced = advance_envelope(
            envelope,
            state=DomainState.JOINED.value,
            provenance=PROVENANCE,
        )
        self.assertEqual(advanced.object_version, 2)
        self.assertEqual(advanced.previous_version, 1)
        self.assertEqual(advanced.state, DomainState.JOINED.value)

    def test_advance_envelope_freezes_identity_fields(self) -> None:
        envelope = self._envelope()
        with self.assertRaises(CoreValidationError):
            advance_envelope(
                envelope,
                state=DomainState.JOINED.value,
                provenance=PROVENANCE,
            ).next_version(domain_id="domain/other")
        with self.assertRaises(CoreValidationError):
            dataclasses.replace(envelope, object_version=5).next_version(
                domain_id="domain/other"
            )

    def test_composite_roundtrip_and_tamper_rejection(self) -> None:
        envelope = self._envelope()
        payload = DomainSpec(
            domain_id="domain/seal-test",
            authority=StateAuthority(
                principal_id=GH_PRINCIPAL,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                verification_digest="a" * 64,
            ),
            registered_at=T0,
        )
        composite = composite_to_dict(envelope, payload, "0" * 64)
        encoded = composite_to_json(envelope, payload, "0" * 64)
        decoded = federation.decode_composite_json(
            encoded, object_type=DOMAIN_OBJECT_TYPE, state_type=DomainState
        )
        self.assertEqual(decoded, composite)
        with self.assertRaises(CoreValidationError):
            federation.decode_composite(
                {"envelope": composite["envelope"], "payload": {}, "integrity_hash": "0" * 64},
                object_type=DOMAIN_OBJECT_TYPE,
                state_type=DomainState,
            )


# ---------------------------------------------------------------------------
# authority and signature scheme
# ---------------------------------------------------------------------------


class TestAuthority(unittest.TestCase):
    def test_state_authority_validates_its_facts(self) -> None:
        authority = StateAuthority(
            principal_id=GH_PRINCIPAL,
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            verification_digest="a" * 64,
        )
        self.assertEqual(authority.principal_id, GH_PRINCIPAL)
        roundtripped = StateAuthority.from_dict(authority.to_dict())
        self.assertEqual(roundtripped, authority)
        with self.assertRaises(CoreValidationError):
            StateAuthority(
                principal_id="",
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                verification_digest="a" * 64,
            )
        with self.assertRaises(CoreValidationError):
            StateAuthority(
                principal_id=GH_PRINCIPAL,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                verification_digest="not-a-digest",
            )

    def test_sign_and_verify_commitment_signature(self) -> None:
        payload_digest = "b" * 64
        signature = sign_commitment(
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            secret_material=GH_SECRET,
            payload_digest=payload_digest,
        )
        self.assertEqual(len(signature), 64)
        verify_commitment_signature(
            signature,
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            secret_material=GH_SECRET,
            payload_digest=payload_digest,
        )
        with self.assertRaises(CoreValidationError):
            verify_commitment_signature(
                signature,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                secret_material=GH_SECRET_2,
                payload_digest=payload_digest,
            )
        with self.assertRaises(CoreValidationError):
            verify_commitment_signature(
                "c" * 64,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                secret_material=GH_SECRET,
                payload_digest=payload_digest,
            )
        with self.assertRaises(CoreValidationError):
            verify_commitment_signature(
                signature,
                key_id=US_KEY_ID,
                public_material=GH_PUBLIC,
                secret_material=GH_SECRET,
                payload_digest=payload_digest,
            )

    def test_signature_is_bound_to_the_payload_digest(self) -> None:
        signature = sign_commitment(
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            secret_material=GH_SECRET,
            payload_digest="b" * 64,
        )
        with self.assertRaises(CoreValidationError):
            verify_commitment_signature(
                signature,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                secret_material=GH_SECRET,
                payload_digest="d" * 64,
            )

    def test_decode_authority_key_enforces_purpose_and_active_state(self) -> None:
        key = decode_authority_key(_gh_key_composite())
        self.assertEqual(key.key_id, GH_KEY_ID)
        self.assertEqual(key.purpose, KeyPurpose.DOMAIN_STATE_COMMITMENT)
        with self.assertRaises(CoreValidationError):
            decode_authority_key(_other_purpose_key_composite())
        tampered = dict(_gh_key_composite())
        tampered["payload"] = dict(tampered["payload"])
        tampered["payload"]["public_material"] = "pk-forged"
        with self.assertRaises(CoreValidationError):
            decode_authority_key(tampered)


# ---------------------------------------------------------------------------
# domain records
# ---------------------------------------------------------------------------


def _authority() -> StateAuthority:
    key = _trust_fixtures()["gh_key"]
    return StateAuthority(
        principal_id=key.owner_principal_id,
        key_id=key.key_id,
        public_material=key.public_material,
        verification_digest=key.verification_digest,
    )


def _us_authority() -> StateAuthority:
    key = _trust_fixtures()["us_key"]
    return StateAuthority(
        principal_id=key.owner_principal_id,
        key_id=key.key_id,
        public_material=key.public_material,
        verification_digest=key.verification_digest,
    )


class TestDomainRecords(unittest.TestCase):
    def test_make_domain_record_register(self) -> None:
        record = make_domain_record(
            domain_id=GH_DOMAIN,
            environment_id=ENV,
            provenance=PROVENANCE,
            authority=_authority(),
            registered_at=T0,
        )
        self.assertIsInstance(record, NetworkDomain)
        self.assertEqual(record.state, DomainState.REGISTERED)
        self.assertEqual(record.object_id, GH_DOMAIN)
        self.assertEqual(record.envelope.domain_id, GH_DOMAIN)
        self.assertEqual(record.spec.domain_id, GH_DOMAIN)
        roundtripped = NetworkDomain.from_dict(record.to_dict())
        self.assertEqual(roundtripped.to_dict(), record.to_dict())
        self.assertEqual(
            InterDomainMessage.__name__,
            "InterDomainMessage",
        )

    def test_domain_record_rejects_identity_disagreement(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_domain_record(
                domain_id=GH_DOMAIN,
                environment_id=ENV,
                provenance=PROVENANCE,
                authority=_authority(),
                registered_at=T0,
            ).__class__(
                envelope=build_domain_envelope(
                    object_id=GH_DOMAIN,
                    object_type=DOMAIN_OBJECT_TYPE,
                    state=DomainState.REGISTERED.value,
                    environment_id=ENV,
                    domain_id=US_DOMAIN,
                    provenance=PROVENANCE,
                ),
                spec=DomainSpec(
                    domain_id=GH_DOMAIN,
                    authority=_authority(),
                    registered_at=T0,
                ),
                integrity_hash="0" * 64,
            )

    def test_join_fact_and_state_coherence(self) -> None:
        us_authority = _us_authority()
        join = JoinFact(
            anchor_domain_id=US_DOMAIN,
            anchor_key_id=US_KEY_ID,
            anchor_public_material=US_PUBLIC,
            anchor_verification_digest=us_authority.verification_digest,
            joined_at=T1,
        )
        registered = make_domain_record(
            domain_id=GH_DOMAIN,
            environment_id=ENV,
            provenance=PROVENANCE,
            authority=_authority(),
            registered_at=T0,
        )
        joined = advance_domain(
            registered,
            state=DomainState.JOINED.value,
            provenance=PROVENANCE,
            spec=dataclasses.replace(registered.spec, join=join),
        )
        self.assertEqual(joined.state, DomainState.JOINED)
        self.assertEqual(joined.spec.join.anchor_domain_id, US_DOMAIN)
        with self.assertRaises(CoreValidationError):
            # REGISTERED state cannot carry a join fact
            make_domain_record(
                domain_id=GH_DOMAIN,
                environment_id=ENV,
                provenance=PROVENANCE,
                authority=_authority(),
                registered_at=T0,
                join=join,
            )
        with self.assertRaises(CoreValidationError):
            # JOINED state requires the join fact
            advance_domain(
                registered,
                state=DomainState.JOINED.value,
                provenance=PROVENANCE,
                spec=dataclasses.replace(registered.spec, join=None),
            )

    def test_leave_is_terminal_with_explicit_fact(self) -> None:
        registered = make_domain_record(
            domain_id=GH_DOMAIN,
            environment_id=ENV,
            provenance=PROVENANCE,
            authority=_authority(),
            registered_at=T0,
        )
        join = JoinFact(
            anchor_domain_id=US_DOMAIN,
            anchor_key_id=US_KEY_ID,
            anchor_public_material=US_PUBLIC,
            anchor_verification_digest=_us_authority().verification_digest,
            joined_at=T1,
        )
        joined = advance_domain(
            registered,
            state=DomainState.JOINED.value,
            provenance=PROVENANCE,
            spec=dataclasses.replace(registered.spec, join=join),
        )
        left = advance_domain(
            joined,
            state=DomainState.LEFT.value,
            provenance=PROVENANCE,
            spec=dataclasses.replace(joined.spec, left_at=T2),
        )
        self.assertEqual(left.state, DomainState.LEFT)
        with self.assertRaises(CoreValidationError):
            # LEFT requires left_at
            advance_domain(
                joined,
                state=DomainState.LEFT.value,
                provenance=PROVENANCE,
            )

    def test_authority_update_and_transfer_facts(self) -> None:
        registered = make_domain_record(
            domain_id=GH_DOMAIN,
            environment_id=ENV,
            provenance=PROVENANCE,
            authority=_authority(),
            registered_at=T0,
        )
        update = AuthorityUpdate(
            prior_key_id=GH_KEY_ID,
            new_key_id=GH_KEY_ID_2,
            new_public_material=GH_PUBLIC_2,
            new_verification_digest="e" * 64,
            updated_at=T1,
        )
        updated = advance_domain(
            registered,
            state=DomainState.REGISTERED.value,
            provenance=PROVENANCE,
            spec=dataclasses.replace(
                registered.spec,
                authority=StateAuthority(
                    principal_id=GH_PRINCIPAL,
                    key_id=GH_KEY_ID_2,
                    public_material=GH_PUBLIC_2,
                    verification_digest="e" * 64,
                ),
                authority_updates=(update,),
            ),
        )
        self.assertEqual(updated.spec.authority.key_id, GH_KEY_ID_2)
        transfer = TransferFact(
            prior_principal_id=GH_PRINCIPAL,
            prior_key_id=GH_KEY_ID_2,
            new_principal_id=GH_PRINCIPAL_2,
            new_key_id=GH_KEY_ID_3,
            new_public_material=GH_PUBLIC_3,
            new_verification_digest="f" * 64,
            transferred_at=T2,
        )
        transferred = advance_domain(
            updated,
            state=DomainState.REGISTERED.value,
            provenance=PROVENANCE,
            spec=dataclasses.replace(
                updated.spec,
                authority=StateAuthority(
                    principal_id=GH_PRINCIPAL_2,
                    key_id=GH_KEY_ID_3,
                    public_material=GH_PUBLIC_3,
                    verification_digest="f" * 64,
                ),
                transfers=(transfer,),
            ),
        )
        self.assertEqual(transferred.spec.authority.principal_id, GH_PRINCIPAL_2)
        self.assertEqual(len(transferred.spec.authority_updates), 1)
        self.assertEqual(len(transferred.spec.transfers), 1)

    def test_domain_record_tamper_rejection(self) -> None:
        record = make_domain_record(
            domain_id=GH_DOMAIN,
            environment_id=ENV,
            provenance=PROVENANCE,
            authority=_authority(),
            registered_at=T0,
        )
        composite = dict(record.to_dict())
        payload = dict(composite["payload"])
        payload["registered_at"] = T5
        composite["payload"] = payload
        with self.assertRaises(CoreValidationError):
            NetworkDomain.from_dict(composite)


# ---------------------------------------------------------------------------
# commitment records
# ---------------------------------------------------------------------------


class TestCommitmentRecords(unittest.TestCase):
    def _bindings(self) -> tuple[FinalityBinding, ...]:
        certificate = _established_finality_composite()
        return (
            FinalityBinding(
                finality_id=certificate["envelope"]["object_id"],
                settlement_id=certificate["payload"]["settlement_id"],
                settlement_digest=certificate["payload"]["settlement_digest"],
                certificate_digest=certificate["integrity_hash"],
            ),
        )

    def test_commitment_payload_digest_is_canonical(self) -> None:
        bindings = self._bindings()
        digest = commitment_payload_digest(
            commitment_id="commitment/gh-1",
            domain_id=GH_DOMAIN,
            sequence=1,
            state_digest="1" * 64,
            finality_bindings=bindings,
        )
        self.assertEqual(len(digest), 64)
        other = commitment_payload_digest(
            commitment_id="commitment/gh-1",
            domain_id=US_DOMAIN,
            sequence=1,
            state_digest="1" * 64,
            finality_bindings=bindings,
        )
        self.assertNotEqual(digest, other)

    def test_make_commitment_record_and_roundtrip(self) -> None:
        bindings = self._bindings()
        state_digest = "2" * 64
        signature = sign_commitment(
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            secret_material=GH_SECRET,
            payload_digest=commitment_payload_digest(
                commitment_id="commitment/gh-1",
                domain_id=GH_DOMAIN,
                sequence=1,
                state_digest=state_digest,
                finality_bindings=bindings,
            ),
        )
        record = make_commitment_record(
            commitment_id="commitment/gh-1",
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            provenance=PROVENANCE,
            sequence=1,
            state_digest=state_digest,
            finality_bindings=bindings,
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            signature=signature,
        )
        self.assertIsInstance(record, StateCommitment)
        self.assertEqual(record.state, CommitmentState.PUBLISHED)
        self.assertEqual(record.spec.sequence, 1)
        self.assertEqual(record.envelope.domain_id, GH_DOMAIN)
        roundtripped = StateCommitment.from_dict(record.to_dict())
        self.assertEqual(roundtripped.to_dict(), record.to_dict())

    def test_commitment_record_rejects_bad_facts(self) -> None:
        bindings = self._bindings()
        with self.assertRaises(CoreValidationError):
            make_commitment_record(
                commitment_id="commitment/gh-1",
                environment_id=ENV,
                domain_id=GH_DOMAIN,
                provenance=PROVENANCE,
                sequence=0,
                state_digest="2" * 64,
                finality_bindings=bindings,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                signature="3" * 64,
            )
        with self.assertRaises(CoreValidationError):
            make_commitment_record(
                commitment_id="commitment/gh-1",
                environment_id=ENV,
                domain_id=GH_DOMAIN,
                provenance=PROVENANCE,
                sequence=1,
                state_digest="not-a-digest",
                finality_bindings=bindings,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                signature="3" * 64,
            )
        with self.assertRaises(CoreValidationError):
            make_commitment_record(
                commitment_id="commitment/gh-1",
                environment_id=ENV,
                domain_id=GH_DOMAIN,
                provenance=PROVENANCE,
                sequence=1,
                state_digest="2" * 64,
                finality_bindings=bindings + bindings,
                key_id=GH_KEY_ID,
                public_material=GH_PUBLIC,
                signature="3" * 64,
            )

    def test_commitment_record_tamper_rejection(self) -> None:
        bindings = self._bindings()
        record = make_commitment_record(
            commitment_id="commitment/gh-1",
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            provenance=PROVENANCE,
            sequence=1,
            state_digest="2" * 64,
            finality_bindings=bindings,
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            signature="3" * 64,
        )
        composite = dict(record.to_dict())
        payload = dict(composite["payload"])
        payload["sequence"] = 9
        composite["payload"] = payload
        with self.assertRaises(CoreValidationError):
            StateCommitment.from_dict(composite)


# ---------------------------------------------------------------------------
# message and acceptance records
# ---------------------------------------------------------------------------


class TestMessageRecords(unittest.TestCase):
    def _message(self) -> InterDomainMessage:
        return make_message_record(
            message_id="message/gh-1",
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            provenance=PROVENANCE,
            origin_domain=GH_DOMAIN,
            destination_domain=US_DOMAIN,
            kind=MessageKind.STATE_COMMITMENT,
            nonce="nonce-gh-1",
            commitment_id="commitment/gh-1",
            commitment_digest="4" * 64,
            issued_at=T2,
        )

    def test_message_record_and_roundtrip(self) -> None:
        record = self._message()
        self.assertEqual(record.state, MessageState.ISSUED)
        self.assertEqual(record.spec.origin_domain, GH_DOMAIN)
        self.assertEqual(record.spec.destination_domain, US_DOMAIN)
        roundtripped = InterDomainMessage.from_dict(record.to_dict())
        self.assertEqual(roundtripped.to_dict(), record.to_dict())

    def test_message_origin_must_match_its_domain(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_message_record(
                message_id="message/gh-1",
                environment_id=ENV,
                domain_id=GH_DOMAIN,
                provenance=PROVENANCE,
                origin_domain=US_DOMAIN,
                destination_domain=GH_DOMAIN,
                kind=MessageKind.STATE_COMMITMENT,
                nonce="nonce-gh-1",
                commitment_id="commitment/gh-1",
                commitment_digest="4" * 64,
                issued_at=T2,
            )

    def test_message_tamper_rejection(self) -> None:
        composite = dict(self._message().to_dict())
        payload = dict(composite["payload"])
        payload["nonce"] = "nonce-forged"
        composite["payload"] = payload
        with self.assertRaises(CoreValidationError):
            InterDomainMessage.from_dict(composite)


class TestAcceptanceRecords(unittest.TestCase):
    def _acceptance(self) -> CommitmentAcceptance:
        return make_acceptance_record(
            acceptance_id="acceptance/us-1",
            environment_id=ENV,
            domain_id=US_DOMAIN,
            provenance=PROVENANCE,
            origin_domain=GH_DOMAIN,
            message_id="message/gh-1",
            message_digest="5" * 64,
            commitment_id="commitment/gh-1",
            commitment_digest="4" * 64,
            sequence=1,
            anchor_key_id=GH_KEY_ID,
            accepted_at=T3,
        )

    def test_acceptance_record_and_roundtrip(self) -> None:
        record = self._acceptance()
        self.assertEqual(record.state, AcceptanceState.ACCEPTED)
        self.assertEqual(record.spec.origin_domain, GH_DOMAIN)
        self.assertEqual(record.envelope.domain_id, US_DOMAIN)
        roundtripped = CommitmentAcceptance.from_dict(record.to_dict())
        self.assertEqual(roundtripped.to_dict(), record.to_dict())

    def test_acceptance_origin_must_be_foreign(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_acceptance_record(
                acceptance_id="acceptance/us-1",
                environment_id=ENV,
                domain_id=US_DOMAIN,
                provenance=PROVENANCE,
                origin_domain=US_DOMAIN,
                message_id="message/gh-1",
                message_digest="5" * 64,
                commitment_id="commitment/gh-1",
                commitment_digest="4" * 64,
                sequence=1,
                anchor_key_id=GH_KEY_ID,
                accepted_at=T3,
            )

    def test_acceptance_tamper_rejection(self) -> None:
        composite = dict(self._acceptance().to_dict())
        payload = dict(composite["payload"])
        payload["sequence"] = 42
        composite["payload"] = payload
        with self.assertRaises(CoreValidationError):
            CommitmentAcceptance.from_dict(composite)


# ---------------------------------------------------------------------------
# engine: domain lifecycle
# ---------------------------------------------------------------------------


class EngineTestCase(unittest.TestCase):
    def gh_engine(self) -> FederationEngine:
        return FederationEngine(environment_id=ENV, domain_id=GH_DOMAIN)

    def us_engine(self) -> FederationEngine:
        return FederationEngine(environment_id=ENV, domain_id=US_DOMAIN)

    def register_gh(self, engine: FederationEngine | None = None) -> None:
        engine = engine or self.gh_engine()
        engine.register_domain(
            command_id="cmd-gh-001",
            requested_at=T0,
            domain_id=GH_DOMAIN,
            authority_key=_gh_key_composite(),
        )
        return engine


class TestEngineDomainLifecycle(EngineTestCase):
    def test_register_creates_the_domain_record(self) -> None:
        engine = self.gh_engine()
        transition = engine.register_domain(
            command_id="cmd-gh-001",
            requested_at=T0,
            domain_id=GH_DOMAIN,
            authority_key=_gh_key_composite(),
        )
        self.assertIsInstance(transition, FederationTransition)
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        domain = engine.domain(GH_DOMAIN)
        self.assertEqual(domain.state, DomainState.REGISTERED)
        self.assertEqual(domain.spec.authority.principal_id, GH_PRINCIPAL)
        self.assertEqual(domain.spec.authority.key_id, GH_KEY_ID)
        self.assertEqual(domain.spec.authority.public_material, GH_PUBLIC)
        self.assertEqual(
            domain.spec.authority.verification_digest,
            derive_key_verification_digest(GH_KEY_ID, KeyPurpose.DOMAIN_STATE_COMMITMENT, GH_PUBLIC, GH_SECRET),
        )

    def test_register_only_accepts_the_engine_domain(self) -> None:
        engine = self.gh_engine()
        with self.assertRaises(CoreValidationError):
            engine.register_domain(
                command_id="cmd-gh-001",
                requested_at=T0,
                domain_id=FOREIGN_DOMAIN,
                authority_key=_gh_key_composite(),
            )

    def test_register_rejects_foreign_purpose_keys(self) -> None:
        engine = self.gh_engine()
        with self.assertRaises(CoreValidationError):
            engine.register_domain(
                command_id="cmd-gh-001",
                requested_at=T0,
                domain_id=GH_DOMAIN,
                authority_key=_other_purpose_key_composite(),
            )

    def test_duplicate_register_converges_and_conflict_fails(self) -> None:
        engine = self.gh_engine()
        command = engine.build_raw_command(
            command_id="cmd-gh-001",
            command_type="federation/register",
            requested_at=T0,
            target_refs=(GH_DOMAIN,),
            payload={"domain_id": GH_DOMAIN, "authority_key": _gh_key_composite()},
            expected_versions={GH_DOMAIN: 0},
        )
        first = engine.submit(command)
        self.assertEqual(first.outcome, Outcome.ACCEPTED)
        replay = engine.submit(command)
        self.assertEqual(replay.outcome, Outcome.DUPLICATE)
        other = engine.build_raw_command(
            command_id="cmd-gh-001",
            command_type="federation/register",
            requested_at=T1,
            target_refs=(GH_DOMAIN,),
            payload={"domain_id": GH_DOMAIN, "authority_key": _gh_key_composite()},
            expected_versions={GH_DOMAIN: 0},
        )
        conflict = engine.submit(other)
        self.assertEqual(conflict.outcome, Outcome.REJECTED)
        self.assertEqual(conflict.reason, RejectionReason.COMMAND_ID_REUSED)

    def test_join_records_the_anchor_trust_facts(self) -> None:
        engine = self.register_gh()
        transition = engine.join_federation(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            anchor_domain_id=US_DOMAIN,
            anchor_key=_us_key_composite(),
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        domain = engine.domain(GH_DOMAIN)
        self.assertEqual(domain.state, DomainState.JOINED)
        self.assertEqual(domain.spec.join.anchor_domain_id, US_DOMAIN)
        self.assertEqual(domain.spec.join.anchor_key_id, US_KEY_ID)
        self.assertEqual(domain.spec.join.anchor_public_material, US_PUBLIC)

    def test_join_requires_the_registered_state(self) -> None:
        engine = self.register_gh()
        engine.join_federation(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            anchor_domain_id=US_DOMAIN,
            anchor_key=_us_key_composite(),
        )
        with self.assertRaises(CoreValidationError):
            engine.join_federation(
                command_id="cmd-gh-003",
                requested_at=T2,
                domain_id=GH_DOMAIN,
                anchor_domain_id=US_DOMAIN,
                anchor_key=_us_key_composite(),
            )

    def test_join_rejects_non_commitment_purpose_anchor_keys(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.join_federation(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                anchor_domain_id=US_DOMAIN,
                anchor_key=_other_purpose_key_composite(),
            )

    def test_leave_is_explicit_and_terminal(self) -> None:
        engine = self.register_gh()
        engine.join_federation(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            anchor_domain_id=US_DOMAIN,
            anchor_key=_us_key_composite(),
        )
        transition = engine.leave_federation(
            command_id="cmd-gh-003",
            requested_at=T2,
            domain_id=GH_DOMAIN,
            reason="sandbox wind-down",
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        domain = engine.domain(GH_DOMAIN)
        self.assertEqual(domain.state, DomainState.LEFT)
        self.assertEqual(domain.spec.left_at, T2)
        with self.assertRaises(CoreValidationError):
            engine.leave_federation(
                command_id="cmd-gh-004",
                requested_at=T3,
                domain_id=GH_DOMAIN,
                reason="double leave",
            )
        with self.assertRaises(CoreValidationError):
            engine.join_federation(
                command_id="cmd-gh-005",
                requested_at=T3,
                domain_id=GH_DOMAIN,
                anchor_domain_id=US_DOMAIN,
                anchor_key=_us_key_composite(),
            )

    def test_leave_requires_membership(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.leave_federation(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                reason="never joined",
            )

    def test_update_authority_rotates_the_commitment_key(self) -> None:
        engine = self.register_gh()
        transition = engine.update_authority(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            new_key=_gh_key_2_composite(),
            current_secret_material=GH_SECRET,
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        domain = engine.domain(GH_DOMAIN)
        self.assertEqual(domain.state, DomainState.REGISTERED)
        self.assertEqual(domain.spec.authority.key_id, GH_KEY_ID_2)
        self.assertEqual(domain.spec.authority_updates[0].prior_key_id, GH_KEY_ID)
        self.assertEqual(domain.spec.authority_updates[0].new_key_id, GH_KEY_ID_2)

    def test_update_authority_requires_the_current_secret(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.update_authority(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                new_key=_gh_key_2_composite(),
                current_secret_material=GH_SECRET_3,
            )

    def test_update_authority_requires_the_same_authority_principal(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.update_authority(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                new_key=_gh_key_3_composite(),
                current_secret_material=GH_SECRET,
            )

    def test_update_authority_rejects_foreign_purpose_new_keys(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.update_authority(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                new_key=_other_purpose_key_composite(),
                current_secret_material=GH_SECRET,
            )

    def test_transfer_domain_moves_authority_atomically(self) -> None:
        engine = self.register_gh()
        transition = engine.transfer_domain(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            new_principal_id=GH_PRINCIPAL_2,
            new_key=_gh_key_3_composite(),
            outgoing_secret_material=GH_SECRET,
            incoming_secret_material=GH_SECRET_3,
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        domain = engine.domain(GH_DOMAIN)
        self.assertEqual(domain.state, DomainState.REGISTERED)
        self.assertEqual(domain.spec.authority.principal_id, GH_PRINCIPAL_2)
        self.assertEqual(domain.spec.authority.key_id, GH_KEY_ID_3)
        transfer = domain.spec.transfers[0]
        self.assertEqual(transfer.prior_principal_id, GH_PRINCIPAL)
        self.assertEqual(transfer.new_principal_id, GH_PRINCIPAL_2)

    def test_transfer_domain_requires_both_secrets(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.transfer_domain(
                command_id="cmd-gh-002",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                new_principal_id=GH_PRINCIPAL_2,
                new_key=_gh_key_3_composite(),
                outgoing_secret_material=GH_SECRET_2,
                incoming_secret_material=GH_SECRET_3,
            )
        with self.assertRaises(CoreValidationError):
            engine.transfer_domain(
                command_id="cmd-gh-003",
                requested_at=T1,
                domain_id=GH_DOMAIN,
                new_principal_id=GH_PRINCIPAL_2,
                new_key=_gh_key_3_composite(),
                outgoing_secret_material=GH_SECRET,
                incoming_secret_material=GH_SECRET_2,
            )


# ---------------------------------------------------------------------------
# engine: publish-commitment
# ---------------------------------------------------------------------------


class TestEnginePublish(EngineTestCase):
    def test_publish_creates_the_signed_commitment_and_message_atomically(self) -> None:
        engine = self.register_gh()
        state_digest = engine.state_digest()
        bindings_from_certificate = _established_finality_composite()
        transition = engine.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[bindings_from_certificate],
            secret_material=GH_SECRET,
            destination_domain_id=US_DOMAIN,
            message_id="message/gh-1",
            message_nonce="nonce-gh-1",
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        commitment = engine.commitment("commitment/gh-1")
        self.assertEqual(commitment.state, CommitmentState.PUBLISHED)
        self.assertEqual(commitment.spec.sequence, 1)
        self.assertEqual(commitment.spec.state_digest, state_digest)
        self.assertEqual(commitment.spec.key_id, GH_KEY_ID)
        self.assertEqual(len(commitment.spec.finality_bindings), 1)
        binding = commitment.spec.finality_bindings[0]
        self.assertEqual(binding.finality_id, "settlement/federation-test/finality-1")
        self.assertEqual(binding.settlement_id, "settlement/federation-test/batch-1")
        self.assertEqual(binding.certificate_digest, bindings_from_certificate["integrity_hash"])
        payload_digest = commitment_payload_digest(
            commitment_id="commitment/gh-1",
            domain_id=GH_DOMAIN,
            sequence=1,
            state_digest=state_digest,
            finality_bindings=commitment.spec.finality_bindings,
        )
        verify_commitment_signature(
            commitment.spec.signature,
            key_id=GH_KEY_ID,
            public_material=GH_PUBLIC,
            secret_material=GH_SECRET,
            payload_digest=payload_digest,
        )
        message = engine.message("message/gh-1")
        self.assertEqual(message.state, MessageState.ISSUED)
        self.assertEqual(message.spec.destination_domain, US_DOMAIN)
        self.assertEqual(message.spec.commitment_id, "commitment/gh-1")
        self.assertEqual(message.spec.commitment_digest, commitment.integrity_hash)
        event = transition.result.event
        self.assertEqual(
            set(event.object_refs),
            {"commitment/gh-1", "message/gh-1"},
        )
        self.assertEqual(event.event_type, "governance/state-commitment-published")

    def test_publish_without_destination_creates_no_message(self) -> None:
        engine = self.register_gh()
        transition = engine.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[],
            secret_material=GH_SECRET,
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        self.assertEqual(engine.latest_commitment_sequence(), 1)
        self.assertEqual(
            set(transition.result.event.object_refs),
            {"commitment/gh-1"},
        )

    def test_publish_enforces_monotone_sequences(self) -> None:
        engine = self.register_gh()
        engine.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[],
            secret_material=GH_SECRET,
        )
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-011",
                requested_at=T2,
                commitment_id="commitment/gh-2",
                sequence=3,
                finality_certificates=[],
                secret_material=GH_SECRET,
            )
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-012",
                requested_at=T2,
                commitment_id="commitment/gh-2",
                sequence=1,
                finality_certificates=[],
                secret_material=GH_SECRET,
            )

    def test_publish_requires_the_current_authority_secret(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-010",
                requested_at=T2,
                commitment_id="commitment/gh-1",
                sequence=1,
                finality_certificates=[],
                secret_material=US_SECRET,
            )

    def test_publish_binds_only_established_finality_certificates(self) -> None:
        engine = self.register_gh()
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-010",
                requested_at=T2,
                commitment_id="commitment/gh-1",
                sequence=1,
                finality_certificates=[_pending_finality_composite()],
                secret_material=GH_SECRET,
            )

    def test_publish_rejects_duplicate_finality_certificates(self) -> None:
        engine = self.register_gh()
        certificate = _established_finality_composite()
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-010",
                requested_at=T2,
                commitment_id="commitment/gh-1",
                sequence=1,
                finality_certificates=[certificate, certificate],
                secret_material=GH_SECRET,
            )

    def test_publish_requires_a_registered_domain(self) -> None:
        engine = self.gh_engine()
        with self.assertRaises(CoreValidationError):
            engine.publish_commitment(
                command_id="cmd-gh-010",
                requested_at=T2,
                commitment_id="commitment/gh-1",
                sequence=1,
                finality_certificates=[],
                secret_material=GH_SECRET,
            )

    def test_handler_rejects_a_wrong_state_digest_via_raw_command(self) -> None:
        engine = self.register_gh()
        domain = engine.domain(GH_DOMAIN)
        payload = {
            "commitment_id": "commitment/gh-raw",
            "sequence": 1,
            "state_digest": "7" * 64,
            "finality_bindings": [],
            "key_id": domain.spec.authority.key_id,
            "public_material": domain.spec.authority.public_material,
            "signature": "8" * 64,
            "destination_domain_id": None,
            "message_id": None,
            "message_nonce": None,
        }
        command = engine.build_raw_command(
            command_id="cmd-gh-raw-1",
            command_type="federation/publish-commitment",
            requested_at=T2,
            target_refs=("commitment/gh-raw",),
            payload=payload,
            expected_versions={"commitment/gh-raw": 0},
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(command)

    def test_handler_rejects_a_foreign_key_claim_via_raw_command(self) -> None:
        engine = self.register_gh()
        payload = {
            "commitment_id": "commitment/gh-raw",
            "sequence": 1,
            "state_digest": engine.state_digest(),
            "finality_bindings": [],
            "key_id": US_KEY_ID,
            "public_material": US_PUBLIC,
            "signature": "8" * 64,
            "destination_domain_id": None,
            "message_id": None,
            "message_nonce": None,
        }
        command = engine.build_raw_command(
            command_id="cmd-gh-raw-2",
            command_type="federation/publish-commitment",
            requested_at=T2,
            target_refs=("commitment/gh-raw",),
            payload=payload,
            expected_versions={"commitment/gh-raw": 0},
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(command)

    def test_handler_rejects_a_sequence_gap_via_raw_command(self) -> None:
        engine = self.register_gh()
        engine.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[],
            secret_material=GH_SECRET,
        )
        domain = engine.domain(GH_DOMAIN)
        payload = {
            "commitment_id": "commitment/gh-raw",
            "sequence": 5,
            "state_digest": engine.state_digest(),
            "finality_bindings": [],
            "key_id": domain.spec.authority.key_id,
            "public_material": domain.spec.authority.public_material,
            "signature": "8" * 64,
            "destination_domain_id": None,
            "message_id": None,
            "message_nonce": None,
        }
        command = engine.build_raw_command(
            command_id="cmd-gh-raw-3",
            command_type="federation/publish-commitment",
            requested_at=T2,
            target_refs=("commitment/gh-raw",),
            payload=payload,
            expected_versions={"commitment/gh-raw": 0},
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(command)


# ---------------------------------------------------------------------------
# engine: accept-commitment
# ---------------------------------------------------------------------------


class TestEngineAccept(EngineTestCase):
    def _gh_joined(self) -> FederationEngine:
        engine = self.register_gh()
        engine.join_federation(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            anchor_domain_id=US_DOMAIN,
            anchor_key=_us_key_composite(),
        )
        return engine

    def _us_joined(self) -> FederationEngine:
        engine = self.us_engine()
        engine.register_domain(
            command_id="cmd-us-001",
            requested_at=T0,
            domain_id=US_DOMAIN,
            authority_key=_us_key_composite(),
        )
        engine.join_federation(
            command_id="cmd-us-002",
            requested_at=T1,
            domain_id=US_DOMAIN,
            anchor_domain_id=GH_DOMAIN,
            anchor_key=_gh_key_composite(),
        )
        return engine

    def _published(self, gh: FederationEngine) -> None:
        gh.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[_established_finality_composite()],
            secret_material=GH_SECRET,
            destination_domain_id=US_DOMAIN,
            message_id="message/gh-1",
            message_nonce="nonce-gh-1",
        )

    def test_accept_verifies_and_records_the_foreign_commitment(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        transition = us.accept_commitment(
            command_id="cmd-us-010",
            requested_at=T3,
            acceptance_id="acceptance/us-1",
            message=gh.message("message/gh-1").to_dict(),
            commitment=gh.commitment("commitment/gh-1").to_dict(),
            anchor_secret_material=GH_SECRET,
        )
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        acceptance = us.acceptance("acceptance/us-1")
        self.assertEqual(acceptance.state, AcceptanceState.ACCEPTED)
        self.assertEqual(acceptance.spec.origin_domain, GH_DOMAIN)
        self.assertEqual(acceptance.spec.message_id, "message/gh-1")
        self.assertEqual(acceptance.spec.commitment_id, "commitment/gh-1")
        self.assertEqual(acceptance.spec.sequence, 1)
        self.assertEqual(acceptance.spec.anchor_key_id, GH_KEY_ID)
        self.assertEqual(transition.result.event.event_type, "governance/commitment-accepted")

    def test_replayed_inter_domain_message_is_rejected(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        message = gh.message("message/gh-1").to_dict()
        commitment = gh.commitment("commitment/gh-1").to_dict()
        us.accept_commitment(
            command_id="cmd-us-010",
            requested_at=T3,
            acceptance_id="acceptance/us-1",
            message=message,
            commitment=commitment,
            anchor_secret_material=GH_SECRET,
        )
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-011",
                requested_at=T4,
                acceptance_id="acceptance/us-2",
                message=message,
                commitment=commitment,
                anchor_secret_material=GH_SECRET,
            )

    def test_handler_rejects_a_replayed_message_via_raw_command(self) -> None:
        # Drives the kernel handler path directly: the handler-side
        # replay gate is the rebuild-safe, load-bearing layer (the
        # engine boundary is an early-warning layer on top of it).
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        message = gh.message("message/gh-1").to_dict()
        commitment = gh.commitment("commitment/gh-1").to_dict()
        us.accept_commitment(
            command_id="cmd-us-010",
            requested_at=T3,
            acceptance_id="acceptance/us-1",
            message=message,
            commitment=commitment,
            anchor_secret_material=GH_SECRET,
        )
        command = us.build_raw_command(
            command_id="cmd-us-raw-1",
            command_type="federation/accept-commitment",
            requested_at=T4,
            target_refs=("acceptance/us-2",),
            payload={
                "acceptance_id": "acceptance/us-2",
                "message": message,
                "commitment": commitment,
            },
            expected_versions={"acceptance/us-2": 0},
        )
        with self.assertRaises(CoreValidationError):
            us.submit(command)

    def test_accept_requires_the_anchor_secret_material(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=gh.message("message/gh-1").to_dict(),
                commitment=gh.commitment("commitment/gh-1").to_dict(),
                anchor_secret_material=US_SECRET,
            )

    def test_accept_rejects_a_forged_commitment_signature(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        # A raw publish command can create a structurally valid commitment
        # with a forged signature (the in-domain boundary is authorization);
        # the cross-domain accept path must fail closed on it.
        domain = gh.domain(GH_DOMAIN)
        payload = {
            "commitment_id": "commitment/gh-forged",
            "sequence": 1,
            "state_digest": gh.state_digest(),
            "finality_bindings": [],
            "key_id": domain.spec.authority.key_id,
            "public_material": domain.spec.authority.public_material,
            "signature": "9" * 64,
            "destination_domain_id": None,
            "message_id": None,
            "message_nonce": None,
        }
        command = gh.build_raw_command(
            command_id="cmd-gh-forged",
            command_type="federation/publish-commitment",
            requested_at=T2,
            target_refs=("commitment/gh-forged",),
            payload=payload,
            expected_versions={"commitment/gh-forged": 0},
        )
        transition = gh.submit(command)
        self.assertEqual(transition.outcome, Outcome.ACCEPTED)
        forged = gh.commitment("commitment/gh-forged").to_dict()
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=self._message_for_forged(gh),
                commitment=forged,
                anchor_secret_material=GH_SECRET,
            )

    def _message_for_forged(self, gh: FederationEngine) -> dict:
        # A locally sealed message carrying the forged commitment digest is
        # constructed through the public record factory (test-side only).
        record = make_message_record(
            message_id="message/gh-forged",
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            provenance=PROVENANCE,
            origin_domain=GH_DOMAIN,
            destination_domain=US_DOMAIN,
            kind=MessageKind.STATE_COMMITMENT,
            nonce="nonce-gh-forged",
            commitment_id="commitment/gh-forged",
            commitment_digest=gh.commitment("commitment/gh-forged").integrity_hash,
            issued_at=T2,
        )
        return record.to_dict()

    def test_accept_requires_the_message_destination_to_match(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        gh.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[],
            secret_material=GH_SECRET,
            destination_domain_id=FOREIGN_DOMAIN,
            message_id="message/gh-1",
            message_nonce="nonce-gh-1",
        )
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=gh.message("message/gh-1").to_dict(),
                commitment=gh.commitment("commitment/gh-1").to_dict(),
                anchor_secret_material=GH_SECRET,
            )

    def test_accept_requires_the_anchor_origin(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        message = gh.message("message/gh-1").to_dict()
        commitment = gh.commitment("commitment/gh-1").to_dict()
        # splice the origin onto the message payload: seal verification
        # fails closed first; then verify the dedicated origin gate by
        # joining a different anchor in a fresh engine.
        tampered = dict(message)
        payload = dict(tampered["payload"])
        payload["origin_domain"] = FOREIGN_DOMAIN
        tampered["payload"] = payload
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=tampered,
                commitment=commitment,
                anchor_secret_material=GH_SECRET,
            )

    def test_accept_requires_message_commitment_binding(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        message = gh.message("message/gh-1").to_dict()
        commitment = gh.commitment("commitment/gh-1").to_dict()
        # bind the message to a different commitment digest: seal fails
        # closed (payload tamper) — assert the rejection of the spliced pair.
        payload = dict(message["payload"])
        payload["commitment_digest"] = "8" * 64
        spliced = dict(message)
        spliced["payload"] = payload
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=spliced,
                commitment=commitment,
                anchor_secret_material=GH_SECRET,
            )

    def test_accept_requires_membership(self) -> None:
        gh = self._gh_joined()
        us = self.us_engine()
        us.register_domain(
            command_id="cmd-us-001",
            requested_at=T0,
            domain_id=US_DOMAIN,
            authority_key=_us_key_composite(),
        )
        self._published(gh)
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=gh.message("message/gh-1").to_dict(),
                commitment=gh.commitment("commitment/gh-1").to_dict(),
                anchor_secret_material=GH_SECRET,
            )

    def test_accept_rejects_a_validly_sealed_non_anchor_origin(self) -> None:
        gh = self._gh_joined()
        us = self._us_joined()
        self._published(gh)
        # A well-sealed message from a THIRD domain (not the joined
        # anchor) must fail the origin gate, not the seal.
        foreign_message = make_message_record(
            message_id="message/foreign-1",
            environment_id=ENV,
            domain_id=FOREIGN_DOMAIN,
            provenance=PROVENANCE,
            origin_domain=FOREIGN_DOMAIN,
            destination_domain=US_DOMAIN,
            kind=MessageKind.STATE_COMMITMENT,
            nonce="nonce-foreign-1",
            commitment_id="commitment/gh-1",
            commitment_digest=gh.commitment("commitment/gh-1").integrity_hash,
            issued_at=T2,
        )
        with self.assertRaises(CoreValidationError):
            us.accept_commitment(
                command_id="cmd-us-010",
                requested_at=T3,
                acceptance_id="acceptance/us-1",
                message=foreign_message.to_dict(),
                commitment=gh.commitment("commitment/gh-1").to_dict(),
                anchor_secret_material=GH_SECRET,
            )


# ---------------------------------------------------------------------------
# engine: kernel binding
# ---------------------------------------------------------------------------


class TestEngineKernelBinding(EngineTestCase):
    def test_unauthorized_actor_is_rejected(self) -> None:
        engine = self.gh_engine()
        command = engine.build_raw_command(
            command_id="cmd-gh-001",
            command_type="federation/register",
            requested_at=T0,
            target_refs=(GH_DOMAIN,),
            payload={"domain_id": GH_DOMAIN, "authority_key": _gh_key_composite()},
            expected_versions={GH_DOMAIN: 0},
            actor="principal/rogue",
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.UNAUTHORIZED)

    def test_unknown_command_type_fails_closed(self) -> None:
        engine = self.gh_engine()
        command = Command.build(
            command_id="cmd-gh-rogue",
            command_type="federation/teleport",
            actor=DEFAULT_ENGINE_ACTOR,
            target_refs=(GH_DOMAIN,),
            payload={},
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            idempotency_key="federation:cmd-gh-rogue",
            nonce="federation-command-1",
            requested_at=T0,
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.UNKNOWN_COMMAND_TYPE)

    def test_environment_mismatch_is_rejected(self) -> None:
        engine = self.gh_engine()
        command = engine.build_raw_command(
            command_id="cmd-gh-001",
            command_type="federation/register",
            requested_at=T0,
            target_refs=(GH_DOMAIN,),
            payload={"domain_id": GH_DOMAIN, "authority_key": _gh_key_composite()},
            expected_versions={GH_DOMAIN: 0},
            environment_id="env/other",
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.ENVIRONMENT_MISMATCH)

    def test_unilateral_foreign_domain_mutation_is_structurally_rejected(self) -> None:
        engine = self.register_gh()
        # A command executed under a foreign domain id cannot touch this
        # engine's domain object: the kernel rejects it at stage 5.
        command = Command.build(
            command_id="cmd-gh-foreign",
            command_type="federation/leave",
            actor=DEFAULT_ENGINE_ACTOR,
            target_refs=(GH_DOMAIN,),
            payload={"reason": "unilateral foreign mutation"},
            environment_id=ENV,
            domain_id=FOREIGN_DOMAIN,
            idempotency_key="federation:cmd-gh-foreign",
            nonce="federation-command-1",
            requested_at=T1,
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.DOMAIN_MISMATCH)
        self.assertEqual(engine.domain(GH_DOMAIN).state, DomainState.REGISTERED)

    def test_stale_expected_versions_are_rejected(self) -> None:
        engine = self.register_gh()
        command = engine.build_raw_command(
            command_id="cmd-gh-002",
            command_type="federation/join",
            requested_at=T1,
            target_refs=(GH_DOMAIN,),
            payload={
                "anchor_domain_id": US_DOMAIN,
                "anchor_key": _us_key_composite(),
            },
            expected_versions={GH_DOMAIN: 5},
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.VERSION_CONFLICT)

    def test_missing_object_is_rejected(self) -> None:
        engine = self.gh_engine()
        command = engine.build_raw_command(
            command_id="cmd-gh-002",
            command_type="federation/join",
            requested_at=T1,
            target_refs=("domain/never-registered",),
            payload={
                "anchor_domain_id": US_DOMAIN,
                "anchor_key": _us_key_composite(),
            },
            expected_versions={"domain/never-registered": 3},
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason, RejectionReason.OBJECT_NOT_FOUND)


# ---------------------------------------------------------------------------
# engine: snapshot, restore and journal rebuild
# ---------------------------------------------------------------------------


class TestEngineSnapshotRebuild(EngineTestCase):
    def _flow(self, engine: FederationEngine) -> None:
        engine.register_domain(
            command_id="cmd-gh-001",
            requested_at=T0,
            domain_id=GH_DOMAIN,
            authority_key=_gh_key_composite(),
        )
        engine.join_federation(
            command_id="cmd-gh-002",
            requested_at=T1,
            domain_id=GH_DOMAIN,
            anchor_domain_id=US_DOMAIN,
            anchor_key=_us_key_composite(),
        )
        engine.publish_commitment(
            command_id="cmd-gh-010",
            requested_at=T2,
            commitment_id="commitment/gh-1",
            sequence=1,
            finality_certificates=[_established_finality_composite()],
            secret_material=GH_SECRET,
            destination_domain_id=US_DOMAIN,
            message_id="message/gh-1",
            message_nonce="nonce-gh-1",
        )

    def test_state_digest_is_deterministic(self) -> None:
        first = self.gh_engine()
        second = self.gh_engine()
        self._flow(first)
        self._flow(second)
        self.assertEqual(first.state_digest(), second.state_digest())
        self.assertEqual(
            first.commitment("commitment/gh-1").integrity_hash,
            second.commitment("commitment/gh-1").integrity_hash,
        )

    def test_snapshot_restore_roundtrip_is_byte_identical(self) -> None:
        engine = self.gh_engine()
        self._flow(engine)
        snapshot = engine.snapshot_state()
        restored = self.gh_engine()
        restored.restore_state(snapshot)
        self.assertEqual(
            [record.to_dict() for record in restored.records()],
            [record.to_dict() for record in engine.records()],
        )
        self.assertEqual(restored.state_digest(), engine.state_digest())
        self.assertEqual(len(restored.journal), len(engine.journal))
        self.assertEqual(restored.domain(GH_DOMAIN).state, DomainState.JOINED)

    def test_restore_rejects_foreign_snapshots(self) -> None:
        engine = self.gh_engine()
        self._flow(engine)
        snapshot = engine.snapshot_state()
        other = self.us_engine()
        with self.assertRaises(CoreValidationError):
            other.restore_state(snapshot)

    def test_rebuild_from_journal_is_byte_identical(self) -> None:
        engine = self.gh_engine()
        self._flow(engine)
        rebuilt = FederationEngine.rebuild_from_journal(
            environment_id=ENV,
            domain_id=GH_DOMAIN,
            journal=engine.journal,
        )
        self.assertEqual(
            [record.to_dict() for record in rebuilt.records()],
            [record.to_dict() for record in engine.records()],
        )
        self.assertEqual(rebuilt.state_digest(), engine.state_digest())
        self.assertEqual(
            rebuilt.message("message/gh-1").to_dict(),
            engine.message("message/gh-1").to_dict(),
        )


# ---------------------------------------------------------------------------
# dogfooding conformance
# ---------------------------------------------------------------------------


class TestDogfoodingConformance(unittest.TestCase):
    def test_transcript_passes_every_check(self) -> None:
        from src.federation.dogfooding import build_transcript

        transcript = build_transcript()
        failed = [
            check for check in transcript["checks"] if not check["pass"]
        ]
        self.assertEqual(failed, [], failed)
        self.assertGreaterEqual(len(transcript["checks"]), 20)

    def test_transcript_is_deterministic(self) -> None:
        from src.federation.dogfooding import build_transcript

        first = build_transcript()
        second = build_transcript()
        self.assertEqual(canonical_json(first), canonical_json(second))


if __name__ == "__main__":
    unittest.main()
