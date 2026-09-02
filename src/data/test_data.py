"""WORK-022 red-first test suite: data governance, privacy and recourse.

Authored BEFORE the implementation (red-first discipline): every test in
this file was written against the frozen v0.1 contracts and the sibling
conventions, then run against a nonexistent ``src.data`` package to prove
the suite fails for the right reason (ImportError) before implementation
started. The suite maps every WORK-022 acceptance criterion and every
required proof class:

* static — boundary, versions, internal object types, consumed domains,
  no wall clock / no entropy, single error authority, no deletion
  operation, no authoritative legal text;
* dynamic — policy lifecycle, disclosure evaluation and reveal,
  commitment-based selective disclosure, retention bookkeeping with legal
  holds, case/claim/recourse lifecycle, kernel-bound engine;
* discrimination — every fail-closed path (unknown policy, unknown
  principal, unclassified field, forbidden-field leakage, tampered
  commitments, wrong-state lifecycle, legal-hold suspension) is pinned by
  at least one test that fails if the protection is removed.
"""

from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.core.errors import CoreValidationError  # noqa: E402
from src.core.envelope import Provenance  # noqa: E402
from src.core.serialization import canonical_sha256  # noqa: E402
from src.transition import (  # noqa: E402
    Command,
    ExpectedVersion,
    MemoryStateStore,
    Outcome,
)
from src.transition.payload import payload_to_json_value  # noqa: E402
from src.trust import TrustRegistry  # noqa: E402
from src.evidence import (  # noqa: E402
    EpistemicType,
    EvidenceArchive,
    ScaledValue,
    submit_evidence,
)

import src.data as data  # noqa: E402
from src.data import (  # noqa: E402
    AssessmentVerdict,
    Case,
    CaseState,
    Claim,
    ClaimType,
    DataClass,
    DataGovernanceEngine,
    DataPolicy,
    DataPolicyRegistry,
    DataPolicySpec,
    DatasetCommitment,
    DatasetRecord,
    DecisionKind,
    DisclosurePurpose,
    DisclosureRecord,
    DisclosureRequest,
    DisclosureState,
    ExecutionRecord,
    FieldRule,
    Investigation,
    IsolatedDataset,
    LegalHold,
    PolicyState,
    PrivacyAssessment,
    ProofPayload,
    ProofRecord,
    ProofState,
    PurposeGrant,
    RecourseDecision,
    RecordCommitment,
    RefundPackage,
    RetentionOutcome,
    RetentionRecord,
    RetentionRule,
    ReversalPackage,
    SelectiveDisclosureProof,
    commit_dataset,
    create_retention_record,
    dataset_record,
)

DOMAIN_SOURCES = tuple(
    sorted(source for source in Path(__file__).parent.glob("*.py") if source.name != "test_data.py")
)
ALLOWED_SRC_DOMAINS = {"core", "transition", "trust", "evidence"}

ENV = "env/test"
DOMAIN = "domain/data"
DATA_GOVERNANCE_SOURCE = "data-governance"

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T06:00:00Z"
T2 = "2026-09-02T12:00:00Z"
T3 = "2026-09-02T18:00:00Z"
T4 = "2026-09-03T00:00:00Z"
T5 = "2026-09-04T00:00:00Z"

OPERATOR = "trust/principal/data-operator"
USER = "trust/principal/user-7"
INVESTIGATOR = "trust/principal/inv-3"
DECIDER = "trust/principal/dec-9"
SUSPENDED = "trust/principal/susp-1"

SUBJECT = "account/wallet-7"
EVIDENCE_TXN = "evidence/evidence/ev-txn"
EVIDENCE_COMPLAINT = "evidence/evidence/ev-complaint"


def prov(source: str = DATA_GOVERNANCE_SOURCE, evidence_refs: tuple[str, ...] = ()) -> Provenance:
    return Provenance(
        issuer=OPERATOR,
        source=source,
        recorded_at=T1,
        evidence_refs=evidence_refs,
    )


def build_registry() -> TrustRegistry:
    registry = TrustRegistry(environment_id=ENV)
    registry.create_principal(principal_id=OPERATOR, display_name="Data Operator", as_of=T0)
    registry.create_principal(principal_id=USER, display_name="User Seven", as_of=T0)
    registry.create_principal(principal_id=INVESTIGATOR, display_name="Investigator", as_of=T0)
    registry.create_principal(principal_id=DECIDER, display_name="Recourse Decider", as_of=T0)
    registry.create_principal(principal_id=SUSPENDED, display_name="Suspended Principal", as_of=T0)
    registry.suspend_principal(principal_id=SUSPENDED, operator=OPERATOR, as_of=T2)
    return registry


def build_policy_spec(
    *,
    policy_id: str = "data-policy/retail-demo",
    effective_from: str = T1,
    valid_until: str = T5,
) -> DataPolicySpec:
    return DataPolicySpec(
        policy_id=policy_id,
        declared_by=OPERATOR,
        declared_at=T0,
        effective_from=effective_from,
        valid_until=valid_until,
        legal_basis_ref="legal-basis/consent-demo",
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
            PurposeGrant(
                purpose=DisclosurePurpose.SUPPORT,
                allowed_classes=(DataClass.PUBLIC,),
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


def build_policy() -> DataPolicy:
    policy = data.declare_policy(
        spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
    )
    return data.activate_policy(policy, provenance=prov())


def build_evidence_archive() -> EvidenceArchive:
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
            provenance=Provenance(
                issuer=OPERATOR, source="data-governance", recorded_at=T1
            ),
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
            provenance=Provenance(
                issuer=OPERATOR, source="data-governance", recorded_at=T2
            ),
        )
    )
    return archive


def build_dataset() -> IsolatedDataset:
    return IsolatedDataset(
        dataset_id="dataset/customers-demo",
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


def build_engine() -> DataGovernanceEngine:
    return DataGovernanceEngine(
        environment_id=ENV,
        operator=OPERATOR,
        trust_registry=build_registry(),
        evidence_archive=build_evidence_archive(),
    )


def build_claim() -> Claim:
    return Claim(
        claim_id="claim-001",
        claimant=USER,
        claim_type=ClaimType.UNAUTHORIZED_TRANSACTION,
        subject_ref=SUBJECT,
        description="Transaction tx-9001 was not authorized by the account holder.",
        asserted_at=T2,
        amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
        evidence_refs=(EVIDENCE_COMPLAINT,),
    )


def build_case() -> Case:
    return data.open_case(
        case_id="data-case/dispute-001",
        subject_ref=SUBJECT,
        opened_by=OPERATOR,
        opened_at=T2,
        claims=(build_claim(),),
        trust_registry=build_registry(),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(evidence_refs=(EVIDENCE_COMPLAINT,)),
    )


# ---------------------------------------------------------------------------
# 1. Static boundary.
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    """The public boundary is typed, versioned and registry-disciplined."""

    def test_api_version_is_declared_and_versioned(self) -> None:
        self.assertEqual(data.DATA_API_VERSION, "v0.1")
        self.assertEqual(data.DATA_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(data.DATA_SCHEMA_VERSION, 1)

    def test_public_surface_is_frozen(self) -> None:
        exported = set(data.__all__)
        self.assertIn("DataGovernanceEngine", exported)
        self.assertIn("DataPolicySpec", exported)
        self.assertIn("SelectiveDisclosureProof", exported)
        self.assertIn("RetentionRecord", exported)
        self.assertIn("Case", exported)
        self.assertEqual(len(exported), len(data.__all__))

    def test_object_types_are_internal_non_registry_formats(self) -> None:
        # frozen registry object types are 'payswap/...' only; the data
        # domain must not invent protocol-visible object kinds.
        for object_type in (
            data.DATA_POLICY_OBJECT_TYPE,
            data.PRIVACY_ASSESSMENT_OBJECT_TYPE,
            data.DISCLOSURE_OBJECT_TYPE,
            data.RETENTION_OBJECT_TYPE,
            data.CASE_OBJECT_TYPE,
            data.SELECTIVE_PROOF_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("data/"))
            self.assertNotIn("payswap/", object_type)

    def test_domain_id_is_declared(self) -> None:
        self.assertEqual(data.DATA_DOMAIN_ID, "domain/data")

    def test_command_types_are_internal_free_form(self) -> None:
        for command_type in data.COMMAND_TYPES:
            self.assertIsInstance(command_type, str)
            self.assertIn("/", command_type)
            self.assertFalse(command_type.startswith("payswap/"))
        self.assertIn("data/policy.activate", data.COMMAND_TYPES)
        self.assertIn("disclosure/request", data.COMMAND_TYPES)
        self.assertIn("recourse/open-case", data.COMMAND_TYPES)
        self.assertIn("recourse/execute-refund", data.COMMAND_TYPES)

    def test_event_types_use_the_frozen_governance_namespace(self) -> None:
        # No 'data'/'privacy'/'recourse' namespace exists in the frozen
        # registry; data-governance lifecycle events are governance-family
        # records and must use the registered 'governance' namespace.
        from src.transition.registry import validate_event_type

        self.assertTrue(data.EVENT_TYPES)
        for event_type in data.EVENT_TYPES:
            self.assertTrue(event_type.startswith("governance/"))
            validate_event_type("data event type", event_type)

    def test_domain_code_imports_only_consumed_domains(self) -> None:
        consumed: set[str] = set()
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        consumed.add(node.module.split(".")[1])
                    elif node.level > 1 and node.module:
                        consumed.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            consumed.add(alias.name.split(".")[1])
        self.assertEqual(consumed, ALLOWED_SRC_DOMAINS)

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "time.monotonic",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "secrets",
                "time.sleep",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_error_authority_is_core(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["field_rules"][0]["data_class"] = "SECRET"
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_retention_module_has_no_deletion_operation(self) -> None:
        # constitution invariant 17: retention records state; the domain
        # must not offer deletion/rewrite of recorded history.
        retention_source = (Path(__file__).parent / "retention.py").read_text(encoding="utf-8")
        for forbidden in ("def delete", "def purge", "def erase", "def rewrite"):
            self.assertNotIn(forbidden, retention_source)

    def test_policy_module_embeds_no_authoritative_legal_text(self) -> None:
        policy_source = (Path(__file__).parent / "policy.py").read_text(encoding="utf-8")
        for marker in ("GDPR", "CCPA", "legal_text", "regulatory_text"):
            self.assertNotIn(marker, policy_source)


# ---------------------------------------------------------------------------
# 2. Data policy (declared, typed references; fail-closed on unknown).
# ---------------------------------------------------------------------------


class PolicyContractTests(unittest.TestCase):
    """Policy contracts: typed declared content, closed vocabularies."""

    def test_field_rule_rejects_unknown_data_class(self) -> None:
        with self.assertRaises(CoreValidationError):
            FieldRule(field_name="email", data_class="SECRET")

    def test_purpose_grant_rejects_unknown_purpose(self) -> None:
        with self.assertRaises(CoreValidationError):
            PurposeGrant(purpose="MARKETING", allowed_classes=(DataClass.PUBLIC,))

    def test_spec_requires_retention_rule_for_every_declared_class(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["retention_rules"] = payload["retention_rules"][:2]
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_duplicate_fields(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["field_rules"] = payload["field_rules"] + [payload["field_rules"][0]]
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_duplicate_purposes(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["purpose_grants"] = payload["purpose_grants"] + [payload["purpose_grants"][0]]
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_misordered_window(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["effective_from"] = T5
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_empty_window(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["valid_until"] = payload["effective_from"]
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_non_governance_principal(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["declared_by"] = "somebody/example"
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_rejects_malformed_legal_basis_reference(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["legal_basis_ref"] = "we-just-made-this-up"
        with self.assertRaises(CoreValidationError):
            DataPolicySpec.from_dict(payload)

    def test_spec_round_trip_is_lossless(self) -> None:
        spec = build_policy_spec()
        self.assertEqual(DataPolicySpec.from_dict(spec.to_dict()), spec)


class PolicyLifecycleTests(unittest.TestCase):
    """Policy lifecycle: DECLARED -> ACTIVE -> RETIRED with fail-closed paths."""

    def test_declare_builds_sealed_version_one_declared(self) -> None:
        policy = data.declare_policy(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        self.assertEqual(policy.envelope.object_version, 1)
        self.assertEqual(policy.state, PolicyState.DECLARED)
        self.assertEqual(policy.envelope.object_type, data.DATA_POLICY_OBJECT_TYPE)
        self.assertEqual(policy.policy_id, "data-policy/retail-demo")
        policy.envelope.verify_integrity()

    def test_activate_advances_to_active_and_pins_version(self) -> None:
        policy = data.activate_policy(
            data.declare_policy(
                spec=build_policy_spec(),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            ),
            provenance=prov(),
        )
        self.assertEqual(policy.state, PolicyState.ACTIVE)
        self.assertEqual(policy.envelope.object_version, 2)
        self.assertEqual(policy.envelope.previous_version, 1)

    def test_activate_rejects_a_policy_that_is_not_declared(self) -> None:
        policy = build_policy()
        with self.assertRaises(CoreValidationError):
            data.activate_policy(policy, provenance=prov())

    def test_retire_requires_active(self) -> None:
        declared = data.declare_policy(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            data.retire_policy(declared, provenance=prov())
        retired = data.retire_policy(build_policy(), provenance=prov())
        self.assertEqual(retired.state, PolicyState.RETIRED)
        with self.assertRaises(CoreValidationError):
            data.retire_policy(retired, provenance=prov())

    def test_identity_fields_are_frozen_across_versions(self) -> None:
        policy = build_policy()
        retired = data.retire_policy(policy, provenance=prov())
        self.assertEqual(retired.envelope.object_id, policy.envelope.object_id)
        self.assertEqual(retired.envelope.object_type, policy.envelope.object_type)
        self.assertEqual(retired.spec, policy.spec)

    def test_policy_is_active_at_respects_window_and_state(self) -> None:
        policy = build_policy()
        self.assertTrue(data.policy_is_active_at(policy, T2))
        self.assertFalse(data.policy_is_active_at(policy, T0))  # before effective_from
        self.assertFalse(data.policy_is_active_at(policy, T5))  # at valid_until (half open)
        retired = data.retire_policy(policy, provenance=prov())
        self.assertFalse(data.policy_is_active_at(retired, T2))

    def test_field_data_class_and_purpose_classes(self) -> None:
        policy = build_policy()
        self.assertEqual(data.field_data_class(policy, "email"), DataClass.RESTRICTED)
        self.assertEqual(
            data.purpose_classes(policy, DisclosurePurpose.DISPUTE),
            frozenset({DataClass.PUBLIC, DataClass.RESTRICTED}),
        )
        self.assertEqual(
            data.purpose_classes(policy, DisclosurePurpose.OPERATIONS), frozenset()
        )
        with self.assertRaises(CoreValidationError):
            data.field_data_class(policy, "nickname")

    def test_retention_seconds_lookup(self) -> None:
        policy = build_policy()
        self.assertEqual(data.retention_seconds_for(policy, DataClass.PUBLIC), 3600)
        self.assertEqual(
            data.retention_seconds_for(policy, DataClass.CONFIDENTIAL), 604800
        )

    def test_policy_round_trip_and_tamper_rejection(self) -> None:
        policy = build_policy()
        decoded = DataPolicy.from_dict(policy.to_dict())
        self.assertEqual(decoded, policy)
        tampered = policy.to_dict()
        tampered["payload"]["legal_basis_ref"] = "legal-basis/forged"
        with self.assertRaises(CoreValidationError):
            DataPolicy.from_dict(tampered)

    def test_policy_rejects_unknown_state_on_decode(self) -> None:
        policy = build_policy()
        payload = policy.to_dict()
        payload["envelope"]["state"] = "MYSTERY"
        with self.assertRaises(CoreValidationError):
            DataPolicy.from_dict(payload)

    def test_policy_json_round_trip_is_byte_stable(self) -> None:
        policy = build_policy()
        self.assertEqual(DataPolicy.from_json(policy.to_json()).to_json(), policy.to_json())


class PolicyRegistryTests(unittest.TestCase):
    """The declared-policy registry fails closed on unknown identifiers."""

    def test_unknown_policy_id_fails_closed(self) -> None:
        registry = DataPolicyRegistry()
        with self.assertRaises(CoreValidationError):
            registry.get("data-policy/unknown")

    def test_require_active_fails_closed_for_declared_policy(self) -> None:
        registry = DataPolicyRegistry()
        registry.declare(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            registry.require_active("data-policy/retail-demo", T2)

    def test_require_active_fails_closed_outside_window(self) -> None:
        registry = DataPolicyRegistry()
        registry.declare(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        registry.activate("data-policy/retail-demo", as_of=T1, provenance=prov())
        with self.assertRaises(CoreValidationError):
            registry.require_active("data-policy/retail-demo", T0)
        with self.assertRaises(CoreValidationError):
            registry.require_active("data-policy/retail-demo", T5)
        policy = registry.require_active("data-policy/retail-demo", T2)
        self.assertEqual(policy.state, PolicyState.ACTIVE)

    def test_registry_history_is_append_only(self) -> None:
        registry = DataPolicyRegistry()
        declared = registry.declare(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        active = registry.activate("data-policy/retail-demo", as_of=T1, provenance=prov())
        history = registry.history("data-policy/retail-demo")
        self.assertEqual(history, (declared, active))
        with self.assertRaises(CoreValidationError):
            registry.append(declared)  # re-appending an old version fails

    def test_registry_get_version(self) -> None:
        registry = DataPolicyRegistry()
        declared = registry.declare(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        registry.activate("data-policy/retail-demo", as_of=T1, provenance=prov())
        self.assertEqual(registry.get_version("data-policy/retail-demo", 1), declared)
        with self.assertRaises(CoreValidationError):
            registry.get_version("data-policy/retail-demo", 5)


# ---------------------------------------------------------------------------
# 3. Disclosure: evaluation, data minimization, fail-closed leakage.
# ---------------------------------------------------------------------------


class DisclosureRequestTests(unittest.TestCase):
    def test_participant_gating_through_the_trust_registry(self) -> None:
        registry = build_registry()
        data.require_active_principal(USER, registry)
        with self.assertRaises(CoreValidationError):
            data.require_active_principal("trust/principal/ghost", registry)

    def test_participant_gating_rejects_suspended_principal(self) -> None:
        registry = build_registry()
        with self.assertRaises(CoreValidationError):
            data.require_active_principal(SUSPENDED, registry)

    def test_request_rejects_empty_field_set_and_bad_format(self) -> None:
        with self.assertRaises(CoreValidationError):
            DisclosureRequest(
                requester=USER,
                subject_ref=SUBJECT,
                purpose=DisclosurePurpose.DISPUTE,
                requested_fields=(),
                requested_at=T2,
            )
        with self.assertRaises(CoreValidationError):
            DisclosureRequest(
                requester="someone",
                subject_ref=SUBJECT,
                purpose=DisclosurePurpose.DISPUTE,
                requested_fields=("account_id",),
                requested_at=T2,
            )

    def test_request_rejects_unknown_purpose(self) -> None:
        with self.assertRaises(CoreValidationError):
            DisclosureRequest(
                requester=USER,
                subject_ref=SUBJECT,
                purpose="MARKETING",
                requested_fields=("account_id",),
                requested_at=T2,
            )

    def test_request_round_trip(self) -> None:
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email"),
            requested_at=T2,
        )
        self.assertEqual(DisclosureRequest.from_dict(request.to_dict()), request)


class DisclosureEvaluationTests(unittest.TestCase):
    def _request(self, fields=("account_id", "email", "balance")) -> DisclosureRequest:
        return DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=fields,
            requested_at=T2,
        )

    def _evaluate(self, request, policy, as_of=T2) -> PrivacyAssessment:
        return data.evaluate_disclosure_request(
            assessment_id="data-assessment/as-001",
            request=request,
            policy=policy,
            as_of=as_of,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )

    def test_fully_permitted_request_yields_permitted_verdict(self) -> None:
        assessment = self._evaluate(self._request(("account_id", "email")), build_policy())
        self.assertEqual(assessment.verdict, AssessmentVerdict.PERMITTED)
        self.assertEqual(assessment.permitted_fields, ("account_id", "email"))
        self.assertEqual(assessment.denied_fields, ())
        self.assertEqual(assessment.policy_id, "data-policy/retail-demo")
        self.assertEqual(assessment.policy_version, 2)
        self.assertEqual(assessment.requester, USER)

    def test_partially_permitted_request_reports_denied_fields(self) -> None:
        assessment = self._evaluate(self._request(), build_policy())
        self.assertEqual(assessment.verdict, AssessmentVerdict.PARTIALLY_PERMITTED)
        self.assertEqual(assessment.permitted_fields, ("account_id", "email"))
        self.assertEqual(assessment.denied_fields, ("balance",))

    def test_ungranted_purpose_yields_denied(self) -> None:
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.OPERATIONS,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        assessment = self._evaluate(request, build_policy())
        self.assertEqual(assessment.verdict, AssessmentVerdict.DENIED)
        self.assertEqual(assessment.permitted_fields, ())
        self.assertEqual(assessment.denied_fields, ("account_id",))

    def test_evaluation_fails_closed_on_unclassified_field(self) -> None:
        request = self._request(("account_id", "nickname"))
        with self.assertRaises(CoreValidationError):
            self._evaluate(request, build_policy())

    def test_evaluation_fails_closed_on_inactive_policy(self) -> None:
        declared = data.declare_policy(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            self._evaluate(self._request(("account_id",)), declared)

    def test_evaluation_fails_closed_when_as_of_precedes_request(self) -> None:
        with self.assertRaises(CoreValidationError):
            self._evaluate(self._request(("account_id",)), build_policy(), as_of=T1)

    def test_assessment_is_a_sealed_durable_record(self) -> None:
        assessment = self._evaluate(self._request(), build_policy())
        self.assertEqual(assessment.envelope.object_type, data.PRIVACY_ASSESSMENT_OBJECT_TYPE)
        self.assertEqual(assessment.assessment_id, "data-assessment/as-001")
        decoded = PrivacyAssessment.from_dict(assessment.to_dict())
        self.assertEqual(decoded, assessment)
        tampered = assessment.to_dict()
        tampered["payload"]["verdict"] = "PERMITTED"
        with self.assertRaises(CoreValidationError):
            PrivacyAssessment.from_dict(tampered)


class DisclosureRecordTests(unittest.TestCase):
    def _request(self, fields=("account_id", "email", "balance")) -> DisclosureRequest:
        return DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=fields,
            requested_at=T2,
        )

    def _record(self, request=None) -> DisclosureRecord:
        request = request or self._request()
        return data.request_disclosure(
            disclosure_id="data-disclosure/req-001",
            request=request,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )

    def _assessment(self, request=None) -> PrivacyAssessment:
        request = request or self._request()
        return data.evaluate_disclosure_request(
            assessment_id="data-assessment/as-001",
            request=request,
            policy=build_policy(),
            as_of=T2,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )

    def test_request_disclosure_creates_requested_record(self) -> None:
        record = self._record()
        self.assertEqual(record.state, DisclosureState.REQUESTED)
        self.assertEqual(record.envelope.object_type, data.DISCLOSURE_OBJECT_TYPE)
        self.assertEqual(record.disclosure_id, "data-disclosure/req-001")
        self.assertEqual(record.requester, USER)
        self.assertEqual(record.requested_fields, ("account_id", "email", "balance"))
        self.assertEqual(record.purpose, DisclosurePurpose.DISPUTE)
        decoded = DisclosureRecord.from_dict(record.to_dict())
        self.assertEqual(decoded, record)

    def test_disclose_reveals_only_permitted_fields(self) -> None:
        record = self._record()
        assessment = self._assessment()
        disclosed = data.disclose(
            record,
            assessment=assessment,
            disclosed_values={"account_id": "acct-001", "email": "user1@example.test"},
            as_of=T2,
            provenance=prov(evidence_refs=("data-assessment/as-001",)),
        )
        self.assertEqual(disclosed.state, DisclosureState.DISCLOSED)
        self.assertEqual(
            dict(disclosed.disclosed_values),
            {"account_id": "acct-001", "email": "user1@example.test"},
        )
        self.assertEqual(disclosed.denied_fields, ("balance",))
        self.assertEqual(disclosed.policy_id, "data-policy/retail-demo")
        self.assertEqual(disclosed.policy_version, 2)
        self.assertEqual(disclosed.assessment_id, "data-assessment/as-001")

    def test_disclose_fails_closed_on_forbidden_field_leakage(self) -> None:
        record = self._record()
        assessment = self._assessment()
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={
                    "account_id": "acct-001",
                    "balance": 125000,  # CONFIDENTIAL: not permitted for DISPUTE
                },
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclose_fails_closed_on_unrequested_permitted_field(self) -> None:
        record = self._record()
        assessment = self._assessment()
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001", "country": "DE"},
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclose_fails_closed_on_wrong_request(self) -> None:
        record = self._record()
        other = DisclosureRequest(
            requester=DECIDER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email", "balance"),
            requested_at=T2,
        )
        assessment = self._assessment(other)
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001"},
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclose_requires_provenance_evidence_refs(self) -> None:
        record = self._record()
        assessment = self._assessment()
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001"},
                as_of=T2,
                provenance=prov(),  # no evidence refs: provenance must be preserved
            )

    def test_disclose_fails_closed_when_not_requested(self) -> None:
        record = self._record()
        assessment = self._assessment()
        disclosed = data.disclose(
            record,
            assessment=assessment,
            disclosed_values={"account_id": "acct-001"},
            as_of=T2,
            provenance=prov(evidence_refs=("data-assessment/as-001",)),
        )
        with self.assertRaises(CoreValidationError):
            data.disclose(
                disclosed,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001"},
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclose_fails_closed_before_the_assessment_instant(self) -> None:
        record = self._record()
        assessment = data.evaluate_disclosure_request(
            assessment_id="data-assessment/as-001",
            request=self._request(),
            policy=build_policy(),
            as_of=T3,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001"},
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_reject_disclosure_records_denial(self) -> None:
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.OPERATIONS,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        record = self._record(request)
        assessment = data.evaluate_disclosure_request(
            assessment_id="data-assessment/as-001",
            request=request,
            policy=build_policy(),
            as_of=T2,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        rejected = data.reject_disclosure(
            record,
            assessment=assessment,
            note="purpose not granted by the declared policy",
            as_of=T3,
            provenance=prov(),
        )
        self.assertEqual(rejected.state, DisclosureState.REJECTED)
        self.assertEqual(rejected.rejection_verdict, AssessmentVerdict.DENIED)
        with self.assertRaises(CoreValidationError):
            data.disclose(
                rejected,
                assessment=assessment,
                disclosed_values={"account_id": "acct-001"},
                as_of=T3,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclosed_values_must_be_canonical_values(self) -> None:
        record = self._record()
        assessment = self._assessment()
        with self.assertRaises(CoreValidationError):
            data.disclose(
                record,
                assessment=assessment,
                disclosed_values={"account_id": 1.5},  # floats are outside the domain
                as_of=T2,
                provenance=prov(evidence_refs=("data-assessment/as-001",)),
            )

    def test_disclosure_record_tamper_rejection(self) -> None:
        record = self._record()
        tampered = record.to_dict()
        tampered["payload"]["requester"] = "trust/principal/attacker"
        with self.assertRaises(CoreValidationError):
            DisclosureRecord.from_dict(tampered)


# ---------------------------------------------------------------------------
# 4. Selective disclosure: commitments and proofs.
# ---------------------------------------------------------------------------


class CommitmentTests(unittest.TestCase):
    def test_commit_dataset_is_deterministic(self) -> None:
        first = commit_dataset(build_dataset())
        second = commit_dataset(build_dataset())
        self.assertEqual(first, second)
        self.assertIsInstance(first, DatasetCommitment)

    def test_commitments_change_when_values_change(self) -> None:
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
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
        other = commit_dataset(tampered)
        self.assertNotEqual(other.root, commitment.root)

    def test_dataset_rejects_floats_and_duplicate_fields(self) -> None:
        with self.assertRaises(CoreValidationError):
            dataset_record("customer-001", {"balance": 1.25})
        with self.assertRaises(CoreValidationError):
            DatasetRecord(
                record_id="customer-001",
                fields=(("account_id", "a"), ("account_id", "b")),
            )

    def test_field_commitment_binds_the_field_name_and_value(self) -> None:
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        record_commitment = commitment.records[0]
        by_field = dict(record_commitment.field_commitments)
        expected = canonical_sha256({"field": "email", "value": "user1@example.test"})
        self.assertEqual(by_field["email"], expected)
        other = canonical_sha256({"field": "account_id", "value": "user1@example.test"})
        self.assertNotEqual(by_field["email"], other)

    def test_record_commitment_covers_every_field(self) -> None:
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        record = commitment.records[0]
        field_map = dict(record.field_commitments)
        expected = canonical_sha256({"record_id": "customer-001", "fields": field_map})
        self.assertEqual(record.record_commitment, expected)

    def test_commitment_round_trip_is_lossless(self) -> None:
        commitment = commit_dataset(build_dataset())
        decoded = DatasetCommitment.from_dict(commitment.to_dict())
        self.assertEqual(decoded, commitment)
        tampered = commitment.to_dict()
        tampered["root"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            DatasetCommitment.from_dict(tampered)


class SelectiveDisclosureTests(unittest.TestCase):
    def _produce(self):
        policy = build_policy()
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email", "balance"),
            requested_at=T2,
        )
        proof = data.produce_disclosure_proof(
            proof_id="data-proof/proof-001",
            dataset=dataset,
            commitment=commitment,
            request=request,
            policy=policy,
            as_of=T2,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        return proof, policy, dataset, commitment, request

    def test_proof_discloses_only_policy_permitted_fields(self) -> None:
        proof, *_ = self._produce()
        disclosed = {}
        for record in proof.disclosed_records:
            disclosed.update(dict(record.disclosed_fields))
        self.assertEqual(set(disclosed), {"account_id", "email"})
        for record in proof.disclosed_records:
            self.assertIn("balance", record.withheld_fields)
            self.assertIn("full_name", record.withheld_fields)

    def test_proof_withholds_values_but_keeps_commitments(self) -> None:
        proof, *_ = self._produce()
        record = proof.disclosed_records[0]
        withheld = set(record.withheld_fields)
        committed = set(dict(record.field_commitments))
        self.assertTrue(withheld.issubset(committed))
        # the withheld fields carry digests only — never values.
        serialized = proof.to_json()
        self.assertNotIn("Ada Example", serialized)
        self.assertNotIn("Bob Example", serialized)

    def test_proof_is_a_sealed_durable_object(self) -> None:
        proof, *_ = self._produce()
        self.assertEqual(proof.state, ProofState.ISSUED)
        self.assertEqual(proof.envelope.object_type, data.SELECTIVE_PROOF_OBJECT_TYPE)
        decoded = SelectiveDisclosureProof.from_dict(proof.to_dict())
        self.assertEqual(decoded, proof)

    def test_verify_accepts_an_honest_proof(self) -> None:
        proof, policy, _, commitment, _ = self._produce()
        data.verify_disclosure_proof(
            proof, policy=policy, as_of=T2, expected_root=commitment.root
        )
        # verification also passes without a trusted root binding
        data.verify_disclosure_proof(proof, policy=policy, as_of=T2)

    def test_verify_fails_closed_on_policy_mismatch(self) -> None:
        # verifying against a different policy (one that does not permit
        # 'email' for DISPUTE) must fail closed: the leakage gate is
        # enforced by the verifier, not only by the producer.
        proof, _, _, commitment, _ = self._produce()
        spec = build_policy_spec()
        tighter = DataPolicySpec(
            policy_id="data-policy/retail-demo",
            declared_by=OPERATOR,
            declared_at=T0,
            effective_from=T1,
            valid_until=T5,
            legal_basis_ref="legal-basis/consent-demo",
            purpose_grants=(
                PurposeGrant(
                    purpose=DisclosurePurpose.DISPUTE,
                    allowed_classes=(DataClass.PUBLIC,),
                ),
            ),
            field_rules=spec.field_rules,
            retention_rules=spec.retention_rules,
        )
        tight_policy = data.activate_policy(
            data.declare_policy(
                spec=tighter, environment_id=ENV, domain_id=DOMAIN, provenance=prov()
            ),
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                proof, policy=tight_policy, as_of=T2, expected_root=commitment.root
            )

    def test_verify_fails_closed_on_tampered_disclosed_value(self) -> None:
        proof, policy, _, commitment, _ = self._produce()
        tampered = proof.to_dict()
        tampered["payload"]["disclosed_records"][0]["disclosed_fields"][0] = [
            "account_id",
            "acct-999",
        ]
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                SelectiveDisclosureProof.from_dict(tampered),
                policy=policy,
                as_of=T2,
                expected_root=commitment.root,
            )

    def test_verify_fails_closed_on_tampered_root(self) -> None:
        proof, policy, _, _, _ = self._produce()
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                proof,
                policy=policy,
                as_of=T2,
                expected_root="0" * 64,
            )

    def test_produce_fails_closed_on_tampered_dataset(self) -> None:
        policy = build_policy()
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email"),
            requested_at=T2,
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
        with self.assertRaises(CoreValidationError):
            data.produce_disclosure_proof(
                proof_id="data-proof/proof-002",
                dataset=tampered,
                commitment=commitment,
                request=request,
                policy=policy,
                as_of=T2,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_produce_fails_closed_on_unclassified_field(self) -> None:
        policy = build_policy()
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "nickname"),
            requested_at=T2,
        )
        with self.assertRaises(CoreValidationError):
            data.produce_disclosure_proof(
                proof_id="data-proof/proof-003",
                dataset=dataset,
                commitment=commitment,
                request=request,
                policy=policy,
                as_of=T2,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_produce_fails_closed_on_spliced_dataset(self) -> None:
        policy = build_policy()
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        spliced = IsolatedDataset(
            dataset_id=dataset.dataset_id,
            records=dataset.records[:1],  # a record is dropped
        )
        with self.assertRaises(CoreValidationError):
            data.produce_disclosure_proof(
                proof_id="data-proof/proof-004",
                dataset=spliced,
                commitment=commitment,
                request=request,
                policy=policy,
                as_of=T2,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_produce_fails_closed_on_extra_dataset_record(self) -> None:
        policy = build_policy()
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        extra = IsolatedDataset(
            dataset_id=dataset.dataset_id,
            records=dataset.records
            + (
                dataset_record(
                    "customer-003",
                    {**dict(dataset.records[0].fields), "account_id": "acct-003"},
                ),
            ),
        )
        with self.assertRaises(CoreValidationError):
            data.produce_disclosure_proof(
                proof_id="data-proof/proof-005",
                dataset=extra,
                commitment=commitment,
                request=request,
                policy=policy,
                as_of=T2,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_produce_fails_closed_on_inactive_policy(self) -> None:
        declared = data.declare_policy(
            spec=build_policy_spec(), environment_id=ENV, domain_id=DOMAIN, provenance=prov()
        )
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        with self.assertRaises(CoreValidationError):
            data.produce_disclosure_proof(
                proof_id="data-proof/proof-006",
                dataset=dataset,
                commitment=commitment,
                request=request,
                policy=declared,
                as_of=T2,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_verify_fails_closed_on_revoked_proof(self) -> None:
        proof, policy, _, commitment, _ = self._produce()
        revoked = data.revoke_disclosure_proof(proof, provenance=prov())
        self.assertEqual(revoked.state, ProofState.REVOKED)
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                revoked, policy=policy, as_of=T2, expected_root=commitment.root
            )

    def test_verify_fails_closed_on_inactive_policy(self) -> None:
        proof, policy, _, commitment, _ = self._produce()
        retired = data.retire_policy(policy, provenance=prov())
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                proof, policy=retired, as_of=T2, expected_root=commitment.root
            )

    def test_proof_is_deterministic(self) -> None:
        first, *_ = self._produce()
        second, *_ = self._produce()
        self.assertEqual(first.to_json(), second.to_json())

    def test_proof_serialization_is_lossless(self) -> None:
        proof, *_ = self._produce()
        decoded = SelectiveDisclosureProof.from_json(proof.to_json())
        self.assertEqual(decoded.to_json(), proof.to_json())

    def test_verify_fails_closed_on_forged_sealed_proof_with_wrong_value(self) -> None:
        # An attacker can compute valid seals for arbitrary content, so a
        # self-consistent composite whose disclosed value does NOT re-hash
        # to its stated commitment must fail verification: the verifier
        # never relies on producer honesty (defense against forged proofs
        # that bypass the producer-side commitment computation).
        from src.core.envelope import ObjectEnvelope
        from src.data.seal import seal_composite

        proof, policy, _, commitment, _ = self._produce()
        forged = proof.to_dict()
        forged["payload"]["disclosed_records"][0]["disclosed_fields"][0] = [
            "account_id",
            "acct-999",
        ]
        envelope = ObjectEnvelope.from_dict(forged["envelope"])
        payload = ProofPayload.from_dict(forged["payload"])
        forged["integrity_hash"] = seal_composite(envelope, payload)
        with self.assertRaises(CoreValidationError):
            data.verify_disclosure_proof(
                SelectiveDisclosureProof.from_dict(forged),
                policy=policy,
                as_of=T2,
                expected_root=commitment.root,
            )


# ---------------------------------------------------------------------------
# 5. Retention: policy-driven bookkeeping, legal hold, append-only.
# ---------------------------------------------------------------------------


class RetentionTests(unittest.TestCase):
    def _record(self) -> RetentionRecord:
        policy = build_policy()
        return create_retention_record(
            retention_id="data-retention/ret-001",
            subject_ref=SUBJECT,
            data_class=DataClass.RESTRICTED,
            collected_at=T1,
            policy=policy,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )

    def test_create_computes_retain_until_from_the_policy(self) -> None:
        record = self._record()
        self.assertEqual(record.state, data.RetentionState.ACTIVE)
        self.assertEqual(record.retain_until, "2026-09-03T06:00:00Z")
        self.assertEqual(record.policy_id, "data-policy/retail-demo")
        self.assertEqual(record.policy_version, 2)
        self.assertEqual(record.data_class, DataClass.RESTRICTED)

    def test_create_fails_closed_for_class_without_retention_rule(self) -> None:
        payload = build_policy_spec().to_dict()
        payload["retention_rules"] = [
            rule for rule in payload["retention_rules"]
            if rule["data_class"] != DataClass.RESTRICTED.value
        ]
        # also drop RESTRICTED fields so the policy stays internally valid
        payload["field_rules"] = [
            rule for rule in payload["field_rules"]
            if rule["data_class"] != DataClass.RESTRICTED.value
        ]
        policy = data.activate_policy(
            data.declare_policy(
                spec=DataPolicySpec.from_dict(payload),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            ),
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            create_retention_record(
                retention_id="data-retention/ret-002",
                subject_ref=SUBJECT,
                data_class=DataClass.RESTRICTED,
                collected_at=T1,
                policy=policy,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_create_fails_closed_when_policy_inactive_at_collection(self) -> None:
        policy = build_policy()  # active window [T1, T5)
        with self.assertRaises(CoreValidationError):
            create_retention_record(
                retention_id="data-retention/ret-003",
                subject_ref=SUBJECT,
                data_class=DataClass.PUBLIC,
                collected_at=T0,
                policy=policy,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_evaluate_retention_state_is_explicit_and_pure(self) -> None:
        record = self._record()
        self.assertEqual(data.evaluate_retention_state(record, T2), RetentionOutcome.RETAINED)
        self.assertEqual(
            data.evaluate_retention_state(record, "2026-09-03T12:00:00Z"),
            RetentionOutcome.DUE,
        )

    def test_mark_due_requires_the_window_to_have_elapsed(self) -> None:
        record = self._record()
        with self.assertRaises(CoreValidationError):
            data.mark_retention_due(record, as_of=T2, provenance=prov())
        due = data.mark_retention_due(
            record, as_of="2026-09-03T12:00:00Z", provenance=prov()
        )
        self.assertEqual(due.state, data.RetentionState.DUE)

    def test_mark_expired_requires_due_state(self) -> None:
        record = self._record()
        with self.assertRaises(CoreValidationError):
            data.mark_retention_expired(
                record, as_of="2026-09-03T12:00:00Z", provenance=prov()
            )
        due = data.mark_retention_due(
            record, as_of="2026-09-03T12:00:00Z", provenance=prov()
        )
        expired = data.mark_retention_expired(
            due, as_of="2026-09-03T18:00:00Z", provenance=prov()
        )
        self.assertEqual(expired.state, data.RetentionState.EXPIRED)
        with self.assertRaises(CoreValidationError):
            data.mark_retention_expired(expired, as_of=T5, provenance=prov())

    def test_legal_hold_suspends_expiry(self) -> None:
        record = self._record()
        hold = LegalHold(
            hold_id="legal-hold/litigation-1",
            declared_by=DECIDER,
            declared_at=T2,
            basis_ref="legal-basis/litigation-demo",
            case_ref="data-case/dispute-001",
        )
        held = data.declare_retention_hold(record, hold=hold, provenance=prov())
        self.assertEqual(
            data.evaluate_retention_state(held, "2026-09-30T00:00:00Z"),
            RetentionOutcome.HELD,
        )
        with self.assertRaises(CoreValidationError):
            data.mark_retention_due(held, as_of="2026-09-30T00:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            data.mark_retention_expired(
                held, as_of="2026-09-30T00:00:00Z", provenance=prov()
            )
        released = data.release_retention_hold(
            held, as_of="2026-09-30T00:00:00Z", provenance=prov()
        )
        self.assertIsNone(released.legal_hold)
        due = data.mark_retention_due(
            released, as_of="2026-09-30T00:00:00Z", provenance=prov()
        )
        self.assertEqual(due.state, data.RetentionState.DUE)

    def test_release_fails_closed_without_a_hold(self) -> None:
        record = self._record()
        with self.assertRaises(CoreValidationError):
            data.release_retention_hold(record, as_of=T2, provenance=prov())

    def test_hold_cannot_be_declared_twice_or_after_expiry(self) -> None:
        record = self._record()
        hold = LegalHold(
            hold_id="legal-hold/litigation-1",
            declared_by=DECIDER,
            declared_at=T2,
            basis_ref="legal-basis/litigation-demo",
        )
        held = data.declare_retention_hold(record, hold=hold, provenance=prov())
        with self.assertRaises(CoreValidationError):
            data.declare_retention_hold(held, hold=hold, provenance=prov())
        released = data.release_retention_hold(held, as_of=T2, provenance=prov())
        due = data.mark_retention_due(released, as_of="2026-09-30T00:00:00Z", provenance=prov())
        expired = data.mark_retention_expired(due, as_of="2026-09-30T00:00:00Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            data.declare_retention_hold(
                expired,
                hold=LegalHold(
                    hold_id="legal-hold/late",
                    declared_by=DECIDER,
                    declared_at=T2,
                    basis_ref="legal-basis/litigation-demo",
                ),
                provenance=prov(),
            )

    def test_archive_record_keeps_data_under_hold(self) -> None:
        record = self._record()
        hold = LegalHold(
            hold_id="legal-hold/litigation-1",
            declared_by=DECIDER,
            declared_at=T2,
            basis_ref="legal-basis/litigation-demo",
        )
        held = data.declare_retention_hold(record, hold=hold, provenance=prov())
        archived = data.archive_retention_record(
            held, as_of=T3, provenance=prov(), archive_ref="archive/cold-store-1"
        )
        self.assertEqual(archived.state, data.RetentionState.ARCHIVED)
        self.assertEqual(archived.archive_ref, "archive/cold-store-1")
        self.assertIsNotNone(archived.legal_hold)

    def test_retention_history_is_append_only(self) -> None:
        record = self._record()
        due = data.mark_retention_due(
            record, as_of="2026-09-03T12:00:00Z", provenance=prov()
        )
        store = MemoryStateStore()
        store.commit((record.envelope,))
        with self.assertRaises(CoreValidationError):
            store.commit((record.envelope,))  # re-appending v1 fails closed
        store.commit((due.envelope,))  # the exact next version commits
        self.assertEqual(store.get(record.retention_id).object_version, 2)

    def test_retention_record_round_trip_and_tamper(self) -> None:
        record = self._record()
        decoded = RetentionRecord.from_dict(record.to_dict())
        self.assertEqual(decoded, record)
        tampered = record.to_dict()
        tampered["payload"]["retain_until"] = "2030-01-01T00:00:00Z"
        with self.assertRaises(CoreValidationError):
            RetentionRecord.from_dict(tampered)

    def test_retention_record_rejects_unknown_state(self) -> None:
        record = self._record()
        payload = record.to_dict()
        payload["envelope"]["state"] = "EVAPORATED"
        with self.assertRaises(CoreValidationError):
            RetentionRecord.from_dict(payload)

    def test_expired_bookkeeping_never_rewrites_the_underlying_data(self) -> None:
        # Retention records state; the underlying financial evidence
        # (append-only per constitution invariant 17) is untouched: the
        # retention record carries no deletion capability at all.
        record = self._record()
        due = data.mark_retention_due(
            record, as_of="2026-09-03T12:00:00Z", provenance=prov()
        )
        expired = data.mark_retention_expired(
            due, as_of="2026-09-03T18:00:00Z", provenance=prov()
        )
        self.assertIsNone(expired.legal_hold)
        self.assertEqual(expired.subject_ref, record.subject_ref)
        self.assertEqual(expired.envelope.object_id, record.envelope.object_id)
        self.assertEqual(expired.data_class, record.data_class)


# ---------------------------------------------------------------------------
# 6. Cases, claims and recourse.
# ---------------------------------------------------------------------------


class CaseContractTests(unittest.TestCase):
    def test_claim_rejects_unknown_claim_type(self) -> None:
        with self.assertRaises(CoreValidationError):
            Claim(
                claim_id="claim-001",
                claimant=USER,
                claim_type="mystery",
                subject_ref=SUBJECT,
                description="d",
                asserted_at=T2,
            )

    def test_claim_round_trip(self) -> None:
        claim = build_claim()
        self.assertEqual(Claim.from_dict(claim.to_dict()), claim)

    def test_claim_rejects_unregistered_claimant_format(self) -> None:
        with self.assertRaises(CoreValidationError):
            Claim(
                claim_id="claim-001",
                claimant="anonymous",
                claim_type=ClaimType.FRAUD,
                subject_ref=SUBJECT,
                description="d",
                asserted_at=T2,
            )

    def test_decision_rejects_empty_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            RecourseDecision(
                decision_id="decision-001",
                kind=DecisionKind.APPROVE_REFUND,
                decided_by=DECIDER,
                decided_at=T3,
                rationale="Unauthorized transaction confirmed.",
                evidence_refs=(),
                amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
            )

    def test_decision_rejects_unknown_kind(self) -> None:
        with self.assertRaises(CoreValidationError):
            RecourseDecision(
                decision_id="decision-001",
                kind="COMPENSATE",
                decided_by=DECIDER,
                decided_at=T3,
                rationale="r",
                evidence_refs=(EVIDENCE_TXN,),
            )

    def test_investigation_rejects_empty_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            Investigation(
                investigator=INVESTIGATOR,
                investigated_at=T3,
                findings="No authorization record exists for tx-9001.",
                evidence_refs=(),
            )

    def test_package_records_require_evidence(self) -> None:
        with self.assertRaises(CoreValidationError):
            RefundPackage(
                package_id="refund-package/001",
                compiled_by=OPERATOR,
                compiled_at=T3,
                amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
                target_ref=SUBJECT,
                execution_domain="domain/settlement",
                evidence_refs=(),
            )
        with self.assertRaises(CoreValidationError):
            ReversalPackage(
                package_id="reversal-package/001",
                compiled_by=OPERATOR,
                compiled_at=T3,
                target_transaction_ref="ledger/entry/tx-9001",
                execution_domain="domain/settlement",
                evidence_refs=(),
            )


class CaseLifecycleTests(unittest.TestCase):
    def _prepared_case(self) -> Case:
        case = build_case()
        return data.investigate_case(
            case,
            investigation=Investigation(
                investigator=INVESTIGATOR,
                investigated_at=T3,
                findings="No authorization record exists for tx-9001; complaint matches evidence.",
                evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
            ),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT)),
        )

    def _decision(self, decision_id="decision-001", kind=DecisionKind.APPROVE_REFUND,
                  amount=None) -> RecourseDecision:
        return RecourseDecision(
            decision_id=decision_id,
            kind=kind,
            decided_by=DECIDER,
            decided_at=T3,
            rationale="Unauthorized transaction confirmed; refund approved."
            if kind is DecisionKind.APPROVE_REFUND
            else "r",
            evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
            amount=amount
            if amount is not None
            else (
                ScaledValue(value=125000, scale=2, unit="asset/USD")
                if kind is DecisionKind.APPROVE_REFUND
                else None
            ),
        )

    def _refund_package(self, package_id="refund-package/001",
                        amount=None) -> RefundPackage:
        return RefundPackage(
            package_id=package_id,
            compiled_by=OPERATOR,
            compiled_at=T3,
            amount=amount
            or ScaledValue(value=125000, scale=2, unit="asset/USD"),
            target_ref=SUBJECT,
            execution_domain="domain/settlement",
            evidence_refs=(EVIDENCE_TXN,),
        )

    def test_open_case_records_claims_and_provenance(self) -> None:
        case = build_case()
        self.assertEqual(case.state, CaseState.OPEN)
        self.assertEqual(len(case.claims), 1)
        self.assertEqual(case.claims[0].claim_id, "claim-001")
        self.assertEqual(case.envelope.object_type, data.CASE_OBJECT_TYPE)
        self.assertEqual(case.envelope.provenance.evidence_refs, (EVIDENCE_COMPLAINT,))
        decoded = Case.from_dict(case.to_dict())
        self.assertEqual(decoded, case)

    def test_open_case_fails_closed_on_unregistered_opener(self) -> None:
        registry = build_registry()
        with self.assertRaises(CoreValidationError):
            data.open_case(
                case_id="data-case/dispute-001",
                subject_ref=SUBJECT,
                opened_by="trust/principal/ghost",
                opened_at=T2,
                claims=(build_claim(),),
                trust_registry=registry,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_open_case_fails_closed_on_suspended_claimant(self) -> None:
        registry = build_registry()
        claim = Claim(
            claim_id="claim-002",
            claimant=SUSPENDED,
            claim_type=ClaimType.BILLING_ERROR,
            subject_ref=SUBJECT,
            description="d",
            asserted_at=T2,
        )
        with self.assertRaises(CoreValidationError):
            data.open_case(
                case_id="data-case/dispute-002",
                subject_ref=SUBJECT,
                opened_by=OPERATOR,
                opened_at=T2,
                claims=(claim,),
                trust_registry=registry,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_open_case_requires_at_least_one_claim(self) -> None:
        with self.assertRaises(CoreValidationError):
            data.open_case(
                case_id="data-case/dispute-003",
                subject_ref=SUBJECT,
                opened_by=OPERATOR,
                opened_at=T2,
                claims=(),
                trust_registry=build_registry(),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_record_claim_extends_the_open_case(self) -> None:
        case = build_case()
        second = Claim(
            claim_id="claim-002",
            claimant=USER,
            claim_type=ClaimType.SERVICE_FAILURE,
            subject_ref=SUBJECT,
            description="Settlement was not confirmed to the user.",
            asserted_at=T2,
        )
        extended = data.record_claim(
            case, claim=second, trust_registry=build_registry(), provenance=prov()
        )
        self.assertEqual(extended.state, CaseState.OPEN)
        self.assertEqual(len(extended.claims), 2)
        self.assertEqual(extended.envelope.object_version, 2)

    def test_record_claim_fails_closed_after_investigation(self) -> None:
        case = self._prepared_case()
        with self.assertRaises(CoreValidationError):
            data.record_claim(
                case,
                claim=Claim(
                    claim_id="claim-003",
                    claimant=USER,
                    claim_type=ClaimType.BILLING_ERROR,
                    subject_ref=SUBJECT,
                    description="late",
                    asserted_at=T2,
                ),
                trust_registry=build_registry(),
                provenance=prov(),
            )

    def test_record_claim_fails_closed_on_duplicate_claim_id(self) -> None:
        case = build_case()
        with self.assertRaises(CoreValidationError):
            data.record_claim(
                case, claim=build_claim(), trust_registry=build_registry(), provenance=prov()
            )

    def test_investigate_requires_resolvable_evidence(self) -> None:
        case = build_case()
        with self.assertRaises(CoreValidationError):
            data.investigate_case(
                case,
                investigation=Investigation(
                    investigator=INVESTIGATOR,
                    investigated_at=T3,
                    findings="Unknown evidence reference.",
                    evidence_refs=("evidence/evidence/ghost",),
                ),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=("evidence/evidence/ghost",)),
            )

    def test_investigate_requires_open_state(self) -> None:
        case = self._prepared_case()
        with self.assertRaises(CoreValidationError):
            data.investigate_case(
                case,
                investigation=Investigation(
                    investigator=INVESTIGATOR,
                    investigated_at=T3,
                    findings="again",
                    evidence_refs=(EVIDENCE_TXN,),
                ),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_investigate_preserves_evidence_provenance(self) -> None:
        case = self._prepared_case()
        self.assertEqual(case.state, CaseState.INVESTIGATED)
        self.assertEqual(case.investigation.evidence_refs, (EVIDENCE_TXN, EVIDENCE_COMPLAINT))
        self.assertEqual(
            case.envelope.provenance.evidence_refs, (EVIDENCE_TXN, EVIDENCE_COMPLAINT)
        )

    def test_decide_requires_investigated_state(self) -> None:
        case = build_case()
        with self.assertRaises(CoreValidationError):
            data.decide_case(
                case,
                decision=self._decision(),
                trust_registry=build_registry(),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_decide_requires_resolvable_evidence(self) -> None:
        case = self._prepared_case()
        decision = RecourseDecision(
            decision_id="decision-001",
            kind=DecisionKind.APPROVE_REFUND,
            decided_by=DECIDER,
            decided_at=T3,
            rationale="r",
            evidence_refs=("evidence/evidence/ghost",),
            amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
        )
        with self.assertRaises(CoreValidationError):
            data.decide_case(
                case,
                decision=decision,
                trust_registry=build_registry(),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=("evidence/evidence/ghost",)),
            )

    def test_decide_fails_closed_on_unregistered_decider(self) -> None:
        case = self._prepared_case()
        decision = RecourseDecision(
            decision_id="decision-001",
            kind=DecisionKind.APPROVE_REFUND,
            decided_by="trust/principal/ghost",
            decided_at=T3,
            rationale="r",
            evidence_refs=(EVIDENCE_TXN,),
            amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
        )
        with self.assertRaises(CoreValidationError):
            data.decide_case(
                case,
                decision=decision,
                trust_registry=build_registry(),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_decide_requires_provenance_evidence_refs(self) -> None:
        case = self._prepared_case()
        with self.assertRaises(CoreValidationError):
            data.decide_case(
                case,
                decision=self._decision(),
                trust_registry=build_registry(),
                evidence_archive=build_evidence_archive(),
                provenance=prov(),  # material decisions preserve provenance
            )

    def test_approve_refund_requires_amount(self) -> None:
        case = self._prepared_case()
        decision = RecourseDecision(
            decision_id="decision-001",
            kind=DecisionKind.APPROVE_REFUND,
            decided_by=DECIDER,
            decided_at=T3,
            rationale="r",
            evidence_refs=(EVIDENCE_TXN,),
        )
        with self.assertRaises(CoreValidationError):
            data.decide_case(
                case,
                decision=decision,
                trust_registry=build_registry(),
                evidence_archive=build_evidence_archive(),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_full_approved_refund_lifecycle(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT)),
        )
        self.assertEqual(decided.state, CaseState.DECIDED)
        compiled = data.compile_refund(
            decided,
            package=self._refund_package(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(compiled.refund_package.package_id, "refund-package/001")
        executed = data.execute_refund(
            compiled,
            execution=ExecutionRecord(
                executed_by=OPERATOR,
                executed_at=T4,
                execution_ref="ledger/refund/tx-9001-r1",
            ),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(executed.state, CaseState.EXECUTED)
        self.assertEqual(executed.execution.execution_ref, "ledger/refund/tx-9001-r1")
        closed = data.close_case(
            executed,
            closed_at=T5,
            close_reason="Refund executed and confirmed.",
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(closed.state, CaseState.CLOSED)
        self.assertEqual(closed.envelope.object_version, 6)

    def test_execute_requires_provenance_evidence_refs(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        compiled = data.compile_refund(
            decided,
            package=self._refund_package(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.execute_refund(
                compiled,
                execution=ExecutionRecord(
                    executed_by=OPERATOR,
                    executed_at=T4,
                    execution_ref="ledger/refund/tx-9001-r1",
                ),
                provenance=prov(),  # material decisions preserve provenance
            )

    def test_compile_fails_closed_without_matching_approval(self) -> None:
        case = self._prepared_case()
        rejected = data.decide_case(
            case,
            decision=self._decision(kind=DecisionKind.REJECT),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.compile_refund(
                rejected,
                package=self._refund_package("refund-package/002"),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_compile_fails_closed_on_amount_mismatch(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.compile_refund(
                decided,
                package=self._refund_package(
                    "refund-package/003",
                    amount=ScaledValue(value=999, scale=2, unit="asset/USD"),
                ),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_execute_fails_closed_without_compiled_package(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.execute_refund(
                decided,
                execution=ExecutionRecord(
                    executed_by=OPERATOR,
                    executed_at=T4,
                    execution_ref="ledger/refund/early",
                ),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_execute_reversal_follows_the_reversal_path(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(kind=DecisionKind.APPROVE_REVERSAL),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        compiled = data.compile_reversal(
            decided,
            package=ReversalPackage(
                package_id="reversal-package/001",
                compiled_by=OPERATOR,
                compiled_at=T3,
                target_transaction_ref="ledger/entry/tx-9001",
                execution_domain="domain/settlement",
                evidence_refs=(EVIDENCE_TXN,),
            ),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        executed = data.execute_reversal(
            compiled,
            execution=ExecutionRecord(
                executed_by=OPERATOR,
                executed_at=T4,
                execution_ref="ledger/reversal/tx-9001-r1",
            ),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(executed.state, CaseState.EXECUTED)
        closed = data.close_case(
            executed,
            closed_at=T5,
            close_reason="Reversal executed.",
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(closed.state, CaseState.CLOSED)

    def test_execute_refund_fails_closed_on_reversal_package(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(kind=DecisionKind.APPROVE_REVERSAL),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        compiled = data.compile_reversal(
            decided,
            package=ReversalPackage(
                package_id="reversal-package/002",
                compiled_by=OPERATOR,
                compiled_at=T3,
                target_transaction_ref="ledger/entry/tx-9001",
                execution_domain="domain/settlement",
                evidence_refs=(EVIDENCE_TXN,),
            ),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.execute_refund(
                compiled,
                execution=ExecutionRecord(
                    executed_by=OPERATOR,
                    executed_at=T4,
                    execution_ref="ledger/refund/wrong-family",
                ),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_close_fails_closed_from_open_state(self) -> None:
        case = build_case()
        with self.assertRaises(CoreValidationError):
            data.close_case(
                case,
                closed_at=T5,
                close_reason="premature",
                provenance=prov(),
            )

    def test_close_allows_rejected_decisions(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(kind=DecisionKind.REJECT),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        closed = data.close_case(
            decided,
            closed_at=T5,
            close_reason="Claim rejected after investigation.",
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(closed.state, CaseState.CLOSED)

    def test_execute_fails_closed_after_close(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        compiled = data.compile_refund(
            decided,
            package=self._refund_package("refund-package/004"),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        executed = data.execute_refund(
            compiled,
            execution=ExecutionRecord(
                executed_by=OPERATOR,
                executed_at=T4,
                execution_ref="ledger/refund/tx-9001-r1",
            ),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        closed = data.close_case(
            executed,
            closed_at=T5,
            close_reason="done",
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        with self.assertRaises(CoreValidationError):
            data.execute_refund(
                closed,
                execution=ExecutionRecord(
                    executed_by=OPERATOR,
                    executed_at=T5,
                    execution_ref="ledger/refund/again",
                ),
                provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
            )

    def test_case_round_trip_preserves_every_claim(self) -> None:
        case = self._prepared_case()
        decoded = Case.from_dict(case.to_dict())
        self.assertEqual(decoded, case)
        self.assertEqual(decoded.claims[0].claim_id, "claim-001")

    def test_case_tamper_rejection(self) -> None:
        case = self._prepared_case()
        tampered = case.to_dict()
        tampered["payload"]["claims"] = []
        with self.assertRaises(CoreValidationError):
            Case.from_dict(tampered)

    def test_case_rejects_unknown_state(self) -> None:
        case = build_case()
        payload = case.to_dict()
        payload["envelope"]["state"] = "FROZEN"
        with self.assertRaises(CoreValidationError):
            Case.from_dict(payload)

    def test_case_lifecycle_is_reflected_in_envelope_states(self) -> None:
        case = self._prepared_case()
        decided = data.decide_case(
            case,
            decision=self._decision(kind=DecisionKind.REJECT),
            trust_registry=build_registry(),
            evidence_archive=build_evidence_archive(),
            provenance=prov(evidence_refs=(EVIDENCE_TXN,)),
        )
        self.assertEqual(case.envelope.state, CaseState.INVESTIGATED.value)
        self.assertEqual(decided.envelope.state, CaseState.DECIDED.value)


# ---------------------------------------------------------------------------
# 7. Kernel-bound engine.
# ---------------------------------------------------------------------------


class EngineTests(unittest.TestCase):
    def test_engine_registers_every_domain_command(self) -> None:
        engine = build_engine()
        handlers = getattr(engine.engine, "_handlers")
        self.assertEqual(set(handlers), set(data.COMMAND_TYPES))

    def test_engine_emits_governance_events_only(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        journal = engine.journal
        self.assertEqual(len(journal), 2)
        for entry in journal:
            self.assertTrue(entry.event.event_type.startswith("governance/"))
        self.assertEqual(journal[0].event.event_type, "governance/data-policy-declared")
        self.assertEqual(journal[1].event.event_type, "governance/data-policy-activated")

    def test_engine_events_carry_payload_hash_commitments(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        entry = engine.journal[0]
        self.assertEqual(
            entry.event.payload_hash,
            canonical_sha256(payload_to_json_value(entry.payload)),
        )

    def test_engine_policy_lifecycle_through_the_kernel(self) -> None:
        engine = build_engine()
        declared = engine.declare_policy(spec=build_policy_spec())
        active = engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        self.assertEqual(declared.state, PolicyState.DECLARED)
        self.assertEqual(active.state, PolicyState.ACTIVE)
        self.assertEqual(active.envelope.object_version, 2)
        retired = engine.retire_policy(policy_id="data-policy/retail-demo", as_of=T2)
        self.assertEqual(retired.state, PolicyState.RETIRED)
        self.assertEqual(engine.get("data-policy/retail-demo").state, PolicyState.RETIRED)

    def test_engine_fails_closed_on_unknown_policy(self) -> None:
        engine = build_engine()
        with self.assertRaises(CoreValidationError):
            engine.activate_policy(policy_id="data-policy/unknown", as_of=T1)

    def test_engine_disclosure_flow(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email", "balance"),
            requested_at=T2,
        )
        record = engine.request_disclosure(
            disclosure_id="data-disclosure/req-001", request=request
        )
        self.assertEqual(record.state, DisclosureState.REQUESTED)
        disclosed = engine.disclose(
            disclosure_id="data-disclosure/req-001",
            disclosed_values={"account_id": "acct-001", "email": "user1@example.test"},
            as_of=T2,
        )
        self.assertEqual(disclosed.state, DisclosureState.DISCLOSED)
        self.assertEqual(dict(disclosed.disclosed_values)["email"], "user1@example.test")
        self.assertEqual(disclosed.denied_fields, ("balance",))
        assessment = engine.get_assessment("data-disclosure/req-001")
        self.assertEqual(assessment.verdict, AssessmentVerdict.PARTIALLY_PERMITTED)

    def test_engine_disclosure_leakage_fails_closed(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "balance"),
            requested_at=T2,
        )
        engine.request_disclosure(disclosure_id="data-disclosure/req-001", request=request)
        with self.assertRaises(CoreValidationError):
            engine.disclose(
                disclosure_id="data-disclosure/req-001",
                disclosed_values={"balance": 125000},
                as_of=T2,
            )

    def test_engine_disclosure_rejection_path(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.OPERATIONS,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        engine.request_disclosure(disclosure_id="data-disclosure/req-002", request=request)
        rejected = engine.reject_disclosure(
            disclosure_id="data-disclosure/req-002",
            note="purpose not granted by the declared policy",
            as_of=T3,
        )
        self.assertEqual(rejected.state, DisclosureState.REJECTED)

    def test_engine_selective_proof_flow(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        dataset = build_dataset()
        commitment = commit_dataset(dataset)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id", "email", "balance"),
            requested_at=T2,
        )
        proof = engine.produce_proof(
            proof_id="data-proof/proof-001",
            dataset=dataset,
            commitment=commitment,
            request=request,
            policy_id="data-policy/retail-demo",
            as_of=T2,
        )
        data.verify_disclosure_proof(
            proof,
            policy=engine.get("data-policy/retail-demo"),
            as_of=T2,
            expected_root=commitment.root,
        )
        self.assertEqual(proof.dataset_id, "dataset/customers-demo")

    def test_engine_retention_flow(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        record = engine.record_retention(
            retention_id="data-retention/ret-001",
            subject_ref=SUBJECT,
            data_class=DataClass.RESTRICTED,
            collected_at=T1,
            policy_id="data-policy/retail-demo",
        )
        self.assertEqual(record.state, data.RetentionState.ACTIVE)
        held = engine.declare_retention_hold(
            retention_id="data-retention/ret-001",
            hold=LegalHold(
                hold_id="legal-hold/litigation-1",
                declared_by=DECIDER,
                declared_at=T2,
                basis_ref="legal-basis/litigation-demo",
                case_ref="data-case/dispute-001",
            ),
        )
        self.assertIsNotNone(held.legal_hold)
        with self.assertRaises(CoreValidationError):
            engine.mark_retention_due(
                retention_id="data-retention/ret-001",
                as_of="2026-09-30T00:00:00Z",
            )
        released = engine.release_retention_hold(
            retention_id="data-retention/ret-001", as_of="2026-09-30T00:00:00Z"
        )
        self.assertIsNone(released.legal_hold)
        due = engine.mark_retention_due(
            retention_id="data-retention/ret-001", as_of="2026-09-30T00:00:00Z"
        )
        self.assertEqual(due.state, data.RetentionState.DUE)

    def test_engine_case_dispute_flow(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        case = engine.open_case(
            case_id="data-case/dispute-001",
            subject_ref=SUBJECT,
            opened_by=OPERATOR,
            opened_at=T2,
            claims=(build_claim(),),
        )
        self.assertEqual(case.state, CaseState.OPEN)
        investigated = engine.investigate(
            case_id="data-case/dispute-001",
            investigation=Investigation(
                investigator=INVESTIGATOR,
                investigated_at=T3,
                findings="No authorization record exists for tx-9001.",
                evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
            ),
        )
        self.assertEqual(investigated.state, CaseState.INVESTIGATED)
        decided = engine.decide(
            case_id="data-case/dispute-001",
            decision=RecourseDecision(
                decision_id="decision-001",
                kind=DecisionKind.APPROVE_REFUND,
                decided_by=DECIDER,
                decided_at=T3,
                rationale="Unauthorized transaction confirmed; refund approved.",
                evidence_refs=(EVIDENCE_TXN, EVIDENCE_COMPLAINT),
                amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
            ),
        )
        self.assertEqual(decided.state, CaseState.DECIDED)
        compiled = engine.compile_refund(
            case_id="data-case/dispute-001",
            package=RefundPackage(
                package_id="refund-package/001",
                compiled_by=OPERATOR,
                compiled_at=T3,
                amount=ScaledValue(value=125000, scale=2, unit="asset/USD"),
                target_ref=SUBJECT,
                execution_domain="domain/settlement",
                evidence_refs=(EVIDENCE_TXN,),
            ),
        )
        executed = engine.execute_refund(
            case_id="data-case/dispute-001",
            execution=ExecutionRecord(
                executed_by=OPERATOR,
                executed_at=T4,
                execution_ref="ledger/refund/tx-9001-r1",
            ),
        )
        self.assertEqual(executed.state, CaseState.EXECUTED)
        closed = engine.close_case(
            case_id="data-case/dispute-001",
            closed_at=T5,
            close_reason="Refund executed and confirmed.",
        )
        self.assertEqual(closed.state, CaseState.CLOSED)

    def test_engine_case_lifecycle_violation_fails_closed(self) -> None:
        engine = build_engine()
        engine.open_case(
            case_id="data-case/dispute-002",
            subject_ref=SUBJECT,
            opened_by=OPERATOR,
            opened_at=T2,
            claims=(build_claim(),),
        )
        with self.assertRaises(CoreValidationError):
            engine.close_case(
                case_id="data-case/dispute-002",
                closed_at=T5,
                close_reason="premature",
            )

    def test_engine_rejects_unauthorized_actor(self) -> None:
        engine = build_engine()
        command = Command.build(
            command_id="command/data/attack-1",
            command_type="data/policy.declare",
            actor="trust/principal/ghost",
            target_refs=("data-policy/attack",),
            payload={},
            environment_id=ENV,
            domain_id=DOMAIN,
            idempotency_key="idem/attack-1",
            nonce="nonce/attack-1",
            requested_at=T1,
        )
        result = engine.engine.process(command)
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_engine_rejects_wrong_environment(self) -> None:
        engine = build_engine()
        command = Command.build(
            command_id="command/data/env-1",
            command_type="data/policy.declare",
            actor=OPERATOR,
            target_refs=("data-policy/env",),
            payload={},
            environment_id="env/other",
            domain_id=DOMAIN,
            idempotency_key="idem/env-1",
            nonce="nonce/env-1",
            requested_at=T1,
        )
        result = engine.engine.process(command)
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_engine_rejects_unknown_command_type(self) -> None:
        engine = build_engine()
        command = Command.build(
            command_id="command/data/unknown-1",
            command_type="data/policy.explode",
            actor=OPERATOR,
            target_refs=("data-policy/unknown",),
            payload={},
            environment_id=ENV,
            domain_id=DOMAIN,
            idempotency_key="idem/unknown-1",
            nonce="nonce/unknown-1",
            requested_at=T1,
        )
        result = engine.engine.process(command)
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_engine_duplicate_commands_converge(self) -> None:
        engine = build_engine()
        first = engine.declare_policy(spec=build_policy_spec())
        again = engine.declare_policy(spec=build_policy_spec())
        self.assertEqual(first, again)
        self.assertEqual(len(engine.journal), 1)

    def test_engine_kernel_rejection_surfaces_fail_closed(self) -> None:
        # Declaring the same policy identifier with DIFFERENT content is a
        # fresh command that the kernel rejects (creation precondition on
        # an object that already exists); the engine must surface that
        # kernel rejection — never fall through to processing a rejected
        # result.
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        payload = build_policy_spec().to_dict()
        payload["legal_basis_ref"] = "legal-basis/conflicting-declaration"
        conflicting = DataPolicySpec.from_dict(payload)
        with self.assertRaisesRegex(CoreValidationError, "rejected by the kernel"):
            engine.declare_policy(spec=conflicting)
        self.assertEqual(len(engine.journal), 1)

    def test_engine_version_conflicts_fail_closed(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        command = Command.build(
            command_id="command/data/conflict-1",
            command_type=data.POLICY_ACTIVATE_COMMAND,
            actor=OPERATOR,
            target_refs=("data-policy/retail-demo",),
            payload={"as_of": T1},
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(ExpectedVersion("data-policy/retail-demo", 9),),
            idempotency_key="idem/conflict-1",
            nonce="nonce/conflict-1",
            requested_at=T1,
        )
        result = engine.engine.process(command)
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_engine_state_digest_is_deterministic(self) -> None:
        first = build_engine()
        first.declare_policy(spec=build_policy_spec())
        first.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        second = build_engine()
        second.declare_policy(spec=build_policy_spec())
        second.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        self.assertEqual(first.state_digest(), second.state_digest())

    def test_engine_state_digest_moves_with_state(self) -> None:
        first = build_engine()
        first.declare_policy(spec=build_policy_spec())
        second = build_engine()
        second.declare_policy(spec=build_policy_spec())
        second.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        self.assertNotEqual(first.state_digest(), second.state_digest())

    def test_engine_resulting_objects_live_in_the_kernel_store(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        envelope = engine.store.get("data-policy/retail-demo")
        self.assertEqual(envelope.object_type, data.DATA_POLICY_OBJECT_TYPE)
        self.assertEqual(envelope.object_version, 1)

    def test_engine_operator_must_be_registered(self) -> None:
        registry = build_registry()
        with self.assertRaises(CoreValidationError):
            DataGovernanceEngine(
                environment_id=ENV,
                operator="trust/principal/ghost",
                trust_registry=registry,
                evidence_archive=build_evidence_archive(),
            )

    def test_engine_rejects_a_second_disclosure_on_a_closed_request(self) -> None:
        engine = build_engine()
        engine.declare_policy(spec=build_policy_spec())
        engine.activate_policy(policy_id="data-policy/retail-demo", as_of=T1)
        request = DisclosureRequest(
            requester=USER,
            subject_ref=SUBJECT,
            purpose=DisclosurePurpose.DISPUTE,
            requested_fields=("account_id",),
            requested_at=T2,
        )
        engine.request_disclosure(disclosure_id="data-disclosure/req-001", request=request)
        engine.disclose(
            disclosure_id="data-disclosure/req-001",
            disclosed_values={"account_id": "acct-001"},
            as_of=T2,
        )
        with self.assertRaises(CoreValidationError):
            engine.disclose(
                disclosure_id="data-disclosure/req-001",
                disclosed_values={"account_id": "acct-001"},
                as_of=T2,
            )


# ---------------------------------------------------------------------------
# 8. Dogfooding conformance.
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    def test_dogfooding_experiment_is_deterministic_and_passes(self) -> None:
        from src.data import dogfooding

        first = dogfooding.run_experiment()
        second = dogfooding.run_experiment()
        self.assertEqual(first, second)
        self.assertIn("DOGFOOD-022: PASS", first)
        self.assertIn("dispute case", first)
        self.assertIn("selective disclosure", first)
        # tamper rejection is part of the experiment
        self.assertIn("tampered", first)


if __name__ == "__main__":
    unittest.main()
