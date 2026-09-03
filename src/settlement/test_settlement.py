"""Settlement domain test suite (WORK-016).

Red-first-authored suite covering the static boundary, record
validation and tamper rejection, the posting model, the settlement /
finality / recourse lifecycles with every gate, the kernel binding
(idempotency, authorization, expected versions), snapshot / restore /
journal-rebuild transformation completeness, and dogfooding
conformance. The suite shares the domain's discipline: sealed
composites only, declared instants, no wall clock, no entropy.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import unittest

from src.clearing import ClearingEngine, Obligation
from src.clearing.contracts import ObligationState
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.evidence.contracts import EpistemicType
from src.execution.contracts import ObservationKind
from src.execution.effects import (
    EffectResultSpec,
    EffectOutcome,
    ExternalObservationSpec,
    make_observation_record,
    make_result_record,
)
from src.interoperability.status import CanonicalPaymentStatus
from src.core.envelope import Provenance
from src.value.amount import Amount

from .contracts import (
    COMMAND_EVENT_TYPES,
    FINALITY_COMMANDS,
    FINALITY_OBJECT_TYPE,
    REFUND_COMMANDS,
    RECOURSE_CASE_OBJECT_TYPE,
    REVERSAL_COMMANDS,
    SETTLEMENT_ALL_COMMANDS,
    SETTLEMENT_API_VERSION,
    SETTLEMENT_COMMANDS,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_PROTOCOL_VERSION,
    SETTLEMENT_SCHEMA_VERSION,
    SETTLEMENT_TRANSITIONS,
    OBJECT_TYPES,
    FinalityState,
    InstructionSourceKind,
    LegState,
    PostingKind,
    RecourseCaseState,
    RecourseKind,
    SettlementState,
    validate_command,
)
from .finality import (
    Finality,
    FinalityClaimBinding,
    make_finality_record,
)
from .postings import (
    ACCOUNT_KINDS,
    PostingEntry,
    account_name,
    verify_journal_balance,
)
from .recourse import (
    RecourseCase,
    RecourseEvidence,
    make_recourse_record,
)
from .records import (
    LegOutcome,
    Settlement,
    SettlementInstruction,
    SettlementSpec,
    SettlementWindow,
    make_settlement_record,
)
from .engine import SettlementEngine

ENVIRONMENT_ID = "env/test-016"
CLEARING_DOMAIN_ID = "clearing/test-016"
SETTLEMENT_DOMAIN_ID = "settlement/test-016"
EXECUTION_DOMAIN_ID = "execution/test-016"
ASSET = "GHS"
ALPHA = "psp/alpha"
BETA = "psp/beta"
GAMMA = "psp/gamma"

T0 = "2026-02-01T08:00:00Z"
T1 = "2026-02-01T09:00:00Z"
T2 = "2026-02-01T10:00:00Z"
T3 = "2026-02-01T11:00:00Z"
T4 = "2026-02-01T12:00:00Z"
T5 = "2026-02-01T13:00:00Z"
T6 = "2026-02-01T14:00:00Z"
T7 = "2026-02-01T15:00:00Z"
T8 = "2026-02-01T16:00:00Z"
SUBMIT_BY = "2026-02-01T18:00:00Z"
SETTLE_BY = "2026-02-02T08:00:00Z"


def _effect_result(index: int, payer: str, payee: str, minor: int) -> dict:
    request_id = f"plan/test-016/request/{index}"
    spec = EffectResultSpec(
        result_id=f"{request_id}/result",
        request_id=request_id,
        step_id=f"plan/test-016/step-{index}",
        effect_type="payment/submit",
        outcome=EffectOutcome.SUCCEEDED,
        native_reference=f"rail/ref-test-016-{index}",
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
            issuer="principal/sandbox-rail", source="execution/domain", recorded_at=T0
        ),
    )
    return record.to_dict()


def _status_observation(
    index: int,
    subject_ref: str,
    subject_digest: str,
    status: str,
    observed_at: str = T3,
) -> dict:
    spec = ExternalObservationSpec(
        observation_id=f"execution/test-016/observation-{index}",
        kind=ObservationKind.STATUS,
        subject_ref=subject_ref,
        adapter_id="adapter/sandbox-rail",
        epistemic=EpistemicType.OBSERVED,
        observed_at=observed_at,
        content={"native_code": f"rail/code-{index}", "canonical_status": status},
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN_ID,
        provenance=Provenance(
            issuer="principal/sandbox-rail", source="execution/domain", recorded_at=observed_at
        ),
    )
    return record.to_dict()


def _finality_observation(
    index: int,
    subject_ref: str,
    subject_digest: str,
    claim: str,
    observed_at: str = T4,
) -> dict:
    spec = ExternalObservationSpec(
        observation_id=f"execution/test-016/finality-{index}",
        kind=ObservationKind.FINALITY,
        subject_ref=subject_ref,
        adapter_id="adapter/sandbox-rail",
        epistemic=EpistemicType.OBSERVED,
        observed_at=observed_at,
        content={"claim": claim, "native_reference": f"rail/finality-{index}"},
        subject_request_digest=subject_digest,
    )
    record = make_observation_record(
        spec=spec,
        environment_id=ENVIRONMENT_ID,
        domain_id=EXECUTION_DOMAIN_ID,
        provenance=Provenance(
            issuer="principal/sandbox-rail", source="execution/domain", recorded_at=observed_at
        ),
    )
    return record.to_dict()


class _Corridor:
    """A small clearing+settlement corridor with three DUE obligations."""

    def __init__(self) -> None:
        self.clearing = ClearingEngine(
            environment_id=ENVIRONMENT_ID, domain_id=CLEARING_DOMAIN_ID
        )
        self.engine = SettlementEngine(
            environment_id=ENVIRONMENT_ID, domain_id=SETTLEMENT_DOMAIN_ID
        )
        self.clearing.create_cycle(
            command_id="clr-001",
            requested_at=T0,
            cycle_id="clearing/test-016/cycle-1",
            opens_at=T0,
            closes_at=T2,
        )
        self.obligations: list[str] = []
        for index, (payer, payee, minor) in enumerate(
            ((ALPHA, BETA, 120000), (BETA, ALPHA, 80000), (GAMMA, ALPHA, 50000)),
            start=1,
        ):
            self.clearing.recognize_obligation(
                command_id=f"clr-rec-{index}",
                requested_at=T1,
                cycle_id="clearing/test-016/cycle-1",
                effect_result=_effect_result(index, payer, payee, minor),
                due_from=T2,
                due_until=SETTLE_BY,
            )
        for record in self.clearing.records():
            if isinstance(record, Obligation):
                self.obligations.append(record.object_id)
        self.obligations.sort()
        for position, obligation_id in enumerate(self.obligations):
            self.clearing.validate_obligation(
                command_id=f"clr-val-{position}", requested_at=T2, obligation_id=obligation_id
            )
        for position, obligation_id in enumerate(self.obligations):
            self.clearing.mark_due_obligation(
                command_id=f"clr-due-{position}", requested_at=T2, obligation_id=obligation_id
            )

    def create_settlement(self, settlement_id: str = "settlement/test-016/batch-1") -> None:
        self.engine.create_settlement(
            command_id="stl-001",
            requested_at=T2,
            settlement_id=settlement_id,
            obligations=[
                self.clearing.obligation(obligation_id).to_dict()
                for obligation_id in self.obligations
            ],
            submit_by=SUBMIT_BY,
            settle_by=SETTLE_BY,
        )

    def drive_submitted(self, settlement_id: str = "settlement/test-016/batch-1") -> dict:
        """Create → authorize → submit and return per-leg digests."""
        self.create_settlement(settlement_id)
        self.engine.authorize_settlement(
            command_id="stl-002", requested_at=T2, settlement_id=settlement_id
        )
        self.engine.submit_settlement(
            command_id="stl-003", requested_at=T2, settlement_id=settlement_id
        )
        settlement = self.engine.settlement(settlement_id)
        return {
            instruction.instruction_id: instruction.instruction_digest()
            for instruction in settlement.spec.instructions
        }

    def leg_for(self, obligation_index: int, settlement_id: str = "settlement/test-016/batch-1") -> str:
        obligation_id = self.obligations[obligation_index]
        settlement = self.engine.settlement(settlement_id)
        for instruction in settlement.spec.instructions:
            if instruction.obligation_id == obligation_id:
                return instruction.instruction_id
        raise AssertionError("obligation not in settlement")


class StaticBoundaryTests(unittest.TestCase):
    def test_public_api_version_is_frozen(self) -> None:
        import src.settlement as settlement

        self.assertEqual(settlement.SETTLEMENT_API_VERSION, "v0.1")
        self.assertEqual(settlement.SETTLEMENT_PROTOCOL_VERSION, SETTLEMENT_PROTOCOL_VERSION)
        self.assertEqual(settlement.SETTLEMENT_SCHEMA_VERSION, 1)
        self.assertEqual(len(settlement.__all__), 83)

    def test_object_types_follow_registry_discipline(self) -> None:
        self.assertEqual(SETTLEMENT_OBJECT_TYPE, "payswap/settlement/v1")
        self.assertEqual(FINALITY_OBJECT_TYPE, "payswap/finality/v1")
        self.assertTrue(RECOURSE_CASE_OBJECT_TYPE.startswith("settlement/"))
        self.assertEqual(
            OBJECT_TYPES,
            (SETTLEMENT_OBJECT_TYPE, FINALITY_OBJECT_TYPE, RECOURSE_CASE_OBJECT_TYPE),
        )

    def test_command_families_match_the_frozen_architecture(self) -> None:
        self.assertEqual(
            sorted(SETTLEMENT_COMMANDS),
            [
                "settlement/authorize",
                "settlement/cancel",
                "settlement/create",
                "settlement/reconcile",
                "settlement/submit",
            ],
        )
        self.assertEqual(
            sorted(FINALITY_COMMANDS),
            [
                "finality/challenge",
                "finality/establish",
                "finality/revoke-claim",
                "finality/validate",
            ],
        )
        self.assertEqual(
            sorted(REFUND_COMMANDS),
            [
                "recourse/refund.approve",
                "recourse/refund.compile",
                "recourse/refund.execute",
                "recourse/refund.reject",
                "recourse/refund.request",
            ],
        )
        self.assertEqual(
            sorted(REVERSAL_COMMANDS),
            [
                "recourse/reversal.approve",
                "recourse/reversal.execute",
                "recourse/reversal.reject",
                "recourse/reversal.request",
            ],
        )
        self.assertEqual(len(SETTLEMENT_ALL_COMMANDS), 18)

    def test_every_event_type_uses_the_registered_settlement_namespace(self) -> None:
        from src.transition.registry import EVENT_NAMESPACES, validate_event_type

        self.assertIn("settlement", EVENT_NAMESPACES)
        for command_type, event_type in COMMAND_EVENT_TYPES.items():
            self.assertIn(command_type, SETTLEMENT_ALL_COMMANDS)
            validate_event_type(f"event for {command_type}", event_type)
            self.assertTrue(event_type.startswith("settlement/"))
        self.assertEqual(len(COMMAND_EVENT_TYPES), 18)

    def test_transitions_table_covers_every_command(self) -> None:
        self.assertEqual(set(SETTLEMENT_TRANSITIONS), set(SETTLEMENT_ALL_COMMANDS))
        for command_type, sources in SETTLEMENT_TRANSITIONS.items():
            self.assertIsInstance(sources, frozenset)
            if command_type.startswith("settlement/"):
                enum_type = SettlementState
            elif command_type.startswith("finality/"):
                enum_type = FinalityState
            else:
                enum_type = RecourseCaseState
            for source in sources:
                self.assertIsInstance(source, enum_type)
        # creation commands carry no source states
        self.assertEqual(SETTLEMENT_TRANSITIONS["settlement/create"], frozenset())
        self.assertEqual(SETTLEMENT_TRANSITIONS["recourse/refund.request"], frozenset())
        self.assertEqual(SETTLEMENT_TRANSITIONS["recourse/reversal.request"], frozenset())

    def test_validate_command_rejects_foreign_commands(self) -> None:
        self.assertEqual(validate_command("settlement/create"), "settlement/create")
        with self.assertRaises(CoreValidationError):
            validate_command("clearing/cycle.create")
        with self.assertRaises(CoreValidationError):
            validate_command("settlement/settle")

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        forbidden_calls = {
            "datetime.now",
            "datetime.today",
            "datetime.utcnow",
            "date.today",
            "time.time",
            "time.monotonic",
            "time.perf_counter",
            "random.random",
            "random.randint",
            "secrets.token",
            "uuid.uuid",
        }
        package_root = pathlib.Path(__file__).parent
        for source_path in sorted(package_root.glob("*.py")):
            tree = ast.parse(source_path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    function = node.func
                    rendered = []
                    while isinstance(function, ast.Attribute):
                        rendered.append(function.attr)
                        function = function.value
                    if isinstance(function, ast.Name):
                        rendered.append(function.id)
                    rendered.reverse()
                    dotted = ".".join(rendered)
                    self.assertNotIn(
                        dotted,
                        forbidden_calls,
                        msg=f"{source_path.name}:{node.lineno} calls {dotted}",
                    )

    def test_import_closure_is_clean_in_isolated_process(self) -> None:
        """The transitive import closure equals exactly merged mainline roots.

        The probe runs in an isolated subprocess (WORK-020 precedent) so
        the assertion is order-robust: sibling suites loaded earlier in
        a combined run never pollute the measured closure. Settlement
        reaches clearing (WORK-015), execution (WORK-014), evidence
        (WORK-018), the value amount (WORK-005), the canonical payment
        status vocabulary (WORK-007) and the transition kernel — and
        exactly their transitive roots, nothing else.
        """
        probe = (
            "import sys, json; import src.settlement; "
            "print(json.dumps(sorted("
            "name for name in sys.modules "
            "if name.startswith('src.') and name.count('.') == 1)))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(pathlib.Path(__file__).resolve().parents[2]),
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        loaded = set(json.loads(completed.stdout))
        expected = {
            "src.settlement",
            "src.clearing",
            "src.core",
            "src.transition",
            "src.value",
            "src.money",
            "src.reservation",
            "src.capability",
            "src.evidence",
            "src.execution",
            "src.safety",
            "src.simulation",
            "src.interoperability",
            "src.trust",
        }
        self.assertEqual(loaded, expected, f"unexpected imports: {loaded ^ expected}")

    def test_no_sibling_surface_is_imported(self) -> None:
        package_root = pathlib.Path(__file__).parent
        for source_path in sorted(package_root.glob("*.py")):
            if source_path.name in {"test_settlement.py", "dogfooding.py"}:
                continue
            tree = ast.parse(source_path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module.startswith("src.compiler")
                        or node.module.startswith("src.extensions")
                        or node.module.startswith("src.agents")
                        or node.module.startswith("src.data")
                        or node.module.startswith("src.safety"),
                        msg=f"{source_path.name} imports {node.module}",
                    )


class RecordValidationTests(unittest.TestCase):
    def test_window_requires_ordered_utc_instants(self) -> None:
        window = SettlementWindow(submit_by=T1, settle_by=T2)
        self.assertEqual(window.to_dict(), {"submit_by": T1, "settle_by": T2})
        with self.assertRaises(CoreValidationError):
            SettlementWindow(submit_by=T2, settle_by=T1)
        with self.assertRaises(CoreValidationError):
            SettlementWindow(submit_by=T2, settle_by=T2)
        with self.assertRaises(CoreValidationError):
            SettlementWindow(submit_by="2026-02-01T09:00:00+00:00", settle_by=T2)

    def test_instruction_requires_exactly_one_source_binding(self) -> None:
        amount = Amount(value=1000, scale=2, asset=ASSET)
        instruction = SettlementInstruction(
            instruction_id="s/leg-1",
            source_kind="OBLIGATION",
            obligation_id="o/1",
            obligation_version=3,
            obligation_digest="a" * 64,
            refund_case_id=None,
            source_instruction_id=None,
            obligor=ALPHA,
            obligee=BETA,
            amount=amount,
        )
        self.assertIsNotNone(instruction.instruction_digest())
        with self.assertRaises(CoreValidationError):
            SettlementInstruction(
                instruction_id="s/leg-1",
                source_kind="OBLIGATION",
                obligation_id=None,
                obligation_version=None,
                obligation_digest=None,
                refund_case_id=None,
                source_instruction_id=None,
                obligor=ALPHA,
                obligee=BETA,
                amount=amount,
            )
        with self.assertRaises(CoreValidationError):
            SettlementInstruction(
                instruction_id="s/leg-1",
                source_kind="OBLIGATION",
                obligation_id="o/1",
                obligation_version=3,
                obligation_digest="a" * 64,
                refund_case_id="case/1",
                source_instruction_id=None,
                obligor=ALPHA,
                obligee=BETA,
                amount=amount,
            )
        with self.assertRaises(CoreValidationError):
            SettlementInstruction(
                instruction_id="s/leg-1",
                source_kind="REFUND_LEG",
                obligation_id=None,
                obligation_version=None,
                obligation_digest=None,
                refund_case_id="case/1",
                source_instruction_id=None,
                obligor=ALPHA,
                obligee=BETA,
                amount=amount,
            )

    def test_instruction_rejects_self_payments_and_non_positive_amounts(self) -> None:
        with self.assertRaises(CoreValidationError):
            SettlementInstruction(
                instruction_id="s/leg-1",
                source_kind="OBLIGATION",
                obligation_id="o/1",
                obligation_version=1,
                obligation_digest="a" * 64,
                refund_case_id=None,
                source_instruction_id=None,
                obligor=ALPHA,
                obligee=ALPHA,
                amount=Amount(value=1000, scale=2, asset=ASSET),
            )
        with self.assertRaises(CoreValidationError):
            SettlementInstruction(
                instruction_id="s/leg-1",
                source_kind="OBLIGATION",
                obligation_id="o/1",
                obligation_version=1,
                obligation_digest="a" * 64,
                refund_case_id=None,
                source_instruction_id=None,
                obligor=ALPHA,
                obligee=BETA,
                amount=Amount(value=0, scale=2, asset=ASSET),
            )

    def test_leg_outcome_state_facts_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            LegOutcome(
                instruction_id="s/leg-1",
                state="SETTLED",
                native_reference=None,
                observation_digest=None,
                observed_at=None,
                suspense=False,
            )
        with self.assertRaises(CoreValidationError):
            LegOutcome(
                instruction_id="s/leg-1",
                state="UNKNOWN",
                native_reference=None,
                observation_digest=None,
                observed_at=None,
                suspense=False,
            )
        with self.assertRaises(CoreValidationError):
            LegOutcome(
                instruction_id="s/leg-1",
                state="SETTLED",
                native_reference="rail/x",
                observation_digest="b" * 64,
                observed_at=T1,
                suspense=True,
            )
        with self.assertRaises(CoreValidationError):
            LegOutcome(
                instruction_id="s/leg-1",
                state="SUBMITTED",
                native_reference="rail/x",
                observation_digest="b" * 64,
                observed_at=T1,
                suspense=False,
            )
        with self.assertRaises(CoreValidationError):
            LegOutcome(
                instruction_id="s/leg-1",
                state="PENDING",
                native_reference=None,
                observation_digest=None,
                observed_at=None,
                suspense=True,
            )

    def test_settlement_spec_rejects_duplicates_and_orphan_outcomes(self) -> None:
        instruction = SettlementInstruction(
            instruction_id="s/leg-1",
            source_kind="OBLIGATION",
            obligation_id="o/1",
            obligation_version=1,
            obligation_digest="a" * 64,
            refund_case_id=None,
            source_instruction_id=None,
            obligor=ALPHA,
            obligee=BETA,
            amount=Amount(value=1000, scale=2, asset=ASSET),
        )
        with self.assertRaises(CoreValidationError):
            SettlementSpec(
                settlement_id="s/1",
                linked_ref=None,
                window=SettlementWindow(submit_by=T1, settle_by=T2),
                instructions=(instruction, instruction),
                instructions_digest="c" * 64,
                submitted_at=None,
                leg_outcomes=(),
                reconciliations=(),
                cancellation=None,
            )
        with self.assertRaises(CoreValidationError):
            SettlementSpec(
                settlement_id="s/1",
                linked_ref=None,
                window=SettlementWindow(submit_by=T1, settle_by=T2),
                instructions=(instruction,),
                instructions_digest="c" * 64,
                submitted_at=None,
                leg_outcomes=(
                    LegOutcome(
                        instruction_id="s/leg-other",
                        state="SETTLED",
                        native_reference="rail/x",
                        observation_digest="b" * 64,
                        observed_at=T1,
                        suspense=False,
                    ),
                ),
                reconciliations=(),
                cancellation=None,
            )

    def test_settlement_state_facts_fail_closed(self) -> None:
        instruction = SettlementInstruction(
            instruction_id="s/leg-1",
            source_kind="OBLIGATION",
            obligation_id="o/1",
            obligation_version=1,
            obligation_digest="a" * 64,
            refund_case_id=None,
            source_instruction_id=None,
            obligor=ALPHA,
            obligee=BETA,
            amount=Amount(value=1000, scale=2, asset=ASSET),
        )
        record = make_settlement_record(
            settlement_id="s/1",
            environment_id=ENVIRONMENT_ID,
            domain_id=SETTLEMENT_DOMAIN_ID,
            provenance=Provenance(issuer="p/test", source="settlement/domain", recorded_at=T1),
            window=SettlementWindow(submit_by=T1, settle_by=T2),
            instructions=(instruction,),
        )
        self.assertEqual(record.state, SettlementState.DRAFT)
        composite = record.to_dict()
        self.assertEqual(Settlement.from_dict(composite).to_dict(), composite)
        self.assertEqual(Settlement.from_json(record.to_json()).to_dict(), composite)
        # DRAFT with leg outcomes is incoherent
        bad = dict(composite)
        payload = dict(composite["payload"])
        payload["leg_outcomes"] = [
            LegOutcome(
                instruction_id="s/leg-1",
                state="SETTLED",
                native_reference="rail/x",
                observation_digest="b" * 64,
                observed_at=T1,
                suspense=False,
            ).to_dict()
        ]
        payload["submitted_at"] = T1
        bad["payload"] = payload
        bad["integrity_hash"] = canonical_sha256(
            {"envelope": bad["envelope"], "payload": payload}
        )
        with self.assertRaises(CoreValidationError):
            Settlement.from_dict(bad)

    def test_settlement_tamper_rejection(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        composite = corridor.engine.settlement("settlement/test-016/batch-1").to_dict()
        tampered = dict(composite)
        payload = dict(composite["payload"])
        payload["instructions_digest"] = "d" * 64
        tampered["payload"] = payload
        with self.assertRaises(CoreValidationError):
            Settlement.from_dict(tampered)

    def test_finality_record_round_trip_and_state_facts(self) -> None:
        binding = FinalityClaimBinding(
            instruction_id="s/leg-1",
            native_reference="rail/finality-1",
            claim="FINAL",
            observation_id="execution/x-1",
            observation_digest="b" * 64,
            observed_at=T1,
        )
        record = make_finality_record(
            finality_id="f/1",
            settlement_id="s/1",
            settlement_digest="c" * 64,
            claims=(binding,),
            environment_id=ENVIRONMENT_ID,
            domain_id=SETTLEMENT_DOMAIN_ID,
            provenance=Provenance(issuer="p/test", source="settlement/domain", recorded_at=T1),
        )
        self.assertEqual(record.state, FinalityState.PENDING)
        composite = record.to_dict()
        self.assertEqual(Finality.from_dict(composite).to_dict(), composite)
        self.assertEqual(Finality.from_json(record.to_json()).to_dict(), composite)

    def test_recourse_evidence_must_be_observed(self) -> None:
        with self.assertRaises(CoreValidationError):
            RecourseEvidence(
                evidence_ref="e/1",
                evidence_digest="b" * 64,
                epistemic_type="SIMULATED",
                reason="simulated justification",
            )

    def test_recourse_case_round_trip(self) -> None:
        case = make_recourse_record(
            case_id="case/1",
            kind="REVERSAL",
            settlement_id="s/1",
            instruction_ids=("s/leg-1",),
            evidence=RecourseEvidence(
                evidence_ref="f/1",
                evidence_digest="b" * 64,
                epistemic_type="OBSERVED",
                reason="finality withdrawn",
            ),
            environment_id=ENVIRONMENT_ID,
            domain_id=SETTLEMENT_DOMAIN_ID,
            provenance=Provenance(issuer="p/test", source="settlement/domain", recorded_at=T1),
        )
        self.assertEqual(case.state, RecourseCaseState.REQUESTED)
        composite = case.to_dict()
        self.assertEqual(RecourseCase.from_dict(composite).to_dict(), composite)

    def test_posting_entry_enforces_double_entry(self) -> None:
        with self.assertRaises(CoreValidationError):
            PostingEntry(
                entry_id="posting/e/1",
                event_id="cmd-1",
                event_type="settlement/settlement-reconciled",
                kind="DISCHARGE",
                asset=ASSET,
                scale=2,
                debit_account=account_name("obligation-liability", ALPHA),
                debit_value=100,
                credit_account=account_name("settled-claim", BETA),
                credit_value=101,
                instruction_ref="s/leg-1",
                posted_at=T1,
            )
        with self.assertRaises(CoreValidationError):
            PostingEntry(
                entry_id="posting/e/1",
                event_id="cmd-1",
                event_type="settlement/settlement-reconciled",
                kind="DISCHARGE",
                asset=ASSET,
                scale=2,
                debit_account=account_name("obligation-liability", ALPHA),
                debit_value=100,
                credit_account=account_name("obligation-liability", ALPHA),
                credit_value=100,
                instruction_ref="s/leg-1",
                posted_at=T1,
            )
        with self.assertRaises(CoreValidationError):
            account_name("unknown-kind", ALPHA)
        self.assertEqual(len(ACCOUNT_KINDS), 6)


class SettlementLifecycleTests(unittest.TestCase):
    def test_create_derives_facts_from_sealed_obligations(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        self.assertEqual(settlement.state, SettlementState.DRAFT)
        self.assertEqual(len(settlement.spec.instructions), 3)
        for instruction, obligation_id in zip(
            sorted(settlement.spec.instructions, key=lambda i: i.obligation_id or ""),
            corridor.obligations,
        ):
            obligation = corridor.clearing.obligation(obligation_id)
            self.assertEqual(instruction.obligor, obligation.spec.obligor)
            self.assertEqual(instruction.obligee, obligation.spec.obligee)
            self.assertEqual(instruction.amount, obligation.spec.amount)
            self.assertEqual(instruction.obligation_digest, obligation.integrity_hash)

    def test_create_rejects_non_due_obligations(self) -> None:
        corridor = _Corridor()
        # drive the obligation to RESOLVED through the clearing engine
        corridor.clearing.resolve_obligation(
            command_id="clr-res-1",
            requested_at=T2,
            obligation_id=corridor.obligations[0],
            evidence_ref="e/elsewhere",
            evidence_digest="b" * 64,
            reason="resolved elsewhere",
        )
        composite = corridor.clearing.obligation(corridor.obligations[0]).to_dict()
        self.assertEqual(ObligationState(composite["envelope"]["state"]), ObligationState.RESOLVED)
        with self.assertRaises(CoreValidationError):
            corridor.engine.create_settlement(
                command_id="stl-x",
                requested_at=T2,
                settlement_id="settlement/test-016/batch-x",
                obligations=[composite],
                submit_by=SUBMIT_BY,
                settle_by=SETTLE_BY,
            )

    def test_create_rejects_duplicate_and_tampered_obligations(self) -> None:
        corridor = _Corridor()
        composite = corridor.clearing.obligation(corridor.obligations[0]).to_dict()
        with self.assertRaises(CoreValidationError):
            corridor.engine.create_settlement(
                command_id="stl-x",
                requested_at=T2,
                settlement_id="settlement/test-016/batch-x",
                obligations=[composite, composite],
                submit_by=SUBMIT_BY,
                settle_by=SETTLE_BY,
            )
        tampered = dict(composite)
        tampered["integrity_hash"] = "e" * 64
        with self.assertRaises(CoreValidationError):
            corridor.engine.create_settlement(
                command_id="stl-y",
                requested_at=T2,
                settlement_id="settlement/test-016/batch-y",
                obligations=[tampered],
                submit_by=SUBMIT_BY,
                settle_by=SETTLE_BY,
            )

    def test_obligation_exclusivity_across_live_settlements(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement("settlement/test-016/batch-a")
        with self.assertRaises(CoreValidationError):
            corridor.engine.create_settlement(
                command_id="stl-b",
                requested_at=T2,
                settlement_id="settlement/test-016/batch-b",
                obligations=[
                    corridor.clearing.obligation(obligation_id).to_dict()
                    for obligation_id in corridor.obligations
                ],
                submit_by=SUBMIT_BY,
                settle_by=SETTLE_BY,
            )

    def test_authorize_submit_cancel_flow(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        corridor.engine.authorize_settlement(
            command_id="stl-002", requested_at=T2, settlement_id="settlement/test-016/batch-1"
        )
        self.assertEqual(
            corridor.engine.settlement("settlement/test-016/batch-1").state,
            SettlementState.AUTHORIZED,
        )
        corridor.engine.cancel_settlement(
            command_id="stl-003",
            requested_at=T2,
            settlement_id="settlement/test-016/batch-1",
            reason="operator stand-down",
        )
        self.assertEqual(
            corridor.engine.settlement("settlement/test-016/batch-1").state,
            SettlementState.CANCELLED,
        )

    def test_submit_outside_window_fails_closed(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        corridor.engine.authorize_settlement(
            command_id="stl-002", requested_at=T2, settlement_id="settlement/test-016/batch-1"
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.submit_settlement(
                command_id="stl-003",
                requested_at="2026-02-02T00:00:00Z",
                settlement_id="settlement/test-016/batch-1",
            )

    def test_reconcile_folds_status_observations_and_completes(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, leg, digests[leg], "SETTLED") for leg in legs
            ],
        )
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        self.assertEqual(settlement.state, SettlementState.COMPLETED)
        postings = corridor.engine.postings()
        self.assertEqual(len(postings), 3)
        self.assertTrue(all(entry.kind == PostingKind.DISCHARGE.value for entry in postings))
        totals = verify_journal_balance(postings)
        self.assertEqual(totals, {ASSET: 250000})

    def test_reconcile_failure_path_never_discharges(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, leg, digests[leg], "FAILED") for leg in legs
            ],
        )
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        self.assertEqual(settlement.state, SettlementState.FAILED)
        self.assertEqual(corridor.engine.postings(), ())

    def test_reconcile_unknown_posts_suspense_once_and_resolves_late(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "UNKNOWN"),
                _status_observation(2, legs[0], digests[legs[0]], "UNKNOWN"),
            ],
        )
        postings = corridor.engine.postings()
        self.assertEqual(len([e for e in postings if e.kind == PostingKind.SUSPENSE.value]), 1)
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        self.assertEqual(settlement.state, SettlementState.SUBMITTED)
        corridor.engine.reconcile_settlement(
            command_id="stl-005",
            requested_at=T4,
            settlement_id="settlement/test-016/batch-1",
            as_of=T4,
            observations=[
                _status_observation(3, legs[1], digests[legs[1]], "SETTLED"),
                _status_observation(4, legs[0], digests[legs[0]], "SETTLED"),
                _status_observation(5, legs[2], digests[legs[2]], "SETTLED"),
            ],
        )
        postings = corridor.engine.postings()
        kinds = [entry.kind for entry in postings]
        self.assertIn(PostingKind.SUSPENSE_RELEASE.value, kinds)
        self.assertEqual(kinds.count(PostingKind.DISCHARGE.value), 3)
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        self.assertEqual(settlement.state, SettlementState.COMPLETED)

    def test_reconcile_ages_stale_legs_into_suspense(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at="2026-02-03T08:00:00Z",
            settlement_id="settlement/test-016/batch-1",
            as_of="2026-02-03T08:00:00Z",
            observations=[],
        )
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        outcomes = {o.state for o in settlement.spec.leg_outcomes}
        self.assertEqual(outcomes, {LegState.UNKNOWN.value})
        self.assertEqual(len(corridor.engine.postings()), 3)
        self.assertEqual(settlement.state, SettlementState.SUBMITTED)

    def test_reconcile_in_flight_status_is_recorded_but_resolves_nothing(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        leg = sorted(digests)[0]
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, leg, digests[leg], "ACKNOWLEDGED"),
            ],
        )
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        outcome = next(o for o in settlement.spec.leg_outcomes if o.instruction_id == leg)
        self.assertEqual(outcome.state, LegState.SUBMITTED.value)
        self.assertEqual(corridor.engine.postings(), ())
        self.assertTrue(settlement.spec.reconciliations[-1].observation_digests)

    def test_reconcile_rejects_spliced_digest_on_a_live_leg(self) -> None:
        # A SUBMITTED (non-terminal) leg with an observation whose
        # subject digest belongs to a different leg fails closed: the
        # digest binding is load-bearing on live legs exactly (a rail
        # observation cannot be spliced onto another instruction).
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        with self.assertRaises(CoreValidationError):
            corridor.engine.reconcile_settlement(
                command_id="stl-x",
                requested_at=T3,
                settlement_id="settlement/test-016/batch-1",
                as_of=T3,
                observations=[
                    _status_observation(1, legs[0], digests[legs[1]], "SETTLED"),
                ],
            )

    def test_reconcile_rejects_terminal_reobservation_and_foreign_subjects(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "SETTLED"),
            ],
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.reconcile_settlement(
                command_id="stl-005",
                requested_at=T4,
                settlement_id="settlement/test-016/batch-1",
                as_of=T4,
                observations=[
                    _status_observation(2, legs[0], digests[legs[0]], "FAILED"),
                ],
            )
        with self.assertRaises(CoreValidationError):
            corridor.engine.reconcile_settlement(
                command_id="stl-006",
                requested_at=T4,
                settlement_id="settlement/test-016/batch-1",
                as_of=T4,
                observations=[
                    _status_observation(
                        3, legs[0], digests[legs[1]], "SETTLED"
                    ),
                ],
            )
        query_like = _status_observation(4, legs[1], digests[legs[1]], "SETTLED")
        # a FINALITY-kind observation cannot fold a leg
        finality_like = _finality_observation(5, legs[1], digests[legs[1]], "FINAL")
        with self.assertRaises(CoreValidationError):
            corridor.engine.reconcile_settlement(
                command_id="stl-007",
                requested_at=T4,
                settlement_id="settlement/test-016/batch-1",
                as_of=T4,
                observations=[finality_like],
            )
        _ = query_like

    def test_discharge_evidence_binds_settled_legs_only(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "SETTLED"),
                _status_observation(2, legs[1], digests[legs[1]], "SETTLED"),
            ],
        )
        evidence = corridor.engine.discharge_evidence("settlement/test-016/batch-1")
        self.assertEqual(len(evidence), 2)
        for binding in evidence:
            self.assertEqual(len(binding["evidence_digest"]), 64)
            self.assertTrue(binding["evidence_ref"].startswith("settlement/"))
            self.assertTrue(binding["obligation_id"].startswith("plan/"))


class FinalityLifecycleTests(unittest.TestCase):
    def _completed(self) -> _Corridor:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(index, leg, digests[leg], "SETTLED")
                for index, leg in enumerate(legs, start=1)
            ],
        )
        corridor._finality_digests = digests  # type: ignore[attr-defined]
        corridor._finality_legs = legs  # type: ignore[attr-defined]
        return corridor

    def test_validate_establish_lifecycle(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        corridor.engine.validate_finality_claim(
            command_id="fin-001",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(1, legs[0], digests[legs[0]], "FINAL"),
        )
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        self.assertEqual(certificate.state, FinalityState.PENDING)
        with self.assertRaises(CoreValidationError):
            corridor.engine.establish_finality(
                command_id="fin-002",
                requested_at=T4,
                finality_id="settlement/test-016/finality-1",
            )
        corridor.engine.validate_finality_claim(
            command_id="fin-003",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(2, legs[1], digests[legs[1]], "SETTLED"),
        )
        corridor.engine.validate_finality_claim(
            command_id="fin-004",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(3, legs[2], digests[legs[2]], "FINAL"),
        )
        corridor.engine.establish_finality(
            command_id="fin-005",
            requested_at=T5,
            finality_id="settlement/test-016/finality-1",
        )
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        self.assertEqual(certificate.state, FinalityState.ESTABLISHED)
        self.assertEqual(len(certificate.spec.claims), 3)

    def test_payment_status_never_validates_into_finality(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        with self.assertRaises(CoreValidationError):
            corridor.engine.validate_finality_claim(
                command_id="fin-x",
                requested_at=T4,
                finality_id="settlement/test-016/finality-x",
                settlement_id="settlement/test-016/batch-1",
                observation=_status_observation(9, legs[0], digests[legs[0]], "SETTLED"),
            )
        self.assertIsNone(
            corridor.engine.finality_for_settlement("settlement/test-016/batch-1")
        )

    def test_revoked_claims_and_unsettled_legs_never_validate(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        with self.assertRaises(CoreValidationError):
            corridor.engine.validate_finality_claim(
                command_id="fin-x",
                requested_at=T4,
                finality_id="settlement/test-016/finality-x",
                settlement_id="settlement/test-016/batch-1",
                observation=_finality_observation(9, legs[0], digests[legs[0]], "REVOKED"),
            )

    def test_establishment_requires_terminal_settlement_and_coverage(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        corridor.engine.validate_finality_claim(
            command_id="fin-001",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(1, legs[0], digests[legs[0]], "FINAL"),
        )
        # coverage incomplete (one settled leg unclaimed)
        with self.assertRaises(CoreValidationError):
            corridor.engine.establish_finality(
                command_id="fin-002",
                requested_at=T4,
                finality_id="settlement/test-016/finality-1",
            )

    def test_establishment_rejects_non_terminal_settlement(self) -> None:
        # an in-flight settlement (one leg still unknown) can never
        # establish finality even with full claim coverage of the
        # settled legs (constitution invariant 11).
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "SETTLED"),
                _status_observation(2, legs[1], digests[legs[1]], "SETTLED"),
                _status_observation(3, legs[2], digests[legs[2]], "UNKNOWN"),
            ],
        )
        self.assertEqual(
            corridor.engine.settlement("settlement/test-016/batch-1").state,
            SettlementState.SUBMITTED,
        )
        corridor.engine.validate_finality_claim(
            command_id="fin-001",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(1, legs[0], digests[legs[0]], "FINAL"),
        )
        corridor.engine.validate_finality_claim(
            command_id="fin-002",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(2, legs[1], digests[legs[1]], "FINAL"),
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.establish_finality(
                command_id="fin-003",
                requested_at=T4,
                finality_id="settlement/test-016/finality-1",
            )

    def test_one_certificate_per_settlement(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        corridor.engine.validate_finality_claim(
            command_id="fin-001",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(1, legs[0], digests[legs[0]], "FINAL"),
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.validate_finality_claim(
                command_id="fin-002",
                requested_at=T4,
                finality_id="settlement/test-016/finality-2",
                settlement_id="settlement/test-016/batch-1",
                observation=_finality_observation(2, legs[1], digests[legs[1]], "FINAL"),
            )

    def test_challenge_and_revocation_paths(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        for index, leg in enumerate(legs, start=1):
            corridor.engine.validate_finality_claim(
                command_id=f"fin-val-{index}",
                requested_at=T4,
                finality_id="settlement/test-016/finality-1",
                settlement_id="settlement/test-016/batch-1",
                observation=_finality_observation(index, leg, digests[leg], "FINAL"),
            )
        corridor.engine.establish_finality(
            command_id="fin-est", requested_at=T5, finality_id="settlement/test-016/finality-1"
        )
        corridor.engine.challenge_finality(
            command_id="fin-ch",
            requested_at=T6,
            finality_id="settlement/test-016/finality-1",
            evidence_ref="e/challenge",
            evidence_digest="b" * 64,
            reason="rail dispute opened",
        )
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        self.assertEqual(certificate.state, FinalityState.CHALLENGED)
        with self.assertRaises(CoreValidationError):
            corridor.engine.challenge_finality(
                command_id="fin-ch2",
                requested_at=T7,
                finality_id="settlement/test-016/finality-1",
                evidence_ref="e/challenge",
                evidence_digest="b" * 64,
                reason="double challenge",
            )
        corridor.engine.revoke_finality_claim(
            command_id="fin-rk",
            requested_at=T7,
            finality_id="settlement/test-016/finality-1",
            evidence_ref="e/revoked-claim",
            evidence_digest="c" * 64,
            reason="rail withdrew the claim",
        )
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        self.assertEqual(certificate.state, FinalityState.REVOKED)
        with self.assertRaises(CoreValidationError):
            corridor.engine.establish_finality(
                command_id="fin-est2",
                requested_at=T8,
                finality_id="settlement/test-016/finality-1",
            )

    def test_revocation_from_pending_is_direct(self) -> None:
        corridor = self._completed()
        digests = corridor._finality_digests  # type: ignore[attr-defined]
        legs = corridor._finality_legs  # type: ignore[attr-defined]
        corridor.engine.validate_finality_claim(
            command_id="fin-001",
            requested_at=T4,
            finality_id="settlement/test-016/finality-1",
            settlement_id="settlement/test-016/batch-1",
            observation=_finality_observation(1, legs[0], digests[legs[0]], "FINAL"),
        )
        corridor.engine.revoke_finality_claim(
            command_id="fin-rk",
            requested_at=T5,
            finality_id="settlement/test-016/finality-1",
            evidence_ref="e/revoked-claim",
            evidence_digest="c" * 64,
            reason="claim withdrawn pre-establishment",
        )
        self.assertEqual(
            corridor.engine.finality("settlement/test-016/finality-1").state,
            FinalityState.REVOKED,
        )


class RecourseLifecycleTests(unittest.TestCase):
    def _revoked_certificate(self) -> _Corridor:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(index, leg, digests[leg], "SETTLED")
                for index, leg in enumerate(legs, start=1)
            ],
        )
        for index, leg in enumerate(legs, start=1):
            corridor.engine.validate_finality_claim(
                command_id=f"fin-val-{index}",
                requested_at=T4,
                finality_id="settlement/test-016/finality-1",
                settlement_id="settlement/test-016/batch-1",
                observation=_finality_observation(index, leg, digests[leg], "FINAL"),
            )
        corridor.engine.establish_finality(
            command_id="fin-est", requested_at=T5, finality_id="settlement/test-016/finality-1"
        )
        corridor.engine.revoke_finality_claim(
            command_id="fin-rk",
            requested_at=T6,
            finality_id="settlement/test-016/finality-1",
            evidence_ref="e/revoked-claim",
            evidence_digest="c" * 64,
            reason="rail withdrew the finality claim",
        )
        corridor._recourse_legs = legs  # type: ignore[attr-defined]
        return corridor

    def test_reversal_requires_withdrawn_certificate_digest_bound(self) -> None:
        corridor = self._revoked_certificate()
        legs = corridor._recourse_legs  # type: ignore[attr-defined]
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        with self.assertRaises(CoreValidationError):
            corridor.engine.request_reversal(
                command_id="rev-x",
                requested_at=T7,
                case_id="settlement/test-016/reversal-x",
                settlement_id="settlement/test-016/batch-1",
                instruction_ids=[legs[0]],
                evidence_ref="e/wrong-ref",
                evidence_digest=certificate.integrity_hash,
                epistemic_type="OBSERVED",
                reason="not digest-bound to the certificate",
            )
        with self.assertRaises(CoreValidationError):
            corridor.engine.request_reversal(
                command_id="rev-y",
                requested_at=T7,
                case_id="settlement/test-016/reversal-y",
                settlement_id="settlement/test-016/batch-1",
                instruction_ids=[legs[0]],
                evidence_ref="settlement/test-016/finality-1",
                evidence_digest="d" * 64,
                epistemic_type="OBSERVED",
                reason="wrong digest",
            )
        with self.assertRaises(CoreValidationError):
            corridor.engine.request_reversal(
                command_id="rev-z",
                requested_at=T7,
                case_id="settlement/test-016/reversal-z",
                settlement_id="settlement/test-016/batch-1",
                instruction_ids=[legs[0]],
                evidence_ref="settlement/test-016/finality-1",
                evidence_digest=certificate.integrity_hash,
                epistemic_type="PREDICTED",
                reason="non-observed justification",
            )

    def test_reversal_executes_exact_compensation_postings(self) -> None:
        corridor = self._revoked_certificate()
        legs = corridor._recourse_legs  # type: ignore[attr-defined]
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        before = list(corridor.engine.postings())
        discharge = next(
            e for e in before if e.instruction_ref == legs[0] and e.kind == "DISCHARGE"
        )
        corridor.engine.request_reversal(
            command_id="rev-001",
            requested_at=T7,
            case_id="settlement/test-016/reversal-1",
            settlement_id="settlement/test-016/batch-1",
            instruction_ids=[legs[0]],
            evidence_ref="settlement/test-016/finality-1",
            evidence_digest=certificate.integrity_hash,
            epistemic_type="OBSERVED",
            reason="compensate the withdrawn discharge",
        )
        corridor.engine.approve_reversal(
            command_id="rev-002", requested_at=T7, case_id="settlement/test-016/reversal-1"
        )
        corridor.engine.execute_reversal(
            command_id="rev-003", requested_at=T7, case_id="settlement/test-016/reversal-1"
        )
        case = corridor.engine.recourse_case("settlement/test-016/reversal-1")
        self.assertEqual(case.state, RecourseCaseState.EXECUTED)
        postings = corridor.engine.postings()
        reversal = [e for e in postings if e.kind == PostingKind.REVERSAL.value]
        self.assertEqual(len(reversal), 1)
        self.assertEqual(reversal[0].debit_value, discharge.credit_value)
        self.assertEqual(reversal[0].debit_account, discharge.credit_account)
        self.assertEqual(reversal[0].instruction_ref, legs[0])
        # the original discharge posting is untouched
        self.assertIn(discharge, postings)
        self.assertEqual(len(postings), len(before) + 1)
        self.assertTrue(case.spec.execution.posting_refs)

    def test_refund_compiles_executes_through_linked_settlement(self) -> None:
        corridor = self._revoked_certificate()
        legs = corridor._recourse_legs  # type: ignore[attr-defined]
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        original = next(
            i for i in settlement.spec.instructions if i.instruction_id == legs[0]
        )
        corridor.engine.request_refund(
            command_id="ref-001",
            requested_at=T7,
            case_id="settlement/test-016/refund-1",
            settlement_id="settlement/test-016/batch-1",
            instruction_ids=[legs[0]],
            evidence_ref="e/refund-request",
            evidence_digest=canonical_sha256({"refund": "customer return"}),
            epistemic_type="OBSERVED",
            reason="customer requested return",
        )
        corridor.engine.approve_refund(
            command_id="ref-002", requested_at=T7, case_id="settlement/test-016/refund-1"
        )
        corridor.engine.compile_refund(
            command_id="ref-003",
            requested_at=T7,
            case_id="settlement/test-016/refund-1",
            submit_by=SUBMIT_BY,
            settle_by=SETTLE_BY,
        )
        refund_settlement = corridor.engine.settlement("settlement/test-016/refund-1/refund")
        self.assertEqual(refund_settlement.state, SettlementState.DRAFT)
        self.assertEqual(refund_settlement.spec.linked_ref, "settlement/test-016/batch-1")
        refund_leg = refund_settlement.spec.instructions[0]
        self.assertEqual(refund_leg.obligor, original.obligee)
        self.assertEqual(refund_leg.obligee, original.obligor)
        self.assertEqual(refund_leg.amount, original.amount)
        self.assertEqual(
            InstructionSourceKind(refund_leg.source_kind), InstructionSourceKind.REFUND_LEG
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.execute_refund(
                command_id="ref-004",
                requested_at=T7,
                case_id="settlement/test-016/refund-1",
                settlement_id="settlement/test-016/batch-1",
            )
        corridor.engine.authorize_settlement(
            command_id="ref-005",
            requested_at=T7,
            settlement_id="settlement/test-016/refund-1/refund",
        )
        corridor.engine.submit_settlement(
            command_id="ref-006",
            requested_at=T7,
            settlement_id="settlement/test-016/refund-1/refund",
        )
        refund_digest = refund_leg.instruction_digest()
        corridor.engine.reconcile_settlement(
            command_id="ref-007",
            requested_at=T7,
            settlement_id="settlement/test-016/refund-1/refund",
            as_of=T7,
            observations=[
                _status_observation(10, refund_leg.instruction_id, refund_digest, "SETTLED")
            ],
        )
        corridor.engine.execute_refund(
            command_id="ref-008",
            requested_at=T7,
            case_id="settlement/test-016/refund-1",
            settlement_id="settlement/test-016/refund-1/refund",
        )
        case = corridor.engine.recourse_case("settlement/test-016/refund-1")
        self.assertEqual(case.state, RecourseCaseState.EXECUTED)
        refund_entries = [
            e for e in corridor.engine.postings() if e.kind == PostingKind.REFUND.value
        ]
        self.assertEqual(len(refund_entries), 1)
        self.assertEqual(
            case.spec.execution.posting_refs, (refund_entries[0].entry_id,)
        )

    def test_reversal_request_requires_certificate(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(index, leg, digests[leg], "SETTLED")
                for index, leg in enumerate(legs, start=1)
            ],
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.request_reversal(
                command_id="rev-x",
                requested_at=T7,
                case_id="settlement/test-016/reversal-x",
                settlement_id="settlement/test-016/batch-1",
                instruction_ids=[legs[0]],
                evidence_ref="settlement/test-016/finality-none",
                evidence_digest="d" * 64,
                epistemic_type="OBSERVED",
                reason="no certificate exists",
            )

    def test_reject_paths(self) -> None:
        corridor = self._revoked_certificate()
        legs = corridor._recourse_legs  # type: ignore[attr-defined]
        certificate = corridor.engine.finality("settlement/test-016/finality-1")
        corridor.engine.request_reversal(
            command_id="rev-001",
            requested_at=T7,
            case_id="settlement/test-016/reversal-1",
            settlement_id="settlement/test-016/batch-1",
            instruction_ids=[legs[0]],
            evidence_ref="settlement/test-016/finality-1",
            evidence_digest=certificate.integrity_hash,
            epistemic_type="OBSERVED",
            reason="compensate",
        )
        corridor.engine.reject_reversal(
            command_id="rev-002",
            requested_at=T7,
            case_id="settlement/test-016/reversal-1",
            reason="no financial effect occurred",
        )
        self.assertEqual(
            corridor.engine.recourse_case("settlement/test-016/reversal-1").state,
            RecourseCaseState.REJECTED,
        )
        with self.assertRaises(CoreValidationError):
            corridor.engine.execute_reversal(
                command_id="rev-003", requested_at=T7, case_id="settlement/test-016/reversal-1"
            )


class EngineKernelTests(unittest.TestCase):
    def test_unauthorized_actor_is_rejected(self) -> None:
        corridor = _Corridor()
        command = corridor.engine.build_raw_command(
            command_id="stl-evil",
            command_type="settlement/create",
            requested_at=T2,
            target_refs=("settlement/test-016/batch-evil",),
            payload={"settlement_id": "settlement/test-016/batch-evil",
                     "window": {"submit_by": SUBMIT_BY, "settle_by": SETTLE_BY},
                     "obligations": []},
            actor="principal/attacker",
        )
        transition = corridor.engine.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")

    def test_unknown_command_type_is_rejected_at_construction(self) -> None:
        engine = SettlementEngine(
            environment_id=ENVIRONMENT_ID, domain_id=SETTLEMENT_DOMAIN_ID
        )
        with self.assertRaises(CoreValidationError):
            engine.build_raw_command(
                command_id="stl-x",
                command_type="settlement/explode",
                requested_at=T2,
                target_refs=("s/x",),
                payload={},
            )

    def test_duplicate_command_is_idempotent(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        settlement = corridor.engine.settlement("settlement/test-016/batch-1")
        command = corridor.engine.build_raw_command(
            command_id="stl-dup",
            command_type="settlement/authorize",
            requested_at=T2,
            target_refs=("settlement/test-016/batch-1",),
            payload={},
            expected_versions={"settlement/test-016/batch-1": settlement.envelope.object_version},
        )
        first = corridor.engine.submit(command)
        second = corridor.engine.submit(command)
        self.assertEqual(first.outcome.value, "accepted")
        self.assertEqual(second.outcome.value, "duplicate")
        # one creation event + one authorization event; the duplicate
        # emitted nothing.
        self.assertEqual(len(corridor.engine.journal), 2)

    def test_stale_expected_version_is_rejected(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        command = corridor.engine.build_raw_command(
            command_id="stl-stale",
            command_type="settlement/authorize",
            requested_at=T2,
            target_refs=("settlement/test-016/batch-1",),
            payload={},
            expected_versions={"settlement/test-016/batch-1": 99},
        )
        transition = corridor.engine.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")

    def test_snapshot_restore_round_trip(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "SETTLED"),
            ],
        )
        snapshot = corridor.engine.snapshot_state()
        restored = SettlementEngine(
            environment_id=ENVIRONMENT_ID, domain_id=SETTLEMENT_DOMAIN_ID
        )
        restored.restore_state(snapshot)
        self.assertEqual(
            [record.to_dict() for record in restored.records()],
            [record.to_dict() for record in corridor.engine.records()],
        )
        self.assertEqual(
            [entry.to_dict() for entry in restored.postings()],
            [entry.to_dict() for entry in corridor.engine.postings()],
        )
        self.assertEqual(restored.postings_digest(), corridor.engine.postings_digest())

    def test_restore_rejects_environment_mismatch(self) -> None:
        corridor = _Corridor()
        corridor.create_settlement()
        snapshot = corridor.engine.snapshot_state()
        other = SettlementEngine(
            environment_id="env/other-016", domain_id=SETTLEMENT_DOMAIN_ID
        )
        with self.assertRaises(CoreValidationError):
            other.restore_state(snapshot)

    def test_journal_rebuild_is_transformation_complete(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(index, leg, digests[leg], "SETTLED")
                for index, leg in enumerate(legs, start=1)
            ],
        )
        rebuilt = SettlementEngine.rebuild_from_journal(
            environment_id=ENVIRONMENT_ID,
            domain_id=SETTLEMENT_DOMAIN_ID,
            journal=corridor.engine.journal,
        )
        self.assertEqual(
            [record.to_dict() for record in rebuilt.records()],
            [record.to_dict() for record in corridor.engine.records()],
        )
        self.assertEqual(rebuilt.postings_digest(), corridor.engine.postings_digest())
        self.assertEqual(rebuilt.journal, corridor.engine.journal)

    def test_postings_are_append_only_by_construction(self) -> None:
        corridor = _Corridor()
        digests = corridor.drive_submitted()
        legs = sorted(digests)
        corridor.engine.reconcile_settlement(
            command_id="stl-004",
            requested_at=T3,
            settlement_id="settlement/test-016/batch-1",
            as_of=T3,
            observations=[
                _status_observation(1, legs[0], digests[legs[0]], "SETTLED"),
            ],
        )
        postings = corridor.engine.postings()
        with self.assertRaises(AttributeError):
            postings.append("forged")  # type: ignore[arg-type]
        with self.assertRaises(AttributeError):
            postings[0].debit_value = 1  # type: ignore[misc]


class DogfoodingConformanceTests(unittest.TestCase):
    def test_dogfooding_transcript_passes(self) -> None:
        from .dogfooding import build_transcript

        transcript = build_transcript()
        self.assertEqual(transcript["classification"], "PASS")
        self.assertEqual(len(transcript["checks"]), 22)
        self.assertTrue(all(check["pass"] for check in transcript["checks"]))
        self.assertEqual(
            transcript["facts"]["settlement_state"],
            "FAILED",
        )
        self.assertEqual(transcript["facts"]["finality_state"], "REVOKED")
        self.assertEqual(transcript["facts"]["reversal_state"], "EXECUTED")
        self.assertEqual(transcript["facts"]["refund_state"], "EXECUTED")
        self.assertEqual(transcript["facts"]["posting_entries"], 6)


if __name__ == "__main__":
    unittest.main()
