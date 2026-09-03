"""Red-first-authored test suite for the clearing domain (WORK-015).

Covers the typed public boundary, the frozen command families and
registries, record validation and tamper rejection, the obligation
lifecycle with every gate, the clearing-cycle lifecycle, bilateral and
multilateral netting arithmetic with conservation and valuation, the
kernel-bound engine (journal events, rebuild, snapshot), the
dogfooding conformance, and the static no-wall-clock/no-entropy and
import-closure discipline.
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys
import unittest
from dataclasses import replace

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json
from src.execution.contracts import EffectOutcome
from src.execution.effects import EffectResultSpec, make_result_record
from src.value.amount import Amount

from src.clearing.contracts import (
    CLEARING_ALL_COMMANDS,
    CLEARING_CYCLE_COMMANDS,
    CLEARING_CYCLE_OBJECT_TYPE,
    CLEARING_TRANSITIONS,
    COMMAND_EVENT_TYPES,
    NETTING_COMMANDS,
    NETTING_CYCLE_OBJECT_TYPE,
    OBLIGATION_COMMANDS,
    OBLIGATION_OBJECT_TYPE,
    OBJECT_TYPES,
    ClearingCycleState,
    NettingCycleState,
    NettingMode,
    ObligationSourceKind,
    ObligationState,
    ResolutionKind,
    validate_command,
)
from src.clearing.cycle import (
    AssetGross,
    ClearingCycle,
    ClearingCycleSpec,
    ClearingStatement,
    PairGross,
    RecognitionWindow,
    compute_clearing_statement,
    make_cycle_record,
)
from src.clearing.engine import ClearingEngine
from src.clearing.netting import (
    MemberBinding,
    NettingCycle,
    NettingCycleSpec,
    NettingStatement,
    PairNet,
    PositionNet,
    ValuationSpec,
    compute_netting_statement,
)
from src.clearing.seal import advance_envelope, seal_composite
from src.clearing.obligations import (
    AmendmentRecord,
    DefaultRecord,
    DisputeRecord,
    DueRecord,
    DueWindow,
    FundingGate,
    Obligation,
    ObligationSpec,
    ResolutionRecord,
    RestructureRecord,
    make_obligation_record,
)

ENV = "env/test-clearing"
DOMAIN = "domain/clearing"
EXEC_DOMAIN = "domain/execution"
T0 = "2026-09-03T08:00:00Z"
T1 = "2026-09-03T09:00:00Z"
T2 = "2026-09-03T12:00:00Z"
T3 = "2026-09-04T12:00:00Z"
USD = "value/asset/usd-test"
GHS = "value/asset/ghs-test"
A = "principal/alpha-payout"
B = "principal/bravo-payout"
C = "principal/charlie-payout"

GHS_TO_USD_RATE = {
    "source_currency": "GHS",
    "source_scale": 2,
    "target_currency": "USD",
    "target_scale": 2,
    "rate_numerator": 1,
    "rate_denominator": 15,
}


def _provenance() -> Provenance:
    return Provenance(issuer="principal/test-operator", source="clearing/test", recorded_at=T0)


def _effect_result(
    result_id: str,
    *,
    payer: str,
    payee: str,
    asset: str,
    value: int,
    outcome: EffectOutcome = EffectOutcome.SUCCEEDED,
    detail: object | None = None,
) -> dict:
    request_id = result_id[: -len("/result")]
    step_id = result_id.split("/request/")[0] + "/step-1"
    if detail is None:
        detail = {
            "payer": payer,
            "payee": payee,
            "asset": asset,
            "amount": {"value": value, "scale": 2, "asset": asset},
        }
    spec = EffectResultSpec(
        result_id=result_id,
        request_id=request_id,
        step_id=step_id,
        effect_type="payment/submit",
        outcome=outcome,
        native_reference=f"rail/ref-{result_id}" if outcome is not EffectOutcome.UNKNOWN else None,
        error_code=None,
        observed_at=T0,
        request_digest="a" * 64,
        detail=detail,
    )
    record = make_result_record(
        spec=spec,
        environment_id=ENV,
        domain_id=EXEC_DOMAIN,
        provenance=Provenance(issuer="principal/rail", source="execution/domain", recorded_at=T0),
    )
    return record.to_dict()


def _make_obligation_spec(
    *,
    obligation_id: str = "plan/req-1/result/obligation",
    cycle_id: str | None = "clearing/cycle/c1",
    obligor: str = A,
    obligee: str = B,
    asset: str = USD,
    value: int = 100_000,
    scale: int = 2,
    source_kind: str = "EXECUTION_EVIDENCE",
    source_ref: str = "plan/req-1/result",
    source_digest: str = "b" * 64,
) -> ObligationSpec:
    return ObligationSpec(
        obligation_id=obligation_id,
        cycle_id=cycle_id,
        obligor=obligor,
        obligee=obligee,
        asset=asset,
        amount=Amount(value=value, scale=scale, asset=asset),
        source_kind=source_kind,
        source_ref=source_ref,
        source_digest=source_digest,
        due_window=DueWindow(due_from=T2, due_until=T3),
    )


def _make_netting_spec(
    *,
    netting_id: str = "clearing/netting/n1",
    mode: str = "BILATERAL",
) -> NettingCycleSpec:
    return NettingCycleSpec(
        netting_id=netting_id,
        mode=mode,
        due_window=DueWindow(due_from=T2, due_until=T3),
    )


def _make_cycle_spec(*, cycle_id: str = "clearing/cycle/c1") -> ClearingCycleSpec:
    return ClearingCycleSpec(
        cycle_id=cycle_id,
        window=RecognitionWindow(opens_at=T0, closes_at=T1),
    )


def _new_engine() -> ClearingEngine:
    return ClearingEngine(environment_id=ENV, domain_id=DOMAIN)


def _recognized_engine() -> tuple[ClearingEngine, str]:
    """Engine with one validated obligation in a finalized cycle."""
    engine = _new_engine()
    engine.create_cycle(
        command_id="cmd-cycle", requested_at=T0, cycle_id="clearing/cycle/c1",
        opens_at=T0, closes_at=T1,
    )
    effect = _effect_result(
        "plan/req-1/result", payer=A, payee=B, asset=USD, value=100_000
    )
    engine.recognize_obligation(
        command_id="cmd-rec", requested_at=T0, cycle_id="clearing/cycle/c1",
        effect_result=effect, due_from=T2, due_until=T3,
    )
    obligation_id = "plan/req-1/result/obligation"
    engine.validate_obligation(
        command_id="cmd-val", requested_at=T0, obligation_id=obligation_id
    )
    engine.validate_cycle(
        command_id="cmd-cval", requested_at=T0, cycle_id="clearing/cycle/c1"
    )
    engine.finalize_cycle(
        command_id="cmd-cfin", requested_at=T0, cycle_id="clearing/cycle/c1"
    )
    return engine, obligation_id


# ---------------------------------------------------------------------------
# static boundary
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    def test_public_api_version_is_frozen(self) -> None:
        import src.clearing as clearing

        self.assertEqual(clearing.CLEARING_API_VERSION, "v0.1")
        self.assertEqual(clearing.CLEARING_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(clearing.CLEARING_SCHEMA_VERSION, 1)

    def test_object_types_follow_registry_discipline(self) -> None:
        self.assertEqual(OBLIGATION_OBJECT_TYPE, "payswap/obligation/v1")
        self.assertTrue(CLEARING_CYCLE_OBJECT_TYPE.startswith("clearing/"))
        self.assertTrue(NETTING_CYCLE_OBJECT_TYPE.startswith("clearing/"))
        self.assertEqual(
            OBJECT_TYPES,
            (OBLIGATION_OBJECT_TYPE, CLEARING_CYCLE_OBJECT_TYPE, NETTING_CYCLE_OBJECT_TYPE),
        )

    def test_command_families_match_the_frozen_architecture(self) -> None:
        self.assertEqual(
            sorted(CLEARING_CYCLE_COMMANDS),
            [
                "clearing/cycle.cancel",
                "clearing/cycle.create",
                "clearing/cycle.finalize",
                "clearing/cycle.validate",
            ],
        )
        self.assertEqual(
            sorted(OBLIGATION_COMMANDS),
            [
                "clearing/obligation.amend",
                "clearing/obligation.create",
                "clearing/obligation.default",
                "clearing/obligation.dispute",
                "clearing/obligation.mark-due",
                "clearing/obligation.resolve",
                "clearing/obligation.restructure",
                "clearing/obligation.validate",
            ],
        )
        self.assertEqual(
            sorted(NETTING_COMMANDS),
            [
                "clearing/netting.add",
                "clearing/netting.calculate",
                "clearing/netting.cancel",
                "clearing/netting.create",
                "clearing/netting.finalize",
                "clearing/netting.remove",
            ],
        )
        self.assertEqual(len(CLEARING_ALL_COMMANDS), 18)

    def test_every_event_type_uses_the_registered_clearing_namespace(self) -> None:
        from src.transition.registry import EVENT_NAMESPACES, validate_event_type

        self.assertIn("clearing", EVENT_NAMESPACES)
        for command_type, event_type in COMMAND_EVENT_TYPES.items():
            self.assertIn(command_type, CLEARING_ALL_COMMANDS)
            validate_event_type(f"event for {command_type}", event_type)
            self.assertTrue(event_type.startswith("clearing/"))
        self.assertEqual(len(COMMAND_EVENT_TYPES), 18)

    def test_transitions_table_covers_every_command(self) -> None:
        self.assertEqual(set(CLEARING_TRANSITIONS), set(CLEARING_ALL_COMMANDS))
        for command_type, sources in CLEARING_TRANSITIONS.items():
            self.assertIsInstance(sources, frozenset)
            for source in sources:
                self.assertIsInstance(
                    source,
                    (
                        ClearingCycleState,
                        ObligationState,
                        NettingCycleState,
                    ),
                )

    def test_validate_command_fails_closed_on_unknown(self) -> None:
        self.assertEqual(validate_command("clearing/cycle.create"), "clearing/cycle.create")
        with self.assertRaises(CoreValidationError):
            validate_command("clearing/cycle.destroy")
        with self.assertRaises(CoreValidationError):
            validate_command("")

    def test_terminal_states_are_closed(self) -> None:
        from src.clearing.contracts import (
            CLEARING_CYCLE_TERMINAL_STATES,
            NETTING_TERMINAL_STATES,
            OBLIGATION_TERMINAL_STATES,
        )

        self.assertEqual(
            OBLIGATION_TERMINAL_STATES,
            frozenset({ObligationState.DEFAULTED, ObligationState.RESOLVED}),
        )
        self.assertIn(ClearingCycleState.FINALIZED, CLEARING_CYCLE_TERMINAL_STATES)
        self.assertIn(NettingCycleState.FINALIZED, NETTING_TERMINAL_STATES)

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
                    dotted = ".".join(reversed(rendered))
                    self.assertNotIn(
                        dotted,
                        forbidden_calls,
                        f"{source_path.name} calls {dotted} — wall-clock/entropy source",
                    )

    def test_import_closure_is_pinned(self) -> None:
        """The transitive import closure equals exactly merged mainline roots.

        The probe runs in an isolated subprocess (WORK-020 precedent) so
        the assertion is order-robust: sibling suites loaded earlier in
        a combined run never pollute the measured closure.
        """
        import subprocess

        probe = (
            "import sys, json; import src.clearing; "
            "print(json.dumps(sorted("
            "name for name in sys.modules "
            "if name.startswith('src.') and name.count('.') == 1)))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[2]),
            check=True,
        )
        loaded = set(json.loads(completed.stdout))
        expected = {
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


# ---------------------------------------------------------------------------
# record validation
# ---------------------------------------------------------------------------


class CycleRecordTests(unittest.TestCase):
    def test_spec_round_trip_is_byte_identical(self) -> None:
        spec = _make_cycle_spec()
        self.assertEqual(ClearingCycleSpec.from_dict(spec.to_dict()), spec)
        self.assertEqual(canonical_json(ClearingCycleSpec.from_dict(spec.to_dict()).to_dict()), canonical_json(spec.to_dict()))

    def test_window_order_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            RecognitionWindow(opens_at=T1, closes_at=T0)

    def test_member_duplicates_rejected(self) -> None:
        with self.assertRaises(CoreValidationError):
            ClearingCycleSpec(
                cycle_id="clearing/cycle/c1",
                window=RecognitionWindow(opens_at=T0, closes_at=T1),
                member_ids=("o1", "o1"),
            )

    def test_statement_rejects_duplicate_assets_and_pairs(self) -> None:
        with self.assertRaises(CoreValidationError):
            ClearingStatement(
                finalized_at=T0,
                member_total=1,
                gross_by_asset=(AssetGross(asset=USD, scale=2, gross=1), AssetGross(asset=USD, scale=2, gross=2)),
                gross_by_pair=(PairGross(obligor=A, obligee=B, asset=USD, scale=2, gross=3),),
            )

    def test_statement_digest_is_deterministic(self) -> None:
        statement = ClearingStatement(
            finalized_at=T0,
            member_total=1,
            gross_by_asset=(AssetGross(asset=USD, scale=2, gross=100),),
            gross_by_pair=(PairGross(obligor=A, obligee=B, asset=USD, scale=2, gross=100),),
        )
        self.assertEqual(statement.digest, statement.from_dict(statement.to_dict()).digest)

    def test_tampered_composite_fails_closed(self) -> None:
        record = make_cycle_record(
            spec=_make_cycle_spec(), environment_id=ENV, domain_id=DOMAIN,
            provenance=_provenance(),
        )
        composite = record.to_dict()
        composite["payload"]["description"] = "tampered"
        with self.assertRaises(CoreValidationError):
            ClearingCycle.from_dict(composite)

    def test_registry_type_claim_rejected_for_internal_kinds(self) -> None:
        record = make_cycle_record(
            spec=_make_cycle_spec(), environment_id=ENV, domain_id=DOMAIN,
            provenance=_provenance(),
        )
        composite = record.to_dict()
        composite["envelope"]["object_type"] = "payswap/obligation/v1"
        # Rebuild the core seal for the swapped type so the failure is the
        # clearing object-type discipline, not the core envelope seal.
        with self.assertRaises(CoreValidationError):
            ClearingCycle.from_dict(composite)


class ObligationRecordTests(unittest.TestCase):
    def test_spec_invariants(self) -> None:
        with self.assertRaises(CoreValidationError):
            _make_obligation_spec(obligor=A, obligee=A)  # self-owed
        with self.assertRaises(CoreValidationError):
            _make_obligation_spec(value=0)  # non-positive
        with self.assertRaises(CoreValidationError):
            _make_obligation_spec(value=-5)
        with self.assertRaises(CoreValidationError):
            # amount asset disagrees with the declared asset
            ObligationSpec(
                obligation_id="o1",
                cycle_id=None,
                obligor=A,
                obligee=B,
                asset=GHS,
                amount=Amount(value=100_000, scale=2, asset=USD),
                source_kind="EXECUTION_EVIDENCE",
                source_ref="plan/req-1/result",
                source_digest="b" * 64,
                due_window=DueWindow(due_from=T2, due_until=T3),
            )
        with self.assertRaises(CoreValidationError):
            _make_obligation_spec(source_digest="zz")  # bad digest

    def test_spec_round_trip_is_byte_identical(self) -> None:
        spec = _make_obligation_spec()
        self.assertEqual(ObligationSpec.from_dict(spec.to_dict()), spec)

    def test_default_and_resolution_are_mutually_exclusive(self) -> None:
        with self.assertRaises(CoreValidationError):
            ObligationSpec(
                obligation_id="o1",
                cycle_id=None,
                obligor=A,
                obligee=B,
                asset=USD,
                amount=Amount(value=1, scale=2, asset=USD),
                source_kind="EXECUTION_EVIDENCE",
                source_ref="plan/req-1/result",
                source_digest="b" * 64,
                due_window=DueWindow(due_from=T2, due_until=T3),
                default=DefaultRecord(
                    evidence_ref="evidence/e1", epistemic_type="OBSERVED",
                    reason="r", defaulted_at=T0,
                ),
                resolution=ResolutionRecord(
                    kind="NETTING", ref="clearing/netting/n1",
                    digest="c" * 64, resolved_at=T0,
                ),
            )

    def test_state_facts_cross_check(self) -> None:
        # RECOGNIZED cannot carry lifecycle facts: force the composite
        # through the constructor with a dispute marker in RECOGNIZED.
        base = _make_obligation_spec(cycle_id=None)
        disputed_spec = replace(
            base,
            dispute=DisputeRecord(
                evidence_ref="evidence/d1", epistemic_type="OBSERVED",
                reason="r", disputed_at=T0,
            ),
        )
        record = make_obligation_record(
            spec=base, environment_id=ENV, domain_id=DOMAIN, provenance=_provenance()
        )
        with self.assertRaises(CoreValidationError):
            Obligation(
                envelope=record.envelope,
                spec=disputed_spec,
                integrity_hash=seal_composite(record.envelope, disputed_spec),
            )
        # AMENDED must carry its amendment marker
        base = _make_obligation_spec()
        record = make_obligation_record(
            spec=base, environment_id=ENV, domain_id=DOMAIN, provenance=_provenance()
        )
        amended_spec = replace(base, amendment=AmendmentRecord(reason="r", amended_at=T0))
        envelope = advance_envelope(record.envelope, state=ObligationState.VALIDATED.value, provenance=_provenance())
        envelope = advance_envelope(envelope, state=ObligationState.AMENDED.value, provenance=_provenance())
        with self.assertRaises(CoreValidationError):
            Obligation(
                envelope=envelope,
                spec=replace(base),  # no amendment marker
                integrity_hash=seal_composite(envelope, base),
            )
        good = Obligation(
            envelope=envelope, spec=amended_spec, integrity_hash=seal_composite(envelope, amended_spec)
        )
        self.assertEqual(good.state, ObligationState.AMENDED)

    def test_evidence_gate_requires_observed(self) -> None:
        for epistemic in ("ESTIMATED", "PREDICTED", "SIMULATED", "COUNTERFACTUAL"):
            with self.assertRaises(CoreValidationError):
                DisputeRecord(
                    evidence_ref="evidence/e1",
                    epistemic_type=epistemic,
                    reason="r",
                    disputed_at=T0,
                )

    def test_funding_gate_requires_held(self) -> None:
        for state in ("RESERVED", "COMMITTED", "RELEASED", "EXPIRED", "DEFAULTED", "CONSUMED"):
            with self.assertRaises(CoreValidationError):
                FundingGate(reservation_id="reservation/r1", state=state, object_version=1)
        gate = FundingGate(reservation_id="reservation/r1", state="HELD", object_version=1)
        self.assertEqual(gate.state, "HELD")

    def test_tampered_obligation_composite_fails_closed(self) -> None:
        record = make_obligation_record(
            spec=_make_obligation_spec(cycle_id=None),
            environment_id=ENV, domain_id=DOMAIN, provenance=_provenance(),
        )
        composite = record.to_dict()
        composite["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            Obligation.from_dict(composite)


class NettingRecordTests(unittest.TestCase):
    def test_statement_conservation_invariants(self) -> None:
        good_positions = (
            PositionNet(participant=A, net=100),
            PositionNet(participant=B, net=-100),
        )
        statement = NettingStatement(
            calculated_at=T0,
            mode="MULTILATERAL",
            member_total=1,
            members=(MemberBinding(obligation_id="o1", object_version=1, obligor=A, obligee=B, amount_value=100),),
            groups=(
                __import__("src.clearing.netting", fromlist=["NettingGroup"]).NettingGroup(
                    asset=USD, scale=2, gross=100, net_total=100, positions=good_positions
                ),
            ),
            gross_total=100,
            net_total=100,
            reduction=0,
        )
        self.assertEqual(statement.mode, "MULTILATERAL")
        # Non-conserving positions fail closed at record level.
        bad_positions = (PositionNet(participant=A, net=100), PositionNet(participant=B, net=-90))
        with self.assertRaises(CoreValidationError):
            replace(
                statement,
                groups=(
                    __import__("src.clearing.netting", fromlist=["NettingGroup"]).NettingGroup(
                        asset=USD, scale=2, gross=100, net_total=100, positions=bad_positions
                    ),
                ),
            )

    def test_mode_shapes_are_closed(self) -> None:
        NettingGroup = __import__("src.clearing.netting", fromlist=["NettingGroup"]).NettingGroup
        with self.assertRaises(CoreValidationError):
            NettingGroup(
                asset=USD, scale=2, gross=10, net_total=10,
                pairs=(PairNet(obligor=A, obligee=B, forward=10, resolved_count=1, issued_obligation_id="i1"),),
                positions=(PositionNet(participant=A, net=10),),
            )

    def test_net_never_exceeds_gross(self) -> None:
        NettingGroup = __import__("src.clearing.netting", fromlist=["NettingGroup"]).NettingGroup
        with self.assertRaises(CoreValidationError):
            NettingGroup(asset=USD, scale=2, gross=10, net_total=11)

    def test_pair_forward_zero_implies_no_issuance(self) -> None:
        with self.assertRaises(CoreValidationError):
            PairNet(obligor=A, obligee=B, forward=0, resolved_count=1, issued_obligation_id="i1")
        with self.assertRaises(CoreValidationError):
            PairNet(obligor=A, obligee=B, forward=10, resolved_count=1, issued_obligation_id=None)

    def test_tampered_netting_composite_fails_closed(self) -> None:
        from src.clearing.netting import make_netting_record

        record = make_netting_record(
            spec=_make_netting_spec(), environment_id=ENV, domain_id=DOMAIN,
            provenance=_provenance(),
        )
        composite = record.to_dict()
        composite["payload"]["mode"] = "MULTILATERAL"
        with self.assertRaises(CoreValidationError):
            NettingCycle.from_dict(composite)


# ---------------------------------------------------------------------------
# netting arithmetic (pure functions)
# ---------------------------------------------------------------------------


def _obligation_for(
    *,
    obligation_id: str,
    obligor: str,
    obligee: str,
    value: int,
    asset: str = USD,
    scale: int = 2,
) -> Obligation:
    """A VALIDATED obligation record for the pure netting arithmetic."""
    record = make_obligation_record(
        spec=_make_obligation_spec(
            obligation_id=obligation_id,
            cycle_id=None,
            obligor=obligor,
            obligee=obligee,
            asset=asset,
            value=value,
            scale=scale,
            source_ref=f"plan/{obligation_id}/result",
            source_digest="d" * 64,
        ),
        environment_id=ENV, domain_id=DOMAIN, provenance=_provenance(),
    )
    envelope = advance_envelope(
        record.envelope, state=ObligationState.VALIDATED.value, provenance=_provenance()
    )
    return Obligation(
        envelope=envelope, spec=record.spec, integrity_hash=seal_composite(envelope, record.spec)
    )


class NettingArithmeticTests(unittest.TestCase):
    def test_bilateral_reciprocal_offset(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=2_500_000),
            _obligation_for(obligation_id="o2", obligor=A, obligee=B, value=500_000),
            _obligation_for(obligation_id="o3", obligor=B, obligee=A, value=1_000_000),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        self.assertEqual(statement.gross_total, 4_000_000)
        self.assertEqual(statement.net_total, 2_000_000)
        self.assertEqual(statement.reduction, 2_000_000)
        pair = statement.groups[0].pairs[0]
        self.assertEqual(pair.obligor, A)
        self.assertEqual(pair.obligee, B)
        self.assertEqual(pair.forward, 2_000_000)
        self.assertEqual(pair.resolved_count, 3)
        self.assertEqual(pair.issued_obligation_id, "clearing/netting/n1/obligation/1")

    def test_bilateral_full_offset_issues_nothing(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000),
            _obligation_for(obligation_id="o2", obligor=B, obligee=A, value=1_000_000),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        pair = statement.groups[0].pairs[0]
        self.assertEqual(pair.forward, 0)
        self.assertIsNone(pair.issued_obligation_id)
        self.assertEqual(statement.net_total, 0)
        self.assertEqual(statement.reduction, statement.gross_total)

    def test_bilateral_without_reciprocity_reduces_nothing(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000),
            _obligation_for(obligation_id="o2", obligor=A, obligee=B, value=500_000),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        self.assertEqual(statement.net_total, 1_500_000)
        self.assertEqual(statement.reduction, 0)

    def test_multilateral_triangle_conserves_and_reduces(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=400_000),
            _obligation_for(obligation_id="o2", obligor=B, obligee=C, value=550_000),
            _obligation_for(obligation_id="o3", obligor=C, obligee=A, value=300_000),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.MULTILATERAL, calculated_at=T0,
        )
        group = statement.groups[0]
        positions = {position.participant: position.net for position in group.positions}
        self.assertEqual(sum(positions.values()), 0)
        # A: +400,000-300,000 = +100,000; B: +550,000-400,000 = +150,000;
        # C: +300,000-550,000 = -250,000.
        self.assertEqual(positions[A], 100_000)
        self.assertEqual(positions[B], 150_000)
        self.assertEqual(positions[C], -250_000)
        self.assertEqual(statement.net_total, 250_000)
        self.assertEqual(statement.gross_total, 1_250_000)
        self.assertEqual(statement.reduction, 1_000_000)
        self.assertFalse(any(pair.issued_obligation_id is not None for pair in group.pairs))

    def test_multi_asset_groups_separate(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000, asset=USD),
            _obligation_for(obligation_id="o2", obligor=B, obligee=A, value=400_000, asset=GHS),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        self.assertEqual(len(statement.groups), 2)
        assets = [group.asset for group in statement.groups]
        self.assertEqual(assets, sorted([USD, GHS]))
        self.assertEqual(statement.gross_total, 1_400_000)

    def test_cross_scale_never_nets_silently(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000, scale=2),
            _obligation_for(obligation_id="o2", obligor=B, obligee=A, value=100_000_000, scale=4),
        ]
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        # Same asset at different scales forms two groups: no silent rescale.
        self.assertEqual(len(statement.groups), 2)
        self.assertEqual(statement.net_total, statement.gross_total)
        self.assertEqual(statement.reduction, 0)

    def test_statement_is_deterministic(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000),
            _obligation_for(obligation_id="o2", obligor=B, obligee=A, value=400_000),
        ]
        first = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        second = compute_netting_statement(
            netting_id="clearing/netting/n1", members=list(members),
            mode=NettingMode.BILATERAL, calculated_at=T0,
        )
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(canonical_json(first.to_dict()), canonical_json(second.to_dict()))

    def test_valuation_uses_money_fx_with_explicit_rounding(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000, asset=GHS),
            _obligation_for(obligation_id="o2", obligor=B, obligee=A, value=400_000, asset=GHS),
        ]
        spec = ValuationSpec(
            base_currency="USD",
            rounding=__import__("src.money.rounding", fromlist=["RoundingMode"]).RoundingMode.FLOOR,
            asset_currencies=((GHS, "GHS"),),
            rates=(
                __import__("src.money.fx", fromlist=["FxRate"]).FxRate.from_dict(GHS_TO_USD_RATE),
            ),
        )
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0, valuation_spec=spec,
        )
        assert statement.valuation is not None
        # gross 1,400,000 GHS minor / 15 = 93,333.33 USD minor -> FLOOR 93,333
        self.assertEqual(statement.valuation.gross_base, 93_333)
        # net 600,000 GHS minor / 15 = 40,000 USD minor exactly
        self.assertEqual(statement.valuation.net_base, 40_000)
        self.assertEqual(statement.valuation.reduction_base, 53_333)
        conversion = statement.valuation.conversions[0]
        self.assertEqual(conversion.currency, "GHS")
        self.assertNotEqual(conversion.gross_residual_numerator, 0)

    def test_valuation_identity_leg_for_base_currency(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000, asset=USD),
        ]
        spec = ValuationSpec(
            base_currency="USD",
            rounding=__import__("src.money.rounding", fromlist=["RoundingMode"]).RoundingMode.FLOOR,
            asset_currencies=((USD, "USD"),),
            rates=(),
        )
        statement = compute_netting_statement(
            netting_id="clearing/netting/n1", members=members,
            mode=NettingMode.BILATERAL, calculated_at=T0, valuation_spec=spec,
        )
        assert statement.valuation is not None
        self.assertEqual(statement.valuation.gross_base, 1_000_000)
        self.assertEqual(statement.valuation.conversions[0].rate, None)

    def test_valuation_fails_closed_on_scale_mismatch(self) -> None:
        members = [_obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1, scale=4, asset=USD)]
        spec = ValuationSpec(
            base_currency="USD",
            rounding=__import__("src.money.rounding", fromlist=["RoundingMode"]).RoundingMode.FLOOR,
            asset_currencies=((USD, "USD"),),
            rates=(),
        )
        with self.assertRaises(CoreValidationError):
            compute_netting_statement(
                netting_id="clearing/netting/n1", members=members,
                mode=NettingMode.BILATERAL, calculated_at=T0, valuation_spec=spec,
            )

    def test_valuation_fails_closed_on_missing_rate(self) -> None:
        members = [_obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000, asset=GHS)]
        spec = ValuationSpec(
            base_currency="USD",
            rounding=__import__("src.money.rounding", fromlist=["RoundingMode"]).RoundingMode.FLOOR,
            asset_currencies=((GHS, "GHS"),),
            rates=(),
        )
        with self.assertRaises(CoreValidationError):
            compute_netting_statement(
                netting_id="clearing/netting/n1", members=members,
                mode=NettingMode.BILATERAL, calculated_at=T0, valuation_spec=spec,
            )

    def test_unnettable_members_fail_closed(self) -> None:
        member = make_obligation_record(
            spec=_make_obligation_spec(cycle_id=None),
            environment_id=ENV, domain_id=DOMAIN, provenance=_provenance(),
        )
        self.assertEqual(member.state, ObligationState.RECOGNIZED)
        # A RECOGNIZED obligation (never validated) cannot net.
        with self.assertRaises(CoreValidationError):
            compute_netting_statement(
                netting_id="clearing/netting/n1", members=[member],
                mode=NettingMode.BILATERAL, calculated_at=T0,
            )

    def test_clearing_statement_grosses(self) -> None:
        members = [
            _obligation_for(obligation_id="o1", obligor=A, obligee=B, value=1_000_000),
            _obligation_for(obligation_id="o2", obligor=A, obligee=B, value=500_000),
            _obligation_for(obligation_id="o3", obligor=B, obligee=A, value=250_000, asset=GHS),
        ]
        statement = compute_clearing_statement(members=members, finalized_at=T0)
        self.assertEqual(statement.member_total, 3)
        by_asset = {entry.asset: entry.gross for entry in statement.gross_by_asset}
        self.assertEqual(by_asset, {USD: 1_500_000, GHS: 250_000})
        by_pair = {
            (entry.obligor, entry.obligee, entry.asset): entry.gross
            for entry in statement.gross_by_pair
        }
        self.assertEqual(by_pair[(A, B, USD)], 1_500_000)
        self.assertEqual(by_pair[(B, A, GHS)], 250_000)


# ---------------------------------------------------------------------------
# engine: clearing-cycle lifecycle
# ---------------------------------------------------------------------------


class CycleLifecycleTests(unittest.TestCase):
    def test_happy_path_binds_the_clearing_statement(self) -> None:
        engine, obligation_id = _recognized_engine()
        cycle = engine.cycle("clearing/cycle/c1")
        self.assertEqual(cycle.state, ClearingCycleState.FINALIZED)
        assert cycle.spec.statement is not None
        self.assertEqual(cycle.spec.statement.member_total, 1)
        self.assertEqual(cycle.spec.member_ids, (obligation_id,))
        self.assertEqual(
            cycle.spec.statement.gross_by_asset,
            (AssetGross(asset=USD, scale=2, gross=100_000),),
        )

    def test_validation_fails_with_recognized_member(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        engine.recognize_obligation(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.validate_cycle(
                command_id="c3", requested_at=T0, cycle_id="clearing/cycle/c1"
            )
        self.assertIn("RECOGNIZED", str(raised.exception))

    def test_finalization_fails_with_disputed_member(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        engine.recognize_obligation(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        engine.validate_obligation(
            command_id="c3", requested_at=T0, obligation_id="plan/req-1/result/obligation"
        )
        engine.dispute_obligation(
            command_id="c4", requested_at=T0, obligation_id="plan/req-1/result/obligation",
            evidence_ref="evidence/dispute-1", epistemic_type="OBSERVED",
            reason="payee disputes the amount",
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.validate_cycle(
                command_id="c5", requested_at=T0, cycle_id="clearing/cycle/c1"
            )
        self.assertIn("DISPUTED", str(raised.exception))

    def test_finalize_fails_with_disputed_member(self) -> None:
        # Validate the cycle while every member is VALIDATED, dispute a
        # member afterwards, then finalization must fail closed.
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        engine.recognize_obligation(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        engine.validate_obligation(
            command_id="c3", requested_at=T0, obligation_id="plan/req-1/result/obligation"
        )
        engine.validate_cycle(
            command_id="c4", requested_at=T0, cycle_id="clearing/cycle/c1"
        )
        engine.dispute_obligation(
            command_id="c5", requested_at=T0, obligation_id="plan/req-1/result/obligation",
            evidence_ref="evidence/dispute-1", epistemic_type="OBSERVED",
            reason="late dispute",
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.finalize_cycle(
                command_id="c6", requested_at=T0, cycle_id="clearing/cycle/c1"
            )
        self.assertIn("DISPUTED", str(raised.exception))

    def test_cancel_closes_without_statement(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        transition = engine.cancel_cycle(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1", reason="abandoned"
        )
        self.assertEqual(transition.outcome.value, "accepted")
        cycle = engine.cycle("clearing/cycle/c1")
        self.assertEqual(cycle.state, ClearingCycleState.CANCELLED)
        self.assertIsNone(cycle.spec.statement)

    def test_finalize_from_open_rejects(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        with self.assertRaises(CoreValidationError):
            engine.finalize_cycle(
                command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1"
            )

    def test_duplicate_cycle_id_version_conflict(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        transition = engine.create_cycle(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        self.assertEqual(transition.outcome.value, "rejected")
        self.assertEqual(transition.reason.value if transition.reason else "", "version_conflict")


# ---------------------------------------------------------------------------
# engine: obligation lifecycle
# ---------------------------------------------------------------------------


class ObligationLifecycleTests(unittest.TestCase):
    def test_recognition_derives_facts_from_evidence(self) -> None:
        engine, obligation_id = _recognized_engine()
        obligation = engine.obligation(obligation_id)
        self.assertEqual(obligation.state, ObligationState.VALIDATED)
        self.assertEqual(obligation.spec.obligor, A)
        self.assertEqual(obligation.spec.obligee, B)
        self.assertEqual(obligation.spec.amount.value, 100_000)
        self.assertEqual(obligation.spec.source_kind, "EXECUTION_EVIDENCE")
        self.assertEqual(obligation.spec.source_digest, obligation.spec.source_digest)
        self.assertEqual(obligation.spec.cycle_id, "clearing/cycle/c1")
        self.assertEqual(
            engine.cycle("clearing/cycle/c1").spec.member_ids, (obligation_id,)
        )

    def test_recognition_from_failed_outcome_fails_closed(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result(
            "plan/req-1/result", payer=A, payee=B, asset=USD, value=100,
            outcome=EffectOutcome.FAILED,
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.recognize_obligation(
                command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
                effect_result=effect, due_from=T2, due_until=T3,
            )
        self.assertIn("SUCCEEDED", str(raised.exception))

    def test_recognition_from_unknown_outcome_fails_closed(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result(
            "plan/req-1/result", payer=A, payee=B, asset=USD, value=100,
            outcome=EffectOutcome.UNKNOWN,
        )
        with self.assertRaises(CoreValidationError):
            engine.recognize_obligation(
                command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
                effect_result=effect, due_from=T2, due_until=T3,
            )

    def test_recognition_with_malformed_detail_fails_closed(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        for detail in (
            {"payer": A, "payee": B, "asset": USD},  # missing amount
            {"payer": A, "payee": B, "asset": USD, "amount": {"value": 1, "scale": 2, "asset": USD}, "memo": "x"},
            {"payer": A, "payee": B, "asset": GHS, "amount": {"value": 1, "scale": 2, "asset": USD}},
            "not-an-object",
        ):
            with self.subTest(detail=detail):
                effect = _effect_result(
                    "plan/req-1/result", payer=A, payee=B, asset=USD, value=100,
                    detail=detail,
                )
                with self.assertRaises(CoreValidationError):
                    engine.recognize_obligation(
                        command_id=f"c2-{abs(hash(json.dumps(detail, default=str)))}",
                        requested_at=T0, cycle_id="clearing/cycle/c1",
                        effect_result=effect, due_from=T2, due_until=T3,
                    )

    def test_recognition_with_tampered_evidence_fails_closed(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        effect["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            engine.recognize_obligation(
                command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
                effect_result=effect, due_from=T2, due_until=T3,
            )

    def test_recognition_requires_open_cycle(self) -> None:
        engine, _ = _recognized_engine()  # cycle already FINALIZED
        effect = _effect_result("plan/req-2/result", payer=A, payee=B, asset=USD, value=100)
        with self.assertRaises(CoreValidationError) as raised:
            engine.recognize_obligation(
                command_id="c9", requested_at=T0, cycle_id="clearing/cycle/c1",
                effect_result=effect, due_from=T2, due_until=T3,
            )
        self.assertIn("OPEN", str(raised.exception))

    def test_duplicate_recognition_version_conflict(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        engine.recognize_obligation(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        transition = engine.recognize_obligation(
            command_id="c3", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        self.assertEqual(transition.outcome.value, "rejected")
        self.assertEqual(transition.reason.value if transition.reason else "", "version_conflict")

    def test_validate_repeats_reject(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError):
            engine.validate_obligation(
                command_id="cv2", requested_at=T0, obligation_id=obligation_id
            )

    def test_amend_changes_terms_with_reason(self) -> None:
        engine, obligation_id = _recognized_engine()
        transition = engine.amend_obligation(
            command_id="ca1", requested_at=T0, obligation_id=obligation_id,
            reason="partial credit memo", amount={"value": 90_000, "scale": 2, "asset": USD},
        )
        self.assertEqual(transition.outcome.value, "accepted")
        obligation = engine.obligation(obligation_id)
        self.assertEqual(obligation.state, ObligationState.AMENDED)
        self.assertEqual(obligation.spec.amount.value, 90_000)
        self.assertEqual(obligation.spec.amendment.reason, "partial credit memo")
        self.assertEqual(obligation.envelope.object_version, 3)

    def test_amend_without_term_change_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError) as raised:
            engine.amend_obligation(
                command_id="ca1", requested_at=T0, obligation_id=obligation_id, reason="noop"
            )
        self.assertIn("at least one term", str(raised.exception))

    def test_amend_from_disputed_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.dispute_obligation(
            command_id="cd1", requested_at=T0, obligation_id=obligation_id,
            evidence_ref="evidence/d1", epistemic_type="OBSERVED", reason="disputed",
        )
        with self.assertRaises(CoreValidationError):
            engine.amend_obligation(
                command_id="ca1", requested_at=T0, obligation_id=obligation_id,
                reason="amend while disputed",
            )

    def test_dispute_requires_observed_evidence(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError) as raised:
            engine.dispute_obligation(
                command_id="cd1", requested_at=T0, obligation_id=obligation_id,
                evidence_ref="evidence/d1", epistemic_type="SIMULATED",
                reason="simulated dispute",
            )
        self.assertIn("OBSERVED", str(raised.exception))

    def test_dispute_twice_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.dispute_obligation(
            command_id="cd1", requested_at=T0, obligation_id=obligation_id,
            evidence_ref="evidence/d1", epistemic_type="OBSERVED", reason="disputed",
        )
        with self.assertRaises(CoreValidationError):
            engine.dispute_obligation(
                command_id="cd2", requested_at=T0, obligation_id=obligation_id,
                evidence_ref="evidence/d2", epistemic_type="OBSERVED", reason="again",
            )

    def test_dispute_then_restructure_with_new_terms(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.dispute_obligation(
            command_id="cd1", requested_at=T0, obligation_id=obligation_id,
            evidence_ref="evidence/d1", epistemic_type="OBSERVED", reason="disputed",
        )
        transition = engine.restructure_obligation(
            command_id="cr1", requested_at=T0, obligation_id=obligation_id,
            evidence_ref="evidence/r1", epistemic_type="OBSERVED",
            reason="settled at 80%", amount={"value": 80_000, "scale": 2, "asset": USD},
        )
        self.assertEqual(transition.outcome.value, "accepted")
        obligation = engine.obligation(obligation_id)
        self.assertEqual(obligation.state, ObligationState.RESTRUCTURED)
        self.assertEqual(obligation.spec.amount.value, 80_000)
        self.assertIsNotNone(obligation.spec.dispute)
        self.assertIsNotNone(obligation.spec.restructure)

    def test_restructure_requires_disputed_source(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError) as raised:
            engine.restructure_obligation(
                command_id="cr1", requested_at=T0, obligation_id=obligation_id,
                evidence_ref="evidence/r1", epistemic_type="OBSERVED",
                reason="no dispute open",
                amount={"value": 90_000, "scale": 2, "asset": USD},
            )
        self.assertIn("DISPUTED", str(raised.exception))

    def test_mark_due_before_window_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError) as raised:
            engine.mark_due_obligation(
                command_id="cm1", requested_at=T0, obligation_id=obligation_id
            )
        self.assertIn("due window opens", str(raised.exception))

    def test_mark_due_with_held_funding(self) -> None:
        engine, obligation_id = _recognized_engine()
        transition = engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id,
            funding={"reservation_id": "reservation/r1", "state": "HELD", "object_version": 2},
        )
        self.assertEqual(transition.outcome.value, "accepted")
        obligation = engine.obligation(obligation_id)
        self.assertEqual(obligation.state, ObligationState.DUE)
        assert obligation.spec.due is not None
        assert obligation.spec.due.funding is not None
        self.assertEqual(obligation.spec.due.funding.reservation_id, "reservation/r1")

    def test_mark_due_with_non_held_funding_fails_closed(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError) as raised:
            engine.mark_due_obligation(
                command_id="cm1", requested_at=T2, obligation_id=obligation_id,
                funding={
                    "reservation_id": "reservation/r1",
                    "state": "RELEASED",
                    "object_version": 2,
                },
            )
        self.assertIn("HELD", str(raised.exception))

    def test_mark_due_twice_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id
        )
        with self.assertRaises(CoreValidationError):
            engine.mark_due_obligation(
                command_id="cm2", requested_at=T2, obligation_id=obligation_id
            )

    def test_default_requires_due_source_and_observed_evidence(self) -> None:
        engine, obligation_id = _recognized_engine()
        with self.assertRaises(CoreValidationError):
            engine.default_obligation(
                command_id="cx1", requested_at=T2, obligation_id=obligation_id,
                evidence_ref="evidence/x1", epistemic_type="OBSERVED", reason="dishonored",
            )  # not DUE yet
        engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id
        )
        transition = engine.default_obligation(
            command_id="cx2", requested_at=T3, obligation_id=obligation_id,
            evidence_ref="evidence/x1", epistemic_type="OBSERVED", reason="dishonored",
        )
        self.assertEqual(transition.outcome.value, "accepted")
        self.assertEqual(engine.obligation(obligation_id).state, ObligationState.DEFAULTED)

    def test_resolve_records_discharge_evidence_never_finality(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id
        )
        transition = engine.resolve_obligation(
            command_id="cr1", requested_at=T3, obligation_id=obligation_id,
            evidence_ref="settlement/discharge-1", evidence_digest="e" * 64,
            reason="rail-reported discharge",
        )
        self.assertEqual(transition.outcome.value, "accepted")
        obligation = engine.obligation(obligation_id)
        self.assertEqual(obligation.state, ObligationState.RESOLVED)
        assert obligation.spec.resolution is not None
        self.assertEqual(obligation.spec.resolution.kind, ResolutionKind.DISCHARGE_EVIDENCE)
        self.assertEqual(obligation.spec.resolution.digest, "e" * 64)

    def test_resolve_bad_digest_rejects(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id
        )
        with self.assertRaises(CoreValidationError):
            engine.resolve_obligation(
                command_id="cr1", requested_at=T3, obligation_id=obligation_id,
                evidence_ref="settlement/discharge-1", evidence_digest="not-a-digest",
                reason="bad digest",
            )

    def test_terminal_states_admit_no_transitions(self) -> None:
        engine, obligation_id = _recognized_engine()
        engine.mark_due_obligation(
            command_id="cm1", requested_at=T2, obligation_id=obligation_id
        )
        engine.default_obligation(
            command_id="cx1", requested_at=T3, obligation_id=obligation_id,
            evidence_ref="evidence/x1", epistemic_type="OBSERVED", reason="dishonored",
        )
        for name, method, kwargs in (
            ("validate", engine.validate_obligation, {}),
            ("amend", engine.amend_obligation, {"reason": "r"}),
            ("dispute", engine.dispute_obligation, {"evidence_ref": "e", "epistemic_type": "OBSERVED", "reason": "r"}),
            ("mark-due", engine.mark_due_obligation, {}),
            ("default", engine.default_obligation, {"evidence_ref": "e", "epistemic_type": "OBSERVED", "reason": "r"}),
            ("resolve", engine.resolve_obligation, {"evidence_ref": "e", "evidence_digest": "e" * 64, "reason": "r"}),
        ):
            with self.subTest(command=name):
                with self.assertRaises(CoreValidationError):
                    method(
                        command_id=f"t-{name}", requested_at=T3,
                        obligation_id=obligation_id, **kwargs
                    )


# ---------------------------------------------------------------------------
# engine: netting lifecycle
# ---------------------------------------------------------------------------


def _nettable_engine() -> tuple[ClearingEngine, list[str]]:
    """Engine with a finalized cycle and two validated reciprocal obligations."""
    engine = _new_engine()
    engine.create_cycle(
        command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
        opens_at=T0, closes_at=T1,
    )
    ids = []
    for index, (payer, payee, value) in enumerate(
        ((A, B, 2_500_000), (B, A, 1_000_000)), start=1
    ):
        effect = _effect_result(
            f"plan/req-{index}/result", payer=payer, payee=payee, asset=USD, value=value
        )
        engine.recognize_obligation(
            command_id=f"c{index + 1}", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        obligation_id = f"plan/req-{index}/result/obligation"
        ids.append(obligation_id)
        engine.validate_obligation(
            command_id=f"cv{index}", requested_at=T0, obligation_id=obligation_id
        )
    engine.validate_cycle(command_id="cval", requested_at=T0, cycle_id="clearing/cycle/c1")
    engine.finalize_cycle(command_id="cfin", requested_at=T0, cycle_id="clearing/cycle/c1")
    return engine, ids


class NettingLifecycleTests(unittest.TestCase):
    def test_add_requires_cycle_cleared_obligation(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        effect = _effect_result("plan/req-1/result", payer=A, payee=B, asset=USD, value=100)
        engine.recognize_obligation(
            command_id="c2", requested_at=T0, cycle_id="clearing/cycle/c1",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        engine.validate_obligation(
            command_id="c3", requested_at=T0, obligation_id="plan/req-1/result/obligation"
        )
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.add_netting_member(
                command_id="n2", requested_at=T0, netting_id="clearing/netting/n1",
                obligation_id="plan/req-1/result/obligation",
            )
        self.assertIn("cycle-cleared", str(raised.exception))

    def test_add_requires_validated_obligation(self) -> None:
        engine, _ = _nettable_engine()
        effect = _effect_result("plan/req-9/result", payer=A, payee=B, asset=USD, value=100)
        # Recognize into a fresh cycle but never validate.
        engine.create_cycle(
            command_id="c10", requested_at=T0, cycle_id="clearing/cycle/c2",
            opens_at=T0, closes_at=T1,
        )
        engine.recognize_obligation(
            command_id="c11", requested_at=T0, cycle_id="clearing/cycle/c2",
            effect_result=effect, due_from=T2, due_until=T3,
        )
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.add_netting_member(
                command_id="n2", requested_at=T0, netting_id="clearing/netting/n1",
                obligation_id="plan/req-9/result/obligation",
            )
        self.assertIn("RECOGNIZED", str(raised.exception))

    def test_add_exclusivity_fails_closed(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        engine.add_netting_member(
            command_id="n2", requested_at=T0, netting_id="clearing/netting/n1",
            obligation_id=ids[0],
        )
        engine.create_netting(
            command_id="n3", requested_at=T0, netting_id="clearing/netting/n2",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.add_netting_member(
                command_id="n4", requested_at=T0, netting_id="clearing/netting/n2",
                obligation_id=ids[0],
            )
        self.assertIn("at most one live netting", str(raised.exception))

    def test_add_after_cancel_allows_remembership(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        engine.add_netting_member(
            command_id="n2", requested_at=T0, netting_id="clearing/netting/n1",
            obligation_id=ids[0],
        )
        engine.cancel_netting(
            command_id="n3", requested_at=T0, netting_id="clearing/netting/n1", reason="abandoned"
        )
        engine.create_netting(
            command_id="n4", requested_at=T0, netting_id="clearing/netting/n2",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        transition = engine.add_netting_member(
            command_id="n5", requested_at=T0, netting_id="clearing/netting/n2",
            obligation_id=ids[0],
        )
        self.assertEqual(transition.outcome.value, "accepted")

    def test_remove_member_then_recalculate(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        transition = engine.remove_netting_member(
            command_id="nr1", requested_at=T0, netting_id="clearing/netting/n1",
            obligation_id=ids[1],
        )
        self.assertEqual(transition.outcome.value, "accepted")
        self.assertEqual(engine.netting("clearing/netting/n1").spec.member_ids, (ids[0],))
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        statement = engine.netting("clearing/netting/n1").spec.statement
        assert statement is not None
        self.assertEqual(statement.member_total, 1)
        self.assertEqual(statement.reduction, 0)  # no reciprocity left

    def test_calculate_requires_members(self) -> None:
        engine, _ = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        with self.assertRaises(CoreValidationError):
            engine.calculate_netting(
                command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
            )

    def test_bilateral_finalize_resolves_and_issues(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        statement = engine.netting("clearing/netting/n1").spec.statement
        assert statement is not None
        transition = engine.finalize_netting(
            command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        self.assertEqual(transition.outcome.value, "accepted")
        for obligation_id in ids:
            obligation = engine.obligation(obligation_id)
            self.assertEqual(obligation.state, ObligationState.RESOLVED)
            assert obligation.spec.resolution is not None
            self.assertEqual(obligation.spec.resolution.kind, ResolutionKind.NETTING)
            self.assertEqual(obligation.spec.resolution.ref, "clearing/netting/n1")
            self.assertEqual(obligation.spec.resolution.digest, statement.digest)
        issued = engine.netting("clearing/netting/n1").spec.statement.groups[0].pairs[0].issued_obligation_id
        assert issued is not None
        net_obligation = engine.obligation(issued)
        self.assertEqual(net_obligation.state, ObligationState.RECOGNIZED)
        self.assertEqual(net_obligation.spec.source_kind, ObligationSourceKind.NETTING_ISSUANCE)
        self.assertEqual(net_obligation.spec.amount.value, 1_500_000)
        self.assertEqual(net_obligation.spec.obligor, A)
        self.assertEqual(net_obligation.spec.cycle_id, None)
        self.assertEqual(net_obligation.spec.source_digest, statement.digest)

    def test_finalize_stale_statement_fails_closed(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        # Mutate a member AFTER calculation: the statement is now stale.
        engine.amend_obligation(
            command_id="na1", requested_at=T0, obligation_id=ids[0],
            reason="post-calculation amendment", amount={"value": 2_000_000, "scale": 2, "asset": USD},
        )
        with self.assertRaises(CoreValidationError) as raised:
            engine.finalize_netting(
                command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
            )
        self.assertIn("stale", str(raised.exception))
        # Nothing was committed: members are untouched.
        self.assertEqual(engine.obligation(ids[0]).state, ObligationState.AMENDED)
        self.assertEqual(engine.obligation(ids[1]).state, ObligationState.VALIDATED)
        self.assertEqual(engine.netting("clearing/netting/n1").state, NettingCycleState.CALCULATED)

    def test_multilateral_finalize_issues_nothing(self) -> None:
        engine = _new_engine()
        engine.create_cycle(
            command_id="c1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        triangle = ((A, B, 400_000), (B, C, 550_000), (C, A, 300_000))
        ids = []
        for index, (payer, payee, value) in enumerate(triangle, start=1):
            effect = _effect_result(
                f"plan/req-{index}/result", payer=payer, payee=payee, asset=USD, value=value
            )
            engine.recognize_obligation(
                command_id=f"c{index + 1}", requested_at=T0, cycle_id="clearing/cycle/c1",
                effect_result=effect, due_from=T2, due_until=T3,
            )
            obligation_id = f"plan/req-{index}/result/obligation"
            ids.append(obligation_id)
            engine.validate_obligation(
                command_id=f"cv{index}", requested_at=T0, obligation_id=obligation_id
            )
        engine.validate_cycle(command_id="cval", requested_at=T0, cycle_id="clearing/cycle/c1")
        engine.finalize_cycle(command_id="cfin", requested_at=T0, cycle_id="clearing/cycle/c1")
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="MULTILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        transition = engine.finalize_netting(
            command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        self.assertEqual(transition.outcome.value, "accepted")
        statement = engine.netting("clearing/netting/n1").spec.statement
        assert statement is not None
        self.assertFalse(
            any(pair.issued_obligation_id is not None for group in statement.groups for pair in group.pairs)
        )
        for obligation_id in ids:
            self.assertEqual(engine.obligation(obligation_id).state, ObligationState.RESOLVED)

    def test_self_netting_rejects_own_issuance(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        engine.finalize_netting(
            command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        issued = engine.netting("clearing/netting/n1").spec.statement.groups[0].pairs[0].issued_obligation_id
        assert issued is not None
        engine.validate_obligation(
            command_id="nv1", requested_at=T0, obligation_id=issued
        )
        # Re-open the same cycle (cancelled + fresh) and try to net its own issuance.
        engine.create_netting(
            command_id="n9", requested_at=T0, netting_id="clearing/netting/n2",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        transition = engine.add_netting_member(
            command_id="n10", requested_at=T0, netting_id="clearing/netting/n2",
            obligation_id=issued,
        )
        # The issued obligation's cycle_id is None and it is VALIDATED —
        # but it was issued BY n1 (a terminal cycle), so joining n2 is fine.
        # Joining its OWN issuing cycle is impossible (n1 is FINALIZED).
        self.assertEqual(transition.outcome.value, "accepted")

    def test_finalize_from_open_rejects(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        engine.add_netting_member(
            command_id="n2", requested_at=T0, netting_id="clearing/netting/n1",
            obligation_id=ids[0],
        )
        with self.assertRaises(CoreValidationError):
            engine.finalize_netting(
                command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
            )


# ---------------------------------------------------------------------------
# engine: kernel binding, rebuild, snapshot
# ---------------------------------------------------------------------------


class EngineKernelTests(unittest.TestCase):
    def test_journal_events_use_the_clearing_namespace(self) -> None:
        engine, _ = _recognized_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for entry in engine.journal:
            self.assertTrue(entry.event.event_type.startswith("clearing/"))
            self.assertIn(entry.event.event_type, set(COMMAND_EVENT_TYPES.values()))

    def test_journal_rebuild_reproduces_index_byte_identically(self) -> None:
        engine, ids = _nettable_engine()
        engine.create_netting(
            command_id="n1", requested_at=T0, netting_id="clearing/netting/n1",
            mode="BILATERAL", due_from=T2, due_until=T3,
        )
        for index, obligation_id in enumerate(ids, start=1):
            engine.add_netting_member(
                command_id=f"n{index + 1}", requested_at=T0,
                netting_id="clearing/netting/n1", obligation_id=obligation_id,
            )
        engine.calculate_netting(
            command_id="nc1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        engine.finalize_netting(
            command_id="nf1", requested_at=T0, netting_id="clearing/netting/n1"
        )
        rebuilt = ClearingEngine.rebuild_from_journal(
            environment_id=ENV, domain_id=DOMAIN, journal=engine.journal
        )
        self.assertEqual(engine.snapshot_state()["index"], rebuilt.snapshot_state()["index"])
        self.assertEqual(
            engine.netting("clearing/netting/n1").spec.statement,
            rebuilt.netting("clearing/netting/n1").spec.statement,
        )

    def test_snapshot_round_trip_is_identical(self) -> None:
        engine, _ = _recognized_engine()
        snapshot = engine.snapshot_state()
        fresh = ClearingEngine(environment_id=ENV, domain_id=DOMAIN)
        fresh.restore_state(snapshot)
        self.assertEqual(fresh.snapshot_state(), snapshot)

    def test_snapshot_tampering_fails_closed(self) -> None:
        engine, _ = _recognized_engine()
        snapshot = engine.snapshot_state()
        obligation_id = "plan/req-1/result/obligation"
        snapshot["index"][obligation_id]["integrity_hash"] = "0" * 64
        fresh = ClearingEngine(environment_id=ENV, domain_id=DOMAIN)
        with self.assertRaises(CoreValidationError):
            fresh.restore_state(snapshot)

    def test_unauthorized_actor_rejected(self) -> None:
        engine = _new_engine()
        command = engine.build_raw_command(
            command_id="x1", command_type="clearing/cycle.create", requested_at=T0,
            target_refs=("clearing/cycle/c1",),
            payload={
                "cycle_id": "clearing/cycle/c1",
                "window": {"opens_at": T0, "closes_at": T1},
                "description": "",
            },
            expected_versions={"clearing/cycle/c1": 0},
            actor="principal/attacker",
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")
        self.assertEqual(transition.reason.value if transition.reason else "", "unauthorized")

    def test_unknown_command_type_rejected(self) -> None:
        engine = _new_engine()
        command = engine.build_raw_command(
            command_id="x1", command_type="clearing/cycle.destroy", requested_at=T0,
            target_refs=("clearing/cycle/c1",), payload={},
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")
        self.assertEqual(transition.reason.value if transition.reason else "", "unknown_command_type")

    def test_environment_mismatch_rejected(self) -> None:
        engine = _new_engine()
        command = engine.build_raw_command(
            command_id="x1", command_type="clearing/cycle.create", requested_at=T0,
            target_refs=("clearing/cycle/c1",),
            payload={
                "cycle_id": "clearing/cycle/c1",
                "window": {"opens_at": T0, "closes_at": T1},
                "description": "",
            },
            expected_versions={"clearing/cycle/c1": 0},
            environment_id="env/other",
        )
        transition = engine.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")

    def test_duplicate_command_id_converges(self) -> None:
        engine = _new_engine()
        first = engine.create_cycle(
            command_id="dup-1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        second = engine.create_cycle(
            command_id="dup-1", requested_at=T0, cycle_id="clearing/cycle/c1",
            opens_at=T0, closes_at=T1,
        )
        self.assertEqual(first.outcome.value, "accepted")
        self.assertEqual(second.outcome.value, "duplicate")
        self.assertEqual(len(engine.journal), 1)


# ---------------------------------------------------------------------------
# dogfooding conformance
# ---------------------------------------------------------------------------


class DogfoodingConformanceTests(unittest.TestCase):
    def test_transcript_classifies_pass_and_proves_reduction(self) -> None:
        from src.clearing.dogfooding import build_transcript

        transcript = build_transcript()
        self.assertEqual(transcript["classification"], "PASS")
        self.assertTrue(all(transcript["checks"].values()))
        reduction = transcript["gross_to_net_capital_reduction"]
        self.assertGreater(reduction["reduction_base_minor"], 0)
        self.assertLess(reduction["net_base_minor"], reduction["gross_base_minor"])
        # 49% capital reduction on reciprocal cross-border demand.
        self.assertEqual(reduction["reduction_base_minor"], 2_187_999)
        self.assertEqual(reduction["reduction_ratio_bp"], 4_906)
        self.assertTrue(transcript["transformation_completeness"]["journal_rebuild_index_match"])
        self.assertTrue(transcript["transformation_completeness"]["snapshot_round_trip_match"])

    def test_transcript_is_deterministic(self) -> None:
        from src.clearing.dogfooding import build_transcript

        first = build_transcript()
        second = build_transcript()
        self.assertEqual(canonical_json(first), canonical_json(second))


if __name__ == "__main__":
    unittest.main()
