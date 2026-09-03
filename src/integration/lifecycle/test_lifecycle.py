"""WORK-027 / IG-002 contract suite — the fulfillment lifecycle integration gate.

Red-first authored against the public boundary of
``src.integration.lifecycle`` (the IG-002 gate). The suite pins:

* the typed, versioned gate identity (IG-002) and its consumed-surface
  discipline (AST import audit, no floats, no wall clock/entropy, import
  closure) — the IG-001 convention applied to the lifecycle subpackage;
* the deterministic declared world (real sibling-domain records only);
* the full composed lifecycle intent → compilation → execution → real
  adapter port → clearing → obligation → netting → settlement →
  reconciliation → finality certificate, on the local deterministic
  sandbox rail (LOCAL_DETERMINISTIC_SANDBOX);
* the dangerous paths: idempotency (no double economic effect), the
  unknown/recovery discipline (reconcile before retry), fail-closed
  probes (skipped preconditions, lifecycle guards, cross-domain and
  cross-environment inputs, tampered composites, payment status never
  promoted to finality);
* offline mode (provider absent → NOT ATTEMPTED, never fake success);
* deterministic journal-driven replay of the composed state;
* the DOGFOOD-027 conformance transcript (local rail).
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import unittest

from src.core.errors import CoreValidationError

import src.integration.lifecycle as gate_package

#: The repository root (for the isolated subprocess audit).
_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[3])


# ---------------------------------------------------------------------------
# 1. static boundary
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    def test_gate_identity_constants(self) -> None:
        self.assertEqual(gate_package.LIFECYCLE_GATE_ID, "IG-002")
        self.assertEqual(gate_package.LIFECYCLE_API_VERSION, "v0.1")
        self.assertEqual(gate_package.LIFECYCLE_SCHEMA_VERSION, 1)
        self.assertEqual(
            gate_package.KNOWN_LIFECYCLE_GATES, frozenset({"IG-002"})
        )

    def test_public_boundary_all_is_explicit_frozen_and_sorted(self) -> None:
        exported = gate_package.__all__
        self.assertTrue(exported)
        self.assertEqual(list(exported), sorted(exported))
        self.assertEqual(len(exported), len(set(exported)))
        module = vars(gate_package)
        for name in exported:
            self.assertIn(name, module, f"__all__ exports missing {name}")

    def test_consumed_surfaces_cover_exactly_the_declared_roots(self) -> None:
        expected = {
            "src.core",
            "src.transition",
            "src.money",
            "src.intent",
            "src.capability",
            "src.market",
            "src.liquidity",
            "src.reservation",
            "src.safety",
            "src.evidence",
            "src.interoperability",
            "src.compiler",
            "src.execution",
            "src.clearing",
            "src.settlement",
        }
        self.assertEqual(set(gate_package.CONSUMED_SURFACES), expected)

    def test_lifecycle_modules_import_only_consumed_roots(self) -> None:
        allowed = set(gate_package.CONSUMED_SURFACES)
        package = pathlib.Path(__file__).parent
        sources = sorted(path for path in package.glob("*.py"))
        self.assertTrue(sources)
        for source in sources:
            if source.name.startswith("test_"):
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        if root == "src":
                            prefix = ".".join(alias.name.split(".")[:2])
                            self.assertIn(
                                prefix, allowed, f"{source.name} imports {alias.name}"
                            )
                        else:
                            self.assertIn(
                                root,
                                sys.stdlib_module_names,
                                f"{source.name} imports {alias.name}",
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.level >= 1:
                        continue
                    module = node.module or ""
                    root = module.split(".", 1)[0]
                    if root == "__future__":
                        continue
                    if root == "src":
                        prefix = ".".join(module.split(".")[:2])
                        self.assertIn(
                            prefix, allowed, f"{source.name} imports from {module}"
                        )
                    else:
                        self.assertIn(
                            root,
                            sys.stdlib_module_names,
                            f"{source.name} imports from {module}",
                        )

    def test_lifecycle_sources_contain_no_float_literals(self) -> None:
        package = pathlib.Path(__file__).parent
        sources = sorted(
            path for path in package.glob("*.py") if not path.name.startswith("test")
        )
        self.assertTrue(sources)
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, float):
                    self.fail(f"float literal found in {path.name} at line {node.lineno}")

    def test_lifecycle_code_has_no_wall_clock_entropy_or_uuids(self) -> None:
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name.startswith("test_") or source.name == "dogfooding.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "time.monotonic",
                "time.process_time",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_importing_the_gate_loads_only_composed_roots(self) -> None:
        # CONSUMED_SURFACES are the DIRECT imports (AST-audited); the
        # transitive closure adds the parent package and the consumed
        # domains' own declared dependencies (src.value via clearing,
        # src.simulation via the execution domain's EffectAuthorization
        # re-export, src.trust via the evidence domain's attestations).
        # The audit runs in an isolated subprocess that imports ONLY the
        # gate package, so the observed closure is exactly what the gate
        # loads (order-robust in fresh-process and combined runs alike —
        # the sibling-convention import-closure pin).
        allowed = set(gate_package.CONSUMED_SURFACES) | {
            "src.integration",
            "src.value",
            "src.simulation",
            "src.trust",
        }
        code = (
            "import sys, json\n"
            "import src.integration.lifecycle\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('src.'))))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = json.loads(result.stdout)
        self.assertTrue(loaded, "the gate import must load its composed roots")
        for name in loaded:
            prefix = ".".join(name.split(".")[:2])
            self.assertIn(
                prefix,
                allowed,
                f"importing src.integration.lifecycle loaded {name}",
            )

    def test_validate_lifecycle_gate_id_fails_closed_on_unknown_gate(self) -> None:
        self.assertEqual(
            gate_package.validate_lifecycle_gate_id("IG-002"), "IG-002"
        )
        for unknown in ("IG-001", "IG-003", "ig-002", "", None, 1):
            with self.assertRaises(CoreValidationError):
                gate_package.validate_lifecycle_gate_id(unknown)

    def test_the_gate_declares_itself_an_ig002_composition(self) -> None:
        docstring = gate_package.__doc__ or ""
        self.assertIn("IG-002", docstring)
        self.assertIn("integration", docstring.lower())


# ---------------------------------------------------------------------------
# 2. the deterministic declared world
# ---------------------------------------------------------------------------


class WorldConstructionTests(unittest.TestCase):
    def test_build_declared_world_is_deterministic(self) -> None:
        from src.integration.lifecycle import build_declared_world
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            PAYEE,
            PAYER,
            WORLD_TAG,
        )

        first = build_declared_world(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            tag=WORLD_TAG,
            payer=PAYER,
            payee=PAYEE,
            amount_minor=10000,
        )
        second = build_declared_world(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            tag=WORLD_TAG,
            payer=PAYER,
            payee=PAYEE,
            amount_minor=10000,
        )
        self.assertEqual(
            first.intent.to_dict(), second.intent.to_dict()
        )
        self.assertEqual(first.hops[0].to_dict(), second.hops[0].to_dict())

    def test_the_world_carries_only_real_sibling_records(self) -> None:
        from src.integration.lifecycle import build_declared_world
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            PAYEE,
            PAYER,
            WORLD_TAG,
        )
        from src.intent import IntentState
        from src.reservation import ReservationState

        world = build_declared_world(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            tag=WORLD_TAG,
            payer=PAYER,
            payee=PAYEE,
            amount_minor=10000,
        )
        self.assertIs(world.intent.state, IntentState.AUTHORIZED)
        self.assertTrue(world.hops)
        for reservation in world.reservations.values():
            self.assertIs(reservation.state, ReservationState.HELD)
        for gate in world.fraud_gates.values():
            self.assertEqual(gate["verdict"], "ALLOW")
        for gate in world.compliance_gates.values():
            self.assertEqual(gate["verdict"], "SATISFIED")
        self.assertEqual(world.payment_legs[world.hops[0].hop_id]["asset"], "USD")
        self.assertEqual(
            world.payment_legs[world.hops[0].hop_id]["amount"]["value"], 10000
        )
        self.assertEqual(world.authorization["authority_class"], "A2")


# ---------------------------------------------------------------------------
# 3. the composed lifecycle on the local deterministic sandbox rail
# ---------------------------------------------------------------------------


class ComposedLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )

        cls.rail = LocalDeterministicRail()
        cls.binding = make_local_binding(cls.rail)
        cls.gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={cls.binding.adapter_id: cls.binding},
        )
        cls.outcome = canonical_lifecycle(cls.gate)

    def test_every_stage_was_accepted(self) -> None:
        for stage in self.gate.stage_journal:
            self.assertEqual(stage["outcome"], "accepted", stage["stage"])
        self.assertTrue(self.outcome["finality_established"])
        self.assertTrue(self.outcome["obligation_resolved"])

    def test_intent_authorization_used_the_real_intent_domain(self) -> None:
        from src.intent import IntentState

        self.assertIs(self.gate.world.intent.state, IntentState.AUTHORIZED)

    def test_compilation_used_the_real_compiler_domain(self) -> None:
        from src.compiler import PlanState

        plan = self.gate.plans[0]
        self.assertIs(plan.state, PlanState.ACCEPTED)
        self.assertEqual(
            plan.spec.intent_id, self.gate.world.intent.object_id
        )
        delivered = plan.spec.totals["total_delivered_value"]
        self.assertGreaterEqual(delivered, 9900)
        self.assertLessEqual(delivered, 10100)

    def test_execution_reached_the_real_terminal_state(self) -> None:
        from src.execution import ExecutionPlanState

        plan = self.gate.execution.plan(
            self.gate.execution_plans[0]
        )
        self.assertIs(plan.state, ExecutionPlanState.COMPLETED)

    def test_clearing_recognized_the_obligation_from_execution_evidence(self) -> None:
        from src.clearing import ObligationState

        obligation = self.gate.clearing.obligation(self.outcome["obligation_ids"][0])
        self.assertIs(obligation.state, ObligationState.RESOLVED)
        self.assertEqual(obligation.spec.source_kind, "EXECUTION_EVIDENCE")
        result = self.gate.execution.effect_result(obligation.spec.source_ref)
        self.assertEqual(obligation.spec.source_digest, result.integrity_hash)
        from src.transition.payload import payload_to_json_value

        detail = payload_to_json_value(result.spec.detail)
        self.assertEqual(
            obligation.spec.amount.value,
            detail["amount"]["value"],
        )

    def test_settlement_folded_the_real_rail_evidence(self) -> None:
        from src.settlement import LegState, SettlementState

        settlement = self.gate.settlement.settlement(self.outcome["settlement_id"])
        self.assertIs(settlement.state, SettlementState.COMPLETED)
        outcomes = {
            outcome.instruction_id: LegState(outcome.state)
            for outcome in settlement.spec.leg_outcomes
        }
        self.assertTrue(
            all(state is LegState.SETTLED for state in outcomes.values())
        )

    def test_finality_certificate_followed_the_settlement_authority(self) -> None:
        from src.settlement import FinalityState

        certificate = self.gate.settlement.finality(self.outcome["finality_id"])
        self.assertIs(certificate.state, FinalityState.ESTABLISHED)
        self.assertEqual(
            certificate.spec.settlement_id, self.outcome["settlement_id"]
        )
        self.assertTrue(certificate.spec.claims)

    def test_invariant_battery_passed_after_every_stage(self) -> None:
        checks = self.outcome["invariant_checks"]
        self.assertTrue(checks)
        self.assertIn("accounting: obligation amounts derive from execution evidence", checks)
        self.assertIn("settlement truth: finality derives from settled legs only", checks)

    def test_stage_journal_is_append_only_and_chained(self) -> None:
        journal = self.gate.stage_journal
        self.assertGreater(len(journal), 20)
        for previous, current in zip(journal, journal[1:]):
            self.assertEqual(previous["state_after"], current["state_before"])
        # Digests may repeat only across rejected/duplicate stages; a new
        # accepted stage always moves the composed state.
        for previous, current in zip(journal, journal[1:]):
            if current["outcome"] == "accepted":
                self.assertNotEqual(
                    current["state_before"], current["state_after"]
                )


# ---------------------------------------------------------------------------
# 4. netting composition
# ---------------------------------------------------------------------------


class NettingCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import netting_lifecycle

        cls.rail = LocalDeterministicRail()
        binding = make_local_binding(cls.rail)
        cls.gate = FulfillmentLifecycleGate(
            environment_id="env/sandbox-ig002-netting-test",
            domain_id="domain/ig002-netting-test",
            bindings={binding.adapter_id: binding},
        )
        cls.outcome = netting_lifecycle(cls.gate)

    def test_two_reciprocal_obligations_were_executed(self) -> None:
        self.assertEqual(len(self.outcome["obligation_ids"]), 2)

    def test_netting_statement_reduced_gross_exposure(self) -> None:
        netting = self.gate.clearing.netting(self.outcome["netting_id"])
        statement = netting.spec.statement
        self.assertIsNotNone(statement)
        self.assertEqual(statement.gross_total, 18000)
        self.assertEqual(statement.net_total, 2000)
        self.assertEqual(statement.reduction, 16000)
        for group in statement.groups:
            if group.pairs:
                self.assertEqual(
                    sum(pair.forward for pair in group.pairs), group.net_total
                )

    def test_netting_finalization_resolved_members_and_issued_net(self) -> None:
        from src.clearing import ObligationState

        for obligation_id in self.outcome["obligation_ids"]:
            obligation = self.gate.clearing.obligation(obligation_id)
            self.assertIs(obligation.state, ObligationState.RESOLVED)
            self.assertEqual(obligation.spec.resolution.kind, "NETTING")
        net_obligation = self.gate.clearing.obligation(
            self.outcome["net_obligation_id"]
        )
        self.assertEqual(net_obligation.spec.amount.value, 2000)
        self.assertEqual(net_obligation.spec.source_kind, "NETTING_ISSUANCE")

    def test_the_net_obligation_settled_to_finality(self) -> None:
        from src.settlement import FinalityState, SettlementState

        settlement = self.gate.settlement.settlement(self.outcome["settlement_id"])
        self.assertIs(settlement.state, SettlementState.COMPLETED)
        certificate = self.gate.settlement.finality(self.outcome["finality_id"])
        self.assertIs(certificate.state, FinalityState.ESTABLISHED)
        resolved = self.gate.clearing.obligation(self.outcome["net_obligation_id"])
        self.assertEqual(resolved.spec.resolution.kind, "DISCHARGE_EVIDENCE")


# ---------------------------------------------------------------------------
# 5. idempotency discipline
# ---------------------------------------------------------------------------


class IdempotencyTests(unittest.TestCase):
    def test_duplicate_effect_submission_never_calls_the_port_twice(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            run_fulfillment_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="submitted")
        step_id = outcome["step_ids"][0]
        key = outcome["idempotency_keys"][0]
        # Replaying the same submission: the port must NEVER be called again.
        first_calls = rail.submit_call_count
        replay = gate.stage_submit_effect(
            step_id,
            command_id="idem/submit-replay",
            requested_at="2026-09-04T00:16:30Z",
        )
        self.assertEqual(replay["outcome"], "duplicate")
        self.assertEqual(rail.submit_call_count, first_calls)
        # The rail processed exactly one economic key.
        self.assertEqual(rail.processed_key_count, 1)
        self.assertIn(key, rail.processed_keys)

    def test_duplicate_effect_declaration_converges_without_rebinding(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            run_fulfillment_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="requested")
        step_id = outcome["step_ids"][0]
        world = gate.world
        from src.integration.lifecycle.scenarios import T_REQUEST

        replay = gate.stage_request_effect(
            step_id,
            idempotency_key=outcome["idempotency_keys"][0],
            command_id="idem/request-replay",
            requested_at=T_REQUEST,
            world=world,
        )
        self.assertEqual(replay["outcome"], "duplicate")

    def test_recognizing_the_same_evidence_twice_fails_closed(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = canonical_lifecycle(gate)
        before = gate.composed_digest()
        obligation_count = len(
            [
                record
                for record in gate.clearing.records()
                if record.__class__.__name__ == "Obligation"
            ]
        )
        entry = gate.stage_recognize_obligation(
            cycle_id=outcome["cycle_id"],
            step_id=outcome["step_ids"][0],
            due_from="2026-09-04T01:00:00Z",
            due_until="2026-09-05T06:00:00Z",
            command_id="idem/recognize-2",
            requested_at="2026-09-04T00:31:00Z",
        )
        # The duplicate recognition converges to an explicit rejection
        # (the obligation already exists; the kernel's absence precondition).
        self.assertEqual(entry["outcome"], "rejected")
        self.assertEqual(gate.composed_digest(), before)
        self.assertEqual(
            len(
                [
                    record
                    for record in gate.clearing.records()
                    if record.__class__.__name__ == "Obligation"
                ]
            ),
            obligation_count,
        )

    def test_no_duplicate_authoritative_posting_or_finality(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = canonical_lifecycle(gate)
        discharge = [
            entry
            for entry in gate.settlement.postings()
            if entry.kind == "DISCHARGE"
        ]
        self.assertEqual(len(discharge), 1)
        certificates = [
            record
            for record in gate.settlement.records()
            if record.__class__.__name__ == "Finality"
        ]
        self.assertEqual(len(certificates), 1)


# ---------------------------------------------------------------------------
# 6. unknown outcome and recovery discipline
# ---------------------------------------------------------------------------


class RecoveryDisciplineTests(unittest.TestCase):
    def test_unknown_submission_reconciles_before_any_retry(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import recovery_lifecycle

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id="env/sandbox-ig002-recovery-test",
            domain_id="domain/ig002-recovery-test",
            bindings={binding.adapter_id: binding},
        )
        outcome = recovery_lifecycle(gate)
        self.assertEqual(outcome["first_submission_state"], "UNKNOWN")
        self.assertEqual(outcome["reconciliation_outcome"], "NOT_FOUND")
        self.assertEqual(outcome["recovered"], True)
        self.assertIsNone(outcome.get("finality_established_at_recovery") or None)
        self.assertTrue(outcome["finality_established"])

    def test_a_failed_rail_effect_never_recognizes_an_obligation(self) -> None:
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import rejection_lifecycle

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id="env/sandbox-ig002-rejection-test",
            domain_id="domain/ig002-rejection-test",
            bindings={binding.adapter_id: binding},
        )
        outcome = rejection_lifecycle(gate)
        self.assertEqual(outcome["step_state"], "FAILED")
        self.assertEqual(outcome["plan_state"], "FAILED")
        self.assertEqual(outcome["obligation_count"], 0)
        self.assertEqual(outcome["obligation_count_after"], 0)
        self.assertTrue(outcome["failed_recognition_rejected"])


# ---------------------------------------------------------------------------
# 7. fail-closed probes
# ---------------------------------------------------------------------------


class FailClosedProbeTests(unittest.TestCase):
    def _gate(self, environment="env/sandbox-ig002-probe-test"):
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=environment,
            domain_id="domain/ig002-probe-test",
            bindings={binding.adapter_id: binding},
        )
        return gate, rail

    def test_requesting_an_effect_before_the_plan_runs_fails_closed(self) -> None:
        from src.integration.lifecycle.scenarios import run_fulfillment_lifecycle

        gate, rail = self._gate()
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="created")
        before = gate.composed_digest()
        with self.assertRaises(CoreValidationError):
            gate.stage_request_effect(
                outcome["step_ids"][0],
                idempotency_key="probe/early",
                command_id="probe/req-early",
                requested_at="2026-09-04T00:15:00Z",
                world=gate.world,
            )
        self.assertEqual(gate.composed_digest(), before)

    def test_completing_a_step_without_a_result_fails_closed(self) -> None:
        from src.integration.lifecycle.scenarios import run_fulfillment_lifecycle

        gate, rail = self._gate()
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="acknowledged")
        before = gate.composed_digest()
        with self.assertRaises(CoreValidationError):
            gate.stage_complete_step(
                outcome["step_ids"][0],
                command_id="probe/complete-early",
                requested_at="2026-09-04T00:17:30Z",
            )
        self.assertEqual(gate.composed_digest(), before)

    def test_a_foreign_environment_command_is_rejected_without_mutation(self) -> None:
        from src.integration.lifecycle.scenarios import run_fulfillment_lifecycle

        gate, rail = self._gate()
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="completed")
        before = gate.composed_digest()
        step_id = outcome["step_ids"][0]
        command = gate.execution.build_raw_command(
            command_id="probe/foreign-env",
            command_type="external/record-finality",
            requested_at="2026-09-04T00:21:30Z",
            target_refs=(step_id,),
            payload={"claim": "FINAL", "native_reference": "ig002-local/none"},
            environment_id="env/sandbox-ig002-OTHER",
        )
        transition = gate.execution.submit(command)
        self.assertEqual(transition.outcome.value, "rejected")
        self.assertEqual(gate.composed_digest(), before)

    def test_a_cross_domain_composite_is_rejected_as_execution_evidence(self) -> None:
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = canonical_lifecycle(gate)
        obligation = gate.clearing.obligation(outcome["obligation_ids"][0]).to_dict()
        with self.assertRaises(CoreValidationError):
            gate.clearing.recognize_obligation(
                command_id="probe/cross-domain",
                requested_at="2026-09-04T00:32:00Z",
                cycle_id=outcome["cycle_id"],
                effect_result=obligation,
                due_from="2026-09-04T01:00:00Z",
                due_until="2026-09-05T06:00:00Z",
            )

    def test_a_tampered_effect_result_never_recognizes_an_obligation(self) -> None:
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = canonical_lifecycle(gate)
        obligation = gate.clearing.obligation(outcome["obligation_ids"][0])
        forged = dict(obligation.spec.to_dict())
        forged["amount"]["value"] = 99999999
        forged_record = dict(forged)
        forged_record["envelope"] = dict(obligation.envelope.to_dict())
        forged_record["spec"] = dict(obligation.spec.to_dict())
        forged_record["spec"]["amount"] = dict(obligation.spec.amount.to_dict())
        forged_record["spec"]["amount"]["value"] = 99999999
        with self.assertRaises(CoreValidationError):
            gate.clearing.recognize_obligation(
                command_id="probe/tampered",
                requested_at="2026-09-04T00:33:00Z",
                cycle_id=outcome["cycle_id"],
                effect_result=forged_record,
                due_from="2026-09-04T01:00:00Z",
                due_until="2026-09-05T06:00:00Z",
            )

    def test_a_payment_status_never_validates_into_finality(self) -> None:
        from src.execution.contracts import ObservationKind
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        outcome = canonical_lifecycle(gate)
        settlement = gate.settlement.settlement(outcome["settlement_id"])
        instruction = settlement.spec.instructions[0]
        # The step's STATUS observation (a payment status) replayed as a
        # finality claim must be rejected by the settlement domain.
        status_observation = None
        for observation in gate.execution.observations():
            if observation.spec.kind is ObservationKind.STATUS:
                status_observation = observation
        self.assertIsNotNone(status_observation)
        splice = dict(status_observation.to_dict())
        splice["spec"] = dict(status_observation.spec.to_dict())
        splice["spec"]["kind"] = "FINALITY"
        splice["spec"]["content"] = {
            "claim": "FINAL",
            "native_reference": "ig002-local/none",
        }
        with self.assertRaises(CoreValidationError):
            gate.settlement.validate_finality_claim(
                command_id="probe/status-finality",
                requested_at="2026-09-04T04:00:00Z",
                finality_id="settlement/ig002/finality-splice",
                settlement_id=outcome["settlement_id"],
                observation=splice,
            )

    def test_a_simulated_observation_cannot_even_be_constructed(self) -> None:
        from src.evidence.contracts import EpistemicType
        from src.execution.contracts import ObservationKind
        from src.execution.effects import (
            ExternalObservationSpec,
            make_observation_record,
        )
        from src.core.envelope import Provenance

        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec(
                observation_id="execution/ig002/observation-x",
                kind=ObservationKind.STATUS,
                subject_ref="execution/plan/ig002-x/step/1/request/1",
                adapter_id="interoperability/adapter/ig002-local-sandbox",
                epistemic=EpistemicType.SIMULATED,
                observed_at="2026-09-04T00:20:00Z",
                content={"native_code": "STLD", "canonical_status": "SETTLED"},
                subject_request_digest="f" * 64,
            )

    def test_settlement_submission_outside_its_window_fails_closed(self) -> None:
        from src.integration.lifecycle.scenarios import (
            DUE_FROM,
            DUE_UNTIL,
            SETTLE_BY,
            run_fulfillment_lifecycle,
        )

        gate, rail = self._gate()
        outcome = run_fulfillment_lifecycle(gate, rail=rail, stop_after="closed")
        obligation_ids = [
            record.object_id
            for record in gate.clearing.records()
            if record.__class__.__name__ == "Obligation"
        ]
        # A settlement whose submission window closed before the request
        # must be rejected at the window gate, without state mutation.
        gate.settlement.create_settlement(
            command_id="probe/late-create",
            requested_at="2026-09-04T03:00:00Z",
            settlement_id="settlement/ig002/late-window",
            obligations=[
                gate.clearing.obligation(obligation_id).to_dict()
                for obligation_id in obligation_ids
            ],
            submit_by="2026-09-04T03:05:00Z",
            settle_by=SETTLE_BY,
        )
        gate.settlement.authorize_settlement(
            command_id="probe/late-authorize",
            requested_at="2026-09-04T03:06:00Z",
            settlement_id="settlement/ig002/late-window",
        )
        before = gate.composed_digest()
        with self.assertRaises(CoreValidationError):
            gate.settlement.submit_settlement(
                command_id="probe/late-submit",
                requested_at="2026-09-04T03:30:00Z",
                settlement_id="settlement/ig002/late-window",
            )
        self.assertEqual(gate.composed_digest(), before)


# ---------------------------------------------------------------------------
# 8. offline mode (provider unavailable → NOT ATTEMPTED)
# ---------------------------------------------------------------------------


class OfflineModeTests(unittest.TestCase):
    def test_absent_credential_means_not_attempted_never_success(self) -> None:
        import os

        from src.integration.lifecycle.dogfooding import (
            StripeTestRail,
            make_stripe_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import offline_lifecycle

        saved = os.environ.pop("STRIPE_SECRET_KEY", None)
        try:
            rail = StripeTestRail()
            binding = make_stripe_binding(rail)
            gate = FulfillmentLifecycleGate(
                environment_id="env/sandbox-ig002-offline-test",
                domain_id="domain/ig002-offline-test",
                bindings={binding.adapter_id: binding},
            )
            outcome = offline_lifecycle(gate)
            self.assertEqual(outcome["submission_state"], "UNKNOWN")
            self.assertEqual(outcome["plan_state"], "RUNNING")
            self.assertIn("NOT ATTEMPTED", outcome["submission_reason"])
            self.assertFalse(outcome["any_settled_or_final"])
            self.assertEqual(rail.call_count, 0)
            self.assertEqual(rail.processed_keys, ())
        finally:
            if saved is not None:
                os.environ["STRIPE_SECRET_KEY"] = saved

    def test_offline_lifecycle_stops_before_settlement(self) -> None:
        import os

        from src.integration.lifecycle.dogfooding import (
            StripeTestRail,
            make_stripe_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import offline_lifecycle

        saved = os.environ.pop("STRIPE_SECRET_KEY", None)
        try:
            rail = StripeTestRail()
            binding = make_stripe_binding(rail)
            gate = FulfillmentLifecycleGate(
                environment_id="env/sandbox-ig002-offline-test",
                domain_id="domain/ig002-offline-test",
                bindings={binding.adapter_id: binding},
            )
            outcome = offline_lifecycle(gate)
            self.assertEqual(len(gate.clearing.records()), 0)
            self.assertEqual(len(gate.settlement.records()), 0)
        finally:
            if saved is not None:
                os.environ["STRIPE_SECRET_KEY"] = saved

    def test_the_offline_rail_never_fabricates_references(self) -> None:
        import os

        from src.core.envelope import Provenance
        from src.integration.lifecycle.dogfooding import StripeTestRail
        from src.execution.contracts import QueryOutcome, SubmissionStatus
        from src.execution.contracts import EffectRequestState
        from src.execution.effects import (
            EffectRequestSpec,
            make_request_record,
        )

        saved = os.environ.pop("STRIPE_SECRET_KEY", None)
        try:
            rail = StripeTestRail()
            spec = EffectRequestSpec(
                request_id="execution/plan/x/step/1/request/1",
                plan_id="execution/plan/x",
                step_id="execution/plan/x/step/1",
                attempt_number=1,
                effect_type="payment/submit",
                adapter_id="interoperability/adapter/stripe-test",
                idempotency_key="offline/probe",
                payload={"currency": "USD", "amount_value": 10000},
                requested_at="2026-09-04T00:15:00Z",
                authorization_digest="a" * 64,
            )
            request = make_request_record(
                spec=spec,
                state=EffectRequestState.REQUESTED,
                environment_id="env/sandbox-ig002-offline-probe",
                domain_id="domain/ig002-offline-probe",
                provenance=Provenance(
                    issuer="principal/ig002-ops",
                    source="integration-gate-ig2",
                    recorded_at="2026-09-04T00:15:00Z",
                ),
            )
            submission = rail.submit_effect(request)
            self.assertIs(submission.status, SubmissionStatus.UNKNOWN)
            self.assertIsNone(submission.native_reference)
            query = rail.query_effect(request)
            self.assertIs(query.outcome, QueryOutcome.NOT_FOUND)
            self.assertEqual(rail.call_count, 0)
        finally:
            if saved is not None:
                os.environ["STRIPE_SECRET_KEY"] = saved


# ---------------------------------------------------------------------------
# 9. deterministic replay
# ---------------------------------------------------------------------------


class ReplayTests(unittest.TestCase):
    def test_the_composed_state_rebuilds_from_journals_byte_identically(self) -> None:
        from src.integration.lifecycle import (
            assert_replay_equivalence,
            rebuild_lifecycle_gate,
        )
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        canonical_lifecycle(gate)
        snapshot = gate.snapshot()
        fresh_binding = make_local_binding(LocalDeterministicRail())
        rebuilt = rebuild_lifecycle_gate(
            snapshot, bindings={fresh_binding.adapter_id: fresh_binding}
        )
        assert_replay_equivalence(gate, rebuilt)

    def test_a_tampered_stage_journal_fails_the_rebuild(self) -> None:
        from src.integration.lifecycle import rebuild_lifecycle_gate
        from src.integration.lifecycle.dogfooding import (
            LocalDeterministicRail,
            make_local_binding,
        )
        from src.integration.lifecycle.harness import FulfillmentLifecycleGate
        from src.integration.lifecycle.scenarios import (
            DOMAIN,
            ENVIRONMENT,
            canonical_lifecycle,
        )

        rail = LocalDeterministicRail()
        binding = make_local_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id=ENVIRONMENT,
            domain_id=DOMAIN,
            bindings={binding.adapter_id: binding},
        )
        canonical_lifecycle(gate)
        snapshot = gate.snapshot()
        snapshot["stage_journal"][-1]["state_after"] = "f" * 64
        fresh_binding = make_local_binding(LocalDeterministicRail())
        with self.assertRaises(CoreValidationError):
            rebuild_lifecycle_gate(
                snapshot, bindings={fresh_binding.adapter_id: fresh_binding}
            )


# ---------------------------------------------------------------------------
# 10. DOGFOOD-027 conformance (local deterministic transcript)
# ---------------------------------------------------------------------------


class DogfoodConformanceTests(unittest.TestCase):
    def test_dogfood_transcript_passes_and_is_deterministic(self) -> None:
        from src.integration.lifecycle.dogfooding import build_transcript

        first, digest_one = build_transcript()
        self.assertIn("DOGFOOD-027: PASS", first)
        second, digest_two = build_transcript()
        self.assertEqual(first, second)
        self.assertEqual(digest_one, digest_two)

    def test_dogfood_transcript_names_the_required_lifecycle_facts(self) -> None:
        from src.integration.lifecycle.dogfooding import build_transcript

        transcript, _ = build_transcript()
        for expected in (
            "architecture=v0.1",
            "work_order=WORK-027",
            "gate=IG-002",
            "intent_id=",
            "plan_id=",
            "execution_plan_id=",
            "effect_request=",
            "clearing_cycle=",
            "obligation=",
            "netting_cycle=",
            "settlement=",
            "reconciliation=",
            "finality=",
        ):
            self.assertIn(expected, transcript)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
