"""WORK-028 / IG-003 contract suite — the simulation parity integration gate.

Red-first authored against the public boundary of
``src.integration.parity`` (the IG-003 gate). The suite pins:

* the typed, versioned gate identity (IG-003) and its consumed-surface
  discipline (AST import audit, no floats, no wall clock/entropy, import
  closure) — the IG-001/IG-002 convention applied to the parity
  subpackage;
* the two-world environment pair: a SIMULATION world (SIMULATION-fidelity
  rail whose outcome source is a WORK-019 ``ScriptedWorld`` of SIMULATED
  observations) and a PRODUCTION-COMPATIBLE world (PRODUCTION-fidelity
  rail through the same typed ports, OBSERVED-class world source), bound
  by the frozen mode→epistemic vocabulary;
* the canonical semantic projection, the explicit field-bound
  normalization layer, difference classification and the parity verdict;
* the five required parity scenarios (canonical success, rejection,
  idempotency, recovery, finality discipline) driven through the public
  IG-002 lifecycle stage API in both environments in lockstep;
* the discrimination battery: real rail-script divergence and corrupted
  projection feeds must fail the gate closed (amount, state, failure
  class, ledger, finality, environment binding, SIMULATED→OBSERVED
  relabel);
* deterministic journal-driven replay of both worlds and verdict
  identity after rebuild;
* the DOGFOOD-028 conformance transcript (deterministic, sanitized).
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import unittest

from src.core.errors import CoreValidationError

import src.integration.parity as parity_package

#: The repository root (for the isolated subprocess audit).
_REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[3])


# ---------------------------------------------------------------------------
# 1. static boundary
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    def test_gate_identity_constants(self) -> None:
        self.assertEqual(parity_package.PARITY_GATE_ID, "IG-003")
        self.assertEqual(parity_package.PARITY_API_VERSION, "v0.1")
        self.assertEqual(parity_package.PARITY_SCHEMA_VERSION, 1)
        self.assertEqual(parity_package.KNOWN_PARITY_GATES, frozenset({"IG-003"}))

    def test_environment_identity_constants_are_frozen(self) -> None:
        self.assertEqual(
            parity_package.SIMULATION_ENVIRONMENT_ID,
            "env/sandbox-ig003-simulation",
        )
        self.assertEqual(
            parity_package.PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
            "env/production-ig003-compatible",
        )
        self.assertEqual(parity_package.PARITY_DOMAIN_ID, "domain/ig003-parity")
        self.assertEqual(
            parity_package.SIMULATION_ADAPTER_ID,
            "interoperability/adapter/ig003-simulation-rail",
        )
        self.assertEqual(
            parity_package.PRODUCTION_ADAPTER_ID,
            "interoperability/adapter/ig003-production-rail",
        )

    def test_public_boundary_all_is_explicit_frozen_and_sorted(self) -> None:
        exported = parity_package.__all__
        self.assertTrue(exported)
        self.assertEqual(list(exported), sorted(exported))
        self.assertEqual(len(exported), len(set(exported)))
        module = vars(parity_package)
        for name in exported:
            self.assertIn(name, module, f"__all__ exports missing {name}")

    def test_consumed_surfaces_cover_exactly_the_declared_roots(self) -> None:
        expected = {
            "src.core",
            "src.transition",
            "src.evidence",
            "src.capability",
            "src.interoperability",
            "src.execution",
            "src.clearing",
            "src.settlement",
            "src.simulation",
            "src.integration.lifecycle",
        }
        self.assertEqual(set(parity_package.CONSUMED_SURFACES), expected)

    def test_parity_modules_import_only_consumed_roots(self) -> None:
        allowed = set(parity_package.CONSUMED_SURFACES)
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
                        self._audit_root(source.name, alias.name, allowed)
                elif isinstance(node, ast.ImportFrom):
                    if node.level >= 1:
                        continue
                    module = node.module or ""
                    if module == "__future__":
                        continue
                    self._audit_root(source.name, module, allowed)

    def _audit_root(self, source_name: str, module: str, allowed: set[str]) -> None:
        root = module.split(".", 1)[0]
        if root == "src":
            matched = any(
                module == surface or module.startswith(surface + ".")
                for surface in allowed
            )
            self.assertTrue(
                matched,
                f"{source_name} imports {module} outside the consumed surfaces",
            )
        else:
            self.assertIn(
                root,
                sys.stdlib_module_names,
                f"{source_name} imports non-stdlib {module}",
            )

    def test_parity_sources_contain_no_float_literals(self) -> None:
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

    def test_parity_code_has_no_wall_clock_entropy_or_uuids(self) -> None:
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name.startswith("test_"):
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
        # domains' own declared dependencies (the full lifecycle
        # dependency tree, exactly as documented for the IG-002 gate).
        allowed = set(parity_package.CONSUMED_SURFACES) | {
            "src.integration",
            "src.transition",
            "src.money",
            "src.value",
            "src.trust",
            "src.intent",
            "src.capability",
            "src.market",
            "src.liquidity",
            "src.reservation",
            "src.safety",
            "src.compiler",
        }
        code = (
            "import sys, json\n"
            "import src.integration.parity\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('src.'))))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = json.loads(result.stdout)
        self.assertTrue(loaded, "the gate import must load its composed roots")
        for name in loaded:
            matched = any(
                name == surface or name.startswith(surface + ".")
                for surface in allowed
            )
            self.assertTrue(
                matched,
                f"importing src.integration.parity loaded {name}",
            )

    def test_validate_parity_gate_id_fails_closed_on_unknown_gate(self) -> None:
        self.assertEqual(parity_package.validate_parity_gate_id("IG-003"), "IG-003")
        for unknown in ("IG-001", "IG-002", "ig-003", "", None, 1):
            with self.assertRaises(CoreValidationError):
                parity_package.validate_parity_gate_id(unknown)

    def test_the_gate_declares_itself_an_ig003_composition(self) -> None:
        docstring = parity_package.__doc__ or ""
        self.assertIn("IG-003", docstring)
        self.assertIn("parity", docstring.lower())


# ---------------------------------------------------------------------------
# 2. the normalization layer contract
# ---------------------------------------------------------------------------


class NormalizationContractTests(unittest.TestCase):
    def test_normalization_rules_are_frozen_documented_and_field_bound(self) -> None:
        rules = parity_package.NORMALIZATION_RULES
        self.assertTrue(rules)
        seen_fields: set[str] = set()
        for rule in rules:
            self.assertTrue(rule.rule_id)
            self.assertTrue(rule.field)
            self.assertNotIn(rule.field, seen_fields)
            seen_fields.add(rule.field)
            for attribute in ("reason", "rule", "safety_argument"):
                text = getattr(rule, attribute)
                self.assertIsInstance(text, str)
                self.assertTrue(text.strip(), f"rule {rule.rule_id} has no {attribute}")
            self.assertNotIn("ignore", rule.rule.lower())

    def test_every_declared_env_bound_digest_field_is_justified(self) -> None:
        fields = parity_package.ENV_BOUND_DIGEST_FIELDS
        self.assertTrue(fields)
        rules = {rule.field: rule for rule in parity_package.NORMALIZATION_RULES}
        for field in fields:
            self.assertIn(
                field,
                rules,
                f"env-bound digest field {field!r} has no normalization rule",
            )


# ---------------------------------------------------------------------------
# 3. the two-world environment pair
# ---------------------------------------------------------------------------


class WorldPairTests(unittest.TestCase):
    def _scripts(self) -> tuple:
        return (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-pay-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )

    def test_build_environment_pair_is_deterministic(self) -> None:
        first = parity_package.build_environment_pair(scripts=self._scripts())
        second = parity_package.build_environment_pair(scripts=self._scripts())
        self.assertEqual(
            first.simulation.environment_id, second.simulation.environment_id
        )
        self.assertEqual(
            first.simulation.world_source.observe(
                "rail/outcome/ig003-pay-1", first.simulation.observation_as_of
            ).value,
            second.simulation.world_source.observe(
                "rail/outcome/ig003-pay-1", second.simulation.observation_as_of
            ).value,
        )
        self.assertEqual(
            first.simulation.binding.world_adapter.fidelity_class,
            second.simulation.binding.world_adapter.fidelity_class,
        )

    def test_the_pair_declares_two_distinct_environments_one_domain(self) -> None:
        pair = parity_package.build_environment_pair(scripts=self._scripts())
        self.assertIs(pair.simulation.role, parity_package.WorldRole.SIMULATION)
        self.assertIs(
            pair.production.role, parity_package.WorldRole.PRODUCTION_COMPATIBLE
        )
        self.assertNotEqual(
            pair.simulation.environment_id, pair.production.environment_id
        )
        self.assertEqual(pair.simulation.domain_id, pair.production.domain_id)
        self.assertEqual(
            pair.simulation.domain_id, parity_package.PARITY_DOMAIN_ID
        )
        self.assertNotEqual(pair.simulation.adapter_id, pair.production.adapter_id)

    def test_simulation_world_declares_simulation_fidelity_and_simulated_evidence(
        self,
    ) -> None:
        pair = parity_package.build_environment_pair(scripts=self._scripts())
        world = pair.simulation
        self.assertEqual(world.fidelity_class, "SIMULATION")
        self.assertEqual(world.epistemic_class.value, "SIMULATED")
        self.assertEqual(world.mode.value, "simulation")
        self.assertEqual(world.environment_class, "sandbox")

    def test_production_world_declares_production_fidelity_and_observed_evidence(
        self,
    ) -> None:
        pair = parity_package.build_environment_pair(scripts=self._scripts())
        world = pair.production
        self.assertEqual(world.fidelity_class, "PRODUCTION")
        self.assertEqual(world.epistemic_class.value, "OBSERVED")
        self.assertEqual(world.mode.value, "production")
        self.assertEqual(world.environment_class, "production")

    def test_mode_epistemic_binding_matches_the_frozen_vocabulary(self) -> None:
        from src.simulation import (
            MODE_EPISTEMIC_TYPES,
            EnvironmentMode,
            mode_epistemic_type,
        )
        from src.evidence.contracts import EpistemicType

        self.assertIs(
            mode_epistemic_type(EnvironmentMode.SIMULATION), EpistemicType.SIMULATED
        )
        self.assertIs(
            mode_epistemic_type(EnvironmentMode.PRODUCTION), EpistemicType.OBSERVED
        )
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.SIMULATION], EpistemicType.SIMULATED
        )
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.PRODUCTION], EpistemicType.OBSERVED
        )

    def test_world_sources_enforce_their_epistemic_class(self) -> None:
        # WORK-019's own gate: a scripted world rejects observations of a
        # foreign epistemic class — the simulation world can never be fed
        # OBSERVED records, and vice versa.
        from src.evidence.contracts import EpistemicType
        from src.simulation import ScriptedWorld, WorldObservation

        simulated = WorldObservation(
            observation_key="rail/outcome/k",
            epistemic_type=EpistemicType.SIMULATED,
            as_of="2026-09-04T00:36:30Z",
            value={"submission": "accept"},
            source="world/ig003-simulation",
        )
        with self.assertRaises(CoreValidationError):
            ScriptedWorld(
                observations=(simulated,), epistemic_type=EpistemicType.OBSERVED
            )

    def test_rails_implement_the_typed_ports_and_carry_status_maps(self) -> None:
        from src.execution.adapters import (
            EffectReconciliationPort,
            EffectSubmissionPort,
        )

        pair = parity_package.build_environment_pair(scripts=self._scripts())
        for world in (pair.simulation, pair.production):
            self.assertIsInstance(world.rail, EffectSubmissionPort)
            self.assertIsInstance(world.rail, EffectReconciliationPort)
            self.assertIsNotNone(world.binding.status_map)
            self.assertEqual(
                world.binding.world_adapter.adapter_id, world.adapter_id
            )
            # The declared native status vocabulary maps STLD -> SETTLED.
            self.assertEqual(world.binding.map_status("STLD"), "SETTLED")

    def test_native_references_carry_the_environment_prefix(self) -> None:
        pair = parity_package.build_environment_pair(scripts=self._scripts())
        self.assertEqual(
            pair.simulation.rail.native_reference_for("ig003-pay-1"),
            "ig003-simulation/ig003-pay-1",
        )
        self.assertEqual(
            pair.production.rail.native_reference_for("ig003-pay-1"),
            "ig003-production/ig003-pay-1",
        )

    def test_the_declared_world_observations_are_semantically_identical(self) -> None:
        pair = parity_package.build_environment_pair(scripts=self._scripts())
        simulation = pair.simulation.world_source.observe(
            "rail/outcome/ig003-pay-1", pair.simulation.observation_as_of
        )
        production = pair.production.world_source.observe(
            "rail/outcome/ig003-pay-1", pair.production.observation_as_of
        )
        # Same declared world outcomes; only the epistemic class differs.
        self.assertEqual(simulation.value, production.value)
        self.assertEqual(simulation.observation_key, production.observation_key)
        self.assertEqual(simulation.as_of, production.as_of)
        self.assertNotEqual(simulation.epistemic_type, production.epistemic_type)


# ---------------------------------------------------------------------------
# 4. scenario A — canonical success parity
# ---------------------------------------------------------------------------


class ScenarioAParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-pay-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        cls.pair = parity_package.build_environment_pair(scripts=cls.scripts)
        cls.gate = parity_package.SimulationParityGate(pair=cls.pair)
        cls.result = parity_package.run_parity_scenario(
            cls.gate,
            tag="pay-1",
            scripts=cls.scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )

    def test_verdict_is_parity_with_zero_differences(self) -> None:
        self.assertEqual(self.result.verdict.verdict, "PARITY")
        self.assertEqual(self.result.verdict.differences, ())
        parity_package.assert_semantic_parity(self.result.verdict)

    def test_semantic_projection_digests_are_equal(self) -> None:
        verdict = self.result.verdict
        self.assertEqual(
            verdict.simulation.semantic_projection_digest,
            verdict.production.semantic_projection_digest,
        )

    def test_raw_state_digests_differ_through_environment_binding(self) -> None:
        verdict = self.result.verdict
        self.assertNotEqual(
            verdict.simulation.raw_state_digest,
            verdict.production.raw_state_digest,
        )

    def test_both_worlds_reach_the_same_terminal_semantics(self) -> None:
        facts = self.result.facts
        self.assertEqual(
            facts["simulation"]["finality_state"],
            facts["production"]["finality_state"],
        )
        self.assertEqual(facts["simulation"]["finality_state"], "ESTABLISHED")
        self.assertEqual(
            facts["simulation"]["obligation_states"],
            facts["production"]["obligation_states"],
        )
        self.assertEqual(
            facts["simulation"]["obligation_states"], ["RESOLVED"]
        )

    def test_economics_are_identical_across_worlds(self) -> None:
        economics = self.result.facts["shared"]["economics"]
        self.assertEqual(economics["intent_amount_minor"], 10000)
        self.assertEqual(economics["obligation_amount_minor"], 10000)
        self.assertEqual(economics["settled_legs"], 1)
        self.assertEqual(economics["posting_count"], 1)
        sim = self.result.facts["simulation"]["economics"]
        prod = self.result.facts["production"]["economics"]
        self.assertEqual(sim, prod)

    def test_stage_sequences_are_identical(self) -> None:
        self.assertEqual(
            self.result.facts["simulation"]["stage_count"],
            self.result.facts["production"]["stage_count"],
        )
        self.assertGreater(self.result.facts["simulation"]["stage_count"], 20)

    def test_epistemic_report_distinguishes_simulated_and_observed(self) -> None:
        epistemic = self.result.verdict.epistemic
        self.assertEqual(
            epistemic.simulation_world_evidence_class, "SIMULATED"
        )
        self.assertEqual(epistemic.production_world_evidence_class, "OBSERVED")
        self.assertEqual(epistemic.execution_observation_class, "OBSERVED")
        self.assertIn("SIMULATED", epistemic.note)
        self.assertIn("OBSERVED", epistemic.note)

    def test_invariant_battery_covers_the_required_dimensions(self) -> None:
        checks = self.result.verdict.invariant_checks
        self.assertEqual(len(checks), 13)
        for required in (
            "protocol identity parity",
            "state-machine parity",
            "accounting parity",
            "authorization parity",
            "idempotency parity",
            "failure-class parity",
            "evidence-type preservation",
            "provenance preservation",
            "environment isolation",
            "domain isolation",
            "append-only history",
            "finality discipline",
            "replay determinism",
        ):
            self.assertTrue(
                any(check.startswith(required) for check in checks),
                f"the parity battery must cover {required!r}",
            )

    def test_shared_input_digest_is_declared_and_stable(self) -> None:
        first = self.result.verdict.shared_input_digest
        second = parity_package.run_parity_scenario(
            parity_package.SimulationParityGate(
                pair=parity_package.build_environment_pair(scripts=self.scripts)
            ),
            tag="pay-1",
            scripts=self.scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        self.assertEqual(first, second.verdict.shared_input_digest)

    def test_normalization_digest_is_declared(self) -> None:
        self.assertTrue(self.result.verdict.normalization_digest)


# ---------------------------------------------------------------------------
# 5. scenario B — rejection parity
# ---------------------------------------------------------------------------


class ScenarioBRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-reject-1",
                submission="reject",
                query="failed",
                native_status="RJCT",
                finality_claim=None,
            ),
        )
        cls.pair = parity_package.build_environment_pair(scripts=cls.scripts)
        cls.gate = parity_package.SimulationParityGate(pair=cls.pair)
        cls.result = parity_package.run_parity_scenario(
            cls.gate,
            tag="reject-1",
            scripts=cls.scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
            mode="rejection",
        )

    def test_verdict_is_parity(self) -> None:
        self.assertEqual(self.result.verdict.verdict, "PARITY")
        self.assertEqual(self.result.verdict.differences, ())

    def test_rejection_failure_class_is_identical(self) -> None:
        facts = self.result.facts
        self.assertEqual(
            facts["simulation"]["step_state"], facts["production"]["step_state"]
        )
        self.assertEqual(facts["simulation"]["step_state"], "FAILED")
        self.assertEqual(
            facts["simulation"]["submission_status"],
            facts["production"]["submission_status"],
        )
        self.assertEqual(facts["simulation"]["submission_status"], "REJECTED")

    def test_no_obligation_is_recognized_in_either_world(self) -> None:
        self.assertEqual(self.result.facts["simulation"]["obligation_states"], [])
        self.assertEqual(self.result.facts["production"]["obligation_states"], [])

    def test_no_economic_effect_in_either_world(self) -> None:
        for world in ("simulation", "production"):
            economics = self.result.facts[world]["economics"]
            self.assertEqual(economics["obligation_amount_minor"], 0)
            self.assertEqual(economics["settled_legs"], 0)
            self.assertEqual(economics["posting_count"], 0)

    def test_the_fail_closed_probe_mutated_nothing(self) -> None:
        facts = self.result.facts["shared"]
        self.assertTrue(facts["recognition_probe_rejected"])
        self.assertEqual(facts["obligation_count"], 0)
        self.assertEqual(facts["obligation_count_after_probe"], 0)

    def test_no_finality_in_either_world(self) -> None:
        self.assertIsNone(self.result.facts["simulation"]["finality_state"])
        self.assertIsNone(self.result.facts["production"]["finality_state"])


# ---------------------------------------------------------------------------
# 6. scenario C — idempotency parity
# ---------------------------------------------------------------------------


class ScenarioCIdempotencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-idem-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        cls.pair = parity_package.build_environment_pair(scripts=cls.scripts)
        cls.gate = parity_package.SimulationParityGate(pair=cls.pair)
        cls.result = parity_package.run_parity_scenario(
            cls.gate,
            tag="idem-1",
            scripts=cls.scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )

    def test_verdict_is_parity(self) -> None:
        self.assertEqual(self.result.verdict.verdict, "PARITY")

    def test_duplicate_re_drive_converges_without_a_second_port_call(self) -> None:
        facts = self.result.facts["shared"]["idempotency"]
        self.assertEqual(facts["simulation"]["re_drive_outcome"], "rejected")
        self.assertEqual(facts["production"]["re_drive_outcome"], "rejected")
        self.assertEqual(facts["simulation"]["port_calls_before"], 1)
        self.assertEqual(facts["production"]["port_calls_before"], 1)
        self.assertEqual(facts["simulation"]["port_calls_after"], 1)
        self.assertEqual(facts["production"]["port_calls_after"], 1)

    def test_same_key_re_request_converges_fail_closed(self) -> None:
        facts = self.result.facts["shared"]["idempotency"]
        self.assertTrue(facts["simulation"]["re_request_rejected"])
        self.assertTrue(facts["production"]["re_request_rejected"])

    def test_submission_ledgers_stay_parity_clean(self) -> None:
        facts = self.result.facts["shared"]["idempotency"]
        self.assertEqual(facts["simulation"]["ledger_keys"], ["ig003-idem-1"])
        self.assertEqual(facts["production"]["ledger_keys"], ["ig003-idem-1"])

    def test_no_duplicate_economic_effect(self) -> None:
        economics = self.result.facts["shared"]["economics"]
        self.assertEqual(economics["settled_legs"], 1)
        self.assertEqual(economics["posting_count"], 1)
        self.assertEqual(economics["obligation_amount_minor"], 10000)


# ---------------------------------------------------------------------------
# 7. scenario D — recovery parity
# ---------------------------------------------------------------------------


class ScenarioDRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-recover-1",
                submission="unknown",
                query="not-found",
                native_status=None,
                finality_claim=None,
            ),
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-recover-1-retry",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        cls.pair = parity_package.build_environment_pair(scripts=cls.scripts)
        cls.gate = parity_package.SimulationParityGate(pair=cls.pair)
        cls.result = parity_package.run_parity_scenario(
            cls.gate,
            tag="recover-1",
            scripts=cls.scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
            mode="recovery",
        )

    def test_verdict_is_parity(self) -> None:
        self.assertEqual(self.result.verdict.verdict, "PARITY")
        self.assertEqual(self.result.verdict.differences, ())

    def test_recovery_semantics_are_identical(self) -> None:
        for world in ("simulation", "production"):
            facts = self.result.facts[world]
            self.assertEqual(facts["first_submission_state"], "UNKNOWN")
            self.assertEqual(facts["reconciliation_outcome"], "NOT_FOUND")
            self.assertTrue(facts["recovered"])
            self.assertEqual(facts["finality_state"], "ESTABLISHED")

    def test_the_retry_used_a_fresh_idempotency_key_in_both_worlds(self) -> None:
        self.assertEqual(
            self.result.facts["simulation"]["idempotency_keys"],
            ["ig003-recover-1", "ig003-recover-1-retry"],
        )
        self.assertEqual(
            self.result.facts["production"]["idempotency_keys"],
            ["ig003-recover-1", "ig003-recover-1-retry"],
        )


# ---------------------------------------------------------------------------
# 8. scenario E — finality discipline parity
# ---------------------------------------------------------------------------


class ScenarioEFinalityDisciplineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-final-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        cls.pair = parity_package.build_environment_pair(scripts=cls.scripts)
        cls.gate = parity_package.SimulationParityGate(pair=cls.pair)
        cls.result = parity_package.run_scenario_e_finality_discipline(
            parity_package.SimulationParityGate(
                pair=parity_package.build_environment_pair(scripts=cls.scripts)
            ),
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )

    def test_payment_status_never_established_finality_at_the_status_point(self) -> None:
        facts = self.result.facts["shared"]["pre_status"]
        self.assertEqual(facts["simulation"]["status_recorded"], True)
        self.assertEqual(facts["production"]["status_recorded"], True)
        self.assertEqual(facts["simulation"]["finality_records"], 0)
        self.assertEqual(facts["production"]["finality_records"], 0)
        self.assertEqual(facts["simulation"]["settled_legs"], 0)
        self.assertEqual(facts["production"]["settled_legs"], 0)

    def test_finality_arrives_only_through_the_settlement_authority(self) -> None:
        for world in ("simulation", "production"):
            facts = self.result.facts[world]
            self.assertEqual(facts["finality_state"], "ESTABLISHED")
            self.assertEqual(facts["finality_authority"], "settlement")

    def test_parity_holds_at_both_checkpoints(self) -> None:
        self.assertEqual(self.result.verdict.verdict, "PARITY")
        pre = self.result.facts["shared"]["pre_status"]
        self.assertEqual(pre["simulation"]["semantic_projection_digest"],
                         pre["production"]["semantic_projection_digest"])


# ---------------------------------------------------------------------------
# 9. discrimination — the comparison must be load-bearing
# ---------------------------------------------------------------------------


class DiscriminationTests(unittest.TestCase):
    def _canonical_scripts(self) -> tuple:
        return (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-diverge-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )

    def test_rail_script_divergence_fails_the_gate(self) -> None:
        scripts = self._canonical_scripts()
        simulation_pair = parity_package.build_environment_pair(scripts=scripts)
        # Diverge the production world: the same declared input, but the
        # production rail definitively rejects the effect.
        divergent_scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-diverge-1",
                submission="reject",
                query="failed",
                native_status="RJCT",
                finality_claim=None,
            ),
        )
        divergent_pair = parity_package.build_environment_pair(
            scripts=divergent_scripts
        )
        gate = parity_package.SimulationParityGate(
            pair=(simulation_pair.simulation, divergent_pair.production)
        )
        result = parity_package.run_parity_scenario(
            gate,
            tag="diverge-1",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        self.assertEqual(result.verdict.verdict, "DIVERGENCE")
        self.assertTrue(result.verdict.differences)
        with self.assertRaises(CoreValidationError):
            parity_package.assert_semantic_parity(result.verdict)

    def test_amount_corruption_is_detected(self) -> None:
        gate, result = self._canonical_run()
        projection = gate.semantic_projection("production")
        self._corrupt(projection, "amount", 99999)
        differences = gate.compare_projections(
            gate.semantic_projection("simulation"), projection
        )
        self.assertTrue(differences)
        self.assertTrue(
            any("amount" in difference.path for difference in differences)
        )

    def test_state_corruption_is_detected(self) -> None:
        gate, result = self._canonical_run()
        projection = gate.semantic_projection("simulation")
        self._corrupt(projection, "state", "TAMPERED")
        differences = gate.compare_projections(
            projection, gate.semantic_projection("production")
        )
        self.assertTrue(differences)

    def test_failure_class_corruption_is_detected(self) -> None:
        gate, result = self._canonical_run()
        projection = gate.semantic_projection("production")
        self._corrupt(projection, "reason", "fabricated-classification")
        differences = gate.compare_projections(
            gate.semantic_projection("simulation"), projection
        )
        self.assertTrue(differences)

    def test_ledger_corruption_is_detected(self) -> None:
        gate, result = self._canonical_run()
        projection = gate.semantic_projection("production")
        ledger = projection.get("submission_ledger")
        self.assertIsNotNone(ledger)
        projection["submission_ledger"] = {
            "entries": [{"key": "fabricated"}],
        }
        differences = gate.compare_projections(
            gate.semantic_projection("simulation"), projection
        )
        self.assertTrue(differences)

    def test_finality_corruption_is_detected(self) -> None:
        gate, result = self._canonical_run()
        projection = gate.semantic_projection("production")
        found = False
        for record in projection["settlement_records"].values():
            if record["envelope"]["object_type"] == "payswap/finality/v1":
                record["state"] = "FABRICATED"
                found = True
        self.assertTrue(found, "the production projection has a finality record")
        differences = gate.compare_projections(
            gate.semantic_projection("simulation"), projection
        )
        self.assertTrue(differences)

    def test_environment_binding_is_validated_not_ignored(self) -> None:
        gate, result = self._canonical_run()
        state = gate.semantic_state("simulation")
        # A foreign NESTED environment id (a record envelope) must fail
        # closed during normalization — not normalize silently. The
        # top-level binding stays intact, so ONLY the per-field
        # environment validation can catch this corruption.
        record_id = next(iter(state["execution_records"]))
        state["execution_records"][record_id]["envelope"][
            "environment_id"
        ] = "env/foreign-world"
        with self.assertRaises(CoreValidationError):
            parity_package.normalize_semantic_state(
                state, gate.simulation_world
            )

    def test_stage_only_divergence_is_detected_by_the_projection(self) -> None:
        # A converged (rejected, no-mutation) re-drive stage appended to
        # ONE world only changes nothing except the stage journal — the
        # semantic projection must classify exactly that difference.
        gate, result = self._canonical_run()
        step_id = result.facts["shared"].get(
            "step_id"
        ) or self._first_step_id(gate)
        gate.simulation_gate.stage_submit_effect(
            step_id,
            command_id="cmd/ig003-div-2/submit-extra",
            requested_at="2026-09-04T05:40:00Z",
        )
        differences = gate.compare_projections()
        self.assertTrue(differences)
        self.assertTrue(
            any(
                "stage_journal" in difference.path
                for difference in differences
            ),
            "a stage-only divergence must surface in the stage journal "
            f"projection (got: {[d.path for d in differences][:4]})",
        )

    def test_battery_fails_closed_on_idempotency_divergence(self) -> None:
        # One world submits a single key; the other runs the full
        # recovery discipline (two keys). The battery's idempotency
        # dimension must fail closed FIRST with its own message.
        scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-idem-6",
                submission="unknown",
                query="not-found",
                native_status=None,
                finality_claim=None,
            ),
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-idem-6-retry",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        pair = parity_package.build_environment_pair(scripts=scripts)
        gate = parity_package.SimulationParityGate(pair=pair)
        from src.integration.parity.scenarios import (
            _drive_recovery,
            _drive_world,
        )

        _drive_world(
            gate.simulation_gate,
            gate.simulation_world,
            tag="idem-6",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
            stop_after="submitted",
        )
        _drive_recovery(
            gate.production_gate,
            gate.production_world,
            tag="idem-6",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        with self.assertRaises(CoreValidationError) as raised:
            parity_package.verify_parity_invariants(gate)
        self.assertIn("idempotency parity", str(raised.exception))

    def test_battery_fails_closed_on_failure_class_divergence(self) -> None:
        # One world's rail definitively rejects; the other's submission
        # is transport-unknown. Same stage sequence, different failure
        # classifications — the failure-class dimension fires first.
        simulation_scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-fail-4",
                submission="reject",
                query="failed",
                native_status="RJCT",
                finality_claim=None,
            ),
        )
        production_scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-fail-4",
                submission="unknown",
                query="not-found",
                native_status=None,
                finality_claim=None,
            ),
        )
        simulation_pair = parity_package.build_environment_pair(
            scripts=simulation_scripts
        )
        production_pair = parity_package.build_environment_pair(
            scripts=production_scripts
        )
        gate = parity_package.SimulationParityGate(
            pair=(simulation_pair.simulation, production_pair.production)
        )
        from src.integration.parity.scenarios import _drive_world

        _drive_world(
            gate.simulation_gate,
            gate.simulation_world,
            tag="fail-4",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
            stop_after="submitted",
        )
        _drive_world(
            gate.production_gate,
            gate.production_world,
            tag="fail-4",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
            stop_after="submitted",
        )
        with self.assertRaises(CoreValidationError) as raised:
            parity_package.verify_parity_invariants(gate)
        self.assertIn("failure-class parity", str(raised.exception))

    def test_battery_fails_closed_on_economics_divergence(self) -> None:
        # The same declared scenario shape with different amounts: the
        # stage sequences, authorizations, ledgers, failure classes,
        # provenance and finality bindings all match — ONLY the
        # economics diverge, and the accounting dimension must fire.
        scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-econ-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        pair = parity_package.build_environment_pair(scripts=scripts)
        gate = parity_package.SimulationParityGate(pair=pair)
        from src.integration.parity.scenarios import _drive_world

        _drive_world(
            gate.simulation_gate,
            gate.simulation_world,
            tag="econ-1",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        _drive_world(
            gate.production_gate,
            gate.production_world,
            tag="econ-1",
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=20000,
        )
        with self.assertRaises(CoreValidationError) as raised:
            parity_package.verify_parity_invariants(gate)
        self.assertIn("accounting parity", str(raised.exception))

    def _first_step_id(self, gate) -> str:
        from src.execution import ExecutionStep

        for record in gate.simulation_gate.execution.objects():
            if isinstance(record, ExecutionStep):
                return record.object_id
        raise AssertionError("the simulation world carries no execution step")

    def test_simulated_to_observed_relabel_fails_closed(self) -> None:
        # The evidence-class check is load-bearing at TWO layers: the
        # world construction (the frozen mode→epistemic binding) AND the
        # parity invariant battery. This probe simulates a mutant that
        # removed the constructor check (a direct frozen-field write)
        # and proves the battery still fails closed on the relabel.
        from src.evidence.contracts import EpistemicType

        scripts = self._canonical_scripts()
        pair = parity_package.build_environment_pair(scripts=scripts)
        world = pair.simulation
        # Construction-level check: relabelling via the public record
        # constructor fails closed (the mode→epistemic binding).
        import dataclasses

        with self.assertRaises(CoreValidationError):
            dataclasses.replace(
                world, epistemic_class=EpistemicType.OBSERVED
            )
        # Battery-level check (defense in depth): a frozen-field write
        # that bypasses the constructor is still caught by the battery.
        object.__setattr__(world, "epistemic_class", EpistemicType.OBSERVED)
        try:
            gate = parity_package.SimulationParityGate(
                pair=(world, pair.production)
            )
            with self.assertRaises(CoreValidationError):
                parity_package.verify_parity_invariants(gate)
        finally:
            object.__setattr__(world, "epistemic_class", EpistemicType.SIMULATED)

    def _canonical_run(self):
        scripts = self._canonical_scripts()
        pair = parity_package.build_environment_pair(scripts=scripts)
        gate = parity_package.SimulationParityGate(pair=pair)
        result = parity_package.run_parity_scenario(
            gate,
            tag="diverge-1",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        self.assertEqual(result.verdict.verdict, "PARITY")
        return gate, result

    def _corrupt(self, value, key, replacement) -> None:
        if isinstance(value, dict):
            for name, item in value.items():
                if name == key:
                    value[name] = replacement
                    return
                self._corrupt(item, key, replacement)
        elif isinstance(value, list):
            for item in value:
                self._corrupt(item, key, replacement)


# ---------------------------------------------------------------------------
# 10. replay determinism
# ---------------------------------------------------------------------------


class ReplayTests(unittest.TestCase):
    def test_rebuild_reproduces_the_semantic_projections_and_verdict(self) -> None:
        scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-replay-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        pair = parity_package.build_environment_pair(scripts=scripts)
        gate = parity_package.SimulationParityGate(pair=pair)
        result = parity_package.run_parity_scenario(
            gate,
            tag="replay-1",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        self.assertEqual(result.verdict.verdict, "PARITY")
        rebuilt = parity_package.rebuild_parity_gate(gate)
        parity_package.assert_replay_equivalence(gate, rebuilt)
        self.assertEqual(
            rebuilt.semantic_projection_digest("simulation"),
            gate.semantic_projection_digest("simulation"),
        )
        self.assertEqual(
            rebuilt.semantic_projection_digest("production"),
            gate.semantic_projection_digest("production"),
        )
        re_verdict = rebuilt.parity_verdict(
            scenario_id="replay-1",
            shared_input_digest=result.verdict.shared_input_digest,
        )
        self.assertEqual(re_verdict.verdict, "PARITY")
        self.assertEqual(
            re_verdict.simulation.semantic_projection_digest,
            result.verdict.simulation.semantic_projection_digest,
        )

    def test_replay_never_calls_the_rails(self) -> None:
        scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-replay-2",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        pair = parity_package.build_environment_pair(scripts=scripts)
        gate = parity_package.SimulationParityGate(pair=pair)
        parity_package.run_parity_scenario(
            gate,
            tag="replay-2",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        before = (
            pair.simulation.rail.submit_call_count,
            pair.production.rail.submit_call_count,
        )
        rebuilt = parity_package.rebuild_parity_gate(gate)
        parity_package.assert_replay_equivalence(gate, rebuilt)
        after = (
            pair.simulation.rail.submit_call_count,
            pair.production.rail.submit_call_count,
        )
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# 11. end-to-end determinism
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_two_full_runs_produce_identical_verdicts(self) -> None:
        scripts = (
            parity_package.DeclaredRailScript(
                idempotency_key="ig003-det-1",
                submission="accept",
                query="succeeded",
                native_status="STLD",
                finality_claim="FINAL",
            ),
        )
        first = parity_package.run_parity_scenario(
            parity_package.SimulationParityGate(
                pair=parity_package.build_environment_pair(scripts=scripts)
            ),
            tag="det-1",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        second = parity_package.run_parity_scenario(
            parity_package.SimulationParityGate(
                pair=parity_package.build_environment_pair(scripts=scripts)
            ),
            tag="det-1",
            scripts=scripts,
            payer="principal/payer-ig003",
            payee="principal/merchant-42",
            amount_minor=10000,
        )
        self.assertEqual(
            first.verdict.to_dict(), second.verdict.to_dict()
        )


# ---------------------------------------------------------------------------
# 12. DOGFOOD-028 conformance
# ---------------------------------------------------------------------------


class DogfoodConformanceTests(unittest.TestCase):
    def test_dogfood_transcript_passes_and_is_deterministic(self) -> None:
        from src.integration.parity.dogfooding import build_transcript

        first, digest_first = build_transcript()
        second, digest_second = build_transcript()
        self.assertEqual(first, second)
        self.assertEqual(digest_first, digest_second)
        self.assertIn("classification: DOGFOOD-028: PASS", first)

    def test_dogfood_transcript_names_the_required_parity_facts(self) -> None:
        from src.integration.parity.dogfooding import build_transcript

        transcript, _ = build_transcript()
        for required in (
            "architecture=v0.1",
            "work_order=WORK-028",
            "gate=IG-003",
            "simulation_environment=env/sandbox-ig003-simulation",
            "production_compatible_environment=env/production-ig003-compatible",
            "shared_input_digest=",
            "simulation_result_digest=",
            "production_compatible_result_digest=",
            "semantic_normalization_digest=",
            "parity_verdict=PARITY",
            "SIMULATED",
            "OBSERVED",
        ):
            self.assertIn(required, transcript)

    def test_dogfood_transcript_contains_no_secret_material(self) -> None:
        from src.integration.parity.dogfooding import build_transcript

        transcript, _ = build_transcript()
        for forbidden in (
            "Bearer",
            "Authorization",
            "secret",
            "sk_",
            "STRIPE_SECRET",
            "password",
        ):
            self.assertNotIn(forbidden, transcript)


if __name__ == "__main__":
    unittest.main()
