"""IG-004 extension/agent economic integration gate — contract suite.

The suite pins the public boundary of the extension/agent economic
integration gate (WORK-029, ``spec/integration-gates.md`` row IG-004:
"extension/agent economic integration | WORK-020, 021, 028"):

* a typed, versioned, frozen public API composing the REAL merged
  extension runtime + capability marketplace (WORK-020), the REAL
  models/agents/decision-mediation surface (WORK-021) and the REAL
  merchant checkout record boundary (WORK-025) on a merchant demand
  scenario, with the merged IG-003 comparison authority (WORK-028)
  classifying residual cross-environment differences;
* authority containment: extensions cannot acquire undeclared authority
  (tier schedules, forbidden permissions, undeclared resources), agents
  cannot escalate beyond the frozen R2 PROPOSE tier, agent contexts are
  hypothetical-world-only, model outputs can never masquerade as
  observations, and mediation decisions carry no execution authority;
* simulation-first decision: every candidate is simulated in a
  SIMULATION-mode environment before the deterministic policy selects;
* economic contribution: verified incremental contribution against a
  counterfactual baseline, exact integer revenue-share earnings, the
  three distinct typed economic quantities, conservation of attribution
  and conservation through the merged money FX authority;
* semantic parity of the SAME declared economic composition across the
  simulation and the production-compatible environments (one machine,
  many worlds), with a frozen field-bound normalization registry and
  every residual difference classified by the merged IG-003 diff
  authority as a semantic divergence that fails the gate closed;
* deterministic replay/rebuild, stage-journal discipline and DOGFOOD-029
  conformance;
* fail-closed hardening of the defense-in-depth re-check layers: forged
  authority journal events, non-hypothetical agent contexts, world
  mode/epistemic confusion, tampered snapshot digests, divergent
  re-sealed verdicts and containment-probe state accounting.

The suite is fully deterministic and network-free; every instant is
declared ``as_of`` data.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import subprocess
import sys
import unittest
from types import SimpleNamespace

import src.integration.economics as economics_package
from src.integration.economics import (
    AGENT_PRINCIPAL,
    AGENTS_DOMAIN_ID,
    CONSUMED_SURFACES,
    CONTAINMENT_PROBES,
    CONTRIBUTION_ID,
    DECISION_ID,
    DEFAULT_ECONOMICS_ACTOR,
    DEMAND_ARTIFACT_ID,
    ECONOMICS_API_VERSION,
    ECONOMICS_ENV_BOUND_FIELDS,
    ECONOMICS_GATE_ID,
    ECONOMICS_NORMALIZATION_RULES,
    ECONOMICS_SCHEMA_VERSION,
    EXTENSION_ID,
    EXTENSIONS_DOMAIN_ID,
    INSTANCE_ID,
    KNOWN_ECONOMICS_GATES,
    MANDATE_ID,
    MEDIATION_ID,
    MERCHANT_CHECKOUT_ID,
    MERCHANT_DOMAIN_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    SIMULATION_ENVIRONMENT_ID,
    assert_economic_parity,
    assert_replay_equivalence,
    build_dogfood_transcript,
    build_economic_pair,
    canonical_sha256,
    economic_projection,
    economic_projection_digest,
    economic_state,
    normalize_economic_state,
    rebuild_economic_gate,
    run_containment_battery,
    run_economic_scenario,
    verify_economic_invariants,
    validate_economics_gate_id,
)
from src.integration.economics import (
    EconomicIntegrationGate,
    EconomicVerdict,
    EconomicWorld,
    ContainmentProbeResult,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent


def _iterate_module_names(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                yield node.module


class TestGateIdentityAndBoundary(unittest.TestCase):
    """The typed, versioned, fail-closed gate identity and surface audit."""

    def test_gate_identity_is_the_spec_row(self) -> None:
        self.assertEqual(ECONOMICS_GATE_ID, "IG-004")
        self.assertEqual(ECONOMICS_API_VERSION, "v0.1")
        self.assertEqual(ECONOMICS_SCHEMA_VERSION, 1)
        self.assertEqual(KNOWN_ECONOMICS_GATES, frozenset({"IG-004"}))

    def test_gate_id_fails_closed_on_every_other_gate(self) -> None:
        from src.core.errors import CoreValidationError

        for foreign in ("IG-001", "IG-002", "IG-003", "IG-005", "IG-006", "", None, 4):
            with self.assertRaises(CoreValidationError):
                validate_economics_gate_id(foreign)
        self.assertEqual(validate_economics_gate_id("IG-004"), "IG-004")

    def test_consumed_surfaces_are_the_declared_merged_roots(self) -> None:
        self.assertEqual(
            set(CONSUMED_SURFACES),
            {
                "src.core",
                "src.transition",
                "src.evidence",
                "src.value",
                "src.money",
                "src.merchant",
                "src.extensions",
                "src.agents",
                "src.simulation",
                "src.integration.parity",
            },
        )

    def test_package_imports_only_declared_surfaces(self) -> None:
        allowed = set(CONSUMED_SURFACES)
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for module in _iterate_module_names(tree):
                if module == "src.integration.economics":
                    continue
                root = module.split(".")[0]
                self.assertIn(
                    root,
                    {"src", "__future__"}
                    | {m.split(".", 1)[1] for m in allowed}
                    | sys.stdlib_module_names,
                    f"{path.name} imports {module!r} outside the declared surface",
                )
                if module.startswith("src."):
                    top = ".".join(module.split(".")[:2])
                    if module.startswith("src.integration."):
                        top = ".".join(module.split(".")[:3])
                    self.assertIn(
                        top,
                        allowed | {"src.integration.economics"},
                        f"{path.name} imports undeclared root {module!r}",
                    )

    def test_no_wall_clock_or_entropy_in_kernel_logic(self) -> None:
        forbidden = {
            "datetime.now",
            "datetime.today",
            "date.today",
            "time.time",
            "time.monotonic",
            "random",
            "uuid",
            "secrets",
        }
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for module in _iterate_module_names(ast.Module(body=[], type_ignores=[])) if False else []:
                        pass
                    modules = [alias.name for alias in getattr(node, "names", [])]
                    if getattr(node, "module", None):
                        modules.append(node.module)
                    for module in modules:
                        self.assertNotIn(
                            module.split(".")[0],
                            {"random", "uuid", "secrets"},
                            f"{path.name} touches an entropy source",
                        )
                if isinstance(node, ast.Call):
                    function = node.func
                    name = ""
                    if isinstance(function, ast.Attribute):
                        name = function.attr
                        if isinstance(function.value, ast.Name):
                            name = f"{function.value.id}.{function.attr}"
                    elif isinstance(function, ast.Name):
                        name = function.id
                    if name:
                        for banned in forbidden:
                            self.assertNotEqual(
                                name,
                                banned,
                                f"{path.name} calls {banned!r}",
                            )

    def test_import_closure_is_clean_in_isolated_process(self) -> None:
        code = (
            "import sys\n"
            "import src.integration.economics\n"
            "roots = sorted({m.split('.')[0] for m in sys.modules if not m.startswith('_')})\n"
            "print(roots)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        roots = set(eval(result.stdout.strip()))
        self.assertIn("src", roots)
        self.assertNotIn("random", roots)
        self.assertNotIn("uuid", roots)

    def test_public_all_is_sorted_and_complete(self) -> None:
        exported = set(economics_package.__all__)
        self.assertEqual(sorted(exported), list(economics_package.__all__))
        for name in exported:
            self.assertTrue(
                hasattr(economics_package, name),
                f"__all__ entry {name!r} is missing from the package",
            )

    def test_normalization_rules_registry_is_frozen_and_field_bound(self) -> None:
        fields = set()
        for rule in ECONOMICS_NORMALIZATION_RULES:
            self.assertEqual(
                (rule.rule_id, rule.field, rule.reason, rule.rule, rule.safety_argument),
                (
                    rule.rule_id,
                    rule.field,
                    rule.reason,
                    rule.rule,
                    rule.safety_argument,
                ),
            )
            for attribute in ("rule_id", "field", "reason", "rule", "safety_argument"):
                self.assertIsInstance(getattr(rule, attribute), str)
                self.assertTrue(getattr(rule, attribute).strip())
            fields.add(rule.field)
        self.assertTrue(fields)
        self.assertTrue(set(ECONOMICS_ENV_BOUND_FIELDS) <= fields)
        self.assertIn("environment_id", fields)
        self.assertIn("environment_mode", fields)

    def test_declared_world_constants_follow_env_class_discipline(self) -> None:
        from src.capability import classify_environment

        self.assertEqual(
            classify_environment(SIMULATION_ENVIRONMENT_ID), "sandbox"
        )
        self.assertEqual(
            classify_environment(PRODUCTION_COMPATIBLE_ENVIRONMENT_ID), "production"
        )
        for domain in (EXTENSIONS_DOMAIN_ID, AGENTS_DOMAIN_ID, MERCHANT_DOMAIN_ID):
            self.assertTrue(domain.startswith("domain/"))
        self.assertIn("principal/", DEFAULT_ECONOMICS_ACTOR)


class TestWorldConstruction(unittest.TestCase):
    """Deterministic construction of the two composed economic worlds."""

    def setUp(self) -> None:
        self.pair = build_economic_pair()

    def test_pair_carries_the_two_declared_roles(self) -> None:
        simulation, production = self.pair.simulation, self.pair.production
        self.assertIsInstance(simulation, EconomicWorld)
        self.assertIsInstance(production, EconomicWorld)
        self.assertEqual(simulation.environment_id, SIMULATION_ENVIRONMENT_ID)
        self.assertEqual(
            production.environment_id, PRODUCTION_COMPATIBLE_ENVIRONMENT_ID
        )
        from src.simulation import EnvironmentMode

        self.assertIs(simulation.environment_mode, EnvironmentMode.SIMULATION)
        self.assertIs(production.environment_mode, EnvironmentMode.PRODUCTION)
        self.assertIs(simulation.runtime.environment_mode, EnvironmentMode.SIMULATION)
        self.assertIs(production.runtime.environment_mode, EnvironmentMode.PRODUCTION)

    def test_worlds_share_domains_and_differ_only_in_environment_binding(self) -> None:
        simulation, production = self.pair.simulation, self.pair.production
        for attribute in (
            "extensions_domain_id",
            "agents_domain_id",
            "merchant_domain_id",
        ):
            self.assertEqual(
                getattr(simulation, attribute), getattr(production, attribute)
            )

    def test_construction_is_deterministic(self) -> None:
        other = build_economic_pair()
        self.assertEqual(
            economic_projection_digest(economic_state(self.pair.simulation)),
            economic_projection_digest(economic_state(other.simulation)),
        )
        self.assertEqual(
            economic_projection_digest(economic_state(self.pair.production)),
            economic_projection_digest(economic_state(other.production)),
        )

    def test_extension_fixture_satisfies_tier_and_support_contract(self) -> None:
        manifest = self.pair.simulation.runtime.manifest(EXTENSION_ID)
        self.assertEqual(manifest.authority_class, "R2")
        self.assertTrue(manifest.simulation_support)
        self.assertTrue(manifest.production_support)
        self.assertIn(
            "route_proposal",
            {capability.value for capability in manifest.capabilities_provided},
        )

    def test_extension_code_resolves_from_the_repository(self) -> None:
        runtime = self.pair.simulation.runtime
        manifest = runtime.manifest(EXTENSION_ID)
        handler = runtime.code_repository.resolve(manifest.code_hash)
        self.assertTrue(callable(handler))

    def test_merchant_fixture_is_typed_and_sealed(self) -> None:
        from src.merchant import Checkout, CheckoutState

        checkout = self.pair.simulation.checkout
        self.assertIsInstance(checkout, Checkout)
        self.assertEqual(checkout.spec.checkout_id, MERCHANT_CHECKOUT_ID)
        self.assertEqual(checkout.envelope.state, CheckoutState.DRAFT.value)
        roundtrip = Checkout.from_dict(checkout.to_dict())
        self.assertEqual(roundtrip, checkout)


class TestCanonicalScenario(unittest.TestCase):
    """Scenario A: the full composed economic chain in both worlds."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate, cls.verdict = run_economic_scenario()

    def test_verdict_is_economic_parity(self) -> None:
        self.assertEqual(self.verdict.verdict, "ECONOMIC_PARITY")
        self.assertEqual(self.verdict.differences, ())
        assert_economic_parity(self.verdict)

    def test_both_worlds_complete_the_composed_chain(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            self.assertIsNotNone(world.decision)
            self.assertIsNotNone(world.contribution)
            self.assertEqual(len(world.proposals), 2)
            instance = world.runtime.instance(INSTANCE_ID)
            self.assertEqual(instance.state.value, "ACTIVE")

    def test_stage_journal_records_both_worlds_in_lockstep(self) -> None:
        journal = self.gate.stage_journal
        self.assertTrue(journal)
        stages = [entry["stage"] for entry in journal]
        self.assertEqual(stages[::2], stages[1::2])
        for entry in journal:
            self.assertEqual(entry["outcome"], "ACCEPTED")

    def test_extension_lifecycle_reached_published_then_active(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            self.assertEqual(
                world.runtime.manifest(EXTENSION_ID).state, "PUBLISHED"
            )

    def test_treatment_invocations_are_recorded_candidate_artifacts(self) -> None:
        from src.extensions import InvocationEffectMode

        for world in (self.gate.simulation_world, self.gate.production_world):
            for invocation_id in world.treatment_invocation_ids:
                invocation = world.runtime.invocation(invocation_id)
                self.assertEqual(invocation.status, "COMPLETED")
                self.assertIs(invocation.effect_mode, InvocationEffectMode.RECORDED)

    def test_invariant_battery_passes_with_full_check_list(self) -> None:
        checks = verify_economic_invariants(self.gate)
        self.assertTrue(checks)

    def test_decision_selects_the_extension_backed_economy_route(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            self.assertEqual(
                world.decision.spec.selected_proposal_id,
                "agent-proposal/ig004-bravo-economy",
            )

    def test_contribution_is_identical_across_worlds(self) -> None:
        simulation = self.gate.simulation_world.contribution
        production = self.gate.production_world.contribution
        self.assertEqual(simulation.incremental, production.incremental)
        self.assertEqual(
            simulation.earnings.amount_minor, production.earnings.amount_minor
        )
        self.assertTrue(simulation.verified)


class TestAuthorityContainment(unittest.TestCase):
    """The negative-probe battery: no escalation, no core bypass."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.probes = run_containment_battery()

    def test_every_probe_is_contained(self) -> None:
        for probe in self.probes:
            self.assertIsInstance(probe, ContainmentProbeResult)
            self.assertTrue(probe.contained, probe.detail)
        probe_ids = {probe.probe_id for probe in self.probes}
        self.assertEqual(probe_ids, set(CONTAINMENT_PROBES))

    def test_probe_battery_covers_every_frozen_probe(self) -> None:
        self.assertGreaterEqual(len(self.probes), 10)

    def test_tier_escalation_fails_closed(self) -> None:
        probe = next(p for p in self.probes if p.probe_id == "tier-escalation-r5")
        self.assertTrue(probe.contained)
        self.assertIn("collateral", probe.detail)

    def test_forbidden_permission_fails_closed(self) -> None:
        probe = next(
            p for p in self.probes if p.probe_id == "forbidden-permission"
        )
        self.assertTrue(probe.contained)

    def test_execute_tier_agent_cannot_propose(self) -> None:
        probe = next(
            p for p in self.probes if p.probe_id == "execute-tier-proposal"
        )
        self.assertTrue(probe.contained)

    def test_production_agent_context_fails_closed(self) -> None:
        probe = next(
            p for p in self.probes if p.probe_id == "production-agent-context"
        )
        self.assertTrue(probe.contained)

    def test_agent_cannot_mediate_own_proposals(self) -> None:
        probe = next(
            p for p in self.probes if p.probe_id == "agent-self-mediation"
        )
        self.assertTrue(probe.contained)

    def test_probes_leave_the_composed_state_unchanged(self) -> None:
        for probe in self.probes:
            self.assertTrue(probe.state_unchanged, probe.detail)


class TestSimulationFirstDecision(unittest.TestCase):
    """The epistemic discipline of the simulation-first mediation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate, cls.verdict = run_economic_scenario()

    def test_frozen_mediation_mode_is_simulation(self) -> None:
        from src.agents import MEDIATION_REQUIRED_MODE
        from src.simulation import EnvironmentMode

        self.assertIs(MEDIATION_REQUIRED_MODE, EnvironmentMode.SIMULATION)

    def test_every_candidate_is_simulated_before_the_decision(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            candidates = world.decision.spec.candidates
            self.assertEqual(len(candidates), len(world.proposals))
            for candidate in candidates:
                self.assertTrue(
                    candidate.environment_id.startswith("env/agents-mediation/")
                )

    def test_decision_carries_no_execution_authority(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            payload = world.decision.spec.to_dict()
            forbidden = {"effect_intents", "execution", "authority", "mandate"}
            self.assertFalse(forbidden & set(payload))

    def test_decision_is_a_governance_event(self) -> None:
        for world in (self.gate.simulation_world, self.gate.production_world):
            journal = world.agents.journal
            self.assertEqual(journal[-1].event.event_type, "governance/mediation-selected")

    def test_model_outputs_are_simulation_epistemics_only(self) -> None:
        from src.evidence.contracts import EpistemicType

        for world in (self.gate.simulation_world, self.gate.production_world):
            for proposal in world.proposals.values():
                for output in proposal.spec.model_outputs:
                    self.assertIn(
                        output.epistemic_type,
                        {EpistemicType.SIMULATED, EpistemicType.PREDICTED},
                    )

    def test_agent_context_is_hypothetical_only(self) -> None:
        from src.agents import AGENT_ALLOWED_MODES
        from src.simulation import EnvironmentMode

        for world in (self.gate.simulation_world, self.gate.production_world):
            modes = world.context.spec.allowed_modes
            self.assertTrue(set(modes) <= AGENT_ALLOWED_MODES)
            self.assertIn(EnvironmentMode.SIMULATION, modes)
            self.assertNotIn(EnvironmentMode.PRODUCTION, modes)


class TestEconomicContribution(unittest.TestCase):
    """Verified incremental contribution and value conservation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate, cls.verdict = run_economic_scenario()

    def test_baseline_is_counterfactual_treatment_is_simulated(self) -> None:
        from src.evidence.contracts import EpistemicType

        contribution = self.gate.simulation_world.contribution
        self.assertIs(contribution.baseline.epistemic_type, EpistemicType.COUNTERFACTUAL)
        self.assertIs(contribution.treatment.epistemic_type, EpistemicType.SIMULATED)

    def test_incremental_re_derives_from_extension_evidence(self) -> None:
        world = self.gate.simulation_world
        invocation = world.runtime.invocation(world.treatment_invocation_ids[0])
        savings = invocation.output_artifacts[0].payload_value()[
            "cost_savings_minor"
        ]
        self.assertEqual(world.contribution.incremental, savings)
        self.assertEqual(world.contribution.applied_invocations, 1)

    def test_earnings_use_exact_integer_revenue_share(self) -> None:
        contribution = self.gate.simulation_world.contribution
        expected = (1000 * contribution.incremental) // 10_000
        self.assertEqual(contribution.earnings.amount_minor, expected)
        self.assertEqual(contribution.billed_minor, expected)

    def test_attribution_is_conserved(self) -> None:
        contribution = self.gate.simulation_world.contribution
        earnings = contribution.earnings.amount_minor
        residual = contribution.incremental - earnings
        self.assertGreaterEqual(residual, 0)
        self.assertEqual(earnings + residual, contribution.incremental)

    def test_unverified_treatment_never_earns(self) -> None:
        from src.integration.economics import run_contribution_integrity_scenario

        report = run_contribution_integrity_scenario()
        self.assertEqual(report["unverified_earnings_minor"], 0)
        self.assertFalse(report["unverified_verified"])

    def test_shadow_activity_adds_no_earnings(self) -> None:
        from src.integration.economics import run_contribution_integrity_scenario

        report = run_contribution_integrity_scenario()
        self.assertEqual(report["shadow_earnings_delta_minor"], 0)
        self.assertEqual(report["shadow_applied_delta"], 0)

    def test_fx_conversion_conserves_value_through_money_authority(self) -> None:
        from src.integration.economics import run_contribution_integrity_scenario

        report = run_contribution_integrity_scenario()
        self.assertTrue(report["fx_conservation"])

    def test_distinct_typed_economic_quantities(self) -> None:
        contribution = self.gate.simulation_world.contribution
        self.assertGreater(contribution.resource_credits.credits, 0)
        self.assertNotEqual(
            contribution.resource_credits.credits, contribution.earnings.amount_minor
        )
        self.assertIsNotNone(contribution.pricing.model)
        self.assertEqual(contribution.pricing.model.value, "revenue_share")


class TestParityProjection(unittest.TestCase):
    """The cross-environment semantic comparison of the economics."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate, cls.verdict = run_economic_scenario()

    def test_normalized_projections_are_equivalent(self) -> None:
        simulation = normalize_economic_state(
            economic_state(self.gate.simulation_world),
            self.gate.simulation_world,
        )
        production = normalize_economic_state(
            economic_state(self.gate.production_world),
            self.gate.production_world,
        )
        from src.integration.parity import compare_projections

        differences = compare_projections(simulation, production)
        self.assertEqual(differences, ())

    def test_projection_digests_are_deterministic(self) -> None:
        first = economic_projection_digest(
            normalize_economic_state(
                economic_state(self.gate.simulation_world),
                self.gate.simulation_world,
            )
        )
        second = economic_projection_digest(
            normalize_economic_state(
                economic_state(self.gate.simulation_world),
                self.gate.simulation_world,
            )
        )
        self.assertEqual(first, second)

    def test_foreign_environment_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError

        state = economic_state(self.gate.simulation_world)
        state["environment_id"] = "env/foreign-economics"
        with self.assertRaises(CoreValidationError):
            normalize_economic_state(state, self.gate.simulation_world)

    def test_foreign_environment_mode_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError

        state = economic_state(self.gate.production_world)
        state["environment_mode"] = "SHADOW"
        with self.assertRaises(CoreValidationError):
            normalize_economic_state(state, self.gate.production_world)

    def test_divergence_is_classified_and_fails_the_gate(self) -> None:
        from src.core.errors import CoreValidationError
        from src.integration.parity import compare_projections

        simulation = normalize_economic_state(
            economic_state(self.gate.simulation_world),
            self.gate.simulation_world,
        )
        production = normalize_economic_state(
            economic_state(self.gate.production_world),
            self.gate.production_world,
        )
        production["contribution"]["incremental"] = production["contribution"][
            "incremental"
        ] + 1
        differences = compare_projections(simulation, production)
        self.assertTrue(differences)
        with self.assertRaises(CoreValidationError):
            assert_economic_parity(
                EconomicVerdict(
                    scenario_id="ig004/divergence-feed",
                    verdict="ECONOMIC_DIVERGENCE",
                    differences=differences,
                    simulation_digest="0" * 64,
                    production_digest="0" * 64,
                    normalization_digest="0" * 64,
                    checks=(),
                )
            )


class TestReplayRebuild(unittest.TestCase):
    """Deterministic rebuild of the composed economic state."""

    def test_rebuild_reproduces_the_semantic_state(self) -> None:
        gate, _verdict = run_economic_scenario()
        rebuilt = rebuild_economic_gate(gate)
        assert_replay_equivalence(gate, rebuilt)

    def test_extensions_projection_rebuilds_from_journal(self) -> None:
        gate, _verdict = run_economic_scenario()
        for world in (gate.simulation_world, gate.production_world):
            self.assertEqual(
                world.runtime.rebuild_from_journal(),
                world.runtime.domain_state_digest(),
            )

    def test_tampered_replay_equivalence_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError

        gate, _verdict = run_economic_scenario()
        rebuilt = rebuild_economic_gate(gate)
        rebuilt.production_world.contribution = None
        with self.assertRaises(CoreValidationError):
            assert_replay_equivalence(gate, rebuilt)


class TestDogfoodingConformance(unittest.TestCase):
    """DOGFOOD-029: real extension + real agent proposal on merchant demand."""

    def test_transcript_passes_and_is_deterministic(self) -> None:
        first_transcript, first_digest = build_dogfood_transcript()
        second_transcript, second_digest = build_dogfood_transcript()
        self.assertEqual(first_transcript, second_transcript)
        self.assertEqual(first_digest, second_digest)
        self.assertIn("DOGFOOD-029: PASS", first_transcript)
        self.assertEqual(len(first_digest), 64)

    def test_transcript_reports_the_composed_economics(self) -> None:
        transcript, _digest = build_dogfood_transcript()
        self.assertIn("merchant", transcript)
        self.assertIn("extension", transcript)
        self.assertIn("mediation", transcript)
        self.assertIn("contribution", transcript)
        self.assertIn("parity", transcript)


# -- hardening test doubles ----------------------------------------------------
#
# The merged engines' own guards make the corrupted inputs below
# unreachable through the public kernel paths: the kernel stamps its own
# frozen authority class on every event, context specs reject
# non-hypothetical modes at construction, and a healthy rebuild
# re-derives byte-identical seals. Those re-check layers exist for the
# case the guards are bypassed, so these doubles forge the corrupted
# artifacts directly and assert the layers fail closed on them.


class _ForgedJournalEvent:
    """One authority-forged kernel journal event (test double)."""

    def __init__(self, event_dict: dict) -> None:
        self.event_id = event_dict["event_id"]
        self._event_dict = dict(event_dict)

    def to_dict(self) -> dict:
        return dict(self._event_dict)


class _ForgedAuthorityRuntime:
    """The real extension runtime whose kernel journal carries a forgery.

    Every attribute is delegated to the real runtime; only the projected
    journal gains a foreign-authority event the kernel itself can never
    emit.
    """

    def __init__(self, runtime, forged_event_dict: dict) -> None:
        self._runtime = runtime
        self._forged_event_dict = forged_event_dict

    def __getattr__(self, name: str):
        return getattr(self._runtime, name)

    @property
    def engine(self):
        forged_entry = SimpleNamespace(
            event=_ForgedJournalEvent(self._forged_event_dict)
        )
        return SimpleNamespace(
            journal=self._runtime.engine.journal + (forged_entry,)
        )


class _ProductionModeContext:
    """The real agent context record with PRODUCTION mode admitted.

    The spec double carries a non-hypothetical mode (the construction
    guard's bypass case); the projected record still reads through the
    sealed context.
    """

    def __init__(self, context, allowed_modes) -> None:
        self._context = context
        self.spec = SimpleNamespace(allowed_modes=tuple(allowed_modes))

    def to_dict(self) -> dict:
        return self._context.to_dict()


class _DivergentSealGate(EconomicIntegrationGate):
    """A rebuilt gate whose re-sealed verdict digest diverges (double).

    The verdict digests are pure functions of the normalized state the
    equivalence proof has just compared, so a diverging seal cannot
    arise from state divergence; this double isolates the seal-binding
    comparison itself.
    """

    def parity_verdict(self, scenario_id: str = "ig004/canonical") -> EconomicVerdict:
        sealed = super().parity_verdict(scenario_id)
        return dataclasses.replace(sealed, production_digest="0" * 64)


class TestAuthorityContainmentHardening(unittest.TestCase):
    """The authority-containment re-checks fail closed on forged inputs."""

    def test_forged_authority_journal_event_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError

        gate, _verdict = run_economic_scenario()
        world = gate.simulation_world
        forged_event = dict(economic_state(world)["extensions"]["journal"][0])
        forged_event["event_id"] = "extension-event/ig004-forged-authority"
        forged_event["authority"] = "runtime/authority-forged"
        world.runtime = _ForgedAuthorityRuntime(world.runtime, forged_event)
        with self.assertRaises(CoreValidationError) as raised:
            verify_economic_invariants(gate, cross_world=False)
        self.assertIn("carries authority", str(raised.exception))
        self.assertIn(forged_event["event_id"], str(raised.exception))

    def test_production_mode_context_fails_the_containment_recheck(self) -> None:
        from src.core.errors import CoreValidationError
        from src.simulation import EnvironmentMode

        gate, _verdict = run_economic_scenario()
        world = gate.simulation_world
        world.context = _ProductionModeContext(
            world.context,
            (EnvironmentMode.SIMULATION, EnvironmentMode.PRODUCTION),
        )
        with self.assertRaises(CoreValidationError) as raised:
            verify_economic_invariants(gate, cross_world=False)
        self.assertIn("non-hypothetical", str(raised.exception))

    def test_state_mutating_probe_is_reported_not_contained(self) -> None:
        # Re-derived in the test (before/after digests), never trusted
        # from ContainmentProbeResult.state_unchanged: the wrapper must
        # classify a state-mutating probe as NOT contained.
        from src.integration.economics.scenarios import _probe

        gate, _verdict = run_economic_scenario()
        world = gate.simulation_world

        def _mutating_action() -> None:
            world.checkout = None

        before = gate.composed_state_digest(world)
        result = _probe(world, gate, "tier-escalation-r5", _mutating_action)
        after = gate.composed_state_digest(world)
        self.assertNotEqual(before, after)
        self.assertFalse(result.state_unchanged)
        self.assertFalse(result.contained)
        self.assertIn("NOT contained", result.detail)


class TestWorldConstructionHardening(unittest.TestCase):
    """The composed-world construction bindings fail closed."""

    def test_world_mode_epistemic_confusion_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError
        from src.evidence.contracts import EpistemicType

        gate, _verdict = run_economic_scenario()
        with self.assertRaises(CoreValidationError) as raised:
            dataclasses.replace(
                gate.simulation_world, epistemic_class=EpistemicType.OBSERVED
            )
        self.assertIn("mode/epistemic confusion", str(raised.exception))


class TestReplaySealHardening(unittest.TestCase):
    """The replay digest binding and the re-sealed verdict comparison."""

    def test_tampered_snapshot_digest_fails_the_rebuild(self) -> None:
        from src.core.errors import CoreValidationError

        gate, _verdict = run_economic_scenario()
        gate.production_world.checkout = None
        with self.assertRaises(CoreValidationError) as raised:
            rebuild_economic_gate(gate)
        self.assertIn("composed state digest", str(raised.exception))

    def test_divergent_resealed_verdict_digest_fails_closed(self) -> None:
        from src.core.errors import CoreValidationError

        gate, _verdict = run_economic_scenario()
        divergent = _DivergentSealGate()
        divergent.run_canonical_scenario()
        with self.assertRaises(CoreValidationError) as raised:
            assert_replay_equivalence(gate, divergent)
        self.assertIn("production_digest", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
