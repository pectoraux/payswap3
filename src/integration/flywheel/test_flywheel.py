"""The IG-006 flywheel contract suite.

Covers the WORK-031 required proofs:

* **static** — the typed, versioned, fail-closed gate identity, the
  consumed-surface AST audit (no second authority, no unmerged
  sibling), the closed vocabularies, no wall-clock/entropy;
* **dynamic** — the complete merchant/customer journey through the
  real composed authorities, the invariant battery and determinism;
* **discrimination** — the containment battery: every probe removes
  or bypasses one claimed protection and proves the journey fails
  closed with the live composed state byte-unchanged;
* **quality-attribute** — the measured execution properties (cost,
  time, reliability/outcome, recovery behavior);
* **dogfooding conformance** — DOGFOOD-031: deterministic, PASS;
* **WorkflowOS contamination regression** — the repository stays free
  of WorkflowOS-specific material (the audit's durable guard).
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .contracts import (
    CONSUMED_SURFACES,
    CONTAINMENT_PROBES,
    FLYWHEEL_API_VERSION,
    FLYWHEEL_GATE_ID,
    FLYWHEEL_SCHEMA_VERSION,
    JOURNEY_STAGE_TOKENS,
    KNOWN_FLYWHEEL_GATES,
    JourneyOutcome,
    JourneyStage,
    validate_flywheel_gate_id,
)
from .dogfooding import build_transcript
from .harness import FlywheelGate
from .invariants import verify_flywheel_invariants
from .scenarios import (
    journey_quality_attributes,
    run_containment_battery,
    run_merchant_journey,
)

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_DIR.parents[2]


def _iterate_module_names(tree: ast.AST):
    """Yield every ABSOLUTE import module name (relative imports are
    intra-package by construction and are not external surface)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                yield node.module


class TestGateIdentityAndBoundary(unittest.TestCase):
    """The typed, versioned, fail-closed gate identity and surface audit."""

    def test_gate_identity_is_the_spec_row(self) -> None:
        self.assertEqual(FLYWHEEL_GATE_ID, "IG-006")
        self.assertEqual(FLYWHEEL_API_VERSION, "v0.1")
        self.assertEqual(FLYWHEEL_SCHEMA_VERSION, 1)
        self.assertEqual(KNOWN_FLYWHEEL_GATES, frozenset({"IG-006"}))

    def test_gate_id_fails_closed_on_every_other_gate(self) -> None:
        for foreign in (
            "IG-001",
            "IG-002",
            "IG-003",
            "IG-004",
            "IG-005",
            "",
            None,
            4,
        ):
            with self.assertRaises(CoreValidationError):
                validate_flywheel_gate_id(foreign)
        self.assertEqual(validate_flywheel_gate_id("IG-006"), "IG-006")

    def test_consumed_surfaces_are_the_declared_merged_roots(self) -> None:
        self.assertEqual(
            set(CONSUMED_SURFACES),
            {
                "src.core",
                "src.transition",
                "src.value",
                "src.evidence",
                "src.merchant",
                "src.operations",
                "src.simulation",
                "src.interoperability",
                "src.execution",
                "src.clearing",
                "src.integration.lifecycle",
                "src.integration.parity",
                "src.integration.rails",
            },
        )

    def test_package_imports_only_declared_surfaces(self) -> None:
        allowed = set(CONSUMED_SURFACES)
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for module in _iterate_module_names(tree):
                if module == "src.integration.flywheel":
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
                        allowed | {"src.integration.flywheel"},
                        f"{path.name} imports undeclared root {module!r}",
                    )

    def test_no_wall_clock_or_entropy_in_kernel_logic(self) -> None:
        forbidden = {
            "datetime.now",
            "datetime.today",
            "time.time",
            "time.monotonic",
            "random.random",
            "random.randint",
            "random.choice",
            "secrets.token",
            "uuid.uuid",
        }
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    function = node.func
                    parts: list[str] = []
                    while isinstance(function, ast.Attribute):
                        parts.append(function.attr)
                        function = function.value
                    if isinstance(function, ast.Name):
                        parts.append(function.id)
                        dotted = ".".join(reversed(parts))
                        self.assertNotIn(
                            dotted,
                            forbidden,
                            f"{path.name} calls non-deterministic {dotted}()",
                        )

    def test_closed_vocabularies_are_exact(self) -> None:
        self.assertEqual(
            JOURNEY_STAGE_TOKENS,
            frozenset(stage.value for stage in JourneyStage),
        )
        self.assertEqual(
            {outcome.value for outcome in JourneyOutcome},
            {"delayed-settlement-completed", "settlement-failed"},
        )
        self.assertEqual(
            CONTAINMENT_PROBES,
            frozenset(
                {
                    "merchant-credit-limit",
                    "unknown-outcome-obligation",
                    "failover-authority-conservation",
                    "resolve-without-recovery",
                    "outcome-before-finality",
                    "outcome-binding-mismatch",
                }
            ),
        )

    def test_public_all_is_sorted_and_complete(self) -> None:
        from . import __all__ as public_all

        self.assertEqual(list(public_all), sorted(public_all))
        for name in public_all:
            self.assertTrue(hasattr(sys.modules["src.integration.flywheel"], name))

    def test_package_projects_no_new_protocol_visible_name(self) -> None:
        """The gate invents no object type and no event namespace.

        Every durable record the journey produces belongs to a consumed
        domain's own registered or internal object types (checked
        structurally: the package declares no ``payswap/`` object type
        and registers no kernel command of its own).
        """
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            source = path.read_text(encoding="utf-8")
            self.assertNotIn(
                '"payswap/',
                source,
                f"{path.name} projects a protocol-visible object type",
            )
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.endswith(
                            "OBJECT_TYPE"
                        ):
                            self.fail(
                                f"{path.name} declares a durable object type "
                                f"{target.id}; the gate owns none"
                            )


class TestMerchantJourney(unittest.TestCase):
    """The complete merchant/customer journey through the real authorities."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = FlywheelGate()
        cls.result = run_merchant_journey(cls.gate)
        cls.checks = verify_flywheel_invariants(cls.gate)

    def test_invariant_battery_passes_with_the_full_check_list(self) -> None:
        self.assertTrue(len(self.checks) >= 40)
        for check in self.checks:
            self.assertIsInstance(check, str)

    def test_merchant_delay_credit_condition_is_explicit(self) -> None:
        records = self.gate.merchant
        self.assertEqual(records["checkout/ig006-1"].envelope.state, "PROMISED")
        promise = records["promise/ig006-1"]
        self.assertEqual(promise.envelope.state, "PENDING")
        self.assertEqual(promise.spec.settlement_id, "settlement/ig006/batch-flywheel-1")
        self.assertLessEqual(promise.spec.amount.value, promise.spec.credit_limit.value)

    def test_the_kill_never_produces_a_false_success(self) -> None:
        facts = self.result["facts"]
        self.assertEqual(facts["first_submission_state"], "UNKNOWN")
        self.assertEqual(facts["dead_leg_reconciliation"], "NOT_FOUND")

    def test_the_delayed_settlement_completed(self) -> None:
        report = self.result["report"]
        self.assertEqual(report["settlement_state"], "COMPLETED")
        self.assertEqual(report["finality_state"], "ESTABLISHED")
        self.assertEqual(report["outcome"], "delayed-settlement-completed")

    def test_recovery_stayed_inside_the_declared_objective(self) -> None:
        facts = self.result["facts"]
        self.assertEqual(facts["incident_final_state"], "RESOLVED")
        self.assertLessEqual(facts["recovery_duration_seconds"], 3600)

    def test_the_outcome_is_durable_evidence(self) -> None:
        report = self.result["report"]
        observation = self.gate.evidence.get(report["outcome_observation_id"])
        evidence = self.gate.evidence.get(report["journey_evidence_id"])
        self.assertIsNotNone(observation)
        self.assertIsNotNone(evidence)
        self.assertEqual(observation.spec.subject_ref, "promise/ig006-1")
        self.assertEqual(evidence.spec.subject_ref, "checkout/ig006-1")

    def test_stage_journal_chains_and_every_stage_is_accepted(self) -> None:
        journal = self.gate.stage_journal
        self.assertGreater(len(journal), 0)
        for index in range(len(journal) - 1):
            self.assertEqual(
                journal[index]["state_after"],
                journal[index + 1]["state_before"],
            )
        self.assertTrue(all(entry["outcome"] == "accepted" for entry in journal))

    def test_the_journey_is_deterministic(self) -> None:
        second_gate = FlywheelGate()
        second_result = run_merchant_journey(second_gate)
        first_digest = canonical_sha256(
            {"snapshot": self.gate.snapshot(), "facts": self.result["facts"]}
        )
        second_digest = canonical_sha256(
            {"snapshot": second_gate.snapshot(), "facts": second_result["facts"]}
        )
        self.assertEqual(first_digest, second_digest)


class TestDiscrimination(unittest.TestCase):
    """The containment battery: remove/bypass each claimed protection."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = FlywheelGate()
        run_merchant_journey(cls.gate)
        cls.battery = run_containment_battery(cls.gate)

    def test_every_probe_is_contained(self) -> None:
        for probe, result in self.battery["probes"].items():
            self.assertTrue(
                result["contained"],
                f"probe {probe} was NOT contained: {result['reason']}",
            )

    def test_the_battery_covers_exactly_the_frozen_probes(self) -> None:
        self.assertEqual(set(self.battery["probes"]), set(CONTAINMENT_PROBES))

    def test_the_live_composed_state_is_byte_unchanged(self) -> None:
        self.assertTrue(self.battery["live_state_unchanged"])

    def test_each_probe_fails_for_its_own_reason(self) -> None:
        expected_reasons = {
            "merchant-credit-limit": "credit limit exceeded",
            "unknown-outcome-obligation": "obligations are recognized",
            "failover-authority-conservation": "conservation gate",
            "resolve-without-recovery": "classify HEALTHY",
            "outcome-before-finality": "finality",
            "outcome-binding-mismatch": "binding",
        }
        for probe, fragment in expected_reasons.items():
            self.assertIn(
                fragment,
                self.battery["probes"][probe]["reason"],
                f"probe {probe} failed for an unexpected reason",
            )


class TestQualityAttributes(unittest.TestCase):
    """The measured execution properties (deterministic, reproducible)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = FlywheelGate()
        run_merchant_journey(cls.gate)
        cls.quality = journey_quality_attributes(cls.gate)

    def test_cost_is_measured(self) -> None:
        self.assertEqual(self.quality["commands_driven"], 45)
        self.assertEqual(self.quality["stages_recorded"], 42)
        self.assertEqual(self.quality["rail_submit_calls_primary"], 1)
        self.assertEqual(self.quality["rail_submit_calls_redundancy"], 1)

    def test_time_is_measured_from_declared_instants(self) -> None:
        self.assertEqual(self.quality["journey_logical_seconds"], 21000)
        self.assertEqual(self.quality["recovery_logical_seconds"], 1620)
        self.assertEqual(self.quality["settlement_delay_window_seconds"], 99600)

    def test_reliability_outcome_is_measured(self) -> None:
        self.assertEqual(self.quality["outcome"], "delayed-settlement-completed")
        self.assertEqual(self.quality["killed_leg_outcome"], "UNKNOWN")
        self.assertEqual(self.quality["dead_leg_reconciliation"], "NOT_FOUND")
        self.assertEqual(self.quality["recovery_step_state"], "SUCCEEDED")
        self.assertEqual(self.quality["settlement_batch_state"], "COMPLETED")
        self.assertEqual(self.quality["false_success_count"], 0)

    def test_recovery_behavior_is_measured(self) -> None:
        self.assertEqual(self.quality["recovery_duration_seconds"], 1500)
        self.assertEqual(self.quality["recovery_time_objective_seconds"], 3600)
        self.assertTrue(self.quality["recovery_within_objective"])
        self.assertEqual(self.quality["recovery_retry_count"], 1)


class TestDogfoodingConformance(unittest.TestCase):
    """DOGFOOD-031: the real merchant/customer sandbox journey."""

    def test_transcript_passes_and_is_deterministic(self) -> None:
        first_transcript, first_digest = build_transcript()
        second_transcript, second_digest = build_transcript()
        self.assertEqual(first_transcript, second_transcript)
        self.assertEqual(first_digest, second_digest)
        self.assertIn("DOGFOOD-031: PASS", first_transcript)
        self.assertEqual(len(first_digest), 64)

    def test_transcript_reports_the_composed_journey(self) -> None:
        transcript, _digest = build_transcript()
        for marker in (
            "checkout",
            "promise",
            "kill",
            "failover",
            "NOT_FOUND",
            "delayed settlement",
            "finality",
            "merchant outcome",
            "invariants: 50/50 PASS",
            "containment battery: 6/6",
            "quality attributes",
        ):
            self.assertIn(marker, transcript)


class TestWorkflowOSContaminationRegression(unittest.TestCase):
    """The repository stays free of WorkflowOS-specific material.

    This is the durable regression guard of the WORK-031 contamination
    audit. It fails closed if any WorkflowOS-specific marker appears in
    the repository's source, specifications, agent material, CI
    configuration, fixtures or generated artifacts.

    Deliberately NOT treated as contamination (the audit's
    classification discipline): GitHub Actions workflow paths
    (``.github/workflows/``), legitimate PaySwap workflow/process
    terminology, worker orchestration/protocol language required by
    PaySwap governance, and ordinary scheduling/state-machine
    vocabulary — the GENERIC word "workflow" is not a marker.
    """

    #: WorkflowOS-specific markers: the project's name variants, its
    #: repository URL, its environment-variable prefix, and its
    #: product-specific host URLs and bridge identifiers.
    MARKERS = (
        "WorkflowOS",
        "workflowos",
        "workflow-os",
        "Workflow OS",
        "WORKFLOWOS_",
        "pectoraux/WorkflowOS",
        "chat.z.ai",
        "claude.com/code",
        "chatgpt.com/codex",
        "workflowos-bridge",
    )

    #: Binary/derived directories never scanned.
    SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}

    #: The audit's own durable record names the markers it guards
    #: against (the honest documentation of what was searched); it is
    #: not contamination and is excluded from the scan.
    RECORD_PATH = _REPO_ROOT / "spec" / "dogfooding" / "DOGFOOD-031.md"

    #: The guard's own file names the markers it guards against
    #: (the same self-referential exclusion as the record).
    GUARD_PATH = Path(__file__).resolve()

    def _scanned_files(self):
        for path in _REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            if path in (self.RECORD_PATH, self.GUARD_PATH):
                continue
            yield path

    def test_no_workflowos_specific_material_remains(self) -> None:
        offenders: list[str] = []
        for path in self._scanned_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for marker in self.MARKERS:
                if marker in text:
                    offenders.append(f"{path.relative_to(_REPO_ROOT)}: {marker}")
                    break
        self.assertEqual(
            offenders,
            [],
            "WorkflowOS-specific contamination found: " + "; ".join(offenders),
        )

    def test_the_audit_baseline_is_recorded(self) -> None:
        """The audit found zero contamination at the WORK-031 base.

        The durable record is ``spec/dogfooding/DOGFOOD-031.md``; this
        check pins the audit's presence so the finding cannot silently
        vanish.
        """
        record = _REPO_ROOT / "spec" / "dogfooding" / "DOGFOOD-031.md"
        self.assertTrue(
            record.exists(),
            "the DOGFOOD-031 experiment record must be persisted",
        )
        text = record.read_text(encoding="utf-8")
        self.assertIn("WorkflowOS", text)
        self.assertIn("contamination", text.casefold())


if __name__ == "__main__":
    unittest.main()
