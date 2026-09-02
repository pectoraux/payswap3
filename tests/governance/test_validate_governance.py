from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GovernanceValidatorTests(unittest.TestCase):
    def run_validator(self, mutate=None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "repo"
            shutil.copytree(ROOT, sandbox, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            if mutate is not None:
                mutate(sandbox)
            return subprocess.run(
                ["python3", str(sandbox / "scripts" / "validate_governance.py")],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_clean_repository_passes(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("PAYSWAP GOVERNANCE: PASS", result.stdout)

    def test_unbound_nonplanned_work_order_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            state = root / "spec" / "development-state" / "program-state.json"
            data = json.loads(state.read_text(encoding="utf-8"))
            data["workOrders"] = []
            state.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing program-state record", result.stderr)

    def test_unknown_dependency_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            path = root / "spec" / "development-state" / "dependency-state.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["workOrders"]["WORK-001"]["dependencies"] = [
                {"id": "WORK-999", "type": "implementation"}
            ]
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown dependency WORK-999", result.stderr)

    def test_active_work_requires_operational_binding(self) -> None:
        def mutate(root: Path) -> None:
            state = root / "spec" / "development-state" / "program-state.json"
            data = json.loads(state.read_text(encoding="utf-8"))
            data["workOrders"] = [{"id": "WORK-001", "status": "in_flight"}]
            state.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            wo = root / "spec" / "work-orders" / "WORK-001.md"
            text = wo.read_text(encoding="utf-8")
            if "Status: in_flight" not in text:
                raise AssertionError("fixture requires active WORK-001")

        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing baseRevision", result.stderr)


if __name__ == "__main__":
    unittest.main()
