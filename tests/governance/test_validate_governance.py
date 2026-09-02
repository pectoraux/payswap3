from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Real commit that predates the W002 implementation merge on main: a valid
# ancestor of main but strictly older than the recorded verified
# implementation frontier. Used to discriminate stale revision bindings.
PRE_FRONTIER = "f8048bb2111771bca4e96eb2f709dad75dc1bc77"

FABRICATED_REVISION = "0" * 40


class GovernanceValidatorTests(unittest.TestCase):
    """Discrimination suite for the fail-closed repository governance validator.

    Each test builds a clean checkout sandbox whose git history is bound to
    the real `main` ref, mutates only control-plane revisions/declarations,
    and proves the validator rejects (or accepts) the resulting state.
    """

    def run_validator(self, mutate=None, with_git: bool = True) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "repo"
            shutil.copytree(ROOT, sandbox, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            if with_git:
                self._bind_main_history(sandbox)
            if mutate is not None:
                mutate(sandbox)
            return subprocess.run(
                ["python3", str(sandbox / "scripts" / "validate_governance.py")],
                text=True,
                capture_output=True,
                check=False,
            )

    @staticmethod
    def _bind_main_history(sandbox: Path) -> None:
        # Boot the sandbox on a scratch branch so `main` can be fetched into
        # refs/heads/main without touching the checkout.
        subprocess.run(
            ["git", "init", "-q", "-b", "sandbox-scratch", str(sandbox)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(sandbox), "fetch", "-q", str(ROOT), "+main:main"],
            check=True,
            capture_output=True,
        )

    @staticmethod
    def _divergent_commit(sandbox: Path) -> str:
        """Create a real commit that is not reachable from main and return it."""
        subprocess.run(
            [
                "git", "-C", str(sandbox),
                "-c", "user.email=governance@test", "-c", "user.name=governance-test",
                "commit", "--allow-empty", "-q", "-m", "divergence",
            ],
            check=True,
            capture_output=True,
        )
        result = subprocess.run(
            ["git", "-C", str(sandbox), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _rewrite_program_state(self, root: Path, apply) -> None:
        path = root / "spec" / "development-state" / "program-state.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        apply(data)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _record(data: dict, wid: str) -> dict:
        return next(record for record in data["workOrders"] if record["id"] == wid)

    def _set_current_main(self, revision: str):
        def mutate(root: Path) -> None:
            self._rewrite_program_state(root, lambda data: data.__setitem__("currentMain", revision))
        return mutate

    def _set_active_base(self, wid: str, revision: str):
        def mutate(root: Path) -> None:
            def apply(data: dict) -> None:
                self._record(data, wid)["baseRevision"] = revision
            self._rewrite_program_state(root, apply)
        return mutate

    def _rewrite_work_order(self, wid: str, old: str, new: str):
        def mutate(root: Path) -> None:
            path = root / "spec" / "work-orders" / f"{wid}.md"
            text = path.read_text(encoding="utf-8")
            assert old in text, f"fixture requires {old!r} in {wid}.md"
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
        return mutate

    # ------------------------------------------------------------------
    # lifecycle compatibility: bootstrap, active, blocked, ready_for_merge, complete
    # ------------------------------------------------------------------

    def test_clean_repository_passes(self) -> None:
        # The reconciled repository state itself is the positive control for
        # the blocked-pending-corrective-dependency lifecycle: W003-W009 are
        # blocked with an incomplete WORK-032 implementation dependency and
        # that state must validate.
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("PAYSWAP GOVERNANCE: PASS", result.stdout)

    def test_unbound_nonplanned_work_order_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            self._rewrite_program_state(root, lambda data: data.__setitem__("workOrders", []))
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
        # WORK-032 is in_flight on the current frontier; stripping its
        # baseRevision must fail closed.
        def mutate(root: Path) -> None:
            def apply(data: dict) -> None:
                self._record(data, "WORK-032").pop("baseRevision", None)
            self._rewrite_program_state(root, apply)
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active Work Order WORK-032 missing baseRevision", result.stderr)

    def test_program_and_document_status_must_match(self) -> None:
        def mutate(root: Path) -> None:
            def apply(data: dict) -> None:
                data["workOrders"][0]["status"] = "ready_for_merge"
            self._rewrite_program_state(root, apply)
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("status drift", result.stderr)

    def test_unknown_work_order_status_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            path = root / "spec" / "work-orders" / "WORK-001.md"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                re.sub(r"^Status: .+$", "Status: nonsense", text, count=1, flags=re.M),
                encoding="utf-8",
            )
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid Work Order status", result.stderr)

    def test_in_flight_work_order_with_incomplete_dependency_is_rejected(self) -> None:
        # Discrimination: blocked with an incomplete dependency is valid,
        # but the same Work Order activated to in_flight must fail closed.
        def mutate(root: Path) -> None:
            def apply(data: dict) -> None:
                self._record(data, "WORK-003")["status"] = "in_flight"
            self._rewrite_program_state(root, apply)
            path = root / "spec" / "work-orders" / "WORK-003.md"
            text = path.read_text(encoding="utf-8")
            assert "Status: blocked" in text, "fixture requires blocked WORK-003"
            path.write_text(text.replace("Status: blocked", "Status: in_flight", 1), encoding="utf-8")
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("implementation dependency not complete for WORK-003: WORK-032", result.stderr)

    # ------------------------------------------------------------------
    # revision binding (W001-1): stale main/currentMain
    # ------------------------------------------------------------------

    def test_unresolvable_currentmain_is_rejected(self) -> None:
        result = self.run_validator(self._set_current_main(FABRICATED_REVISION))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("currentMain is not resolvable", result.stderr)

    def test_currentmain_off_main_history_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            self._set_current_main(self._divergent_commit(root))(root)
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("currentMain is not an ancestor of main", result.stderr)

    def test_currentmain_implementation_drift_is_rejected(self) -> None:
        # currentMain older than the W002 implementation merge: main contains
        # non-control-plane changes beyond the recorded frontier.
        result = self.run_validator(self._set_current_main(PRE_FRONTIER))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "non-control-plane changes beyond the verified implementation frontier",
            result.stderr,
        )

    def test_non_revision_currentmain_is_rejected(self) -> None:
        result = self.run_validator(self._set_current_main("HEAD"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid revision recorded", result.stderr)

    # ------------------------------------------------------------------
    # revision binding (W001-1): stale active Work Order baseRevision
    # ------------------------------------------------------------------

    def test_stale_active_base_revision_predating_frontier_is_rejected(self) -> None:
        result = self.run_validator(self._set_active_base("WORK-032", PRE_FRONTIER))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("predates the verified implementation frontier", result.stderr)

    def test_active_base_revision_off_main_history_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            self._set_active_base("WORK-032", self._divergent_commit(root))(root)
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not an ancestor of main", result.stderr)

    def test_unresolvable_active_base_revision_is_rejected(self) -> None:
        result = self.run_validator(self._set_active_base("WORK-032", FABRICATED_REVISION))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("base revision for active Work Order WORK-032 is not resolvable", result.stderr)

    # ------------------------------------------------------------------
    # fail-closed dependency parsing (W001-2)
    # ------------------------------------------------------------------

    def test_malformed_dependency_syntax_is_rejected(self) -> None:
        # missing type annotation: previously silently ignored by the parser
        result = self.run_validator(
            self._rewrite_work_order("WORK-032", "WORK-002 (implementation)", "WORK-002 implementation")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed dependency declaration for WORK-032", result.stderr)

    def test_dangling_dependency_token_is_rejected(self) -> None:
        # partially parseable trailing token: previously silently dropped
        result = self.run_validator(
            self._rewrite_work_order(
                "WORK-032", "WORK-002 (implementation)", "WORK-002 (implementation) WORK-032"
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed dependency declaration for WORK-032", result.stderr)

    def test_unknown_dependency_type_in_document_is_rejected(self) -> None:
        # typo'd/unknown type vocabulary: previously silently ignored
        result = self.run_validator(
            self._rewrite_work_order("WORK-032", "WORK-002 (implementation)", "WORK-002 (implemenation)")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown dependency type for WORK-032", result.stderr)

    def test_unknown_dependency_type_in_state_is_rejected(self) -> None:
        def mutate(root: Path) -> None:
            path = root / "spec" / "development-state" / "dependency-state.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["workOrders"]["WORK-032"]["dependencies"][0]["type"] = "gated"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        result = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown dependency type for WORK-032", result.stderr)

    def test_duplicate_dependency_declaration_is_rejected(self) -> None:
        result = self.run_validator(
            self._rewrite_work_order(
                "WORK-032",
                "WORK-002 (implementation)",
                "WORK-002 (implementation), WORK-002 (contract)",
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate dependency declaration for WORK-032", result.stderr)

    # ------------------------------------------------------------------
    # git binding itself must fail closed
    # ------------------------------------------------------------------

    def test_git_facts_unavailable_fails_closed(self) -> None:
        result = self.run_validator(with_git=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("git facts unavailable", result.stderr)


if __name__ == "__main__":
    unittest.main()
