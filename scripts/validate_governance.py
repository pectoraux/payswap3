#!/usr/bin/env python3
"""Fail-closed repository governance validator for PaySwap.

No network access is needed. The repository is the source of truth.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
WO_DIR = SPEC / "work-orders"
STATE = SPEC / "development-state"
ARCH = SPEC / "architecture" / "v0.1"


def load(name: str):
    p = STATE / name
    return json.loads(p.read_text(encoding="utf-8"))


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def main() -> int:
    try:
        required = [
            ARCH / "architecture-lock.md", ARCH / "constitution.md",
            SPEC / "governance" / "governance-model.json",
            SPEC / "governance" / "worker-protocol.json",
            SPEC / "governance" / "checkpoint-contract.json",
            SPEC / "governance" / "dogfooding-protocol.md",
            SPEC / "governance" / "parallel-execution.md",
            SPEC / "governance" / "fresh-architect-bootstrap.md",
            SPEC / "requirements.md", SPEC / "proof-matrix.md",
            SPEC / "registry" / "protocol-registry.json",
        ]
        for p in required:
            if not p.exists(): fail(f"missing required governance artifact: {p.relative_to(ROOT)}")

        gm = json.loads((SPEC / "governance" / "governance-model.json").read_text())
        if gm["governingArchitecture"] != "v0.1": fail("governing architecture mismatch")
        if gm["architectCardinality"] != 1 or gm["mergeAuthority"] != "architect": fail("architect authority contract mismatch")

        program = load("program-state.json")
        deps = load("dependency-state.json")
        frontier = load("frontier-state.json")
        roadmap = load("future-roadmap.json")
        if program.get("governingArchitecture") != "v0.1": fail("program state architecture mismatch")
        if program.get("workOrders") != []: fail("bootstrap must not activate a Work Order")
        if program.get("activeHandoffs") != []: fail("bootstrap must not contain active handoffs")

        files = sorted(p.stem for p in WO_DIR.glob("WORK-[0-9][0-9][0-9].md"))
        if not files: fail("no Work Orders found")
        expected_ids = [f"WORK-{n:03d}" for n in range(1, len(files) + 1)]
        if files != expected_ids: fail(f"Work Order identities must be contiguous: {files}")
        if set(deps["workOrders"]) != set(expected_ids): fail("dependency-state Work Order identity set mismatch")
        if set(roadmap["sequence"]) != set(expected_ids) or len(roadmap["sequence"]) != len(expected_ids): fail("roadmap sequence must contain every Work Order exactly once")
        if [x for wave in roadmap["parallelWaves"] for x in wave] != roadmap["sequence"]: fail("parallel waves must flatten exactly to roadmap sequence")

        graph = {k: [d["id"] for d in v["dependencies"]] for k, v in deps["workOrders"].items()}
        for node, ds in graph.items():
            for dep in ds:
                if dep not in graph: fail(f"unknown dependency {dep} referenced by {node}")
        indegree = {n: 0 for n in graph}; rev = {n: [] for n in graph}
        for n, ds in graph.items():
            for d in ds: indegree[n] += 1; rev[d].append(n)
        queue = [n for n, i in indegree.items() if i == 0]; seen = 0
        while queue:
            n = queue.pop(0); seen += 1
            for child in rev[n]:
                indegree[child] -= 1
                if indegree[child] == 0: queue.append(child)
        if seen != len(graph): fail("dependency graph contains a cycle")

        wo_text = {wid: (WO_DIR / f"{wid}.md").read_text(encoding="utf-8") for wid in expected_ids}
        allowed_assurance = {"LIGHT", "STANDARD", "HIGH_ASSURANCE", "CRITICAL"}
        for wid, text in wo_text.items():
            am = re.search(r"^Assurance:\s*(\S+)$", text, re.M)
            if not am or am.group(1) not in allowed_assurance: fail(f"missing or invalid assurance profile for {wid}")
            if "Status: planned" not in text: fail(f"bootstrap Work Order is not planned: {wid}")
            if "Owned surfaces:" not in text or "Forbidden surfaces:" not in text: fail(f"missing protected-surface declarations: {wid}")
            pm = re.search(r"^Required proofs:\s*(.*)$", text, re.M)
            if not pm: fail(f"missing proof declaration: {wid}")
            if am.group(1) == "CRITICAL":
                for required_proof in ("static", "dynamic", "discrimination"):
                    if required_proof not in pm.group(1): fail(f"CRITICAL Work Order {wid} is missing proof class {required_proof}")
            if "Dogfooding" not in text and "conformance" not in text: fail(f"missing dogfooding/conformance contract: {wid}")
            m = re.search(r"^Dependencies:\s*(.*)$", text, re.M)
            if not m: fail(f"missing dependency declaration: {wid}")
            docdeps = [] if m.group(1).strip().lower() == "none" else re.findall(r"(WORK-\d{3})\s+\((contract|implementation|integration)\)", m.group(1))
            jsondeps = [(x["id"], x["type"]) for x in deps["workOrders"][wid]["dependencies"]]
            if docdeps != jsondeps: fail(f"dependency drift for {wid}: markdown={docdeps} json={jsondeps}")

        owned = {}
        for wid, text in wo_text.items():
            m = re.search(r"Owned surfaces:\s*`([^`]+)`", text)
            if not m: fail(f"cannot parse owned surface for {wid}")
            owned[wid] = {s.strip() for s in m.group(1).split(",")}
        for idx, wave in enumerate(roadmap["parallelWaves"]):
            for i, a in enumerate(wave):
                for b in wave[i + 1:]:
                    if owned[a] & owned[b]: fail(f"protected-surface conflict in wave {idx}: {a} vs {b}: {owned[a] & owned[b]}")

        levels = {}
        remaining = set(graph)
        while remaining:
            ready = sorted([n for n in remaining if all(dep in levels for dep in graph[n])], key=lambda x: int(x.split("-")[1]))
            if not ready: fail("cannot derive topological planning layers")
            for n in ready: levels[n] = 0 if not graph[n] else 1 + max(levels[d] for d in graph[n])
            remaining -= set(ready)
        expected_waves = [[n for n in sorted(levels, key=lambda x: int(x.split("-")[1])) if levels[n] == idx] for idx in range(max(levels.values()) + 1)]
        if roadmap["parallelWaves"] != expected_waves: fail("parallel waves are not dependency-derived topological layers")
        if frontier.get("authority") != "derived_projection": fail("frontier state must declare itself derived")
        if roadmap.get("status") != "frozen-plan": fail("roadmap must be frozen-plan at bootstrap")
        registry = json.loads((SPEC / "registry" / "protocol-registry.json").read_text())
        if registry.get("status") != "frozen": fail("protocol registry must be frozen")

        print("PAYSWAP GOVERNANCE: PASS")
        print(f"architecture: v0.1\nwork orders: {len(expected_ids)}\nactive work orders: 0\ndependency DAG: acyclic\nroadmap↔work-order identity: exact\nparallel protected surfaces: disjoint\nsource of truth: repository")
        return 0
    except Exception as exc:
        print(f"PAYSWAP GOVERNANCE: FAIL — {exc}", file=sys.stderr); return 1

if __name__ == "__main__": raise SystemExit(main())
