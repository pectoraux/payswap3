#!/usr/bin/env python3
"""Fail-closed repository governance validator for PaySwap.

The same validator must remain valid from clean bootstrap through active,
blocked, ready-for-merge and completed Work Orders.
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

WORK_STATES = {"planned", "in_flight", "blocked", "ready_for_merge", "complete"}
ACTIVE_STATES = {"in_flight", "blocked", "ready_for_merge"}

def load(name: str):
    return json.loads((STATE / name).read_text(encoding="utf-8"))

def fail(msg: str) -> None:
    raise RuntimeError(msg)

def ids_from_files() -> list[str]:
    ids = sorted(p.stem for p in WO_DIR.glob("WORK-[0-9][0-9][0-9].md"))
    if not ids:
        fail("no Work Orders found")
    expected = [f"WORK-{n:03d}" for n in range(1, len(ids) + 1)]
    if ids != expected:
        fail(f"Work Order identities must be contiguous: {ids}")
    return ids

def parse_status(text: str) -> str:
    m = re.search(r"^Status:\s*(\S+)$", text, re.M)
    return m.group(1) if m else ""

def parse_assurance(text: str) -> str:
    m = re.search(r"^Assurance:\s*(\S+)$", text, re.M)
    return m.group(1) if m else ""

def parse_deps(text: str):
    m = re.search(r"^Dependencies:\s*(.*)$", text, re.M)
    if not m:
        fail("missing dependency declaration")
    raw = m.group(1).strip()
    return [] if raw.lower() == "none" else re.findall(r"(WORK-\d{3})\s+\((contract|implementation|integration)\)", raw)

def parse_owned(text: str):
    m = re.search(r"Owned surfaces:\s*`([^`]+)`", text)
    if not m:
        fail("missing owned-surface declaration")
    return {x.strip() for x in m.group(1).split(",")}

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
            if not p.exists():
                fail(f"missing required governance artifact: {p.relative_to(ROOT)}")

        gm = json.loads((SPEC / "governance" / "governance-model.json").read_text(encoding="utf-8"))
        if gm.get("governingArchitecture") != "v0.1": fail("governing architecture mismatch")
        if gm.get("architectCardinality") != 1 or gm.get("mergeAuthority") != "architect": fail("architect authority contract mismatch")
        registry = json.loads((SPEC / "registry" / "protocol-registry.json").read_text(encoding="utf-8"))
        if registry.get("status") != "frozen": fail("protocol registry must be frozen")

        program = load("program-state.json")
        deps = load("dependency-state.json")
        frontier = load("frontier-state.json")
        roadmap = load("future-roadmap.json")
        if program.get("governingArchitecture") != "v0.1": fail("program state architecture mismatch")
        if not isinstance(program.get("workOrders"), list): fail("program workOrders must be an array")
        if not isinstance(program.get("activeHandoffs"), list): fail("activeHandoffs must be an array")

        ids = ids_from_files()
        if set(deps.get("workOrders", {})) != set(ids): fail("dependency-state Work Order identity set mismatch")
        sequence = roadmap.get("sequence", [])
        if set(sequence) != set(ids) or len(sequence) != len(ids): fail("roadmap sequence must contain every Work Order exactly once")
        if [x for wave in roadmap.get("parallelWaves", []) for x in wave] != sequence: fail("parallel waves must flatten exactly to sequence")

        graph = {k: [d["id"] for d in v["dependencies"]] for k, v in deps["workOrders"].items()}
        for node, ds in graph.items():
            for dep in ds:
                if dep not in graph: fail(f"unknown dependency {dep} referenced by {node}")

        indegree = {n: 0 for n in graph}; rev = {n: [] for n in graph}
        for n, ds in graph.items():
            for d in ds:
                indegree[n] += 1; rev[d].append(n)
        q = [n for n, i in indegree.items() if i == 0]; seen = 0
        while q:
            n = q.pop(0); seen += 1
            for c in rev[n]:
                indegree[c] -= 1
                if indegree[c] == 0: q.append(c)
        if seen != len(graph): fail("dependency graph contains a cycle")

        wo_text = {wid: (WO_DIR / f"{wid}.md").read_text(encoding="utf-8") for wid in ids}
        allowed_assurance = {"LIGHT", "STANDARD", "HIGH_ASSURANCE", "CRITICAL"}
        owned = {}
        for wid, text in wo_text.items():
            assurance = parse_assurance(text)
            if assurance not in allowed_assurance: fail(f"missing or invalid assurance profile for {wid}")
            status = parse_status(text)
            if status not in WORK_STATES: fail(f"invalid Work Order status for {wid}: {status or '<missing>'}")
            if "Owned surfaces:" not in text or "Forbidden surfaces:" not in text: fail(f"missing protected-surface declarations: {wid}")
            pm = re.search(r"^Required proofs:\s*(.*)$", text, re.M)
            if not pm: fail(f"missing proof declaration: {wid}")
            if assurance == "CRITICAL":
                for rp in ("static", "dynamic", "discrimination"):
                    if rp not in pm.group(1): fail(f"CRITICAL Work Order {wid} is missing proof class {rp}")
            if "Dogfooding" not in text and "conformance" not in text: fail(f"missing dogfooding/conformance contract: {wid}")
            docdeps = parse_deps(text)
            jsondeps = [(x["id"], x["type"]) for x in deps["workOrders"][wid]["dependencies"]]
            if docdeps != jsondeps: fail(f"dependency drift for {wid}: markdown={docdeps} json={jsondeps}")
            owned[wid] = parse_owned(text)

        records = {}
        for record in program["workOrders"]:
            if not isinstance(record, dict) or "id" not in record or "status" not in record:
                fail("invalid program-state Work Order record")
            wid = record["id"]
            if wid not in ids: fail(f"program-state references unknown Work Order: {wid}")
            if wid in records: fail(f"duplicate program-state Work Order: {wid}")
            status = record["status"]
            if status not in WORK_STATES: fail(f"invalid program-state status for {wid}: {status}")
            doc_status = parse_status(wo_text[wid])
            if status != doc_status: fail(f"status drift for {wid}: program={status} doc={doc_status}")
            if status in ACTIVE_STATES:
                for field in ("baseRevision", "branch"):
                    if not isinstance(record.get(field), str) or len(record[field]) < 7:
                        fail(f"active Work Order {wid} missing {field}")
            if status == "ready_for_merge" and not isinstance(record.get("pr"), int):
                fail(f"ready_for_merge Work Order {wid} missing PR")
            if status == "complete":
                merged = record.get("mergedAs")
                if not isinstance(merged, dict) or not isinstance(merged.get("pr"), int) or not isinstance(merged.get("mergeCommit"), str):
                    fail(f"complete Work Order {wid} missing mergedAs")
            records[wid] = record

        for wid, text in wo_text.items():
            if wid not in records:
                doc_status = parse_status(text)
                if doc_status != "planned":
                    fail(f"Work Order {wid} is non-planned but missing program-state record")

        active = [(wid, records[wid]) for wid in records if records[wid]["status"] in ACTIVE_STATES]
        branches = {}
        for wid, record in active:
            branch = record["branch"]
            if branch in branches: fail(f"one-branch-per-active-Work-Order violation: {branches[branch]} and {wid}")
            branches[branch] = wid
            for dep in deps["workOrders"][wid]["dependencies"]:
                if dep["type"] == "implementation":
                    dep_record = records.get(dep["id"])
                    if not dep_record or dep_record["status"] != "complete":
                        fail(f"implementation dependency not complete for {wid}: {dep['id']}")
        for i, (a, _) in enumerate(active):
            for b, _ in active[i + 1:]:
                if owned[a] & owned[b]: fail(f"active protected-surface conflict: {a} vs {b}: {owned[a] & owned[b]}")

        levels = {}
        remaining = set(graph)
        while remaining:
            ready = sorted([n for n in remaining if all(d in levels for d in graph[n])], key=lambda x: int(x.split("-")[1]))
            if not ready: fail("cannot derive topological planning layers")
            for n in ready: levels[n] = 0 if not graph[n] else 1 + max(levels[d] for d in graph[n])
            remaining -= set(ready)
        expected_waves = [[n for n in sorted(levels, key=lambda x: int(x.split("-")[1])) if levels[n] == i] for i in range(max(levels.values()) + 1)]
        if roadmap["parallelWaves"] != expected_waves: fail("parallel waves are not dependency-derived topological layers")
        if frontier.get("authority") != "derived_projection": fail("frontier state must declare itself derived")
        if roadmap.get("status") != "frozen-plan": fail("roadmap must be frozen-plan")

        print("PAYSWAP GOVERNANCE: PASS")
        print("architecture: v0.1")
        print(f"work orders: {len(ids)}")
        print(f"active work orders: {len(active)}")
        print("dependency DAG: acyclic")
        print("roadmap↔work-order identity: exact")
        print("parallel protected surfaces: disjoint")
        print("lifecycle: bootstrap/active/completion compatible")
        print("source of truth: repository")
        return 0
    except Exception as exc:
        print(f"PAYSWAP GOVERNANCE: FAIL — {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
