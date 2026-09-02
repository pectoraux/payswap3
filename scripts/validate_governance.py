#!/usr/bin/env python3
"""Fail-closed repository governance validator for PaySwap.

The same validator must remain valid from clean bootstrap through active,
blocked, ready-for-merge and completed Work Orders.

Governance is bound to authoritative Git facts: program-state.json.currentMain
must resolve inside the repository's main history, main may only advance
beyond the recorded verified implementation frontier through control-plane
changes, and active Work Order base revisions must be real ancestors of main
that do not predate the verified implementation frontier. A Work Order in the
`blocked` state is the sanctioned fail-closed holding state for incomplete
implementation dependencies; `in_flight` and `ready_for_merge` Work Orders
still require complete implementation dependencies.

Dependency declarations are parsed fail-closed: malformed, partially
parseable, duplicate, or unknown-type declarations are rejected instead of
being silently ignored.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
WO_DIR = SPEC / "work-orders"
STATE = SPEC / "development-state"
ARCH = SPEC / "architecture" / "v0.1"

WORK_STATES = {"planned", "in_flight", "blocked", "ready_for_merge", "complete"}
ACTIVE_STATES = {"in_flight", "blocked", "ready_for_merge"}
# Work Orders that are executing and therefore require complete
# implementation dependencies. `blocked` is deliberately excluded: it is the
# lifecycle state for work held pending an incomplete dependency.
EXECUTING_STATES = {"in_flight", "ready_for_merge"}
# Paths that carry governance/control-plane authority. Any other path changed
# between the recorded verified implementation frontier and main constitutes
# unreconciled implementation drift.
CONTROL_PLANE_PREFIXES = ("spec/", "agents/")
REVISION_PATTERN = re.compile(r"[0-9a-f]{7,40}")
DEP_TOKEN_PATTERN = re.compile(r"^(WORK-\d{3})\s+\((\w+)\)$")


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


def parse_deps(text: str, wid: str, allowed_types: set[str]) -> list[tuple[str, str]]:
    """Parse a Work Order dependency declaration strictly.

    The declaration must be `none` or a complete list of
    `WORK-NNN (type)` tokens separated by `,` or `+`. Any leftover,
    partially parseable, duplicate or unknown-type token fails closed.
    """
    m = re.search(r"^Dependencies:\s*(.*)$", text, re.M)
    if not m:
        fail(f"missing dependency declaration for {wid}")
    raw = m.group(1).strip()
    if not raw or raw.lower() == "none":
        return []
    declared: list[tuple[str, str]] = []
    seen: set[str] = set()
    for token in re.split(r"[,+]", raw):
        token = token.strip()
        match = DEP_TOKEN_PATTERN.match(token)
        if not match:
            fail(f"malformed dependency declaration for {wid}: unexpected token {token!r}")
        dep_id, dep_type = match.group(1), match.group(2)
        if dep_type not in allowed_types:
            fail(f"unknown dependency type for {wid}: {dep_type!r}")
        if dep_id in seen:
            fail(f"duplicate dependency declaration for {wid}: {dep_id}")
        seen.add(dep_id)
        declared.append((dep_id, dep_type))
    return declared


def parse_owned(text: str):
    m = re.search(r"Owned surfaces:\s*`([^`]+)`", text)
    if not m:
        fail("missing owned-surface declaration")
    return {x.strip() for x in m.group(1).split(",")}


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        fail(f"git facts unavailable: {exc}")
        raise  # unreachable: fail() always raises


def resolve_main_ref() -> str:
    result = _git("rev-parse", "--verify", "main")
    if result.returncode != 0:
        fail("git facts unavailable: the main ref is not resolvable in this repository")
    return result.stdout.strip()


def resolve_revision(revision: str, label: str) -> str:
    result = _git("rev-parse", "--verify", f"{revision}^{{commit}}")
    if result.returncode != 0:
        fail(f"{label} is not resolvable in the repository: {revision}")
    return result.stdout.strip()


def is_ancestor(ancestor: str, descendant: str) -> bool:
    result = _git("merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        fail(f"git facts unavailable: ancestry check failed for {ancestor}..{descendant}")
    return result.returncode == 0


def changed_paths(older: str, newer: str) -> list[str]:
    result = _git("diff", "--name-only", older, newer)
    if result.returncode != 0:
        fail(f"git facts unavailable: revision diff failed for {older}..{newer}")
    return [line for line in result.stdout.splitlines() if line]


def require_revision_format(name: str, revision: str) -> None:
    if not isinstance(revision, str) or not REVISION_PATTERN.fullmatch(revision):
        fail(f"invalid revision recorded in program-state {name}: {revision!r}")


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

        allowed_types = set(deps.get("dependencyTypes", []))
        if not allowed_types: fail("dependency-state must declare dependency types")
        graph: dict[str, list[str]] = {}
        for wid, entry in deps["workOrders"].items():
            declarations = entry.get("dependencies") if isinstance(entry, dict) else None
            if not isinstance(declarations, list):
                fail(f"dependency-state entry for {wid} must declare a dependencies array")
            parsed_ids: list[str] = []
            for declaration in declarations:
                if not isinstance(declaration, dict) or set(declaration) != {"id", "type"}:
                    fail(f"malformed dependency record in dependency-state for {wid}: {declaration!r}")
                dep_id = declaration["id"]
                dep_type = declaration["type"]
                if not isinstance(dep_id, str) or not re.fullmatch(r"WORK-\d{3}", dep_id):
                    fail(f"malformed dependency id in dependency-state for {wid}: {dep_id!r}")
                if dep_type not in allowed_types:
                    fail(f"unknown dependency type for {wid}: {dep_type!r}")
                parsed_ids.append(dep_id)
            graph[wid] = parsed_ids

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
            docdeps = parse_deps(text, wid, allowed_types)
            jsondeps = [
                (declaration["id"], declaration["type"])
                for declaration in deps["workOrders"][wid]["dependencies"]
            ]
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

        # Revision binding: program-state control-plane revisions must agree
        # with authoritative Git facts. Fail closed on any drift.
        main_ref = resolve_main_ref()
        current_main = program.get("currentMain")
        require_revision_format("currentMain", current_main)
        resolve_revision(current_main, "program-state currentMain")
        if not is_ancestor(current_main, main_ref):
            fail(f"program-state currentMain is not an ancestor of main: {current_main}")
        drift = [
            path for path in changed_paths(current_main, main_ref)
            if not path.startswith(CONTROL_PLANE_PREFIXES)
        ]
        if drift:
            fail(
                "currentMain drift: main contains non-control-plane changes "
                f"beyond the verified implementation frontier: {drift}"
            )
        for wid, record in active:
            base = record.get("baseRevision")
            require_revision_format(f"baseRevision of {wid}", base)
            resolve_revision(base, f"base revision for active Work Order {wid}")
            if not is_ancestor(base, main_ref):
                fail(f"stale base revision for active Work Order {wid}: {base} is not an ancestor of main")
            if not is_ancestor(current_main, base):
                fail(
                    f"stale base revision for active Work Order {wid}: {base} "
                    f"predates the verified implementation frontier {current_main}"
                )

        branches = {}
        for wid, record in active:
            branch = record["branch"]
            if branch in branches: fail(f"one-branch-per-active-Work-Order violation: {branches[branch]} and {wid}")
            branches[branch] = wid
            if record["status"] in EXECUTING_STATES:
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

        blocked_count = sum(1 for _, record in active if record["status"] == "blocked")
        print("PAYSWAP GOVERNANCE: PASS")
        print("architecture: v0.1")
        print(f"work orders: {len(ids)}")
        print(f"active work orders: {len(active)}")
        print(f"blocked work orders (dependency-gated): {blocked_count}")
        print("revision binding: currentMain is an ancestor of main; delta is control-plane only")
        print("active base revisions: resolved, on main, at or after the verified frontier")
        print("dependency DAG: acyclic")
        print("dependency declarations: fail-closed")
        print("roadmap↔work-order identity: exact")
        print("parallel protected surfaces: disjoint")
        print("lifecycle: bootstrap/active/blocked/completion compatible")
        print("source of truth: repository")
        return 0
    except Exception as exc:
        print(f"PAYSWAP GOVERNANCE: FAIL — {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
