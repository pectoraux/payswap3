# DOGFOOD-031 — Merchant/global end-to-end dogfood (IG-006)

Status: PASS (deterministic; transcript digest
`6927dd8aa6996383c4ba5d0596cb40c7fab43c5b91a7863b05b61f6caa8105bc`)

## Binding

- Work Order: WORK-031 — Merchant/end-to-end global fulfillment dogfood
- Architecture version: v0.1 (frozen)
- Implementation revision: WORK-031 branch `work-031/flywheel`, base
  `9dc4b2f67d2ac87693f513814c60ae915ea5ee7c` (the recorded
  implementation frontier; all hard dependencies — WORK-024, WORK-025,
  WORK-028, WORK-030 — complete and merged on `main`)
- Environment: `env/sandbox-ig006-flywheel` — ONE isolated sandbox
  environment of the same protocol (the merged IG-003 parity
  vocabulary's simulation role). No production financial state is
  reachable or mutated.
- Surface/host: `src/integration/flywheel/` — the IG-006 gate composing
  the real merged authorities: the merchant record boundary
  (`src/merchant`), the fulfillment lifecycle harness
  (`src/integration/lifecycle`) over two local deterministic rails
  (the merged WORK-030 public re-export), the operations resilience
  authority (`src/operations`) and the evidence domain
  (`src/evidence`).

## Task

Prove a real user-facing merchant outcome through the complete PaySwap
network, including delay/credit, recovery and evidence: a merchant
checkout and settlement promise; the canonical intent/fulfillment path
killed mid-flight on the primary rail; the governed
incident/degradation/failover and the recovery retry through the
declared redundancy; the delayed settlement completing with finality;
and the final merchant/customer outcome as durable evidence.

## Starting state

A freshly constructed composed world (deterministic; every instant
declared data): one merchant (84.50 USD checkout, 100.00 USD credit
limit), one customer, two scripted sandbox rails (primary + declared
redundancy), one operations authority declaring both rails as provider
dependencies of the payment-execution service, and an empty evidence
archive.

## Expected

Every stage accepted through the real authority boundaries; the killed
leg never produces a false success (step UNKNOWN, no effect result,
nothing recorded rail-side, zero obligations); the recovery stays
inside the declared 3600s objective; the delayed settlement completes
(settlement COMPLETED, every leg SETTLED, finality ESTABLISHED,
obligations RESOLVED with digest-bound discharge evidence); the
incident RESOLVES with conservation evidence; the merchant outcome is
an OBSERVED evidence record; and the full invariant battery passes
with the live composed state byte-stable under the containment
battery.

## Observed

All of the above held. The journey: 42 recorded stages, 45 commands;
first submission UNKNOWN; dead-leg reconciliation NOT_FOUND; recovery
step SUCCEEDED; settlement batch COMPLETED with legs SETTLED; finality
ESTABLISHED; incident RESOLVED (recovery duration 1500s ≤ 3600s
objective); outcome `delayed-settlement-completed`; 50/50 invariant
checks PASS; 6/6 containment probes contained fail-closed with the
live composed state byte-unchanged. Quality attributes (deterministic
measurements): cost 45 commands / 42 stages / 2 rail submit calls;
logical journey span 21000s, recovery window 1620s, declared
settlement delay window 99600s; reliability: 0 false successes, 1
recovery retry; the promise remains PENDING at the merchant boundary
(the explicit delay representation) while the network-side settlement
completed — the outcome classification is derived only from real
authority reads.

Transcript: `python3 -m src.integration.flywheel.dogfooding`
(byte-identical across clean processes; digest above).

## Evidence

- `src/integration/flywheel/dogfooding.py` — the deterministic
  DOGFOOD-031 transcript (`build_transcript()`; canonical SHA-256
  `6927dd8aa6996383c4ba5d0596cb40c7fab43c5b91a7863b05b61f6caa8105bc`).
- `src/integration/flywheel/test_flywheel.py` — the contract suite
  (static identity/surface audit, the dynamic journey, the
  discrimination containment battery, the quality-attribute
  measurements, the dogfooding conformance and the WorkflowOS
  contamination regression guard).
- `src/integration/flywheel/invariants.py` — the 50-check invariant
  battery (merchant delay/credit discipline, no false success,
  recovery discipline, settlement truth, resilience conservation,
  evidence discipline, journal honesty, environment isolation).
- `src/integration/flywheel/scenarios.py` — the journey scenario and
  the six containment probes.

## WorkflowOS contamination audit (WORK-031's second mandate)

A repository-wide SEMANTIC audit (not a bare string search) was
performed over source, tests, specifications, agent prompts,
CI/configuration and fixtures, searching for: the WorkflowOS name
variants (`WorkflowOS`, `workflowos`, `workflow-os`, `Workflow OS`),
WorkflowOS-specific repository URLs, environment-variable prefixes,
package/module names, imports, host URLs (`chat.z.ai`,
`claude.com/code`, `chatgpt.com/codex`), object types, commands,
events, roadmap/work-item semantics copied from WorkflowOS, fixtures,
and accidental identity replacement. **Findings: zero
contamination.** Every candidate hit was classified: the one
`companion` occurrence (`src/federation/__init__.py`) is PaySwap's own
domain vocabulary (a federation message record), not the WorkflowOS
Companion concept; `interoperability/adapter/stripe-test` is PaySwap's
merged IG-005 rail adapter, not WorkflowOS material; all `workflow`
occurrences are legitimate PaySwap governance/process terminology or
GitHub Actions workflow paths; the PaySwap identity is intact
throughout. Nothing was removed (nothing to remove); no frozen
architecture was rewritten. The durable regression guard
(`TestWorkflowOSContaminationRegression`) fails closed if any
WorkflowOS-specific marker reappears, while explicitly NOT classifying
generic workflow terminology, GitHub Actions workflow paths, or worker
orchestration language as contamination.

## Classification

`PASS`

## Resulting action

WORK-031 implementation complete on branch `work-031/flywheel`; PR
opened for Architect review. Merge decision and post-merge
finalization remain with the Architect.

## Limitations

- The merchant domain's kernel-binding engine path is pre-existing red
  at this base (the disclosed WORK-025 `TransitionApplication`
  NameError in `src/merchant/engine.py`; its pytest-style suite
  collects 0 tests under unittest discovery). The gate composes
  through the merchant public RECORD boundary (the working merged
  surface, exactly the merged WORK-029 precedent) and discloses the
  engine defect here; fixing it belongs to WORK-025's owned surface.
- The merchant promise remains `PENDING` at the merchant boundary by
  design: no merged surface advances promise/checkout records to their
  terminal states, and this gate does not mutate sibling lifecycles.
  The final merchant outcome is therefore OBSERVED (the evidence-domain
  outcome observation + the typed journey report derived from real
  authority reads), never claimed by mutating the merchant records.
- The rails are local deterministic sandbox rails (the merged WORK-030
  public re-export): the journey proves the protocol path, not live
  external rail connectivity (that is IG-005's own real-rail surface).
- `frontier-state.json` is a stale architect-owned projection at this
  base (pre-existing, disclosed in prior work orders);
  `program-state.json` is the source of truth for activation state.
