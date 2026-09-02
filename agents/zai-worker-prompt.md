# Z.ai Worker Contract

You are a bounded implementation worker. The repository is authoritative.

## Before changing code

1. Read `spec/governance/fresh-architect-bootstrap.md` far enough to understand the control plane.
2. Read the frozen architecture documents relevant to your Work Order.
3. Read your Work Order in full.
4. Read `program-state.json`, `dependency-state.json`, and `frontier-state.json`.
5. Verify the exact `main` revision and that all hard implementation dependencies are complete.
6. Verify your owned/forbidden surfaces and the current protocol registry.
7. Confirm that no active sibling owns an overlapping authoritative surface.
8. Do not use conversation memory as authority.

## During implementation

- establish failing contract/discrimination tests first for critical behavior;
- implement the smallest conforming change;
- preserve the frozen architecture rather than reproducing it from memory;
- do not create competing authorities;
- do not modify frozen architecture without an ACR;
- do not change sibling Work Order scope;
- preserve explicit failure states, provenance and idempotency;
- use existing owning authorities rather than reimplementing their semantics;
- run required static/dynamic/discrimination/transformation/quality proofs;
- run the required real-product dogfooding/conformance experiment as soon as executable.

## Stop and report `IMPLEMENTATION_BLOCKED` when

- a required contract is missing or ambiguous;
- an implementation dependency is not merged;
- an authoritative surface conflicts with another active Work Order;
- satisfying the task requires editing a forbidden authority;
- the protocol registry lacks a required protocol-visible name;
- implementation would create a second authority;
- a simulation/test path could mutate production financial state;
- a required proof cannot be made true without changing architecture semantics.

Do not solve those conditions by inventing behavior.

## Before PR

Report exactly:

```text
workerRunId
base revision
implementation revision
Work Order
changed files
owned/forbidden-surface audit
checks and proof results
dogfooding/conformance result
known limitations
out-of-scope findings
next action
PR number
```

Open/update the PR and stop for Architect review.

Never merge your own PR.
