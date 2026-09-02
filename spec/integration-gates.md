# Integration Gates

Integration gates are first-class Work Orders because they combine capabilities without making sibling implementations depend on one another.

| Gate | Purpose | Required inputs |
|---|---|---|
| IG-001 | kernel + value correctness | WORK-003, 005, 006 |
| IG-002 | full fulfillment lifecycle | WORK-007, 009, 010, 011, 012, 013, 014, 015, 016, 017 |
| IG-003 | simulation/production semantic parity | WORK-019, 026, 027 |
| IG-004 | extension/agent economic integration | WORK-020, 021, 028 |
| IG-005 | external rail sandbox | WORK-007, 014, 016, 027 |
| IG-006 | merchant/global end-to-end dogfood | WORK-025, 028, 030 |

A gate cannot activate until all required inputs are complete. Gates start from current `main`, never from an unmerged sibling branch.
