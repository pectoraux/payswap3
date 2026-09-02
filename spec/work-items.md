# PaySwap Implementation Work Items

This catalog is a navigation projection over the authoritative Work Orders in `spec/work-orders/`. Dependency truth is cross-checked by governance validation.

| Work Order | Objective | Assurance | Dependencies | Status |
|---|---|---|---|---|
| `WORK-001` | Governance/bootstrap validator | `STANDARD` | None | complete |
| `WORK-002` | Canonical protocol primitives | `STANDARD` | WORK-001 (implementation) | complete |
| `WORK-033` | Governance revision-binding remediation | `HIGH_ASSURANCE` | WORK-001 (implementation) | planned |
| `WORK-032` | Canonical core integrity remediation | `HIGH_ASSURANCE` | WORK-002 (implementation) | planned |
| `WORK-003` | Command/event transition kernel | `HIGH_ASSURANCE` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-004` | Identity, authentication, authority and keys | `CRITICAL` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-005` | Value instruments, accounts and ledger | `CRITICAL` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-006` | Monetary arithmetic and FX | `HIGH_ASSURANCE` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-007` | Endpoint resolution and interoperability | `HIGH_ASSURANCE` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-008` | Intent, fulfillment policy and demand | `STANDARD` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-009` | Capability, commitments and operating windows | `HIGH_ASSURANCE` | WORK-002 (implementation), WORK-032 (implementation) | blocked |
| `WORK-010` | Market mechanisms, quotes and allocation | `HIGH_ASSURANCE` | WORK-006 (implementation), WORK-008 (implementation), WORK-009 (implementation) | planned |
| `WORK-011` | Liquidity, credit and exposure | `CRITICAL` | WORK-005 (implementation), WORK-006 (implementation), WORK-009 (implementation) | planned |
| `WORK-012` | Reservation and concurrency | `CRITICAL` | WORK-003 (implementation), WORK-005 (implementation), WORK-009 (implementation) | planned |
| `WORK-013` | Fulfillment compiler and economic optimization | `HIGH_ASSURANCE` | WORK-006 (implementation), WORK-008 (implementation), WORK-009 (implementation), WORK-010 (implementation), WORK-011 (implementation), WORK-012 (implementation), WORK-017 (implementation) | planned |
| `WORK-014` | External effect adapters and execution | `CRITICAL` | WORK-003 (implementation), WORK-007 (implementation), WORK-012 (implementation), WORK-017 (implementation), WORK-018 (implementation), WORK-019 (contract) | planned |
| `WORK-015` | Clearing, obligations and netting | `CRITICAL` | WORK-005 (implementation), WORK-006 (implementation), WORK-012 (implementation), WORK-014 (implementation), WORK-018 (contract) | planned |
| `WORK-016` | Settlement, finality and reconciliation | `CRITICAL` | WORK-005 (implementation), WORK-006 (implementation), WORK-014 (implementation), WORK-015 (implementation), WORK-018 (implementation) | planned |
| `WORK-017` | Risk, fraud, compliance and policy engine | `CRITICAL` | WORK-004 (implementation), WORK-006 (implementation), WORK-008 (implementation), WORK-009 (implementation) | planned |
| `WORK-018` | Evidence, knowledge and uncertainty | `HIGH_ASSURANCE` | WORK-003 (implementation), WORK-004 (implementation) | planned |
| `WORK-019` | Simulation, replay, forecast and shadow | `CRITICAL` | WORK-003 (implementation), WORK-005 (implementation) | planned |
| `WORK-020` | Extension runtime and capability marketplace | `CRITICAL` | WORK-003 (implementation), WORK-009 (implementation), WORK-017 (implementation), WORK-018 (implementation) | planned |
| `WORK-021` | Models, agents and decision mediation | `HIGH_ASSURANCE` | WORK-017 (implementation), WORK-018 (implementation), WORK-019 (implementation) | planned |
| `WORK-022` | Data governance, privacy and recourse | `HIGH_ASSURANCE` | WORK-004 (implementation), WORK-018 (implementation) | planned |
| `WORK-023` | Domains, federation and state commitments | `CRITICAL` | WORK-003 (implementation), WORK-004 (implementation), WORK-016 (implementation) | planned |
| `WORK-024` | Resilience, observability and recovery | `HIGH_ASSURANCE` | WORK-003 (implementation), WORK-018 (implementation), WORK-023 (implementation) | planned |
| `WORK-025` | Merchant checkout and settlement promises | `CRITICAL` | WORK-006 (implementation), WORK-008 (implementation), WORK-013 (implementation), WORK-016 (implementation), WORK-017 (implementation) | planned |
| `WORK-026` | Kernel/value integration gate | `CRITICAL` | WORK-003 (implementation), WORK-005 (implementation), WORK-006 (implementation) | planned |
| `WORK-027` | Fulfillment lifecycle integration gate | `CRITICAL` | WORK-007 (implementation), WORK-009 (implementation), WORK-010 (implementation), WORK-011 (implementation), WORK-012 (implementation), WORK-013 (implementation), WORK-014 (implementation), WORK-015 (implementation), WORK-016 (implementation), WORK-017 (implementation), WORK-018 (implementation) | planned |
| `WORK-028` | Simulation parity integration gate | `CRITICAL` | WORK-019 (implementation), WORK-026 (implementation), WORK-027 (implementation) | planned |
| `WORK-029` | Extension/agent economic integration gate | `CRITICAL` | WORK-020 (implementation), WORK-021 (implementation), WORK-028 (implementation) | planned |
| `WORK-030` | External rail sandbox integration gate | `CRITICAL` | WORK-007 (implementation), WORK-014 (implementation), WORK-016 (implementation), WORK-023 (implementation), WORK-027 (implementation) | planned |
| `WORK-031` | Merchant/end-to-end global fulfillment dogfood | `CRITICAL` | WORK-024 (implementation), WORK-025 (implementation), WORK-028 (implementation), WORK-030 (implementation) | planned |

## Derived implementation layers

- Wave 0: `WORK-001`
- Wave 1: `WORK-002` || `WORK-033`
- Wave 2: `WORK-032`
- Wave 3: `WORK-003` || `WORK-004` || `WORK-005` || `WORK-006` || `WORK-007` || `WORK-008` || `WORK-009`
- Wave 4: `WORK-010` || `WORK-011` || `WORK-012` || `WORK-017` || `WORK-018` || `WORK-019` || `WORK-026`
- Wave 5: `WORK-013` || `WORK-014` || `WORK-020` || `WORK-021` || `WORK-022`
- Wave 6: `WORK-015`
- Wave 7: `WORK-016`
- Wave 8: `WORK-023` || `WORK-025` || `WORK-027`
- Wave 9: `WORK-024` || `WORK-028` || `WORK-030`
- Wave 10: `WORK-029` || `WORK-031`

## Authority

`spec/work-orders/` is authoritative for scope and acceptance. `spec/development-state/dependency-state.json` and `frontier-state.json` are derived projections. This catalog never authorizes work.
