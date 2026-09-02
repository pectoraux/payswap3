# Extension Architecture

An extension is a versioned, permissioned, measurable capability provider that can participate in PaySwap's economic system.

## Authority tiers

```text
R0 OBSERVE
R1 ANALYZE
R2 PROPOSE
R3 RESERVE
R4 EXECUTE
R5 FINANCIAL_EXPOSURE
```

Higher tiers require stronger verification, collateral, monitoring and risk limits.

## Manifest

```text
ExtensionManifest {
  extension_id, developer, version, code_hash,
  capabilities_provided[], capabilities_required[],
  permissions[], dependencies[], inputs[], outputs[],
  pricing, resource_requirements,
  authority_class, risk_class, jurisdictions[],
  protocol_versions[], schema_versions[],
  simulation_support, production_support
}
```

## Composition

Extensions exchange typed artifacts such as `DemandSignal`, `RouteProposal`, `QuoteSet`, `RiskAssessment`, `ComplianceProof`, `Attestation`, `ExecutionAdapter`, and `SettlementInstruction`.

Artifacts carry schema version, producer, provenance, expiry, confidence, dependencies and risk.

## Security

Extensions cannot directly mutate authoritative ledger state, modify finality, grant authority, bypass compliance, or access undeclared resources.

## Economics

Keep distinct:

1. resource credits;
2. real economic earnings;
3. financial collateral.

Rewards are based on verified incremental contribution, preferably against counterfactual baseline/treatment comparisons. Activity volume alone is not a valid contribution measure.

## Lifecycle

`DRAFT → SANDBOX → TESTED → SUBMITTED → SECURITY_REVIEW → POLICY_REVIEW → PUBLISHED → INSTALLED → ACTIVE → DEGRADED → SUSPENDED → DEPRECATED → ARCHIVED`.

## Opportunity loop

```text
unmet demand → missing capability → opportunity → developer → extension → simulation → certification → verified capability → new route → more fulfillment
```
