# Canonical Object Model

All durable objects carry a common envelope:

```text
ObjectEnvelope {
  object_id, object_type, object_version,
  environment_id, domain_id,
  schema_version, protocol_version,
  state, provenance,
  causation_id, correlation_id,
  previous_version, integrity_hash
}
```

## Object families

### Identity and authority
`Principal`, `Credential`, `AuthenticationEvent`, `AuthorizationGrant`, `Mandate`, `ResponsibilityAssignment`, `ParticipantProfile`.

### Value
`Asset`, `ValueInstrument`, `Account`, `Balance`, `LedgerEntry`, `Journal`, `Hold`, `FundingSource`.

### Destination and intent
`Endpoint`, `EndpointResolution`, `Intent`, `FulfillmentPolicy`, `EconomicSlack`, `Demand`, `DemandClass`.

### Capabilities and markets
`Capability`, `CapabilityCommitment`, `OperatingWindow`, `Quote`, `MarketMechanism`, `MarketSubmission`, `LiquidityOffer`, `CreditOffer`, `CreditExposure`, `Reservation`.

### Fulfillment and settlement
`FulfillmentPlan`, `ExecutionPlan`, `ExecutionStep`, `ExecutionAttempt`, `EffectRequest`, `EffectResult`, `Fulfillment`, `ClearingCycle`, `Obligation`, `NettingCycle`, `Settlement`, `Finality`, `Receipt`.

### Safety and knowledge
`RiskAssessment`, `FraudSignal`, `FraudAssessment`, `FraudDecision`, `ComplianceAssessment`, `PrivacyPolicy`, `PrivacyAssessment`, `Evidence`, `Attestation`, `Observation`, `Uncertainty`.

### Extensibility and simulation
`ExtensionManifest`, `ExtensionInstance`, `CapabilityGrant`, `ExtensionInvocation`, `ExtensionContribution`, `Model`, `ModelOutput`, `Simulation`, `SimulationCheckpoint`, `SimulationResult`, `SimulationEvidence`, `ForecastError`.

### Federation and operations
`NetworkDomain`, `StateAuthority`, `StateCommitment`, `InterDomainMessage`, `SystemicRiskAssessment`, `Dependency`, `ResilienceProfile`, `Case`, `Investigation`, `ProtocolVersion`, `GovernanceProposal`, `MigrationPlan`.

## Ownership relationships

Objects use explicit relationships rather than assuming one universal owner:

`OWNS`, `CONTROLS`, `CUSTODIES`, `AUTHORIZES`, `ADMINISTERS`, `ISSUES`, `ATTESTS`, `SERVICES`, `OWES`, `IS_ENTITLED_TO`, `OBSERVES`, `DEPENDS_ON`.

Derived objects never outrank their source of truth.
