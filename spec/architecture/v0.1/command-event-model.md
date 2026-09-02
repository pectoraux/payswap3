# Command and Event Model

## Three entry mechanisms

1. **Command** — requested state change.
2. **External observation** — authoritative evidence about the outside world.
3. **System trigger** — time- or policy-driven transition.

All three converge on one State Transition Engine.

```text
input → authorization → preconditions → policy → invariant check → transition → immutable event
```

## Command envelope

```text
Command {
  command_id, command_type,
  actor, authority_refs[], target_refs[], payload,
  environment_id, domain_id,
  expected_versions[], idempotency_key, nonce,
  requested_at, causation_id, correlation_id
}
```

## Event envelope

```text
Event {
  event_id, event_type,
  object_refs[], environment_id, domain_id,
  actor, authority,
  previous_state[], resulting_state[], object_versions[],
  occurred_at, logical_time,
  causation_id, correlation_id,
  payload_hash, protocol_version
}
```

## Complete command families

```text
Identity: Create/Update/Suspend/Reinstate/RetirePrincipal,
Issue/Rotate/RevokeCredential, Grant/Amend/RevokeAuthority,
Create/Activate/Suspend/Resume/Amend/RevokeMandate

Value: Register/Activate/Suspend/RetireAsset,
Issue/Redeem/TransferInstrument,
Create/Activate/Restrict/CloseAccount,
Create/Post/Reverse/Adjust/ReconcileJournal,
Create/Release/Expire/Increase/DecreaseHold

Intent: Create/Authorize/Reject/Amend/Cancel/Suspend/Resume
Endpoint: Register/Update/Suspend/Reactivate/Remove/ResolveEndpoint
Capability: Register/Verify/Activate/Update/Suspend/Resume/Retire
Commitment: Create/Amend/Cancel/Expire/RecordBreach
Market: Create/Open/Close/Submit/Withdraw/Accept/Reject/Allocate/Cancel
Quote: Create/Amend/Accept/Reject/Commit/Cancel/Expire/Invalidate
Liquidity/Credit: Create/Amend/Withdraw/Suspend/Resume/Expire; Draw/Repay/Restructure/Default
Reservation: Create/Hold/Commit/Amend/Release/Expire/Default/Consume
Fulfillment: Compile/Recompile/Accept/Reject/Invalidate
Execution: Create/Authorize/Start/Submit/Acknowledge/Complete/Fail/Timeout/Retry/Cancel
External: RequestEffect/RecordObservation/RecordEffectResult/RecordStatus/RecordFinality
Clearing: Create/Validate/Finalize/Cancel
Obligation: Create/Validate/Amend/Dispute/Restructure/MarkDue/Default/Resolve
Netting: Create/Add/Remove/Calculate/Finalize/Cancel
Settlement: Create/Authorize/Submit/Cancel/Reconcile
Finality: Validate/Establish/Challenge/RevokeClaim
Recourse: Request/Approve/Reject/Compile/ExecuteRefund; Request/Approve/Reject/ExecuteReversal
Safety: SubmitFraudSignal/CreateFraudAssessment/CreateFraudDecision/Hold/Release/Block
Compliance: RequestAssessment/RecordResult/InvalidateResult
Evidence: Submit/Verify/Reject/RevokeEvidence; Issue/Renew/RevokeAttestation
Extension: Register/Submit/Approve/Reject/Publish/Install/Activate/Degrade/Suspend/Resume/Deprecate/Archive
Model: Register/Validate/Approve/Deploy/Suspend/Resume/Retire
Simulation: Create/Initialize/Run/Pause/Resume/Checkpoint/Step/InjectFault/Branch/Complete/Fail/Cancel/Replay
Federation: Register/Join/Leave/UpdateAuthority/PublishCommitment/AcceptCommitment/TransferDomain
Governance: Create/Submit/Approve/Reject/ActivateProposal; Propose/Simulate/Shadow/Approve/Stage/Activate/Deprecate/RetireVersion
Operations: DeclareDegradation/Failover/Incident/Emergency/Resolve
```

## Event rule

Every accepted normative state transition emits immutable canonical events. Rejected commands emit audit/rejection events where policy requires. Events never rewrite history.

## Generated transitions

Expiry, scheduled windows, policy-triggered holds, fraud circuit breakers, reconciliation discoveries and external observations may be system-generated. They still pass through the same transition engine.
