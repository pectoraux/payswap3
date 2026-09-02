# Security, Risk, Fraud, Compliance and Resilience

## Identity and authorization

Authentication proves identity/control. Authorization is a separate deterministic decision over principal, delegation, object, domain, amount, jurisdiction and policy.

## Fraud

Fraud is an explicit plane, including account takeover, authorized-push scams, merchant fraud, provider fraud, collusion and credential compromise.

Actions include `ALLOW`, `STEP_UP`, `HOLD`, `DELAY`, `BLOCK`, `RECONFIRM`, `ESCALATE`.

## Risk

Risk is multidimensional and includes counterparty, liquidity, credit, settlement, operational, concentration, systemic, model, extension and fraud risk.

## Systemic contagion

The protocol maintains a dependency/exposure graph and supports stress propagation through simulation.

## Compliance

Regulatory envelopes are versioned by jurisdiction, participant, asset, transaction type, amount and effective time. Compliance is a hard constraint.

## Privacy

Privacy is both policy and mechanism: data minimization, selective disclosure, attribute proofs and privacy-preserving attestations are supported where legal requirements permit.

## Cryptography

Keys are purpose-bound and support rotation, revocation, recovery and threshold authorization. Extension signing, participant authorization, domain state commitments and finality evidence are separately scoped.

## Resilience

Critical services declare availability, capacity, redundancy, recovery point/time, failover and dependency policies. Operational failure is isolated and observable.

## No hidden authority

Models, fraud signals, risk scores, extensions, agents and external adapters provide evidence/proposals or operate under explicit authority; none silently becomes the canonical financial authority.
