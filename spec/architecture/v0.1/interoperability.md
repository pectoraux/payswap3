# Interoperability

PaySwap defines a canonical semantic layer above heterogeneous rails.

```text
PaySwap semantics
  ↕
ISO 20022 / domestic IPS / bank / PSP / card / MoMo / blockchain / cash adapters
```

## Endpoint resolution

```text
Endpoint → EndpointResolution → Destination
```

Resolution may use IBAN, account numbers, aliases, phone numbers, merchant IDs, QR data, wallet addresses or other jurisdictional identifiers.

## Canonical payment lifecycle

`INITIATED → AUTHORIZED → ACCEPTED → RESERVED → COMMITTED → SUBMITTED → ACKNOWLEDGED → PROCESSING → CAPTURED/POSTED → SETTLED → FINAL`, with explicit `RETURNED`, `REVERSED`, `FAILED`, `EXPIRED`, `DISPUTED`, and `UNKNOWN` branches where relevant.

Adapters map native status into this semantic vocabulary; they do not redefine it.

## Unknown outcome

An ambiguous external response enters reconciliation/investigation before any unsafe retry.

## World adapter

```text
WorldAdapter {
  adapter_id,
  capability_id,
  observation_interface,
  effect_interface,
  fidelity_class
}
```

Production and simulation adapters implement the same semantic interface.
