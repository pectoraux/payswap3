# PaySwap Development Governance

PaySwap uses a deliberately small control plane.

```text
ONE ARCHITECT
      │
      ├── activates Work Orders
      ├── dispatches Z.ai workers
      ├── reviews exact PR heads
      ├── merges
      └── reconciles state

MANY Z.AI WORKERS
      │
      └── one Work Order + one branch/PR each
```

The repository itself is the durable control surface. The governance package exists to make the following facts machine-checkable:

- what architecture governs;
- what Work Orders exist;
- what dependencies are required;
- what surfaces may be changed;
- what proof is required;
- which work can safely proceed in parallel;
- what evidence is required before completion.

There is intentionally no separate planning database and no second workflow authority.
