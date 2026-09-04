# PaySwap v0.2 — Product UX Architecture

Status: proposed product-layer direction
Scope: user experience, information architecture, access model, and product surfaces
Protocol authority: frozen PaySwap v0.1 remains unchanged

## 1. Product thesis

PaySwap is a coordination layer for financial outcomes. The underlying system can reason over intent, capabilities, market choices, routing, liquidity, risk, extensions, agents, execution, interoperability, clearing, settlement, finality, evidence, simulation, and operations. The product should not ask users to understand those nouns before they can accomplish a goal.

The product mental model is therefore:

`Outcome → Options → Decision → Execution → Evidence → Resolution`

A user should be able to describe an outcome in ordinary language, see only the choices that materially affect them, approve when authority is actually required, watch progress without learning protocol terminology, and inspect proof when they need confidence.

The protocol remains the system of record and authority. The product shell is an interaction layer and must never become a second financial authority.

## 2. Design council

This is a fictional design council informed by publicly documented Apple Human Interface Guidelines and Stripe Dashboard / Stripe Apps patterns. It does not represent the views of named Apple or Stripe employees.

### Apple voice — Human-centered platform designer

> Start with the person's purpose, not the system's vocabulary. Keep the first screen calm. Delay authentication and advanced configuration until the moment they become useful. Preserve context, make state obvious, and make recovery understandable.

Argument for PaySwap: the complexity is real but should be progressively disclosed. A customer should see “Your payment is being recovered” before seeing a dependency graph. A merchant should see “$8,450 expected” before seeing lifecycle stages.

### Stripe voice — Product systems designer

> Make the common path fast and the exceptional path legible. Organize around records and tasks, use strong primary actions, communicate status explicitly, and let details appear in context rather than forcing a user through an all-purpose control center.

Argument for PaySwap: the dashboard should be operational. Lists, details, status, action controls, and focused task views should be reusable across roles. A user should be able to enter from an object or task and return to the same context.

### Apple voice — Accessibility / interaction specialist

> Complexity is not depth. Depth can exist behind disclosure. Keep interaction patterns predictable, support keyboard, touch, remote/focus, and assistive technologies, and avoid time-boxed information that disappears before it can be understood.

Argument for PaySwap: use stable navigation, semantic controls, readable status, clear focus states, and persistent evidence access. Do not rely on color alone for payment or risk state.

### Stripe voice — Operations designer

> A network product earns trust when users can answer four questions immediately: what happened, what is happening now, what needs me, and what happens next?

Argument for PaySwap: every high-value object should expose a compact “state / next step / evidence” summary. Advanced diagnostics should be one click away.

### Council decision

The winning model is a **calm shell over a deep system**. The interface is not a visualization of the protocol. It is a set of task-oriented views over protocol state.

The council rejects:

- a universal control panel that exposes every subsystem at once;
- forcing users to learn intent, route, capability, clearing, or evidence terminology;
- role-specific applications that feel like eight unrelated products;
- AI that silently takes irreversible authority;
- hiding failures behind generic “something went wrong” messaging.

The council adopts:

- one shared navigation grammar;
- role-aware home priorities;
- progressive disclosure;
- object-centered details;
- visible state and next action;
- explicit authority boundaries;
- evidence on demand;
- simulations and AI proposals as suggestions, never invisible authority.

## 3. The shared product model

Every meaningful PaySwap interaction can be framed as one of six user questions:

1. **What am I trying to accomplish?** — outcome / intent
2. **What choices do I have?** — routes, providers, liquidity, capabilities, agent proposals
3. **What should I approve?** — authority, risk, price, limits, policy
4. **What is happening?** — execution, recovery, settlement, incident state
5. **Can I prove it?** — evidence, provenance, finality, receipts
6. **What happens if it goes wrong?** — recovery, reconciliation, refund, dispute, operations

This is the primary information architecture. Protocol concepts are secondary layers beneath these questions.

## 4. Navigation

### Global navigation

The desktop shell should expose only:

**Home · Activity · Network · Evidence · More**

Plus a persistent primary action: **Ask PaySwap**.

On small screens this becomes:

**Home · Activity · Ask · More**

`Network` and `Evidence` move behind `More` unless the role uses them frequently.

### Role adaptation

The same navigation labels stay stable, but the home screen and default filters change by role.

| Role | Primary job | Home emphasis | Secondary depth |
|---|---|---|---|
| Customer | get an outcome / resolve a problem | active payments, promises, receipts | routes, evidence, recourse |
| Merchant | create demand and get reliably paid | checkouts, fulfillment, exceptions | analytics, capabilities, settlement |
| Provider | supply a capability or rail | opportunities, capacity, performance | contracts, execution, evidence |
| Liquidity Provider | supply capital / credit | demand, commitments, pricing | collateral, risk, returns |
| Capability Developer | build and prove extensions | projects, simulations, review | marketplace, manifests, metrics |
| Agent / Mediator | propose decisions | proposals, comparisons, pending approvals | simulation, counterfactuals, evidence |
| Network Operations | keep the network healthy | incidents, degraded dependencies, recovery | cases, forensics, evidence |
| Administrator | control access and platform state | access queue, participants, platform health | governance, configuration, audit |

Admin is deliberately not treated as a normal business role in the public product; it is a privileged control surface.

## 5. Ask PaySwap

`Ask PaySwap` is the universal entry point, not an AI chat toy.

A user starts with natural language or a compact structured request:

- “Pay this supplier next Friday.”
- “Get me paid for this order.”
- “Find the lowest-risk way to move $2m.”
- “Why is this payment delayed?”
- “Compare the routes for this payment.”
- “Show me the proof that this settled.”

The system turns the request into a **task card** with only the information required to progress.

### Task card states

`Draft → Options → Needs decision → In progress → Waiting → Completed → Needs attention`

Each card has:

- outcome in plain language;
- amount / asset when relevant;
- timing;
- current state;
- one primary next action;
- compact confidence / risk indicator when material;
- evidence affordance.

Advanced protocol detail sits behind `Why?`, `Details`, or `Evidence` disclosures.

## 6. Progressive disclosure rules

Level 0 — **Outcome**

Show what the user asked for and whether PaySwap can help.

Level 1 — **Decision**

Show only material choices: amount, timing, route recommendation, approval, permissions, and exceptions.

Level 2 — **Execution**

Show live state, stage, estimated completion, exception, and recovery path.

Level 3 — **Proof**

Show evidence records, provenance, finality, reconciliation, authority digests, and audit detail.

Level 4 — **Protocol / operator detail**

Expose object IDs, adapter details, dependencies, commands, and implementation diagnostics only to roles that need them.

No screen should begin at Level 3 or 4 for a normal customer or merchant task.

## 7. Core task patterns

### Pay / send

`Describe → Review amount and timing → Review one recommended route → Approve → Track → Receipt`

Advanced route alternatives are collapsed unless the user requests them or policy requires a choice.

### Get paid

`Create demand → Choose when/where → PaySwap finds execution path → Track fulfillment → Settlement → Evidence`

The merchant sees expected money and important delays, not clearing internals.

### Find liquidity

`State need → Compare offers → Review cost / risk / constraints → Commit → Monitor → Resolve`

### Route / optimize

`State outcome → See recommendation → Compare 2–3 meaningful alternatives → Choose or accept policy default`

Never present ten equivalent routes unless the user is an expert role explicitly asking for the full market.

### Recover a failed payment

`Problem detected → What happened? → Reconcile → Recovery proposal → Approve if required → Retry / alternate route → Result → Proof`

A failure must never visually look like success. Unknown is a distinct state.

### Create / publish a capability

`Describe capability → Build → Simulate → Review risks → Publish → Observe usage`

Simulation is the default confidence-building surface for developers and agents.

### Operate the network

`Detect → Triage → Diagnose → Contain → Recover → Verify → Close`

Operators see the detailed authority graph because that is their job, but the first row of every incident stays outcome-oriented.

## 8. Role-specific home screens

### Customer

Hero: **“What do you need to make happen?”**

Primary actions: Pay · Track · Resolve

Below: active promises, next settlement, recent receipts.

### Merchant

Hero: **“Turn demand into a reliable outcome.”**

Primary actions: New checkout · Get paid · Resolve an exception

Below: today's volume, fulfillment health, pending settlements.

### Provider

Hero: **“Where can your capability help?”**

Primary actions: Opportunities · Capacity · Performance

Below: live commitments and observed reliability.

### Liquidity Provider

Hero: **“Where is capital needed?”**

Primary actions: Demand · Offers · Risk

Below: active commitments and returns.

### Developer

Hero: **“Build. Prove. Publish.”**

Primary actions: New capability · Simulate · Submit

Below: projects and review status.

### Agent

Hero: **“What decision needs a better answer?”**

Primary actions: Analyze · Compare · Simulate

Below: proposals awaiting human or policy decisions.

### Operator

Hero: **“What needs attention?”**

Primary actions: Incidents · Recovery · Cases

Below: network health and unresolved risk.

### Admin

Hero: **“Keep PaySwap trusted and accessible.”**

Primary actions: Access · Participants · Platform

Below: waitlist queue, account lifecycle, audit signals.

## 9. Object details

Every important record gets the same detail pattern:

**Header** — plain-language name + state + primary action

**Summary** — amount, parties, timing, current outcome

**Timeline** — human-readable milestones

**Next** — exactly one recommended next action, or “Nothing needed”

**Evidence** — proof and provenance, collapsed by default

**Technical** — protocol details, role-gated

This pattern should be reused for intents, checkouts, promises, routes, execution attempts, obligations, settlements, capabilities, proposals, incidents, and evidence records.

## 10. State language

Prefer user language first, protocol language second.

| Internal state | Product language |
|---|---|
| UNKNOWN | We don't yet know whether the payment took effect. |
| PENDING | Waiting for the agreed condition. |
| SUCCEEDED | Payment completed. |
| FAILED | Payment did not complete. |
| UNAVAILABLE | This route is temporarily unavailable. |
| RECOVERING | PaySwap is recovering this payment. |
| FINALITY ESTABLISHED | Settlement is final. |
| OBSERVED | Confirmed from recorded evidence. |

Never relabel UNKNOWN as “failed”. That destroys one of PaySwap's most important safety distinctions.

## 11. Trust UX

Trust should be earned through legibility, not decoration.

Every consequential action gets:

- what will happen;
- what authority is acting;
- what is reversible;
- what PaySwap observed versus inferred;
- what happens next if execution fails.

AI-generated recommendations are visually marked as recommendations. Human, policy, or protocol authority is separately identified.

Evidence is always inspectable, but not always visible.

## 12. AI interaction model

The agent should operate as a **copilot layer over the protocol**, not as a replacement for authority.

It can:

- turn natural language into a structured intent;
- summarize options;
- compare routes;
- forecast outcomes;
- run simulations and counterfactuals;
- explain an incident;
- draft recovery actions;
- prepare evidence summaries;
- suggest capability matches.

It cannot silently:

- create a second financial authority;
- bypass policy or limits;
- hide uncertainty;
- convert an UNKNOWN result into a success claim;
- mutate durable financial state without the authority that owns it.

The UI should reinforce this by using language such as **Proposed**, **Recommended**, **Observed**, **Approved**, and **Confirmed**.

## 13. Notifications

Notifications are task-oriented, not telemetry-oriented.

Prioritize:

1. action required;
2. outcome changed;
3. exception / risk;
4. evidence available.

Do not notify users about every protocol event.

Examples:

- “Your payment needs your approval.”
- “Payment delayed — PaySwap is checking another route.”
- “Settlement completed. Receipt available.”
- “Merchant action needed: provide a missing document.”

## 14. Search

Global search should be an **object and task search**, not a protocol log search.

Support natural inputs such as:

- merchant name;
- customer name;
- payment amount;
- checkout ID;
- settlement reference;
- incident ID;
- “payments delayed today”.

Results are grouped by object type and state, then opened in the common object-detail pattern.

## 15. Empty, loading, and waiting states

Every view answers:

- Is data loading?
- Is there no data?
- Is the system waiting?
- Is an action required?

Waiting screens must explain what is being awaited and whether the user needs to do anything. They should not imply failure merely because the network is processing.

## 16. Access and authentication UX

### Public entry

The landing page should communicate the product before requiring authentication.

Primary choices:

**Explore PaySwap** · **Join the waitlist** · **Sign in**

### Sign-up

For the current beta stage, sign-up is intentionally a waitlist request, not account creation.

The form asks only:

- name;
- email;
- intended role;
- organization (optional).

On completion: **“You're on the list.”**

No password should be requested during waitlist entry.

### Account creation

A non-demo administrator later converts a waitlist entry into a real account. The original request stays immutable as historical context; the admin may select a final product role and issue the first password.

The account lifecycle is:

`Waitlist → Admin review → Account created → Sign in`

### Demo access

Demo mode is explicit and visually labeled. A single page provides one-click entry to every role, including administrator, without implying that demo access has real financial authority.

## 17. Authentication security baseline

The product shell should:

- hash passwords with a memory-hard password hashing function;
- never store plaintext passwords;
- use HTTP-only, SameSite session cookies;
- use secure cookies in HTTPS deployment;
- separate demo identities from real users;
- keep admin privileges server-side and role-gated;
- support a future migration to passkeys / SSO without changing the product mental model;
- protect privileged POST actions against CSRF;
- make session expiration and sign-out explicit.

## 18. Admin access model

The administrator should not need to understand the authentication storage model.

Their access screen should show:

**Waiting → Review → Create account → Done**

For each request:

- original email / name / requested role;
- organization;
- request date;
- current lifecycle state;
- final account role;
- account creation action.

Later extensions can add invitation delivery, password reset, SSO assignment, suspension, role change, and audit history without changing the basic queue model.

## 19. Use-case inventory

### Customers

Pay a person, pay a business, track a payment, understand a delay, retry after an unknown outcome, receive a receipt, inspect evidence, request a refund or recourse, compare choices, authorize a consequential action.

### Merchants

Create checkout demand, create promises, accept or cancel demand, receive settlement, monitor fulfillment, inspect exceptions, recover failed payments, compare routes, manage refund paths, inspect settlement evidence, review customer outcomes, connect capabilities.

### Providers

Publish capabilities, declare capacity, receive demand, quote, accept work, execute, reconcile, report availability, inspect performance, prove reliability, handle investigation cases.

### Liquidity providers

Publish liquidity, define pricing and constraints, evaluate demand, commit liquidity, monitor utilization, manage collateral / limits, inspect contribution, handle settlement and risk events.

### Developers

Create extension, define manifest, simulate, run tests, inspect evidence, submit for review, publish, version, observe usage, measure contribution.

### Agents / mediators

Interpret demand, generate proposals, compare routes, simulate outcomes, forecast, recommend, request approval, coordinate recovery, summarize evidence, never become final authority.

### Operators

Monitor dependencies, detect incidents, triage, declare degradation, fail over, reconcile, retry, rebuild from evidence/journals, verify recovery, resolve incidents, inspect forensic evidence.

### Administrators

Manage waitlist, create accounts, assign roles, manage access, review participants, inspect platform state, oversee governance, audit activity, control demo mode in appropriate environments.

## 20. What users should never see by default

Do not put these in the first-level experience:

`A0–A7`, `R0–R5`, object type URNs, raw command IDs, adapter contract details, authority digests, internal work-order IDs, implementation branch names, validator output, worker IDs, protocol event namespaces, or dependency graphs.

They remain accessible to operators, developers, auditors, and administrators where useful.

## 21. Cross-device behavior

The product should preserve the same mental model across laptop, phone, tablet, and future embedded surfaces.

Phone: task-first, compact details, bottom navigation.

Laptop: task-first plus lists and side-by-side comparison.

Large display / TV: status-first, large typography, focus navigation, minimal text, remote-friendly controls.

The destination is not “the same layout everywhere”; it is **the same product grammar everywhere**.

## 22. Recommended product surface map

```text
PaySwap
├── Home
│   ├── Ask PaySwap
│   ├── Current work
│   ├── Recent outcomes
│   └── Needs attention
├── Activity
│   ├── Tasks
│   ├── Payments / checkouts
│   ├── Proposals
│   └── Incidents
├── Network
│   ├── Routes
│   ├── Providers
│   ├── Capabilities
│   └── Liquidity
├── Evidence
│   ├── Receipts
│   ├── Settlement proof
│   ├── Finality
│   └── Audit trail
└── More
    ├── Simulations
    ├── Developer / capability tools
    ├── Settings
    └── Admin (privileged)
```

## 23. Product success criteria

A new user should understand the product within one minute without learning PaySwap vocabulary.

A returning user should reach their most common action in two interactions.

A user should always be able to answer “what is happening?” from the object or task they are viewing.

A consequential action should make authority and uncertainty explicit before commitment.

An expert should be able to drill from a friendly outcome view into the complete evidence and protocol story without leaving the object context.

The system should expose its depth on demand instead of exposing its complexity by default.

## 24. Public design references

- Apple Human Interface Guidelines — Design Principles: https://developer.apple.com/design/human-interface-guidelines/design-principles
- Apple Human Interface Guidelines — Managing Accounts: https://developer.apple.com/design/human-interface-guidelines/managing-accounts
- Apple Human Interface Guidelines — Privacy: https://developer.apple.com/design/human-interface-guidelines/privacy/
- Apple Human Interface Guidelines — Accessibility: https://developer.apple.com/design/human-interface-guidelines/accessibility
- Stripe Apps — Design your app: https://docs.stripe.com/stripe-apps/design
- Stripe Apps — Design patterns: https://docs.stripe.com/stripe-apps/patterns
- Stripe Apps — UI components: https://docs.stripe.com/stripe-apps/components
