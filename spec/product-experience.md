# PaySwap Product Experience Architecture

## Product thesis

PaySwap should feel like an **outcome workspace**, not a financial protocol console.

The protocol underneath is intentionally rich: identities and authority, assets and ledgers, intents, capabilities, markets, liquidity, reservations, fulfilment, execution, clearing, settlement, finality, risk/compliance, evidence, simulation, extensions, agents, federation, resilience, and operations. The v0.1 architecture makes those capabilities explicit and keeps them separately authoritative.

The interface should therefore reverse the exposure: users start with an outcome and only encounter protocol complexity when a decision, exception, or proof requires it.

> **Ask for an outcome. PaySwap finds—and explains—the way.**

## Senior design council — synthesized debate

This is a design review modelled on a senior Apple-caliber product council, not a claim of participation by Apple employees.

### Product designer

The primary object in the UI should be the **intent** rather than a protocol object. A person should never need to understand `ExecutionPlan`, `ClearingCycle`, or `Finality` in order to make a payment happen.

Proposal: a single primary command, “What do you need to make happen?” followed by a small set of context-aware actions.

### UX architect

Agree, but the system must preserve a stable mental model. Use five persistent areas:

`Home` · `Activity` · `Opportunities` · `Network` · `Account`

Role-specific tools live inside those areas rather than generating a separate navigation system per role.

### Information designer

Do not put every protocol dimension on one screen. Use progressive disclosure:

1. **Outcome** — what will happen.
2. **Important choices** — amount, timing, route preference, permissions, risk.
3. **Why** — evidence, trade-offs, provenance.
4. **Technical detail** — exact plans, attempts, adapters, state transitions.

The default view is therefore readable in seconds; the full protocol remains inspectable.

### Interaction designer

Every important action should have an obvious recovery path. A failed external effect should read as **“Unknown — checking”**, never “failed” when the network cannot prove failure. Recovery should then appear as a guided next step.

Avoid busy dashboards full of status lights. Surface only exceptions and decisions.

### Visual designer

The visual language should be quiet, spacious, and editorial: high-contrast type, restrained surfaces, soft separators, one strong action per view, and very little chrome. The product should feel trustworthy before it feels powerful.

### Security designer

Authentication should not leak into the core experience. Ask for an account only where it creates value. Admin and operator capabilities must be strongly separated from demo personas and from ordinary participant workflows.

### Council decision

**Adopt outcome-first navigation with progressive disclosure and role-aware surfaces.**

The interface has three levels:

`Outcome → Decision → Proof`

Everything deeper is available on demand.

## Information architecture

### Home

The personalised starting point.

- primary command / intent creation
- current commitments and active outcomes
- exceptions requiring attention
- recent evidence-backed activity
- relevant opportunity cards
- contextual shortcuts

### Activity

The user's history, but organised by **things that happened**, not internal objects.

Examples:

- Payment sent
- Payment requires confirmation
- Merchant paid
- Settlement completed
- Incident recovered
- Capability installed
- Proposal accepted

Selecting an activity opens the timeline. Technical protocol records are a secondary detail layer.

### Opportunities

A marketplace for economic coordination.

- unmet demand
- quotes
- capability offers
- liquidity/credit offers
- extension opportunities
- agent proposals
- counterfactual comparisons

The default card answers: **“What could I gain or solve here?”**

### Network

Trust and reliability without exposing internals by default.

- provider health
- route quality
- fulfilment reliability
- settlement confidence
- incidents/recovery
- jurisdiction and policy context

### Account

Identity, access, payment preferences, connected capabilities, privacy, audit history, notification policy.

## Role lenses

| Role | Primary job | Default lens |
|---|---|---|
| Customer | achieve a payment/outcome | My outcomes |
| Merchant | convert demand into fulfilment | Merchant desk |
| Financial/service provider | supply execution capacity | Capability desk |
| Liquidity provider | price and allocate liquidity | Capital desk |
| Developer | build and publish capabilities | Capability studio |
| Agent/mediator | analyse and propose | Mediation workspace |
| Network operations | monitor/recover the network | Operations desk |
| Administrator | control access/platform configuration | Admin console |

No role gets a second protocol authority through the UI.

## Canonical user journeys

### Pay someone

`Describe amount + recipient → review route → confirm → observe progress → receive evidence-backed result`

### Get paid

`Create checkout → choose settlement terms → observe fulfilment → reconcile → receive finality/receipt`

### Find liquidity

`Describe need → compare offers → inspect risk/terms → reserve → observe funding → settle`

### Recover a payment

`Open exception → see what is known → inspect recovery option → approve recovery → monitor → reconcile`

### Build a capability

`Describe capability → sandbox → simulate → inspect contribution → submit review → publish`

### Agent-assisted coordination

`State goal → agent analyses → show alternatives + confidence + trade-offs → user/policy authorises → execute through existing authorities`

### Operations

`Exception queue → incident detail → evidence → recovery action → re-probe → close → preserve audit trail`

### Administration

`Waitlist → review → create account → assign role → issue/reset credentials → suspend/revoke → audit`

## Progressive-disclosure rule

A screen should not show the entire protocol chain. It should reveal the smallest amount of detail needed at the current decision point.

Example:

**Default**
> Payment scheduled for tomorrow · $8,450 · route secured

**Why**
> 2 eligible routes · selected for reliability + lower expected cost

**Proof**
> settlement completed · finality established · evidence attached

**Technical**
> execution attempt IDs, adapter, effect result, ledger postings, provenance, authority digests

## Authentication experience

Sign-up intentionally means **join the waitlist** until account issuance is enabled.

`Landing → Join waitlist → Name / email / role / organisation → Confirmation`

No password is requested during waitlist sign-up.

Later:

`Waitlist → Admin creates account → User receives credentials/invite → Sign in`

For the demo, a separate **Demo access** area provides one-click entry to every supported role. Demo sessions are visibly labelled and never imply production financial authority.

## Architectural boundary

The UI is an orchestration/presentation layer.

It may:
- collect intent
- present choices
- call existing protocol boundaries
- display evidence
- display derived projections
- help users recover

It must not:
- create a second ledger
- create a second finality authority
- bypass compliance
- grant protocol authority because a UI role says so
- treat payment status as settlement finality
- let an agent/extension mutate authoritative financial state

The protocol remains the source of truth; the UI turns its breadth into a human-scale experience.
