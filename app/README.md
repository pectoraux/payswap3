# PaySwap product shell

This folder is the user-facing shell around the frozen PaySwap protocol. It deliberately does **not** become a second financial authority.

## UX direction

The product follows an outcome-first interaction model:

`Outcome → Options → Decision → Execution → Evidence → Resolution`

The interface is role-aware, but the navigation grammar stays shared so Customer, Merchant, Provider, Liquidity Provider, Developer, Agent, Operator, and Administrator experiences feel like one product rather than eight dashboards. Protocol internals appear through progressive disclosure instead of occupying the default workspace.

The full product UX architecture and design-council decision record lives in `spec/product/ux-architecture-v0.2.md`.

## Authentication and access

- waitlist-only public sign-up
- password-authenticated real user/admin accounts
- admin conversion from waitlist entry → real account
- role-aware workspaces
- explicit demo mode with one-click persona entry for every product role
- SQLite persistence for waitlist/users
- scrypt password hashing
- HTTP-only, SameSite session cookies

### Development administrator bootstrap

A non-demo administrator is seeded on first startup as:

```text
username: ekontetevi@gmail
password: Payswap123456
```

The repository contains only a one-way scrypt verifier for that development bootstrap password, never the plaintext password. An environment-configured administrator (`PAYSWAP_ADMIN_EMAIL` / `PAYSWAP_ADMIN_PASSWORD`) takes precedence and is suitable for deployment-specific credentials. Rotate the bootstrap credential before using the product outside controlled development/demo environments.

For deployment, also set `PAYSWAP_SESSION_SECRET` and use `PAYSWAP_COOKIE_SECURE=true` behind HTTPS.

## Demo access

Demo mode is enabled by default and provides quick links for:

Customer · Merchant · Financial / Service Provider · Liquidity Provider · Capability Developer · Agent / Mediator · Network Operations · Administrator

Disable it outside demo environments with:

```bash
export PAYSWAP_DEMO_MODE=false
```

The demo personas are flagged as demo sessions and are not granted real financial authority.

## Account lifecycle

`Sign up → waitlist → admin review → account creation → normal sign in`

The waitlist stores the original role and organization request. Administrators can change the eventual account role while preserving that original request.

The account-creation screen is deliberately simple: select the queue entry, confirm identity/role, issue the user's first temporary password, and create the account. Future additions such as invitations, password reset, SSO, passkeys, suspension, and audit history can layer onto the same lifecycle without changing the user's mental model.
