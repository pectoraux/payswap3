# PaySwap product shell

This folder is the user-facing shell around the frozen PaySwap protocol. It deliberately does **not** become a second financial authority.

## What is here

- calm, outcome-first landing and workspace
- password-authenticated administrator/user accounts
- waitlist-only sign-up
- admin conversion from waitlist entry → real account
- role-aware workspaces
- explicit demo mode with one-click persona entry for every product role
- SQLite persistence for waitlist/users
- scrypt password hashing
- HTTP-only, SameSite session cookies

## First-run admin bootstrap

The repository does not commit a plaintext administrator password. Set the requested bootstrap credentials in the runtime environment:

```bash
export PAYSWAP_ADMIN_EMAIL='ekontetevi@gmail.com'
export PAYSWAP_ADMIN_PASSWORD='Payswap123456'
export PAYSWAP_SESSION_SECRET='replace-with-a-long-random-secret'
python3 -m app
```

The bootstrap is idempotent: restarting with the same credentials updates the real admin account rather than creating duplicates.

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
