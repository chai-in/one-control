# Loopback development workspace

The development API and React console run as the current user. The API binds to `127.0.0.1:4317`; the console uses `127.0.0.1:4318`. No SYSTEM startup task or presentation website is included. The original persistent POC scripts remain archived.

## Start development

Run `pnpm install --frozen-lockfile`, then run `pnpm setup:local` once. Start `pnpm dev` and `pnpm dev:console` in separate terminals. Setup creates three independent development role tokens in the ignored `.env`. Existing configuration is preserved. Use the appropriate token to open the console. Tokens stay in browser memory.

## API boundaries

`DEPLOYMENT_STAGE` defaults to `poc`. The default device limit is five and the configurable range is one to ten. Concurrent enrollment locks the capacity check in a transaction. Revoked devices free capacity while their history remains. Rejected enrollment leaves its token unused.

POC devices and operations stay in the canary ring. Broader assignments, dispatch and approvals are rejected. Changing deployment stage does not revoke credentials or replay uncertain work. Existing leases can still report results.

Development authentication is restricted to loopback. A remotely hosted pilot needs production OIDC, verified PostgreSQL TLS and trusted HTTPS ingress. Do not expose the development API through a public tunnel.

## Roles and acceptance

Viewers inspect inventory, receipts and audit records. Operators request typed operations and reconcile uncertain outcomes with evidence. A different approver reviews the exact installation batch. The creator cannot approve it.

`pnpm test:console` creates local simulated identities and receipts, checks role boundaries and desktop/mobile behavior, then revokes its fixtures. It does not run endpoint providers. Screenshots stay under ignored `.local/screenshots`. Current results are in the phase 1 report.

The imported native service is a source foundation. Endpoint installation and the thin bootstrap need separate implementation and acceptance. A persistent backend also needs an immutable protected deployment tree, rather than a startup task that executes this user-owned checkout.
