# One Control

One Control is a modular endpoint-management platform licensed under
**AGPL-3.0-only**. See [LICENSE](LICENSE) and [third-party notices](NOTICE).

The server hosts the complete public module catalog and management console. The
endpoint installer is exclusively a thin bootstrap for identity, enrollment,
secure transport, signed package delivery and module lifecycle management.
Management settings select the optional modules and exact shared dependencies
that a device downloads. Unselected feature payloads are absent from a clean
bootstrap installation.

**Development is in progress. This is not a production-ready release.** See the
[current implementation and acceptance status](docs/development-status.md).

## Source layout

- `modules/<feature>/`: optional feature server, console and platform providers.
- `native/`: shared bootstrap, authority, transport, storage and lifecycle code.
- `packages/`: shared protocol, wire contracts and pure dependency planner.
- `apps/`: control plane, management console and artifact delivery service.
- `agent/`: imported Windows compatibility projects used during provider extraction.
- `scripts/` and `deploy/`: explicit development, packaging and deployment tools.

The [module architecture](docs/module-architecture.md) and
[source layout](docs/module-layout.md) describe module ownership and release
boundaries. File transfer and clipboard synchronization are optional features;
clipboard belongs to the selected user's session. CRM, Android management, AMAPI
and the Android companion are excluded.

Company-private modules, credentials and operational archives are excluded from
this public repository and its history.

## Develop

Use Node 24, pnpm 11.25.0, Go 1.27.2, .NET SDK 10.0.402 and PowerShell 7.4 or newer.

```powershell
pnpm install --frozen-lockfile
pnpm setup:local
pnpm dev
```

Run `pnpm dev:console` in a separate terminal. Local setup creates independent
role credentials outside version control and binds the development application
to loopback. It does not install an endpoint service.

```powershell
pnpm check
pnpm test:native
dotnet restore OneControl.slnx --locked-mode
dotnet build OneControl.slnx -c Release --no-restore
dotnet test OneControl.slnx -c Release --no-build
./scripts/check-powershell.ps1
pnpm test:postgres
```

Protected Windows storage checks require an elevated Windows account; local
skips do not replace CI coverage. PostgreSQL checks create an isolated fixture
and verify actual transactions. See [database checks](docs/database-postgres-tests.md).

Deployment requires newly configured identity, database, signing and artifact
services. `CREDENTIAL_ROOT` names the protected absolute directory containing
private signing and escrow key files; keep it outside the source checkout.
No deployment template contains production credentials or authorizes reuse of
another installation's identities.

Report vulnerabilities privately to the [repository owner](https://github.com/chai-in),
as described in [SECURITY.md](SECURITY.md).
