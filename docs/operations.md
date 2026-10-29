# Operations

Imported and adapted design guidance. See phase 1 validation for current results. Source-era pilot observations remain historical evidence in the preserved transfer; they do not establish One Control deployment or live endpoint acceptance.

## Local development

Install Node 24 LTS, pnpm 11.25.0 and .NET SDK 10.0.402. Run:

```powershell
pnpm install --frozen-lockfile
pnpm setup:local
pnpm dev
# Separate terminal, optional console:
pnpm dev:console
```

The API binds to `127.0.0.1:4317`; the console uses `127.0.0.1:4318`. Use a separate local operator, approver or viewer token from the ignored `.env` file. Tokens stay in browser memory. The first view has no enrolled computers. Local PGlite state persists under `.local/control-plane`. Workspaces default to a five-device, canary-only POC. See [POC boundaries](poc-workspace.md).

With both local processes running, install Chromium with `pnpm exec playwright install chromium` and run `pnpm test:console`. This checks enrollment fixtures, inventory, update selection, separate approval, viewer isolation, reconciliation, stale responses and desktop/mobile layout. It revokes its own fixtures and stores screenshots under `.local/screenshots`. It never installs the service or executes a Windows update.

The former persistent POC startup task and its setup, backup, restore and verification wrappers remain archived. They are excluded from the active import because they could launch user-writable checkout code as SYSTEM. A persistent backend requires an immutable, administrator-owned deployment tree and validated executable dependencies. Phase 1 uses ordinary-user loopback development processes.

The Windows service always requires HTTPS and LocalSystem, including when talking to a local test ingress. Its read-only inventory diagnostic is the only service executable mode permitted outside SYSTEM:

```powershell
dotnet run --project agent/OneControl.Agent.Service -- --inventory
```

## Production configuration

Startup enforces `sslmode=verify-full` in the PostgreSQL URL and rejects disabled certificate verification. Readiness also checks the required schema migration. Use a verified CA chain; never work around a certificate failure by weakening TLS. See the [driver TLS settings](https://github.com/brianc/node-postgres/blob/master/packages/pg-connection-string/README.md).

Set `NODE_ENV=production`, `HOST`, `DATABASE_URL` (PostgreSQL with verified TLS), `OIDC_ISSUER`, `OIDC_AUDIENCE`, comma-separated `OPERATOR_SUBJECTS`, `APPROVER_SUBJECTS`, optional `VIEWER_SUBJECTS`, `RELEASE_PUBLIC_KEY_FILE`, and `ARTIFACT_HOSTS`. Never set development tokens in production. Register a public OIDC client with code+PKCE and only the deployed console's exact callback URL. The console separately receives `VITE_OIDC_ISSUER`, `VITE_OIDC_CLIENT_ID`, and `VITE_OIDC_AUDIENCE` at build time.

Build the API with `deploy/Dockerfile.api`; build the console independently with `deploy/Dockerfile.console` only if wanted. Configure `ONE_CONTROL_HOST` and `OIDC_ORIGIN` for Caddy's TLS and CSP. If omitting the console, route `/v1/*` and `/health/*` to the API through your existing private TLS ingress. Ingress is a deployment responsibility, not a dependency on the console module. Pin base-image digests in the final environment.

Use a separate migration database role. Run `pnpm --filter @one-control/control-plane migrate` with production environment configuration before starting replicas. Restrict the runtime role to the necessary tables, no DDL; give `audit_events` INSERT/SELECT and its sequence USAGE, with no UPDATE/DELETE. Back up PostgreSQL and test restoration. Monitor `/health/live`, `/health/ready`, overdue jobs, `indeterminate` outcomes, offline devices and expiring credentials. Request/response bodies and installer output are not application logs.

## Windows provisioning

The complete release tree, including runtime configuration and dependency maps, must first be staged under an administrator-controlled path with protected files and ancestors. An ordinary user must not be able to write the tree or replace an ancestor. An IT-owned, explicitly secured release directory under Program Files is suitable; a user-writable download/share directory is rejected. The public release key needs the same protection. The installer copies into an atomically secured destination, verifies its actual executable bytes, and rejects reparse points or unsafe existing parents without resetting shared OneControl/EMA permissions.

1. Publish self-contained service, broker, provisioning and independent recovery binaries with `scripts/publish-agent.ps1`. Use the locked restore and [signing/packaging procedure](release-signing.md). The installer rejects unsigned output and unknown publishers. Use `DependencyPublisherThumbprints` only for explicitly verified third-party publisher certificates; all four OneControl modules must match `PublisherThumbprint`. Verify the endpoint's application-control requirements before rollout: a locally trusted Authenticode certificate alone does not guarantee that Windows permits the program to execute. Do not disable Smart App Control, WDAC, AppLocker or security tooling to complete enrollment.
2. Create an enrollment token through the IT console or authenticated `POST /v1/enrollment-tokens` with `{}`. Transfer it using a private IT channel, not a command line, log, email or source-control file.
3. Create a protected enrollment JSON file containing `controlPlane`, `token`, `artifactHosts`, `allowedPackages`, `releasePublicKeyFile` and `brokerPath`. The installer fills its trusted absolute paths. Allow only actual, approved MSI package identities. Agent self-update requires its separate lifecycle acceptance before `one-control-agent` is enabled.
4. Run `scripts/install-agent.ps1` elevated with the release folder, enrollment JSON, public release key and pinned publisher thumbprint. It creates both LocalSystem services, starts recovery before the agent, and protects state. No console is installed. Preserve failed state for reconciliation; do not delete it to force reenrollment. Securely delete the input enrollment file after enrollment.

The installer and selected providers have run in a bounded company-computer pilot. See the dated initial pilot (archived reference) and live recovery evidence (archived reference) for specific results and remaining acceptance work. This does not establish broad production readiness.

## Release signing

Approvers first read `GET /v1/batches/{id}`. It returns the exact command, creator, signed release metadata, all targets/windows and `reviewDigest`. Approval requires `POST /v1/batches/{id}/approve` with `{ "reviewDigest": "<digest returned by the review>" }`. The console presents that review before approval. A device cannot change rollout rings while work remains pending, leased or indeterminate.

Use an offline RSA key of at least 3072 bits. Keep private keys outside this repository and the API. Create metadata matching `manifestSchema` in `packages/protocol` and include a monotonically increasing package sequence, expiry, allowed HTTPS `.msi` URL, SHA-256, exact byte size, version and expected publisher thumbprint. Run:

```powershell
node scripts/sign-release.mjs manifest.json offline-private.pem envelope.json
```

Register the envelope through `POST /v1/releases`. Target a canary device with `package.install` and its release ID. An independent approver then approves the batch. Do not treat an installer receipt as proof that the app is running correctly.

## Agent update and recovery

`one-control-agent` is reserved for the independent recovery path; the generic MSI provider refuses it. Agent payload versions must have three numeric components within Windows Installer limits, increase over the active executable, and use a new package sequence. The API refuses a self-update batch if any target has not reported a running recovery service; the endpoint checks again before handoff. Deploy the recovery host separately to older agents before enabling this package.

Build and sign an immutable stage-only MSI using `scripts/package-agent.ps1`, then sign the MSI and construct metadata from its final bytes. It stages `Service`, `Broker` and `Provision` beneath `Program Files\OneControl\Agent\versions\<version>`. It cannot update `Recovery`, stop services or run custom actions. Recovery retains previous versions and SQLite/DPAPI state; do not uninstall old payload registrations while they may be needed for rollback.

The private `state\recovery\active.json` checkpoints request, installer, activation, verification and reporting. A fresh authenticated heartbeat must match device ID, live SCM PID, executable path and version. Failed candidate health restores the previous signed, hash-verified executable and broker configuration. The rollback changes local service configuration even when the network is unavailable; proof of authenticated recovery still requires connectivity. Unproven recovery remains indeterminate.

If recovery restarts during MSI installation, it records `recovery_restarted_during_installer` and does not replay it. Inspect the specific installer client, Windows Installer execution state, installed payload registration, signatures, active service path and heartbeat. An idle `msiexec /V` service alone does not establish an active installer. Reconcile only after proving the previous operation has ended and recording the actual outcome. Issue a new version and sequence rather than trying the same immutable payload again. Preserve the checkpoint and cached installer as evidence.

## Uncertain outcomes

The imported package adapters use fixed source/package acceptance flags only for exact approved jobs. Deployment must explicitly approve the applicable agreement policy before enabling these modules. This does not authorize any current rollout or accept terms merely by importing source.

The coordinator sweeps expired work every 15 seconds, including offline devices. Competing replicas skip locked device rows and preserve mutation quarantine; an offline computer is never a reason to replay an installer. Maintenance deadlines are checked again after Windows Update downloads and immediately before the user broker starts its provider. Starting inside the window does not guarantee an operating-system installation can be safely interrupted at its end.

Credential rotation first persists a machine-DPAPI-protected pending secret. The API registers only its hash, idempotently; a lost response can be recovered by authenticating with the saved pending secret. The old credential overlaps for five minutes. Active state changes only after the new secret authenticates and its configuration replacement succeeds. The former `/v1/agent/rotate` route returns `410`; upgrade the service and broker together before using this revision.

Agent settings serialize protected values only, and diagnostic formatting redacts the secret. A stopped pilot can be repaired by an elevated IT operator using `OneControl.Agent.Provision --repair-settings <protected-agent.json>`, with temporary administrator write access to the protected state directory restored afterward. It preserves the device identity, encrypted credential, issuance age and journal. The service also sanitizes legacy settings before its next authenticated operation. Back up sensitive material with DPAPI rather than creating plaintext copies. Preserve partial state and reconcile it instead of reenrolling blindly.

An expired mutating lease or interrupted installation is marked `indeterminate` and blocks further work on that device. Inspect the actual endpoint, verify installer completion/stoppage and installed state, then record evidence:

```text
POST /v1/jobs/{job-id}/reconcile
{ "state": "failed", "evidence": "Detailed observed installed state and proof no previous installer remains active..." }
```

Use an operator identity; reconciliation is audited. Never mark success solely to unblock a rollout. Pending-job cancellation does not abort running installs. Reboot remains an explicit IT/OS policy action outside this API.

## CrowdStrike

Set `FALCON_CLOUD`, `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` using deployment secret management. `GET /v1/integrations/falcon/capabilities` performs read-only checks. Do not infer a write scope from a successful read, OAuth token or HTTP 400. No RTR execution, host containment, policy mutation, security exclusion, or sensor replacement is implemented here.

## Intel EMA

The optional server-side adapter reuses the existing independent EMA installation. Configure `EMA_BASE_URL`, `EMA_USERNAME` and `EMA_PASSWORD` together using protected server settings and a suitably scoped account. The Intel EMA console view reads inventory only. One Control EMA connectivity and AMT operations need their own live acceptance. Read the [reuse decision, credential handling and preservation boundary](intel-ema.md) before removing any legacy infrastructure.
