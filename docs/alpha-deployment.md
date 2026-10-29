# Prepare an independent private alpha deployment

Prepare the server independently of the managed Windows computer and the proposed Ubuntu wake relay. Use an approved, supervised Node API origin and durable PostgreSQL. Keep the console, artifact service, endpoint identities, and signing custody separate. A sleeping Windows target must not remove the API, database, or owner sign-in.

This package is deployment preparation. It has not run containers, PostgreSQL, a provider deployment, a tunnel, or a real endpoint pilot. A valid template or passing fixture does not establish readiness. Keep the full roadmap in the scope document and [module architecture](module-architecture.md).

## Record the operator decisions

Before provisioning, record the following inputs in a protected deployment record outside Git. Use fresh product identities and configuration. Leave an unresolved input as a blocking gate.

| Gate | Exact operator input and acceptance evidence |
| --- | --- |
| Ownership | Named owner, recovery contact, single private-alpha workspace, allowed users, approved home target, and separately revocable relay identity. |
| API host | Provider or explicitly approved existing host, region, administrator, supported architecture, maintenance policy, persistent supervision, restart policy, outbound access, capacity, and health monitoring. Prove it remains available when the managed Windows PC sleeps. |
| Host isolation | Administrative access and immutable release paths, service account, inbound firewall policy, patching, log retention, and a recovery path independent of One Control. The Ubuntu Jellyfin laptop is not an accepted API or database host by default. |
| Budget | Dated monthly quote with currency, tax, compute, database, storage, backups, egress, domain, Cloudflare plan, and metered usage. Record the approved cap, alert threshold, and budget owner. No provider, plan, or purchase is selected by this package. |
| Domains and ingress | Exact console origin, API routing, artifact hostname, DNS owner, TLS certificate custody, renewal, and origin exposure. Keep PostgreSQL and RDP off public unauthenticated ingress. Preserve same-origin `/v1/*` and `/health/*` routing. |
| Human identity | Exact HTTPS OIDC issuer including any path or trailing slash, public browser client ID, API audience, callback `<console-origin>/auth/callback`, logout origin, and exact owner `sub`. Record separate operator and approver subjects when update approval remains enabled. |
| OIDC behavior | Public-client code flow with PKCE S256, exact redirects, no browser client secret, access token with accepted issuer/audience, RS256 or ES256, `sub`, `exp`, and `iat`, and token age within one hour. Prove these through the actual issuer and browser. |
| Database | Dedicated database name, server identity, supported PostgreSQL version, CA chain, verified TLS hostname, maximum connections, separate runtime and migration roles, protected credentials, and provider recovery access. Budget at least the current maximum 20 connections per API process plus migration and operations headroom. |
| Runtime role | Prove no superuser, database creation, role creation, replication, bypass-RLS, object ownership, inherited elevated role, database `CREATE`, or schema `CREATE`. Prove DDL and audit mutation denials on the actual role. A declaration in a config file does not prove these grants. |
| Backup | Backup operator and storage, retention, encryption, recovery point objective, recovery time objective, last successful backup alert, and an isolated restore destination. Retain restore proof for the exact schema and release. A backup listing is insufficient. |
| Executable trust | Fresh installed root trust, policy/catalog/freshness authority, native package publisher, installer publisher, release trust, rotation and revocation owners. Keep private keys and recovery material outside Git and outside the public web root. |
| Artifacts | Dedicated private object storage and delivery identity, hostname allowlist, immutable content-addressed objects, protected read-capability key, and full independent size/hash verification. Artifact read authority must not grant signing, enrollment, or database authority. |
| Operations | Restricted diagnostics destination, retention and redaction policy, alert recipient, maintenance access, exact release digests, previous known-good release, approved rollback decision maker, and incident procedure. |

Use Cloudflare hosting for the intended public console and artifact role only after explicit new account, resource, binding, domain, and budget selection. The current Fastify entrypoint is a long-running Node process. No accepted Worker port exists in this source. Use the cf CLI for new Cloudflare configuration while no actual Wrangler project configuration exists. The example configuration and existing Sophos pilot do not select product targets or authorize account changes.

## Preserve the current source boundaries

Before selecting a release, inspect these exact contracts again after root integrates the parallel work.

| Source contract | Deployment consequence |
| --- | --- |
| `apps/control-plane/src/main.ts` | Production startup opens the database and starts the API and a 15-second reconciliation timer. It skips migrations. Keep one supervised API process for the first rehearsal. Do not add a shell command that migrates before API start. |
| `apps/control-plane/src/migrate.ts` and `database.ts` | The dedicated command parses the full API configuration and runs the version-1 schema under an advisory transaction lock. It returns when version 1 already exists. It has no ordered upgrade registry, dry-run mode, down migration, or restore quarantine switch. |
| `apps/control-plane/src/app.ts` | `/health/live` reports process response. `/health/ready` checks for schema version 1 and returns 503 on a failed database query or missing marker. A ready response does not prove the complete schema, grants, identity, module authority, or recovery. |
| `apps/control-plane/src/config.ts` | Production requires PostgreSQL with exactly one `sslmode=verify-full`, HTTPS OIDC, no development tokens, release trust, artifact hosts, operator subjects, and approver subjects. `DEPLOYMENT_STAGE` is independent of `NODE_ENV`. Keep production authentication even in the bounded POC stage. |
| `apps/console/src/auth.ts` | Issuer, client ID, and audience are public build-time values. The callback is the console origin plus `/auth/callback`. The user token stays in memory, with OIDC transaction state in session storage. Rebuild for changed issuer, client, or audience. |
| `deploy/Caddyfile` | Routes `/v1/*` and `/health/*` to the API and other paths to the console. Set `ONE_CONTROL_HOST` and the issuer origin `OIDC_ORIGIN`. The issuer origin has no discovery path. Test that API errors stay JSON and the callback reaches the SPA. |
| `deploy/Dockerfile.api` and `Dockerfile.console` | Existing build inputs use mutable base tags and copy a broad build tree. Pin and review final image digests and the runtime dependency closure before a release. These files do not provision a database or supply supervision. |
| `apps/artifacts/src/policy.ts` | The integrated native-package extension adds explicitly enabled content-addressed ZIP reads beside the existing MSI path. Actual Worker/R2 framing, immutable publication and native downloader acceptance remain open deployment gates. |

Do not provide dummy release keys, unwanted module configuration, or fake subjects to satisfy unrelated production startup requirements. Root must integrate module-aware startup and route admission. All feature payloads, API routes, console entry points, background tasks, and migrations remain optional under explicit shared dependencies. A hidden console control does not disable its API.

## Validate the explicit local inputs

Copy the following examples to a protected directory outside Git and outside the image build context. Replace every `REQUIRED` sentinel with fresh approved inputs. The examples deliberately fail validation.

- `deploy/alpha/deployment.example.json` defines the closed `AlphaDeploymentV1` plan.
- `deploy/alpha/runtime.env.example` supplies runtime API inputs and the matching console build and Caddy inputs.
- `deploy/alpha/migration.env.example` supplies the separate migration credential and full production API configuration.

Run this command from the repository root with the three actual file paths.

```powershell
node deploy/alpha/preflight.mjs --config C:/Private/OneControl/deployment.json --runtime-env C:/Private/OneControl/runtime.env --migration-env C:/Private/OneControl/migration.env
```

The checker reads only those named files and the plan's explicit release public-key file. It performs no network requests, SQL, subprocess calls, application imports, or writes. Each input must be a regular file of at most 1 MiB. The public key must be public PEM RSA with at least 3072 bits. Private-key PEM input is rejected.

Use literal `NAME=value` environment assignments, one per line. Blank lines and full-line `#` comments are allowed. Do not use quotes, `export`, interpolation, multiline values, or inline comments. Duplicate and unknown keys fail. JSON duplicate members and unknown plan fields also fail. Keep UTF-8 files free of a byte-order mark.

The plan binds the exact issuer, public client, audience, subjects, console origin, artifact hostnames, release public key, image digest references, database roles, and bounded deployment stage. The runtime bundle includes the console's three `VITE_OIDC_*` build values, `ONE_CONTROL_HOST`, and `OIDC_ORIGIN` for matching. Do not treat those values as proof of what an existing image contains. Rebuild the console and supply the actual Caddy inputs separately.

Both environment files require `NODE_ENV=production`, `HOST=0.0.0.0`, and `PORT=4317` for this package's current Caddy target. The POC stage retains production authentication and an explicit device limit between 1 and 10. Database URLs must name the same server and database with distinct declared roles and password values. The checker accepts only one URL query parameter, `sslmode=verify-full`. It rejects other query parameters, known placeholders, development authentication, `NODE_OPTIONS`, and TLS bypass variables in the input files. It cannot prove password entropy, freshness, or actual role privileges.

The optional `NODE_EXTRA_CA_CERTS` value must be an absolute literal path. The checker does not read the CA file. The approved Node supervisor must supply the actual protected CA bundle and variable before process start. Prove certificate and hostname verification through a real PostgreSQL connection. Do not weaken TLS for the disposable rehearsal.

Use profile `production` for the deployment candidate. Profile `disposable-rehearsal` permits `.test` hostnames for an isolated fixture. It still requires production process mode, explicit credentials, and verified TLS. The plan requires `database.runtimeDdl` to be `forbidden` and `database.migrationExecution` to be `explicit-one-shot`. These are checker constraints. The application does not read them or change grants in response.

Exit 0 returns `configuration-valid`. Exit 1 returns `configuration-invalid` with fixed field paths and diagnostic codes. Every result includes `productionAcceptance: false`. Errors do not print input values, credential URLs, arbitrary parser errors, or key bytes. The checker ignores ambient application configuration. Node itself processes runtime environment before the checker starts, so use a controlled launch environment.

The unchanged Dockerfiles do not invoke this checker automatically. After validation, the operator must inject exactly the reviewed values through the selected supervisor, with no ambient overrides. Build arguments, Caddy configuration, runtime credentials, and migration credentials have separate destinations. Never source the checker bundle as shell code or put migration credentials in the API process.

Run `pnpm --filter @one-control/control-plane migrate` separately with the full production migration environment already supplied by the approved supervisor. That package command uses `tsx` and does not load this environment file itself. After a matching build, the equivalent compiled entrypoint is `apps/control-plane/dist/apps/control-plane/src/migrate.js`. Neither command belongs in an API start, restart, healthcheck, or deployment retry loop.

## Rehearse without contacting infrastructure

Run only the deployment fixture checks in this workstream. They read synthetic configuration and exercise the local validation interface. They must not contact an issuer, a database, DNS, object storage, or a provider.

```powershell
node --test deploy/tests/alpha-preflight.test.mjs
git diff --check
```

Record the command, exit code, exact checkout SHA, changed file hashes, and limitations. Do not convert a local check into a readiness claim.

## Plan a disposable infrastructure rehearsal

This procedure is for a later explicitly owned fixture. It has not run as part of this package.

1. Obtain approval for a disposable isolated VM or test host, dedicated database, temporary test issuer, domains, and a destruction boundary. Confirm that every credential and target is new.
2. Bind test ingress only to the fixture network or local loopback. Deny access to production networks and real endpoints. Use verified TLS and explicit test certificate trust. Never disable TLS checks to make a rehearsal pass.
3. Build from the integrated exact revision with the frozen lockfile. Record base-image digests and final API and console image digests. Inspect the image contents and omit secret files, archives, host runtime state, signing keys, and inherited deployment configuration.
4. Create the test database with an operations identity. Create distinct migration and runtime roles through a reviewed fixture script owned by root. Give the runtime no DDL or ownership. Do not put a database administrator credential in the API environment.
5. With the API stopped, run the explicit migration command once with the migration identity and the full production environment. The current source supports only fresh version-1 setup. Do not treat a successful rerun as an upgrade rehearsal.
6. Remove the migration credential from the runtime environment. Start the API with the runtime identity. Prove DML succeeds only where required, `audit_events` is append-only, and DDL, role changes, schema creation, and audit modification fail on actual PostgreSQL.
7. Test live and ready probes separately. Stop database access and confirm ready fails without returning the console HTML. Remove the version marker only in a newly recreated disposable fixture. Confirm that startup does not recreate it and that readiness fails.
8. Verify console routes, security headers, OIDC discovery and JWKS access, code and PKCE exchange, callback refresh, accepted access token, exact role mapping, unknown subject denial, expired or wrong-audience token denial, and sign-out cleanup. Never store bearer tokens in evidence.
9. Validate the separate private artifact path with synthetic harmless content. Prove unsigned access, wrong host, expired capability, wrong size, and range requests fail. Read approved bytes back independently. Do not substitute the old MSI path for native module delivery.
10. Restart the API and ingress. Record downtime and reconcile durable state without resubmitting mutations. Test lost-response and unknown database commit handling through root's owned PostgreSQL suite.
11. Back up the disposable database. Restore to a separately named, network-isolated database. Keep API and endpoint egress disabled. Prove restored credentials and executable authority are quarantined and queued mutations cannot resume. This requires root's pending ordered migration and recovery work. No current template supplies that behavior.
12. Remove only the exact fixture resources listed in its approved ownership record. Preserve sanitized logs, hashes, probe results, grant denials, and restore verdicts. Never use a blanket delete against an unverified host or provider account.

Stop the rehearsal at a failed gate. A fresh-install rehearsal is separate from upgrading an existing version-1 database. Both require the future ordered migration implementation and exact-source PostgreSQL acceptance before deployment with new tables.

## Deploy only after the independent gates pass

Perform these steps on the selected environment after review and explicit deployment authorization.

1. Freeze the integrated source revision. Run `pnpm check`, locked Windows restore, build and tests, PowerShell parsing, and root's actual PostgreSQL suite against that revision. Require elevated Windows CI for protected storage. Local skips do not supply coverage.
2. Accept the thin bootstrap and selected optional modules separately. Do not install the imported provider monolith as the thin agent or require a preinstalled Node or .NET runtime as hidden endpoint baggage.
3. Accept the independent host and database input record. Verify TLS, restricted runtime grants, backup retention, isolated restore, disk capacity, supervision, restart behavior, and alert delivery. Keep the API unreachable from unauthenticated public ingress until its identity and admission gates pass.
4. Register the fresh public OIDC client and exact subjects. Review Access policy separately from application OIDC and machine authentication. An Access email challenge cannot serve as a device credential. Prove logout, wrong subject, wrong audience, expiry, and missing bearer failures on the actual origin.
5. Publish immutable API and console artifacts to the approved registry or host. Record digest, source SHA, dependency manifest, config digest without secrets, and previous known-good release. Pin base images before building the accepted candidate.
6. Stop API writers before the separately reviewed migration window. Take a verified recovery checkpoint. Run the dedicated migration command with its separate identity. Preserve unknown outcomes and inspect durable state before deciding what to do next. Never auto-retry a failed command merely because its output was lost.
7. Remove migration authority and start the API with restricted runtime credentials. Confirm production environment, exact TLS chain, probes, API error routing, headers, and sanitized diagnostics. Check container or service restart supervision on the actual host.
8. Publish the console to explicitly approved Cloudflare targets with same-origin API routing and the exact build-time OIDC settings. Accept the actual callback and bearer exchange. Do not expose development listeners through a public tunnel.
9. Configure the separate artifact service and private storage with fresh identities and keys. Verify immutable bytes and full download hashes. Keep private signing keys, database credentials, device tokens, and capability URLs out of console assets and logs.
10. Authorize the real endpoint pilot separately. Install only the protected native bootstrap and explicitly selected feature packages. Enroll Windows and Ubuntu with distinct identities, owner and site bindings, revocation, signed catalog/policy, publisher evidence, and challenge-bound freshness.
11. Complete the real-machine acceptance below. Retain exact source, artifact and config identities for each observation. Keep failed or untested gates open.

## Accept the real home path

Record separate timestamps for application contact, inventory observation, relay contact, wake transmission, target contact after wake, route reachability, and authenticated RDP. A packet-send receipt does not prove power-on or RDP readiness.

- With the managed Windows PC asleep, prove owner console login, API, database, artifact service, and Ubuntu relay remain available through an independent client.
- Prove optional inventory activation and disabled collector absence. Confirm disabled payloads are absent on a clean install and retained inventory cannot change through a disabled entrypoint.
- Prove protected installation, restart custody, identity rotation and revocation, network loss, stale authority refusal, failed activation, rollback, and decommissioning on the real Windows computer and Ubuntu relay.
- Verify Ubuntu OS, architecture, protected storage, site interface and VLAN, automatic service start, lid/suspend behavior, coexisting workloads, and recovery after power loss. Do not infer these from reported uptime.
- Test wake from S3, hibernation, full shutdown, long shutdown, and power restoration with the owner present. Record firmware, NIC, DHCP mapping, broadcast path, BitLocker preboot behavior, and each unsupported condition.
- Verify native RDP from the approved Windows, Mac, and iPhone clients through the reviewed route. Preserve Windows authentication and NLA decisions. Test actual handoff, reconnect, sign-out, wrong target, expired authorization, and fallback. Mobile web is not accepted as an installable PWA.
- Disconnect the relay and the Internet independently. Display stale observations and uncertain outcomes without replaying old wake or management mutations when connectivity returns.
- Prove the isolated restore and operator recovery procedure before enabling mutation authority after a disaster. Never let restored queued work execute automatically.

Office wake, roaming Mac hosting, physical desktop control, file sharing, selected-user clipboard, policy, indexing, rich history, and advanced fleet workflows remain separate roadmap gates. CRM, Android, and AMAPI remain excluded.

## Roll back within the proved boundary

If a candidate fails before migration, keep the previous immutable API and console release and its protected configuration. Restore only the deployment routing or release pointer approved for that environment.

After a schema change, return to old API code only when an explicit compatibility check proves it can use the new schema. The current dedicated migration command has no down operation. Stop ingress and writers when compatibility is unknown. Preserve the database and logs for diagnosis.

A backup restore creates a separate recovery environment. It is not an automatic in-place rollback. Quarantine credentials, executable authority, queued operations, and nonterminal mutation outcomes before reconnecting endpoints. Preserve `indeterminate` and unknown outcomes. Reauthorize recovery from current durable evidence rather than replaying requests.

Console OIDC changes require a matching rebuilt bundle and exact callback registration. Do not roll back issuer trust, device revocation, package trust, or signing policy merely to make old code start. Never overwrite content-addressed artifact bytes. Revoke compromised read authority through its separately reviewed rotation procedure.

Keep the previous approved image digests, deployment configuration version, database checkpoint, signing trust version, and rollback evidence together in the protected operator record. No endpoint installation, account grant, signing-key rotation, database restoration, or provider deletion is authorized by this preparation guide alone.
