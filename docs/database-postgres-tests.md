# Owned PostgreSQL test runner

The required PostgreSQL suite has distinct `owned-local` and `ci-service` custody profiles. Arbitrary external URLs remain unsupported. Each changed custody implementation requires exact-commit GitHub acceptance. Local metadata tests do not establish container acceptance.

From the repository root, run these commands.

```powershell
pnpm test:postgres:runner
pnpm test:postgres
```

The first command exercises profile, service metadata, server identity and bounded-command controls. It creates no database. The second requires the existing PostgreSQL 18.6 binaries in `.tools/postgresql/pgsql/bin`. It starts a new direct child without installing a service. It never adopts a prior cluster or reads `.env`.

The default control-plane test command remains PGlite. The required configuration runs eight suites, including the existing control-plane, release, product-boundary, POC-boundary and independent-fixture tests, PostgreSQL fixture and adapter controls, and frozen-v1 catalog admission. Local backup tests remain separate fast-suite evidence. Skipped or missing required tests fail the runner.

The baseline suite uses only the existing fresh owned runner and fixture custody. It admits independently created frozen v1 and empty state under authenticated migrator transactions, advisory locking and nine sorted ACCESS EXCLUSIVE table locks. It checks structural and marker drift, independent catalog invariance, preserved representative rows and denied runtime DDL and migration-marker writes. `migration-baseline.json` has a fixed scenario inventory and bounded allowlisted fields. A successful run requires every observation and exact fixture cleanup. This is the first preparation component described in [Frozen v1 catalog admission](migration-baseline.md). Ordered target2 execution, readiness and backup-v2 integration remain later work.

## Local custody

Each local invocation exclusively creates a random directory inside `.local/database-tests`. Windows ACLs remove inheritance and grant only the invoking account access. Other systems use directory mode 0700 and credential mode 0600. The binary version must be exactly 18.6. The cluster uses checksums, SCRAM authentication and a loopback listener.

Before CREATE DATABASE, a fresh setup connection must match the actual owned child PID, canonical data directory, `pg_controldata` system identifier, PostgreSQL version 180006 and checksums. One fixed SQL call reads at most 4097 binary bytes from `postmaster.pid`. Its first four complete lines must match the PID, directory, recorded epoch and internal port acquired independently from the owned directory. The common parser rejects more than 4096 bytes, invalid UTF-8, NUL, partial required lines and malformed fields. LF and CRLF are supported. External reads use the same bound.

PID-file time and `pg_postmaster_start_time()` are separate observations. PostgreSQL assigns `MyStartTime` before `PgStartTime` in `PostmasterMain`, so their integer seconds can differ. The first SQL start text is pinned only after independent admission. Every later privileged connection must match that exact SQL text and the original PID-file identity. No tolerance or cross-clock equality is used. A deliberately wrong expected cluster identity rejects with the database catalog unchanged. The new database connection repeats validation and external child observation before privilege or marker changes.

The protected version 1 custody file is passed to the child test process. Its mandatory `postmaster` object records the four independent facts. Old incomplete receipts are rejected. Each fixture re-observes database OID, engine, cluster, server start and run marker before its writes. Local fixtures also check the live runner and postmaster and the exact data directory. A same-URL marker alone is insufficient authority.

## Dedicated CI service custody

Verify preserves its preceding default `pnpm check`. Its PostgreSQL step runs `pnpm test:postgres:runner && pnpm test:postgres:ci`. The latter invokes `node scripts/test-postgres.mjs --profile ci-service` on the Ubuntu host. It requires these workflow-provided values.

| Environment value | Workflow source |
| --- | --- |
| `ONE_CONTROL_PG_SERVICE_ID` | `job.services.postgres.id` |
| `ONE_CONTROL_PG_SERVICE_NETWORK` | `job.services.postgres.network` |
| `ONE_CONTROL_PG_SERVICE_PORT` | `job.services.postgres.ports[5432]` |
| `ONE_CONTROL_PG_PASSWORD` | Dedicated test service configuration |

The official service image is pinned to the supported minor tag `postgres:18.6-bookworm`. The tag can receive packaging rebuilds. The runner records the actual Docker image ID and independently requires PostgreSQL 18.6. No unverified image digest is asserted. The service publishes only `127.0.0.1:5432:5432`, initializes checksums and host SCRAM, and uses its separate test-only setup account. Container-local authentication trusts only the dedicated container boundary.

Before any DDL, a narrow Docker inspection must match the full service container ID, running state, positive host PID, start timestamp, exact image tag, actual image ID, job network and published loopback port. The runner independently executes `postgres --version`, `readlink`, `pg_controldata` and `head -c 4097 postmaster.pid` inside that exact container as its postgres OS account. The PostgreSQL 18 image data directory must be `/var/lib/postgresql/18/docker`. The host SQL connection must match that independent directory, system identifier and all four PID-file facts, plus actual version, setup identity and checksums. Internal port 5432 is distinct from the mapped host port. Internal PID 1 is legitimate. Repeated observation checks both the original host PID and original container postmaster PID.

The fixture re-observes the actual container, image, start and cluster identity before provisioning and cleanup. It never interprets the container postmaster PID as a host child PID. GitHub owns service teardown. The runner never stops a container or host service.

`TEST_DATABASE_URL`, inherited custody files and arbitrary connection target overrides are rejected. Missing, local, malformed and unsupported profiles fail closed. `GITHUB_ACTIONS=true` is required context but is insufficient authority. The trust boundary includes the workflow, runner account, Docker daemon, executables and test source. This is not a cryptographic defense against malicious job code or a host administrator.

## Authenticated test identities

Each fixture creates distinct no-login owner, migration login and runtime login principals. Migration actually authenticates as the migrator and assumes its explicit owner membership. Application Database handles authenticate directly as runtime. Runtime has no owner or migrator membership, administrative attributes, database CREATE or schema CREATE.

Before migration, separate fresh migrator and runtime connections each prove their authenticated session identity and require SQLSTATE 42501 for the fixed PID-file read. No file-read privilege is granted. Sanitized fixture evidence includes only the two successful denial booleans.

The fixture grants SELECT on the nine historical tables, INSERT on eight application tables, UPDATE on the five tables modified by existing routes and USAGE on the audit sequence. Migration metadata is read-only. Actual application tests exercise these provisional grants. This is not production privilege acceptance.

Actual tests require denied CREATE SCHEMA, CREATE in public and its own schema, SET ROLE to owner/migrator and schema-qualified cross-fixture access. Removing a required INSERT grant must reject the real write; restoring exactly that grant must permit it. Collision and schema/role ownership tampering must retain the exact mismatched object for independent observation.

## Bounded failure and exact cleanup

Runner and fixture clients have connection, SQL and closure deadlines. The independent test-only `setupConnection` helper in `postgres/fixture.postgres.ts` has no per-operation deadline for connection, SQL or closure. Its containing tests have 30-second deadlines, and the runner bounds the entire test child to 180 seconds. Runner subprocesses, readiness and postmaster stop also have deadlines. Required Vitest workers use threads so terminating its exact child does not orphan worker processes. SIGINT/SIGTERM interrupt active work and enter exact cleanup. Primary operation, cleanup and evidence-persistence failures retain that order in aggregate errors. A single failure retains its exact thrown value. Public diagnostics expose fixed runner messages and SQLSTATE only. Raw driver errors, SQL, parameters and connection strings are withheld.

Fixture close first closes runtime, then verifies cluster/database and exact namespace OID, owner and marker before DROP. Role cleanup checks exact OIDs and run comments. A collision never transfers ownership. Role creation receipts are written as resources are created.

The local runner verifies its child and directory identity, targets only that data directory with fast stop, observes child exit and removes only the exact directory after refusing links/substitution. A mismatched object remains within the owned cluster until whole-run teardown.

The CI runner independently re-observes the service, then verifies its successfully created database's exact OID, owner and run marker before DROP. It removes only remaining roles from exact creation receipts whose OIDs and run comments still match. It does not force-drop a database, terminate unrelated sessions or scan/drop by prefix. A mismatch or connection prevents cleanup, retains affected resources and fails the run. The receipt distinguishes database removal from subsequent role cleanup. GitHub later tears down its isolated service.

## Sanitized evidence and acceptance limits

Runner receipts go to `.local/orchestrate/full-build/evidence/database-fixture-ci-implementation`. They contain source SHA-256 values, revision, profile, actual engine/driver identity, generated names/OIDs, allowed role observations, test statuses/counts, UTC timestamps and cleanup. Fixture data is projected through a deliberate field allowlist. Protected custody, database files and raw test JSON remain inside the transient directory.

Verify uploads exactly `upload/runner-manifest.json` under that evidence directory, including on failure. It never uploads custody, directory contents, arbitrary JSON or raw test output. Missing evidence is a workflow failure.

The Linux `test-postgres-service-custody.mjs` step creates a separate container and network using fresh owner labels and returned creation IDs. The workflow service is observed read-only. The probe uses the already cached exact image ID, a protected fresh environment file and a loopback-only random port. Its legacy `--tmpfs /var/lib/postgresql:rw,mode=1777,size=256m` configuration appears in `HostConfig.Tmpfs`. Configured typed mounts, binds and volumes-from must project as Docker null values or empty arrays. Docker may omit the optional API `HostConfig.Mounts` key. The template uses `index` for that key and optional mount `Name`, while required fields remain strict. An omitted API key projects as null; an omitted output key or malformed value still fails. The top-level user `Mounts` list must be an empty array. Incorrect options, extra destinations and persistent user mounts fail the check. The allowlisted inspect projection never requests `Config.Env`.

Before each corrected storage inspection, the probe revalidates the exact container and owner, executes its previous exact template as a diagnostic, and revalidates ownership again. Only the exact bounded optional-Mounts missing-key diagnostic can classify an expected previous-template failure. Unknown diagnostics fail without retaining their text. A successful old projection must itself pass identity and storage validation. The corrected projection records actual API-key presence by comparing HostConfig keys, independently of null or empty values. An absent key requires the old fixed missing-key outcome and corrected null. A present null or empty key requires coherent successful old and corrected projections. The receipt retains only fixed outcomes, integer exit and the presence boolean. This formatting control is separate from the old typed-mount predicate and cannot replace filesystem, SQL, generation or cleanup gates.

Before and after restart, the probe verifies its exact returned container ID and owner label. It runs the fixed read-only `stat -f --format=%T --` command at `/var/lib/postgresql`. After positive SQL admission, it repeats the command at the admitted fixed PGDATA `/var/lib/postgresql/18/docker`. Both results must be exactly `tmpfs`. The sanitized storage observation retains bounded counts, fixed destination and option classifications, and the previous typed-mount predicate's result. That previous predicate is diagnostic only. It cannot authorize a different storage arrangement. Tmpfs can use host swap. These checks exclude persistent PostgreSQL user mounts. They do not establish that bytes never reach disk or exclude Docker's system mounts.

The probe proves initial admission and catalog invariance, then restarts only its own container. All ten independent service-observation negatives must reject. Stale Docker generation and pinned SQL start expectations must reject. Restart clears the tmpfs cluster, so this test also changes cluster identity. A successful read-only SQL diagnostic first matches all newly acquired independent facts and requires a different SQL start. The negative then changes only the expected SQL start to its original value. The catalog must remain unchanged across both comparisons. The manifest retains the successful diagnostic and its safe clock facts. This diagnostic grants no fixture, DDL or continued-use authority over the restarted container. The probe performs no application DDL.

Each operation has a fixed stage. Owned predicate failures retain fixed codes. Docker process failures retain an allowlisted operation identifier, integer exit code when available, and fixed termination classification. Arbitrary error messages, connection strings, arguments, output and nested causes are withheld. Unknown errors retain `UNCLASSIFIED_FAILURE` at the active stage. Cleanup retains separate failure summaries without overwriting the primary failure stage. Failure to persist evidence still fails the command.

Readiness retries an unsuccessful connection only after confirmed client closure. A close failure or close deadline is terminal. Its fixed `CLIENT_CLEANUP_FAILED` summary preserves the primary operation classification and a distinct `client-close` classification. Raw aggregate members stay outside the receipt.

Cleanup rechecks the exact creation ID and owner label, removes that container, verifies absence through a successful filtered Docker listing, removes the exact empty owned network and then the protected temporary directory. It never scans or removes by prefix. Its immutable GUID manifest and mutable upload pointer are under `database-startup-identity-implementation/service-custody`. Verify uploads only `upload/service-custody-manifest.json` as `postgres-generation-custody`. The actual successful command exit and source-bound immutable receipt are required acceptance evidence. A latest pointer alone cannot prove a fresh execution.

Local tests cover validator metadata and the actual owned Windows PostgreSQL 18.6 path. They do not prove Docker execution. Verify run `39435350780` failed the creator-owned probe at its old broad `create` stage. That receipt lacks a storage observation, so its exact failed predicate remains unknown. The source-proven mismatch between legacy tmpfs creation and typed-mount observation does not prove that historical runtime cause. The next acceptance is the exact corrected revision on GitHub Ubuntu. It must retain live legacy storage and both filesystem observations before and after restart, the old predicate's actual result, all generation negatives, zero required skips and verified resource cleanup. Linux/macOS local supervision, actual foreign-engine execution, process/directory substitution, stop/remove failures and abrupt uncatchable termination remain unexecuted fault cases. SIGKILL or machine loss cannot run in-process cleanup. Production TLS, independent recovery, U02 transaction faults and real endpoint acceptance remain separate gates.

The later `ba3d609` CI probe failed at `storage-inspect` with Docker exit 1. Its retained receipt lacks the raw diagnostic and storage response. Real Go-template controls demonstrate the optional-key defect but do not establish that historical process cause. Corrected-head Linux must execute the coherent same-container formatting control before acceptance.

The Windows loopback TLS fixture retains client/assertion, owned server-task and cleanup exceptions separately. Repeated disposal reuses the same completed join and faults, with one resource cleanup and exact owned CNG-key absence. Fixed monotonic milestones witness accept, TLS authentication, request and response headers, body delivery, client outcome, teardown and terminal join. The truncated control must flush its actual three-byte payload before closing and preserve the fixed known 500 error. Oversized and chunked controls must witness their intended body path. Functional framing uses a finite five-second test budget; the unchanged production budget is 25 seconds. A separate held-response control witnesses the unchanged 350 millisecond deadline before response delivery and demonstrates the old cleanup masking pattern with an actual deliberately disposed-stream write failure. The stalled-body control first witnesses client response headers, then explicitly arms caller cancellation. It does not count a handshake timeout as stalled-body coverage. The existing fast-stream tests retain total-deadline coverage. No arbitrary transport exception is suppressed. These owned test fixtures do not establish production TLS or endpoint acceptance.

## Primary references

- [GitHub PostgreSQL services](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers) documents host access through a published port.
- [GitHub job context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context) documents actual service IDs, networks and ports.
- [Official PostgreSQL image](https://hub.docker.com/_/postgres) lists the 18.6-bookworm tag and PostgreSQL 18 data directory.
- [Docker inspect](https://docs.docker.com/reference/cli/docker/inspect/) documents selective formatted inspection.
- [Docker publishing](https://docs.docker.com/reference/cli/docker/container/run/#publish) documents loopback-only port mapping.
- [GitHub runner Docker implementation](https://github.com/actions/runner/blob/main/src/Runner.Worker/Container/DockerCommandManager.cs) passes service port mappings to Docker publishing.
- [PostgreSQL pg_controldata](https://www.postgresql.org/docs/18/app-pgcontroldata.html) documents independent control data inspection.
- [PostgreSQL postmaster source](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/postmaster/postmaster.c) defines the separate `MyStartTime` and `PgStartTime` assignments.
- [PostgreSQL file functions](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADMIN-GENFILE) documents the privileged bounded binary read.
