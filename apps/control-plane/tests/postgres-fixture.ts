import { randomBytes } from "node:crypto";
import { readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import pg from "pg";
import { z } from "zod";
import { type Database, migrate, openDatabase, type TransactionQuery } from "../src/database.js";

import { frozenV1Units } from "./fixtures/frozen-v1.js";

const identifier = z.string().regex(/^oc_[a-z]+_[a-f0-9]{32}$/);
const postmasterSchema = z
  .object({
    pid: z.number().int().min(1).max(2_147_483_647),
    dataDirectory: z.string().min(1),
    startEpoch: z.string().regex(/^[1-9][0-9]*$/),
    port: z.number().int().min(1).max(65535),
  })
  .strict();
const custodySchema = z
  .object({
    version: z.literal(1),
    profile: z.enum(["owned-local", "ci-service"]),
    run: z.string().regex(/^[a-f0-9]{32}$/),
    directory: z.string(),
    dataDirectory: z.string(),
    runnerPid: z.number().int().positive(),
    postmasterPid: z.number().int().positive(),
    postmaster: postmasterSchema,
    port: z.number().int().min(1).max(65535),
    setup: identifier,
    password: z.string().min(16).max(128),
    database: identifier,
    databaseOid: z.number().int().positive(),
    serverStart: z.string(),
    systemIdentifier: z.string(),
    service: z
      .object({
        id: z.string().regex(/^[a-f0-9]{64}$/),
        network: z.string().regex(/^github_network_[a-zA-Z0-9]+$/),
        port: z.number().int().min(1).max(65535),
        observed: z
          .object({
            imageId: z.string().regex(/^sha256:[a-f0-9]{64}$/),
            started: z.string(),
            pid: z.number().int().positive(),
          })
          .strict(),
        system: z.string().regex(/^\d+$/),
        startEpoch: z.string().regex(/^\d+$/),
        postmasterPid: z.number().int().positive(),
        postmaster: postmasterSchema,
      })
      .strict()
      .optional(),
  })
  .strict();
type Custody = z.infer<typeof custodySchema>;
type Receipt = { oid: number; owner: number; marker: string };

async function closeWithin(promise: Promise<void>) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("PostgreSQL connection close deadline expired")), 5000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function connection(custody: Custody, user: string, password: string, options?: string) {
  const url = new URL(`postgresql://127.0.0.1:${custody.port}/${custody.database}`);
  url.username = user;
  url.password = password;
  if (options) url.searchParams.set("options", options);
  url.searchParams.set("connectionTimeoutMillis", "5000");
  url.searchParams.set("query_timeout", "10000");
  url.searchParams.set("statement_timeout", "10000");
  return url.toString();
}

export async function loadPostgresCustody(env: NodeJS.ProcessEnv = process.env): Promise<Custody> {
  if (
    !["owned-local", "ci-service"].includes(env.ONE_CONTROL_POSTGRES_PROFILE ?? "") ||
    env.TEST_DATABASE_URL
  ) {
    throw new Error("Required PostgreSQL custody profile rejected");
  }
  const filename = env.ONE_CONTROL_POSTGRES_CUSTODY;
  if (!filename) throw new Error("Required PostgreSQL custody receipt missing");
  const custody = custodySchema.parse(JSON.parse(await readFile(filename, "utf8")));
  if (custody.profile !== env.ONE_CONTROL_POSTGRES_PROFILE)
    throw new Error("Required PostgreSQL profile mismatch");
  const root = await realpath(path.resolve("../../.local/database-tests"));
  const directory = await realpath(custody.directory);
  if (
    path.dirname(directory) !== root ||
    path.basename(directory) !== custody.run ||
    (await realpath(filename)) !== path.join(directory, "custody.json")
  ) {
    throw new Error("Required PostgreSQL directory custody mismatch");
  }
  process.kill(custody.runnerPid, 0);
  if (
    custody.postmaster.pid !== custody.postmasterPid ||
    custody.postmaster.dataDirectory !== custody.dataDirectory
  )
    throw new Error("Required PostgreSQL process custody mismatch");
  if (custody.profile === "ci-service") {
    if (
      !custody.service ||
      custody.service.id !== env.ONE_CONTROL_PG_SERVICE_ID ||
      custody.service.network !== env.ONE_CONTROL_PG_SERVICE_NETWORK ||
      String(custody.port) !== env.ONE_CONTROL_PG_SERVICE_PORT ||
      custody.service.port !== custody.port ||
      custody.service.system !== custody.systemIdentifier ||
      custody.service.startEpoch !== custody.postmaster.startEpoch ||
      custody.service.postmasterPid !== custody.postmasterPid ||
      JSON.stringify(custody.service.postmaster) !== JSON.stringify(custody.postmaster) ||
      custody.postmaster.port !== 5432
    )
      throw new Error("Required PostgreSQL service custody mismatch");
    const { observeService } = await import(
      new URL("../../../scripts/test-postgres.mjs", import.meta.url).href
    );
    await observeService(custody.service);
    return custody;
  }
  if (custody.service || (await realpath(custody.dataDirectory)) !== path.join(directory, "data"))
    throw new Error("Required PostgreSQL directory custody mismatch");
  process.kill(custody.postmasterPid, 0);
  const { readPostmasterFile, validatePostmaster } = await import(
    new URL("../../../scripts/test-postgres.mjs", import.meta.url).href
  );
  const actual = await readPostmasterFile(custody.dataDirectory);
  actual.dataDirectory = await realpath(actual.dataDirectory);
  validatePostmaster(actual, custody.postmaster);
  if (custody.postmaster.port !== custody.port)
    throw new Error("Required PostgreSQL process custody mismatch");
  return custody;
}

async function observeTarget(setup: pg.Client, custody: Custody) {
  const { verifyOwnedTarget } = await import(
    new URL("../../../scripts/test-postgres.mjs", import.meta.url).href
  );
  await verifyOwnedTarget(setup, {
    setup: custody.setup,
    profile: custody.profile,
    dataDirectory: custody.dataDirectory,
    system: custody.systemIdentifier,
    postmaster: custody.postmaster,
    serverStart: custody.serverStart,
  });
  const {
    rows: [row],
  } = await setup.query(`SELECT current_user AS actor,
    current_database() AS database, d.oid::int AS oid,
    current_setting('server_version_num')::int AS version,
    current_setting('data_directory') AS directory,
    pg_postmaster_start_time()::text AS started,
    shobj_description(d.oid, 'pg_database') AS marker,
    (pg_control_system()).system_identifier::text AS system
    FROM pg_database d WHERE d.datname=current_database()`);
  const matches = {
    setup: row?.actor === custody.setup,
    database: row?.database === custody.database,
    oid: row?.oid === custody.databaseOid,
    version: row?.version === 180006,
    directory:
      row &&
      (custody.profile === "ci-service"
        ? row.directory === custody.dataDirectory
        : (await realpath(row.directory)) === (await realpath(custody.dataDirectory))),
    start: row?.started === custody.serverStart,
    system: row?.system === custody.systemIdentifier,
    marker: row?.marker === `one-control-owned-run:${custody.run}`,
  };
  const mismatch = Object.entries(matches).find(([, matches]) => !matches)?.[0];
  if (mismatch) throw new Error(`Required PostgreSQL target identity mismatch (${mismatch})`);
}

export interface PostgresFixture extends Database {
  openRuntimeThrough(endpoint: { host: "127.0.0.1"; port: number; upstreamPort: number }): Promise<Database>;
}
export interface PostgresBaselineFixture extends PostgresFixture {
  readonly namespace: string;
  withMigrator<T>(work: (tx: TransactionQuery) => Promise<T>): Promise<T>;
  openMigrator(): Promise<Database>;
}
export async function openPostgresFixture(
  suffix = randomBytes(16).toString("hex"),
): Promise<PostgresFixture> {
  return createFixture(suffix);
}
export async function openPostgresBaselineFixture(
  baseline: "empty" | "frozen-v1",
): Promise<PostgresBaselineFixture> {
  return createFixture(randomBytes(16).toString("hex"), baseline);
}
async function createFixture(
  suffix: string,
  baseline?: "empty" | "frozen-v1",
): Promise<PostgresBaselineFixture> {
  z.string()
    .regex(/^[a-f0-9]{32}$/)
    .parse(suffix);
  const custody = await loadPostgresCustody();
  const setup = new pg.Client({
    connectionString: connection(custody, custody.setup, custody.password),
    connectionTimeoutMillis: 5000,
    query_timeout: 10000,
    statement_timeout: 10000,
    options: "-c log_min_error_statement=panic -c log_statement=none",
  });
  await setup.connect();
  try {
    await observeTarget(setup, custody);
  } catch (error) {
    try {
      await closeWithin(setup.end());
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], "PostgreSQL target validation and close failed");
    }
    throw error;
  }
  const namespace = `oc_schema_${suffix}`;
  const owner = `oc_owner_${suffix}`;
  const migrator = `oc_migrator_${suffix}`;
  const runtime = `oc_runtime_${suffix}`;
  for (const name of [namespace, owner, migrator, runtime]) identifier.parse(name);
  const migratorPassword = randomBytes(32).toString("hex");
  const runtimePassword = randomBytes(32).toString("hex");
  const marker = `one-control-fixture:${custody.run}:${suffix}`;
  const createdRoles: Array<{ name: string; oid: number }> = [];
  let receipt: Receipt | undefined;
  let db: Database | undefined;
  const runtimeConnections: Database[] = [];
  let closing: Promise<void> | undefined;
  const evidence: Record<string, unknown> = {
    namespace,
    owner,
    migrator,
    runtime,
    createdRoles,
    cleanup: "not-started",
  };
  const record = () =>
    writeFile(path.join(custody.directory, `fixture-${suffix}.json`), JSON.stringify(evidence), {
      mode: 0o600,
    });

  async function schemaReceipt(): Promise<Receipt | undefined> {
    const {
      rows: [row],
    } = await setup.query(
      `SELECT oid::int, nspowner::int AS owner,
      obj_description(oid,'pg_namespace') AS marker FROM pg_namespace WHERE nspname=$1`,
      [namespace],
    );
    return row;
  }

  const close = () => {
    closing ??= (async () => {
      const errors: unknown[] = [];
      for (const runtimeConnection of runtimeConnections) {
        try {
          await closeWithin(runtimeConnection.close());
        } catch (error) {
          errors.push(error);
        }
      }
      try {
        if (db) await closeWithin(db.close());
      } catch (error) {
        errors.push(error);
      }
      try {
        await loadPostgresCustody();
        await observeTarget(setup, custody);
        if (receipt) {
          const current = await schemaReceipt();
          if (
            !current ||
            current.oid !== receipt.oid ||
            current.owner !== receipt.owner ||
            current.marker !== receipt.marker
          ) {
            throw new Error("PostgreSQL fixture cleanup ownership mismatch; resources retained");
          }
          await setup.query(`DROP SCHEMA ${namespace} CASCADE`);
        }
        for (const role of createdRoles.toReversed()) {
          const {
            rows: [current],
          } = await setup.query(
            "SELECT oid::int,shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=$1",
            [role.name],
          );
          if (!current || current.oid !== role.oid || current.marker !== marker)
            throw new Error("PostgreSQL role cleanup ownership mismatch");
          await setup.query(`DROP ROLE ${role.name}`);
        }
      } catch (error) {
        errors.push(error);
      }
      evidence.cleanup = errors.length ? "failed-resources-retained" : "exact-resources-removed";
      try {
        await record();
      } catch (error) {
        errors.push(error);
      }
      try {
        await closeWithin(setup.end());
      } catch (error) {
        errors.push(error);
      }
      if (errors.length) throw new AggregateError(errors, "PostgreSQL fixture cleanup failed");
    })();
    return closing;
  };

  try {
    for (const [name, password] of [
      [owner, undefined],
      [migrator, migratorPassword],
      [runtime, runtimePassword],
    ] as const) {
      await setup.query(`CREATE ROLE ${name} ${password ? `LOGIN PASSWORD '${password}'` : "NOLOGIN"}
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
      const {
        rows: [role],
      } = await setup.query("SELECT oid::int FROM pg_roles WHERE rolname=$1", [name]);
      createdRoles.push({ name, oid: role.oid });
      await setup.query(`COMMENT ON ROLE ${name} IS '${marker}'`);
      await record();
    }
    const fileReadDenials: Record<string, boolean> = {};
    for (const [name, password, label] of [
      [migrator, migratorPassword, "migrator"],
      [runtime, runtimePassword, "runtime"],
    ] as const) {
      const login = new pg.Client({ connectionString: connection(custody, name, password) });
      let primary: unknown;
      let failed = false;
      try {
        await login.connect();
        const {
          rows: [identity],
        } = await login.query("SELECT session_user AS actor,current_user AS current");
        if (identity.actor !== name || identity.current !== name)
          throw new Error("PostgreSQL restricted login identity mismatch");
        try {
          await login.query("SELECT pg_read_binary_file('postmaster.pid',0,4097,false)");
          throw new Error("PostgreSQL restricted login read privileged file");
        } catch (error) {
          if (!(error instanceof Error) || !("code" in error) || error.code !== "42501") throw error;
          fileReadDenials[label] = true;
        }
      } catch (error) {
        failed = true;
        primary = error;
      }
      try {
        await closeWithin(login.end());
      } catch (cleanup) {
        if (failed) throw new AggregateError([primary, cleanup], "PostgreSQL login proof and close failed");
        throw cleanup;
      }
      if (failed) throw primary;
    }
    evidence.fileReadDenials = fileReadDenials;
    await record();
    await setup.query(`GRANT ${owner} TO ${migrator}`);
    await setup.query(`CREATE SCHEMA ${namespace} AUTHORIZATION ${owner}`);
    const provisional = await schemaReceipt();
    if (!provisional || provisional.owner !== createdRoles[0]?.oid)
      throw new Error("PostgreSQL schema creation receipt missing");
    receipt = { ...provisional, marker };
    await setup.query(`COMMENT ON SCHEMA ${namespace} IS '${marker}'`);
    const migration = await openDatabase(
      connection(custody, migrator, migratorPassword, `-c search_path=${namespace} -c role=${owner}`),
    );
    let migrationFailure: unknown;
    let migrationFailed = false;
    try {
      const [identity] = await migration.query("SELECT session_user AS actor,current_user AS current");
      if (identity?.actor !== migrator || identity.current !== owner)
        throw new Error("PostgreSQL migration login identity mismatch");
      evidence.migration = identity;
      if (baseline === "frozen-v1") {
        await migration.transaction(async (tx) => {
          for (const unit of frozenV1Units) await tx.query(unit);
        });
      } else if (baseline !== "empty") await migrate(migration);
    } catch (error) {
      migrationFailure = error;
      migrationFailed = true;
    }
    try {
      if (baseline) runtimeConnections.push(migration);
      else await closeWithin(migration.close());
    } catch (cleanup) {
      if (migrationFailed)
        throw new AggregateError([migrationFailure, cleanup], "PostgreSQL migration and close failed");
      throw cleanup;
    }
    if (migrationFailed) throw migrationFailure;
    await setup.query(`GRANT USAGE ON SCHEMA ${namespace} TO ${runtime}`);
    if (baseline !== "empty") {
      await setup.query(`GRANT SELECT ON ALL TABLES IN SCHEMA ${namespace} TO ${runtime}`);
      for (const table of [
        "devices",
        "enrollment_tokens",
        "credentials",
        "releases",
        "batches",
        "jobs",
        "audit_events",
        "idempotency_keys",
      ]) {
        await setup.query(`GRANT INSERT ON ${namespace}.${table} TO ${runtime}`);
      }
      for (const table of ["devices", "enrollment_tokens", "credentials", "batches", "jobs"]) {
        await setup.query(`GRANT UPDATE ON ${namespace}.${table} TO ${runtime}`);
      }
      await setup.query(`GRANT USAGE ON SEQUENCE ${namespace}.audit_events_sequence_seq TO ${runtime}`);
    }
    evidence.roles = (
      await setup.query(
        "SELECT oid::int,rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname",
        [[custody.setup, owner, migrator, runtime]],
      )
    ).rows;
    db = await openDatabase(connection(custody, runtime, runtimePassword, `-c search_path=${namespace}`));
    const [authority] = await db.query(
      `SELECT session_user AS actor, current_user AS current,
      rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
      pg_has_role(current_user,$1,'MEMBER') AS owner_member,
      pg_has_role(current_user,$2,'MEMBER') AS migrator_member,
      has_database_privilege(current_user,current_database(),'CREATE') AS database_create,
      has_schema_privilege(current_user,'public','CREATE') AS public_create
      FROM pg_roles WHERE rolname=current_user`,
      [owner, migrator],
    );
    if (
      !authority ||
      authority.actor !== runtime ||
      authority.current !== runtime ||
      Object.entries(authority).some(
        ([key, value]) => key !== "actor" && key !== "current" && value !== false,
      )
    ) {
      throw new Error("PostgreSQL runtime identity is not restricted");
    }
    evidence.schema = receipt;
    evidence.authority = authority;
    await record();
    return {
      namespace,
      async openMigrator() {
        if (!baseline || closing) throw new Error("Baseline migration capability unavailable");
        await loadPostgresCustody();
        await observeTarget(setup, custody);
        const current = await schemaReceipt();
        if (
          !receipt ||
          current?.oid !== receipt.oid ||
          current.owner !== receipt.owner ||
          current.marker !== receipt.marker
        )
          throw new Error("Baseline namespace custody mismatch");
        const handle = await openDatabase(
          connection(custody, migrator, migratorPassword, `-c search_path=${namespace} -c role=${owner}`),
        );
        runtimeConnections.push(handle);
        return handle;
      },
      async withMigrator(work) {
        if (!baseline || closing) throw new Error("Baseline migration capability unavailable");
        await loadPostgresCustody();
        await observeTarget(setup, custody);
        const current = await schemaReceipt();
        if (
          !receipt ||
          !current ||
          current.oid !== receipt.oid ||
          current.owner !== receipt.owner ||
          current.marker !== receipt.marker
        )
          throw new Error("Baseline namespace custody mismatch");
        const result = await migration.transaction(async (tx) => {
          const [identity] = await tx.query(
            "SELECT session_user AS actor,current_user AS current,current_schema() AS namespace",
          );
          if (identity?.actor !== migrator || identity.current !== owner || identity.namespace !== namespace)
            throw new Error("Baseline migration identity mismatch");
          return work(tx);
        });
        await setup.query(`GRANT SELECT ON ALL TABLES IN SCHEMA ${namespace} TO ${runtime}`);
        return result;
      },
      query: db.query,
      transaction: db.transaction,
      close,
      async openRuntimeThrough(endpoint) {
        if (
          closing ||
          endpoint.host !== "127.0.0.1" ||
          endpoint.upstreamPort !== custody.port ||
          !Number.isInteger(endpoint.port) ||
          endpoint.port < 1 ||
          endpoint.port > 65535
        )
          throw new Error("PostgreSQL runtime loopback endpoint rejected");
        await loadPostgresCustody();
        await observeTarget(setup, custody);
        const runtimeConnection = await openDatabase(
          connection(
            { ...custody, port: endpoint.port },
            runtime,
            runtimePassword,
            `-c search_path=${namespace}`,
          ),
        );
        runtimeConnections.push(runtimeConnection);
        return runtimeConnection;
      },
    };
  } catch (error) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], "PostgreSQL fixture setup failed and cleanup failed");
    }
    throw error;
  }
}
