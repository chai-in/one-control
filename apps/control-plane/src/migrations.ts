import { createHash } from "node:crypto";
import { assetSchema } from "../../../modules/asset-management/server/schema.js";
import { desktopPolicySchema } from "../../../modules/desktop-policies/server/schema.js";
import { falconDataSchema } from "../../../modules/falcon-sync/server/schema.js";
import {
  nativeClaimReconciliationSchema,
  nativeJobSchema,
} from "../../../modules/native-dispatch/server/jobs.js";
import { nativeAuthoritySchema } from "../../../modules/native-distribution/server/schema.js";
import { nativeObservationSchema } from "../../../modules/native-observations/server/observations.js";
import { recoveryEscrowSchema } from "../../../modules/recovery-escrow/server/escrow.js";
import type { Database, TransactionQuery } from "./database.js";
import { frozenV1Statements } from "./frozen-v1.js";
import { inspectFrozenV1 } from "./migration-baseline.js";
import { schemaVersions, v1Tables } from "./schema-inventory.js";

// Complete statements: never split procedural SQL on semicolons. Frozen v1 stays byte-identical.
const authorityFoundation = [
  `CREATE TABLE migration_metadata (
    version int PRIMARY KEY REFERENCES schema_migrations(version) DEFERRABLE INITIALLY DEFERRED,
    migration_id text NOT NULL UNIQUE, checksum text NOT NULL CHECK (checksum ~ '^[a-f0-9]{64}$')
  )`,
  `CREATE TABLE authority_runtime (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    state text NOT NULL CHECK(state IN ('unconfigured','active','quarantined')),
    authority_epoch numeric(20,0), root_version numeric(20,0), custody_reference text,
    CHECK(authority_epoch BETWEEN 1 AND 18446744073709551615),
    CHECK(root_version BETWEEN 1 AND 18446744073709551615),
    CHECK(state <> 'active' OR (authority_epoch IS NOT NULL AND root_version IS NOT NULL AND custody_reference IS NOT NULL))
  )`,
  `INSERT INTO authority_runtime(singleton,state) VALUES(true,'unconfigured')`,
  `CREATE TABLE management_scopes (
    id uuid PRIMARY KEY, kind text NOT NULL CHECK(kind IN ('personal','company')),
    name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
    state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked','quarantined')),
    version numeric(20,0) NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 18446744073709551615),
    permission_ceiling jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE scope_grants (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), issuer text NOT NULL, subject text NOT NULL,
    permission text NOT NULL CHECK(permission IN ('owner','view','enroll','configure','approve','command')),
    revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(scope_id,issuer,subject,permission),
    CHECK(length(issuer) BETWEEN 1 AND 2048), CHECK(length(subject) BETWEEN 1 AND 255)
  )`,
  `CREATE TABLE native_invitations (
    hash text PRIMARY KEY CHECK(hash ~ '^[a-f0-9]{64}$'),
    scope_id uuid NOT NULL REFERENCES management_scopes(id),
    device_id uuid NOT NULL, existing_device boolean NOT NULL, hostname text NOT NULL CHECK(length(hostname) BETWEEN 1 AND 255),
    platform text NOT NULL CHECK(platform IN ('win-x64','win-arm64','osx-arm64','osx-x64','linux-x64','linux-arm64')),
    machine_id text NOT NULL CHECK(length(machine_id) BETWEEN 1 AND 128),
    issuer text NOT NULL, subject text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(hash,scope_id,device_id,platform,machine_id)
  )`,
  `CREATE TABLE native_enrollments (
    id uuid PRIMARY KEY, scope_id uuid NOT NULL REFERENCES management_scopes(id),
    device_id uuid NOT NULL REFERENCES devices(id), invitation_hash text NOT NULL UNIQUE REFERENCES native_invitations(hash),
    platform text NOT NULL, machine_id text NOT NULL,
    revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(id,device_id), CHECK(length(machine_id) BETWEEN 1 AND 128),
    CHECK(platform IN ('win-x64','win-arm64','osx-arm64','osx-x64','linux-x64','linux-arm64')),
    FOREIGN KEY(invitation_hash,scope_id,device_id,platform,machine_id) REFERENCES native_invitations(hash,scope_id,device_id,platform,machine_id)
  )`,
  `CREATE UNIQUE INDEX native_enrollments_active_device ON native_enrollments(device_id) WHERE revoked_at IS NULL`,
  `CREATE INDEX native_enrollments_scope ON native_enrollments(scope_id,device_id)`,
  `ALTER TABLE credentials ADD COLUMN enrollment_id uuid`,
  `ALTER TABLE credentials ADD CONSTRAINT credentials_enrollment_device FOREIGN KEY(enrollment_id,device_id) REFERENCES native_enrollments(id,device_id)`,
  `CREATE INDEX credentials_enrollment ON credentials(enrollment_id) WHERE enrollment_id IS NOT NULL`,
  `CREATE TABLE module_states (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), module_id text NOT NULL CHECK(module_id ~ '^[a-z][a-z0-9.-]{0,199}$'),
    state text NOT NULL DEFAULT 'disabled' CHECK(state IN ('enabled','quiescing','disabled')),
    version numeric(20,0) NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 18446744073709551615),
    settings jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(scope_id,module_id)
  )`,
  `UPDATE jobs SET state=CASE WHEN state='leased' THEN 'indeterminate' ELSE 'cancelled' END,
    lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp(),
    result=jsonb_build_object('status',CASE WHEN state='leased' THEN 'indeterminate' ELSE 'cancelled' END,
      'summary','Authority upgrade requires explicit new admission; prior execution is not replayed')
    WHERE state IN ('awaiting_approval','queued','leased')`,
] as const;
export const orderedMigrations = [
  { version: 2, id: "authority.foundation-v2", statements: authorityFoundation },
  { version: 3, id: "desktop.policies-v3", statements: desktopPolicySchema },
  { version: 4, id: "company.assets-v4", statements: assetSchema },
  { version: 5, id: "falcon.data-v5", statements: falconDataSchema },
  { version: 6, id: "native.publication-v6", statements: nativeAuthoritySchema },
  { version: 7, id: "native.observations-v7", statements: nativeObservationSchema },
  { version: 8, id: "native.dispatch-v8", statements: nativeJobSchema },
  { version: 9, id: "recovery.escrow-v9", statements: recoveryEscrowSchema },
  { version: 10, id: "native.claim-reconciliation-v10", statements: nativeClaimReconciliationSchema },
].map((migration) =>
  Object.freeze({
    ...migration,
    checksum: createHash("sha256").update(JSON.stringify(migration)).digest("hex"),
  }),
);

export async function currentSchemaReady(tx: TransactionQuery): Promise<boolean> {
  const versions = await tx.query<{ version: number }>(
    "SELECT version FROM schema_migrations ORDER BY version",
  );
  if (JSON.stringify(versions.map((row) => row.version)) !== JSON.stringify(schemaVersions)) return false;
  const metadata = await tx.query<{ version: number; migration_id: string; checksum: string }>(
    "SELECT version,migration_id,checksum FROM migration_metadata ORDER BY version",
  );
  return (
    JSON.stringify(metadata) ===
    JSON.stringify(
      orderedMigrations.map((entry) => ({
        version: entry.version,
        migration_id: entry.id,
        checksum: entry.checksum,
      })),
    )
  );
}

export async function migrateOrdered(db: Database): Promise<void> {
  await db.transaction(async (tx) => {
    // A fresh statement snapshot after waiting is necessary for concurrent migrators.
    const [isolation] = await tx.query(
      "SELECT pg_catalog.current_setting('transaction_isolation') AS isolation",
    );
    if (isolation?.isolation !== "read committed")
      throw new Error("Migrations require READ COMMITTED isolation");
    await tx.query("SELECT pg_catalog.pg_advisory_xact_lock(748391234)");
    const [boundary] = await tx.query<{ namespace: string }>(
      "SELECT pg_catalog.current_schema() AS namespace",
    );
    if (!boundary?.namespace || Buffer.byteLength(boundary.namespace) > 63)
      throw new Error("Invalid migration namespace");
    const namespace = `"${boundary.namespace.replaceAll('"', '""')}"`;
    await tx.query(`SET LOCAL search_path TO ${namespace},pg_catalog`);
    const [marker] = await tx.query("SELECT pg_catalog.to_regclass($1)::pg_catalog.text AS name", [
      `${namespace}.schema_migrations`,
    ]);
    let versions: number[] = [];
    if (marker?.name) {
      versions = (
        await tx.query<{ version: number }>(
          `SELECT version FROM ${namespace}.schema_migrations ORDER BY version`,
        )
      ).map((row) => row.version);
      if (!versions.length || versions.some((version, index) => version !== schemaVersions[index]))
        throw new Error("Unsupported database migration history");
      if (versions.length > 1) {
        const metadata = await tx.query<{ version: number; migration_id: string; checksum: string }>(
          "SELECT version,migration_id,checksum FROM migration_metadata ORDER BY version",
        );
        const expected = orderedMigrations
          .filter((entry) => versions.includes(entry.version))
          .map((entry) => ({
            version: entry.version,
            migration_id: entry.id,
            checksum: entry.checksum,
          }));
        if (JSON.stringify(metadata) !== JSON.stringify(expected))
          throw new Error("Inconsistent database migration metadata");
      }
      if (versions.length === schemaVersions.length) {
        if (!(await currentSchemaReady(tx))) throw new Error("Inconsistent database migration metadata");
        return;
      }
      for (const table of [...v1Tables].sort())
        await tx.query(`LOCK TABLE ${namespace}.${table} IN ACCESS EXCLUSIVE MODE`);
    }
    // The pinned PostgreSQL and PGlite catalogs have independently frozen, identical descriptors.
    if (versions.length <= 1) {
      const admission = await inspectFrozenV1(tx, { engine: "postgres-18.6", namespace: boundary.namespace });
      if (admission.kind === "incompatible" || (versions.length > 0 && admission.kind !== "compatible"))
        throw new Error("Incompatible frozen v1 database");
      if (admission.kind === "empty") {
        for (const statement of frozenV1Statements) await tx.query(statement);
        versions = [1];
      }
    }
    for (const migration of orderedMigrations) {
      if (migration.version <= versions.length) continue;
      for (const statement of migration.statements) await tx.query(statement);
      await tx.query("INSERT INTO migration_metadata(version,migration_id,checksum) VALUES($1,$2,$3)", [
        migration.version,
        migration.id,
        migration.checksum,
      ]);
      await tx.query("INSERT INTO schema_migrations(version) VALUES($1)", [migration.version]);
      versions.push(migration.version);
    }
  });
}
