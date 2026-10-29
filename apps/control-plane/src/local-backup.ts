import { createHash } from "node:crypto";
import { link, lstat, mkdir, open, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { PGlite } from "@electric-sql/pglite";
import { z } from "zod";
import type { Database, TransactionQuery } from "./database.js";
import { migrateOrdered } from "./migrations.js";
import { quarantineAuthority, quarantineLegacy, verifyQuarantine } from "./restore-quarantine.js";
import {
  tablesForVersions,
  v1Tables,
  v2Tables,
  v3Tables,
  v4Tables,
  v5Tables,
  v6Tables,
  v7Tables,
  v8Tables,
  v9Tables,
  v10Tables,
} from "./schema-inventory.js";

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 512 * 1024 * 1024;
const MAX_ROWS_PER_TABLE = 100_000;
const uuid = z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
export const backupIdentity = z.strictObject({ workspaceId: uuid, runId: uuid, requestId: uuid });
export type BackupIdentity = z.infer<typeof backupIdentity>;
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const tableProof = z.strictObject({ rows: z.number().int().min(0).max(MAX_ROWS_PER_TABLE), sha256: digest });
const inventoryV1 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([z.literal(1)]),
  tables: z.record(z.enum(v1Tables), tableProof),
});
const inventoryV2 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([z.literal(1), z.literal(2)]),
  tables: z.record(z.enum(v2Tables), tableProof),
});
const inventoryV3 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([z.literal(1), z.literal(2), z.literal(3)]),
  tables: z.record(z.enum(v3Tables), tableProof),
});
const inventoryV4 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  tables: z.record(z.enum(v4Tables), tableProof),
});
const inventoryV5 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5)]),
  tables: z.record(z.enum(v5Tables), tableProof),
});
const inventoryV6 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
  ]),
  tables: z.record(z.enum(v6Tables), tableProof),
});
const inventoryV7 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
    z.literal(7),
  ]),
  tables: z.record(z.enum(v7Tables), tableProof),
});
const inventoryV8 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
    z.literal(7),
    z.literal(8),
  ]),
  tables: z.record(z.enum(v8Tables), tableProof),
});
const inventoryV9 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
    z.literal(7),
    z.literal(8),
    z.literal(9),
  ]),
  tables: z.record(z.enum(v9Tables), tableProof),
});
const inventoryV10 = z.strictObject({
  serverVersion: z.string().regex(/^\d{6}$/),
  schemaVersions: z.tuple([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
    z.literal(7),
    z.literal(8),
    z.literal(9),
    z.literal(10),
  ]),
  tables: z.record(z.enum(v10Tables), tableProof),
});
const inventorySchema = z.union([
  inventoryV1,
  inventoryV2,
  inventoryV3,
  inventoryV4,
  inventoryV5,
  inventoryV6,
  inventoryV7,
  inventoryV8,
  inventoryV9,
  inventoryV10,
]);
const manifestFields = {
  identity: backupIdentity,
  createdAt: z.iso.datetime(),
  archive: z.strictObject({
    file: z.literal("database.tar.gz"),
    bytes: z.number().int().min(1).max(MAX_ARCHIVE_BYTES),
    sha256: digest,
  }),
};
const manifestSchema = z.discriminatedUnion("schemaVersion", [
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(10),
    format: z.literal("one-control-pglite-backup-v10"),
    database: inventoryV10,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(9),
    format: z.literal("one-control-pglite-backup-v9"),
    database: inventoryV9,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(8),
    format: z.literal("one-control-pglite-backup-v8"),
    database: inventoryV8,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(7),
    format: z.literal("one-control-pglite-backup-v7"),
    database: inventoryV7,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(6),
    format: z.literal("one-control-pglite-backup-v6"),
    database: inventoryV6,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(5),
    format: z.literal("one-control-pglite-backup-v5"),
    database: inventoryV5,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(4),
    format: z.literal("one-control-pglite-backup-v4"),
    database: inventoryV4,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(3),
    format: z.literal("one-control-pglite-backup-v3"),
    database: inventoryV3,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(1),
    format: z.literal("one-control-pglite-backup-v1"),
    database: inventoryV1,
  }),
  z.strictObject({
    ...manifestFields,
    schemaVersion: z.literal(2),
    format: z.literal("one-control-pglite-backup-v2"),
    database: inventoryV2,
  }),
]);
export type BackupManifest = z.infer<typeof manifestSchema>;
const sha256 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");

async function realPath(path: string, directory: boolean): Promise<void> {
  if (!isAbsolute(path) || path.startsWith("\\\\"))
    throw new Error("Backup storage must be local and absolute");
  let current = resolve(path);
  const leaf = await lstat(current);
  if (directory ? !leaf.isDirectory() : !leaf.isFile()) throw new Error("Unexpected backup path type");
  for (;;) {
    if ((await lstat(current)).isSymbolicLink()) throw new Error("Backup paths cannot traverse links");
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
async function privateNewFile(path: string, bytes: Uint8Array | string): Promise<void> {
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}
async function publishRecord(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.new`;
  await privateNewFile(temporary, JSON.stringify(value));
  // Hard-link publication is atomic and refuses an existing destination on Windows and POSIX.
  await link(temporary, path);
  await unlink(temporary).catch(() => {
    // Publication has succeeded. Preserve a leftover link for inspection.
    process.stderr.write("Published backup record retained its temporary link; inspect protected storage\n");
  });
}
async function boundedFile(path: string, maximum: number): Promise<Buffer<ArrayBuffer>> {
  await realPath(path, false);
  const file = await open(path, "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum)
      throw new Error("Backup file exceeds its bound");
    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buffer.length) {
      const read = await file.read(buffer, offset, buffer.length - offset, offset);
      if (!read.bytesRead) throw new Error("Backup file is truncated");
      offset += read.bytesRead;
    }
    const extra = await file.read(Buffer.alloc(1), 0, 1, offset);
    if (extra.bytesRead) throw new Error("Backup file changed during verification");
    return buffer;
  } finally {
    await file.close();
  }
}

// Reject traversal, links, extensions and oversized expansion before giving an archive to PGlite.
function validateArchive(bytes: Buffer): void {
  const tar = gunzipSync(bytes, { maxOutputLength: MAX_EXPANDED_BYTES });
  let offset = 0;
  let entries = 0;
  const names = new Set<string>();
  const text = (start: number, length: number) =>
    tar
      .subarray(start, start + length)
      .toString("utf8")
      .replace(/\0.*$/s, "");
  while (offset + 512 <= tar.length) {
    if (tar.subarray(offset, offset + 512).every((byte) => byte === 0)) {
      if (tar.length - offset < 1024 || !tar.subarray(offset).every((byte) => byte === 0))
        throw new Error("Invalid archive terminator");
      if (!entries) throw new Error("Empty database archive");
      return;
    }
    if (++entries > 10_000) throw new Error("Database archive contains too many entries");
    const name = [text(offset + 345, 155), text(offset, 100)].filter(Boolean).join("/");
    // PGlite's own TAR format uses one leading slash, relative to its virtual PGDATA root.
    const parts = name.replace(/^\//, "").replace(/^\.\//, "").replace(/\/$/, "").split("/");
    if (
      !name ||
      name.startsWith("//") ||
      name.includes("\\") ||
      name.includes(":") ||
      parts.some((part) => !part || part === "." || part === "..")
    )
      throw new Error("Unsafe database archive path");
    const canonical = parts.join("/").toLowerCase();
    if (names.has(canonical)) throw new Error("Duplicate database archive path");
    names.add(canonical);
    const type = tar[offset + 156];
    if (text(offset + 157, 100)) throw new Error("Database archive cannot contain link targets");
    if (![0, 48, 53].includes(type ?? -1)) throw new Error("Unsupported database archive entry type");
    const rawSize = text(offset + 124, 12).trim();
    const rawChecksum = text(offset + 148, 8).trim();
    if (!/^[0-7]+$/.test(rawSize) || !/^[0-7]+$/.test(rawChecksum))
      throw new Error("Invalid archive header numbers");
    const size = Number.parseInt(rawSize, 8);
    let checksum = 0;
    for (let index = 0; index < 512; index++)
      checksum += index >= 148 && index < 156 ? 32 : (tar[offset + index] ?? 0);
    if (checksum !== Number.parseInt(rawChecksum, 8) || (type === 53 && size !== 0))
      throw new Error("Invalid archive header");
    offset += 512 + Math.ceil(size / 512) * 512;
    if (offset > tar.length) throw new Error("Truncated database archive entry");
  }
  throw new Error("Database archive has no complete terminator");
}

async function inventory(db: PGlite): Promise<z.infer<typeof inventorySchema>> {
  return db.transaction(async (tx) => {
    await tx.query("SET TRANSACTION READ ONLY");
    await tx.query("SET LOCAL TIME ZONE 'UTC'");
    const versions = (
      await tx.query<{ version: number }>("SELECT version FROM schema_migrations ORDER BY version")
    ).rows.map((row) => row.version);
    const tables = tablesForVersions(versions);
    const actual = (
      await tx.query<{ tablename: string }>(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
      )
    ).rows.map((row) => row.tablename);
    if (JSON.stringify(actual) !== JSON.stringify([...tables].sort()))
      throw new Error("Unsupported database table set");
    const proof: Record<string, z.infer<typeof tableProof>> = {};
    for (const table of tables) {
      const rows = (
        await tx.query<{ row: string }>(
          `SELECT to_jsonb(t)::text AS row FROM public.${table} t ORDER BY to_jsonb(t)::text COLLATE "C" LIMIT ${MAX_ROWS_PER_TABLE + 1}`,
        )
      ).rows;
      if (rows.length > MAX_ROWS_PER_TABLE) throw new Error("POC backup row limit exceeded");
      const hash = createHash("sha256");
      for (const row of rows) hash.update(`${Buffer.byteLength(row.row)}:`).update(row.row);
      proof[table] = { rows: rows.length, sha256: hash.digest("hex") };
    }
    const version = (
      await tx.query<{ version: string }>("SELECT current_setting('server_version_num') AS version")
    ).rows[0]?.version;
    return inventorySchema.parse({ serverVersion: version, schemaVersions: versions, tables: proof });
  });
}

async function loadArchive(bytes: Buffer<ArrayBuffer>): Promise<PGlite> {
  validateArchive(bytes);
  const db = new PGlite({ loadDataDir: new Blob([bytes], { type: "application/x-gzip" }) });
  try {
    await db.waitReady;
    return db;
  } catch {
    await db.close().catch(() => {});
    throw new Error("Database archive could not be restored");
  }
}
export async function createLocalBackup(
  snapshot: () => Promise<Blob>,
  destination: string,
  identity: BackupIdentity,
): Promise<BackupManifest> {
  backupIdentity.parse(identity);
  destination = resolve(destination);
  await realPath(dirname(destination), true);
  await mkdir(destination, { mode: 0o700 }); // Persistent claim: never overwrite/replay a partial capture.
  await privateNewFile(join(destination, "claim.json"), JSON.stringify(identity));
  try {
    const blob = await snapshot();
    if (!blob.size || blob.size > MAX_ARCHIVE_BYTES) throw new Error("POC snapshot exceeds its size bound");
    const bytes = Buffer.from(await blob.arrayBuffer());
    await privateNewFile(join(destination, "database.tar.gz"), bytes);
    const restored = await loadArchive(bytes);
    let database: z.infer<typeof inventorySchema>;
    try {
      database = await inventory(restored);
    } finally {
      await restored.close();
    }
    const manifest = manifestSchema.parse({
      schemaVersion: database.schemaVersions.length,
      format: `one-control-pglite-backup-v${database.schemaVersions.length}`,
      identity,
      createdAt: new Date().toISOString(),
      archive: { file: "database.tar.gz", bytes: bytes.length, sha256: sha256(bytes) },
      database,
    });
    await publishRecord(join(destination, "manifest.json"), manifest);
    await publishRecord(join(destination, "result.json"), {
      state: "succeeded",
      identity,
      archive: manifest.archive,
      completedAt: new Date().toISOString(),
    });
    return manifest;
  } catch {
    await publishRecord(join(destination, "result.json"), {
      state: "failed",
      identity,
      reason: "snapshot_or_restore_verification_failed",
      completedAt: new Date().toISOString(),
    }).catch(() => {});
    throw new Error("POC backup failed; preserve its claimed directory for diagnosis");
  }
}
async function checkedBackup(directory: string): Promise<{ manifest: BackupManifest; db: PGlite }> {
  await realPath(directory, true);
  const manifest = manifestSchema.parse(
    JSON.parse((await boundedFile(join(directory, "manifest.json"), 64 * 1024)).toString("utf8")),
  );
  const bytes = await boundedFile(join(directory, manifest.archive.file), MAX_ARCHIVE_BYTES);
  if (bytes.length !== manifest.archive.bytes || sha256(bytes) !== manifest.archive.sha256)
    throw new Error("Backup archive integrity mismatch");
  const db = await loadArchive(bytes);
  try {
    if (JSON.stringify(await inventory(db)) !== JSON.stringify(manifest.database))
      throw new Error("Restored database does not match its recorded contents");
    return { manifest, db };
  } catch (error) {
    await db.close();
    throw error;
  }
}
export async function verifyLocalBackup(directory: string): Promise<BackupManifest> {
  const { manifest, db } = await checkedBackup(directory);
  await db.close();
  return manifest;
}
export async function restoreLocalBackup(
  directory: string,
  destination: string,
): Promise<Record<string, unknown>> {
  const { manifest, db } = await checkedBackup(directory);
  try {
    destination = resolve(destination);
    await realPath(dirname(destination), true);
    await mkdir(destination, { mode: 0o700 });
    await privateNewFile(
      join(destination, "restore-claim.json"),
      JSON.stringify({ backup: manifest.identity, createdAt: new Date().toISOString() }),
    );
    const adapter: Database = {
      query: async <T extends Record<string, unknown>>(sql: string, params?: unknown[]) =>
        (await db.query<T>(sql, params)).rows,
      transaction: (work) =>
        db.transaction((tx) =>
          work({
            query: async <T extends Record<string, unknown>>(sql: string, params?: unknown[]) =>
              (await tx.query<T>(sql, params)).rows,
          }),
        ),
      close: async () => {},
    };
    // Legacy authentication and work become inert before the upgrade. Neither intermediate
    // database is exposed to service traffic or published as a restored destination.
    const legacy = await adapter.transaction(quarantineLegacy);
    await migrateOrdered(adapter);
    const quarantined = await adapter.transaction(async (tx) => {
      const counts = { ...legacy, ...(await quarantineAuthority(tx)) };
      await tx.query(
        "INSERT INTO audit_events(actor,action,subject,detail) VALUES('system:restore','database.restore.quarantined',$1,$2)",
        [
          manifest.identity.workspaceId,
          JSON.stringify({
            backupRequestId: manifest.identity.requestId,
            archiveSha256: manifest.archive.sha256,
            quarantined: counts,
          }),
        ],
      );
      await verifyQuarantine(tx);
      return counts;
    });
    await db.query("CHECKPOINT");
    const clean = await db.dumpDataDir("gzip");
    const persistent = new PGlite({ dataDir: join(destination, "database"), loadDataDir: clean });
    try {
      await persistent.waitReady;
      const restoredQuery: TransactionQuery = {
        query: async <T extends Record<string, unknown>>(sql: string, params?: unknown[]) =>
          (await persistent.query<T>(sql, params)).rows,
      };
      await verifyQuarantine(restoredQuery);
      const outstanding = (
        await persistent.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM jobs WHERE state IN ('awaiting_approval','queued','leased')",
        )
      ).rows[0]?.count;
      if (outstanding !== "0") throw new Error("Restored work was not quarantined");
      const liveCredentials = (
        await persistent.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM credentials WHERE revoked_at IS NULL",
        )
      ).rows[0]?.count;
      const unusedEnrollments = (
        await persistent.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM enrollment_tokens WHERE used_at IS NULL",
        )
      ).rows[0]?.count;
      if (liveCredentials !== "0" || unusedEnrollments !== "0")
        throw new Error("Restored authentication was not quarantined");
      const after = await inventory(persistent);
      for (const table of ["devices", "releases", "batches", "idempotency_keys"] as const) {
        if (JSON.stringify(after.tables[table]) !== JSON.stringify(manifest.database.tables[table]))
          throw new Error("Restoration changed preserved history or identity");
      }
    } finally {
      await persistent.close();
    }
    const result = {
      schemaVersion: 2,
      state: "quarantined",
      restoredAt: new Date().toISOString(),
      source: manifest.identity,
      archiveSha256: manifest.archive.sha256,
      quarantined,
      runtimeStarted: false,
      credentialsReactivated: false,
      destination,
    };
    await publishRecord(join(destination, "restoration.json"), result);
    return result;
  } finally {
    await db.close();
  }
}
