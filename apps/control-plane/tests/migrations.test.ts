import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { type Database, migrate, openDatabase } from "../src/database.js";
import { currentSchemaReady } from "../src/migrations.js";
import { v9Tables } from "../src/schema-inventory.js";
import { frozenV1Units, seedBaselineRows } from "./fixtures/frozen-v1.js";

test("populated frozen v1 upgrades without granting native authority or replaying work", async () => {
  const db = await openDatabase("local");
  try {
    for (const statement of frozenV1Units) await db.query(statement);
    const device = randomUUID();
    await db.transaction((tx) => seedBaselineRows(tx, device));
    for (const state of ["queued", "awaiting_approval", "leased"]) {
      const id = randomUUID();
      await db.query("INSERT INTO batches(id,created_by,command,ring) VALUES($1,'test','{}','canary')", [id]);
      await db.query(
        "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at,lease_hash,lease_expires_at) VALUES($1,$1,$2,'system','inventory.scan','{}',$3,now(),now()+interval '1 hour',$4,$5)",
        [
          id,
          device,
          state,
          state === "leased" ? "old-lease" : null,
          state === "leased" ? new Date(Date.now() + 60_000) : null,
        ],
      );
    }
    const terminal = await db.query("SELECT to_jsonb(j)::text AS row FROM jobs j WHERE state='succeeded'");
    const devices = await db.query("SELECT to_jsonb(d)::text AS row FROM devices d");
    await migrate(db);
    expect(await currentSchemaReady(db)).toBe(true);
    expect(await db.query("SELECT to_jsonb(d)::text AS row FROM devices d")).toEqual(devices);
    expect(await db.query("SELECT to_jsonb(j)::text AS row FROM jobs j WHERE state='succeeded'")).toEqual(
      terminal,
    );
    expect(
      await db.query("SELECT state,count(*)::int AS count FROM jobs GROUP BY state ORDER BY state"),
    ).toEqual([
      { state: "cancelled", count: 2 },
      { state: "indeterminate", count: 1 },
      { state: "succeeded", count: 1 },
    ]);
    expect(await db.query("SELECT enrollment_id FROM credentials")).toEqual([{ enrollment_id: null }]);
    expect(await db.query("SELECT state,authority_epoch,root_version FROM authority_runtime")).toEqual([
      { state: "unconfigured", authority_epoch: null, root_version: null },
    ]);
    for (const table of [
      "management_scopes",
      "scope_grants",
      "native_invitations",
      "native_enrollments",
      "module_states",
    ])
      expect(await db.query(`SELECT * FROM ${table}`)).toEqual([]);
    expect(
      (
        await db.query<{ tablename: string }>(
          "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
        )
      ).map((row) => row.tablename),
    ).toEqual([...v9Tables].sort());
    const markers = await db.query("SELECT * FROM schema_migrations ORDER BY version");
    await migrate(db);
    expect(await db.query("SELECT * FROM schema_migrations ORDER BY version")).toEqual(markers);
    await db.query("UPDATE migration_metadata SET checksum=repeat('0',64)");
    expect(await currentSchemaReady(db)).toBe(false);
    await expect(migrate(db)).rejects.toThrow("Inconsistent database migration metadata");
  } finally {
    await db.close();
  }
}, 30_000);

test("a failure at the v2 marker rolls back all DDL and data; retry then converges", async () => {
  const db = await openDatabase("local");
  try {
    for (const statement of frozenV1Units) await db.query(statement);
    await db.transaction((tx) => seedBaselineRows(tx, randomUUID()));
    const before = await db.query("SELECT to_jsonb(c)::text AS row FROM credentials c");
    const broken: Database = {
      ...db,
      transaction: (work) =>
        db.transaction((tx) =>
          work({
            query: async (sql, params) => {
              if (sql === "INSERT INTO schema_migrations(version) VALUES($1)")
                throw new Error("injected marker failure");
              return tx.query(sql, params);
            },
          }),
        ),
    };
    await expect(migrate(broken)).rejects.toThrow("injected marker failure");
    expect(await db.query("SELECT version FROM schema_migrations")).toEqual([{ version: 1 }]);
    expect(await db.query("SELECT to_regclass('authority_runtime') AS name")).toEqual([{ name: null }]);
    expect(await db.query("SELECT to_jsonb(c)::text AS row FROM credentials c")).toEqual(before);
    await migrate(db);
    expect(await currentSchemaReady(db)).toBe(true);
  } finally {
    await db.close();
  }
}, 30_000);

test("a v1 marker cannot authorize an altered or counterfeit catalog", async () => {
  const db = await openDatabase("local");
  try {
    for (const statement of frozenV1Units) await db.query(statement);
    await db.query("ALTER TABLE devices ADD COLUMN drift text");
    await expect(migrate(db)).rejects.toThrow("Incompatible frozen v1 database");
    expect(await db.query("SELECT version FROM schema_migrations")).toEqual([{ version: 1 }]);
  } finally {
    await db.close();
  }
}, 30_000);
