import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { expect, test } from "vitest";
import { type Database, migrate } from "../../src/database.js";
import { currentSchemaReady } from "../../src/migrations.js";
import { seedBaselineRows } from "../fixtures/frozen-v1.js";
import { openPostgresBaselineFixture } from "../postgres-fixture.js";
import { withCleanup } from "./cleanup.js";

test("independent PostgreSQL migrators serialize a populated frozen v1 upgrade exactly once", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresBaselineFixture("frozen-v1");
    own("fixture", () => db.close());
    await db.transaction((tx) => seedBaselineRows(tx, randomUUID()));
    const before = await db.query("SELECT to_jsonb(d)::text AS row FROM devices d");
    const first = await db.openMigrator(),
      second = await db.openMigrator();
    let release!: () => void, reached!: () => void, waiting!: (pid: number) => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prepared = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const contender = new Promise<number>((resolve) => {
      waiting = resolve;
    });
    const one: Database = {
      ...first,
      transaction: (work) =>
        first.transaction((tx) =>
          work({
            query: async (sql, params) => {
              if (sql === "INSERT INTO schema_migrations(version) VALUES($1)") {
                reached();
                await barrier;
              }
              return tx.query(sql, params);
            },
          }),
        ),
    };
    const two: Database = {
      ...second,
      transaction: (work) =>
        second.transaction(async (tx) => {
          const [row] = await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
          if (!row) throw new Error("Missing contender PID");
          waiting(row.pid);
          return work(tx);
        }),
    };
    const a = migrate(one);
    let b: Promise<void> | undefined;
    try {
      await prepared;
      b = migrate(two);
      const pid = await contender;
      let blocked = false;
      const deadline = Date.now() + 4000;
      while (Date.now() < deadline) {
        const [row] = await db.query<{ blocked: boolean }>(
          "SELECT cardinality(pg_blocking_pids($1))>0 AS blocked",
          [pid],
        );
        if (row?.blocked) {
          blocked = true;
          break;
        }
        await delay(10);
      }
      expect(blocked).toBe(true);
    } finally {
      release();
      await Promise.all([a, b]);
    }
    await db.withMigrator(async () => {}); // Explicit fixture grants for newly created runtime tables.
    expect(await currentSchemaReady(db)).toBe(true);
    expect(await db.query("SELECT to_jsonb(d)::text AS row FROM devices d")).toEqual(before);
    expect(await db.query("SELECT version FROM schema_migrations ORDER BY version")).toEqual([
      { version: 1 },
      { version: 2 },
    ]);
    expect(await db.query("SELECT count(*)::int AS count FROM migration_metadata")).toEqual([{ count: 1 }]);
    expect(await db.query("SELECT enrollment_id FROM credentials")).toEqual([{ enrollment_id: null }]);
    await migrate(first);
  });
}, 30_000);

test("PostgreSQL rolls back v2 schema and rows on marker failure, then accepts a deliberate retry", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresBaselineFixture("frozen-v1");
    own("fixture", () => db.close());
    await db.transaction((tx) => seedBaselineRows(tx, randomUUID()));
    const first = await db.openMigrator();
    const before = await db.query("SELECT to_jsonb(c)::text AS row FROM credentials c");
    const broken: Database = {
      ...first,
      transaction: (work) =>
        first.transaction((tx) =>
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
    expect(await db.query("SELECT to_regclass('authority_runtime') AS name")).toEqual([{ name: null }]);
    expect(await db.query("SELECT version FROM schema_migrations")).toEqual([{ version: 1 }]);
    expect(await db.query("SELECT to_jsonb(c)::text AS row FROM credentials c")).toEqual(before);
    await migrate(first);
    await db.withMigrator(async () => {});
    expect(await currentSchemaReady(db)).toBe(true);
    await expect(db.query("UPDATE migration_metadata SET checksum=repeat('0',64)")).rejects.toMatchObject({
      code: "42501",
    });
  });
}, 30_000);
