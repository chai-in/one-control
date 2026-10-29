import { createHash, randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { expect, test } from "vitest";
import { buildApp } from "../../src/app.js";
import { parseConfig } from "../../src/config.js";
import { migrate } from "../../src/database.js";
import { frozenV1Identity } from "../../src/frozen-v1.js";
import { inspectFrozenV1 } from "../../src/migration-baseline.js";
import {
  baselineBoundary,
  baselineMutations,
  baselineRows,
  independentCatalog,
  seedBaselineRows,
} from "../fixtures/frozen-v1.js";
import { loadPostgresCustody, openPostgresBaselineFixture } from "../postgres-fixture.js";
import { withCleanup } from "./cleanup.js";

test("PostgreSQL rejects future and gapped migration markers without changing them", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresBaselineFixture("frozen-v1");
    own("fixture", () => db.close());
    const app = await buildApp(db, parseConfig({ NODE_ENV: "test", DEPLOYMENT_STAGE: "production" }));
    own("runtime", () => app.close());
    const migrator = {
      query: db.query.bind(db),
      transaction: db.withMigrator.bind(db),
      close: async () => {},
    };
    await migrate(migrator);
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(200);
    await db.withMigrator((tx) => tx.query("INSERT INTO schema_migrations(version) VALUES (3)"));
    await expect(migrate(migrator)).rejects.toThrow("Unsupported database migration history");
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(503);
    expect(await db.query("SELECT version FROM schema_migrations ORDER BY version")).toEqual([
      { version: 1 },
      { version: 2 },
      { version: 3 },
    ]);
    await db.withMigrator((tx) => tx.query("DELETE FROM schema_migrations WHERE version = 1"));
    await expect(migrate(migrator)).rejects.toThrow("Unsupported database migration history");
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(503);
    expect(await db.query("SELECT version FROM schema_migrations ORDER BY version")).toEqual([
      { version: 2 },
      { version: 3 },
    ]);
  });
}, 30_000);

test("actual frozen-v1 PostgreSQL admission and denials preserve catalog and business rows under owned migrator locks", async () => {
  const custody = await loadPostgresCustody();
  const observations: Record<string, boolean> = {};
  let catalogSha256: string | null = null;
  const rollback = Symbol("rollback-test-only");
  await withCleanup(
    async (own) => {
      const empty = await openPostgresBaselineFixture("empty");
      own("fixture", () => empty.close());
      await empty.withMigrator(async (tx) => {
        await baselineBoundary(tx, empty.namespace);
        const boundary = { engine: "postgres-18.6", namespace: empty.namespace } as const;
        expect(await inspectFrozenV1(tx, boundary)).toEqual({ kind: "empty" });
        observations.empty = true;
        await tx.query(
          "CREATE TABLE schema_migrations(version int PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())",
        );
        await tx.query("INSERT INTO schema_migrations(version) VALUES(1)");
        expect((await inspectFrozenV1(tx, boundary)).kind).toBe("incompatible");
        observations.counterfeit = true;
      });
      const frozen = await openPostgresBaselineFixture("frozen-v1");
      own("fixture", () => frozen.close());
      const id = randomUUID();
      await frozen.transaction((tx) => seedBaselineRows(tx, id));
      const rows = async () =>
        createHash("sha256")
          .update(await frozen.transaction(baselineRows))
          .digest("hex");
      const beforeRows = await rows();
      await frozen.transaction(async (tx) => {
        await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
        await tx.query(`SET LOCAL search_path TO "${frozen.namespace}", pg_catalog`);
        expect(
          (await inspectFrozenV1(tx, { engine: "postgres-18.6", namespace: frozen.namespace })).kind,
        ).toBe("compatible");
        observations.readOnly = true;
      });
      await frozen.withMigrator(async (tx) => {
        await baselineBoundary(tx, frozen.namespace);
        const before = await independentCatalog(tx, frozen.namespace);
        const beforeRows = createHash("sha256")
          .update(await baselineRows(tx))
          .digest("hex");
        const admitted = await inspectFrozenV1(tx, { engine: "postgres-18.6", namespace: frozen.namespace });
        expect(admitted.kind).toBe("compatible");
        if (admitted.kind !== "compatible") throw new Error("Exact source catalog rejected");
        catalogSha256 = admitted.catalogSha256;
        expect(await independentCatalog(tx, frozen.namespace)).toBe(before);
        expect(
          createHash("sha256")
            .update(await baselineRows(tx))
            .digest("hex"),
        ).toBe(beforeRows);
        observations.frozen = true;
        const locks = await tx.query(
          "SELECT mode,granted FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' AND mode='AccessExclusiveLock'",
        );
        expect(locks.filter((row) => row.granted)).toHaveLength(9);
        observations.locks = true;
      });
      for (const [scenario, units] of baselineMutations) {
        await expect(
          frozen.withMigrator(async (tx) => {
            await baselineBoundary(tx, frozen.namespace);
            for (const unit of units) await tx.query(unit);
            const before = await independentCatalog(tx, frozen.namespace);
            const beforeRows = createHash("sha256")
              .update(await baselineRows(tx))
              .digest("hex");
            expect(
              (await inspectFrozenV1(tx, { engine: "postgres-18.6", namespace: frozen.namespace })).kind,
            ).toBe("incompatible");
            expect(await independentCatalog(tx, frozen.namespace)).toBe(before);
            expect(
              createHash("sha256")
                .update(await baselineRows(tx))
                .digest("hex"),
            ).toBe(beforeRows);
            if (scenario === "operator")
              expect(
                await tx.query("SELECT count(*)::pg_catalog.int4 AS calls FROM pg_temp.operator_calls"),
              ).toEqual([{ calls: 0 }]);
            observations[scenario] = true;
            throw rollback;
          }),
        ).rejects.toBe(rollback);
      }
      expect(await rows()).toBe(beforeRows);
      observations.rows = true;
      await expect(
        frozen.query(`CREATE TABLE "${frozen.namespace}".runtime_forbidden(id int)`),
      ).rejects.toMatchObject({ code: "42501" });
      observations.runtimeDdl = true;
      await expect(frozen.query("INSERT INTO schema_migrations(version) VALUES(2)")).rejects.toMatchObject({
        code: "42501",
      });
      observations.runtimeHistory = true;
    },
    async (cleanup) => {
      await writeFile(
        path.join(custody.directory, "observations", "migration-baseline.json"),
        JSON.stringify({
          run: custody.run,
          sourceSha256: frozenV1Identity.sqlSha256,
          catalogSha256,
          observations,
          cleanup: cleanup.result,
        }),
        { flag: "wx", mode: 0o600 },
      );
    },
  );
}, 30_000);
