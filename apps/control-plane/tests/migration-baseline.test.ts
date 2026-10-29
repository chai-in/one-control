import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test } from "vitest";
import { openDatabase } from "../src/database.js";
import {
  frozenV1Catalogs,
  frozenV1Identity,
  frozenV1Prefix,
  frozenV1Separator,
  frozenV1Statements,
  frozenV1Suffix,
} from "../src/frozen-v1.js";
import { inspectFrozenV1 } from "../src/migration-baseline.js";
import { schema } from "../src/schema.js";
import {
  baselineBoundary,
  baselineMutations,
  baselineRows,
  frozenV1Sql,
  frozenV1Units,
  independentCatalog,
  seedBaselineRows,
} from "./fixtures/frozen-v1.js";

const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
test("frozen complete units reconstruct exact historical SQL and retain distinct provenance", async () => {
  expect(frozenV1Statements).toHaveLength(12);
  expect(frozenV1Prefix + frozenV1Statements.join(frozenV1Separator) + frozenV1Suffix).toBe(schema);
  expect(frozenV1Sql).toBe(schema);
  expect(frozenV1Units).toHaveLength(12);
  expect(`\n${frozenV1Units.join("\n")}\n`).toBe(schema);
  expect(sha256(schema)).toBe(frozenV1Identity.sqlSha256);
  const source = await readFile(new URL("../src/schema.ts", import.meta.url));
  expect(sha256(source)).toBe(frozenV1Identity.sourceSha256);
  expect(
    sha256(
      JSON.stringify({
        format: "one-control-migration-v1",
        version: 1,
        id: "foundation.frozen-v1",
        owner: "foundation",
        requires: [],
        transaction: "required",
        statements: frozenV1Statements,
      }),
    ),
  ).toBe(frozenV1Identity.checksum);
  for (const engine of ["pglite", "postgres"]) {
    const fixture = JSON.parse(
      await readFile(new URL(`./fixtures/frozen-v1-catalog/${engine}.json`, import.meta.url), "utf8"),
    );
    expect(fixture.sqlSha256).toBe(frozenV1Identity.sqlSha256);
    expect(fixture.sourceSha256).toBe(frozenV1Identity.sourceSha256);
    expect(sha256(frozenV1Catalogs[fixture.engine as keyof typeof frozenV1Catalogs])).toBe(
      fixture.catalogSha256,
    );
    expect(fixture.catalogSha256).toBe("7648810dad3ecf14fc5949072c986e4b1a38191d5e06b3b87a6523e71d01c8b0");
  }
});

test("actual pinned PGlite independently admits frozen source, empty and rejects structural or marker drift read-only", async () => {
  const db = await openDatabase("local");
  const boundary = { engine: "pglite-0.5.9", namespace: "baseline_test" } as const;
  const rollback = Symbol("rollback-test-only");
  try {
    await db.query("CREATE SCHEMA baseline_test");
    await db.query("CREATE SCHEMA baseline_external");
    await db.query("CREATE TABLE baseline_external.parent()");
    await db.transaction(async (tx) => {
      await baselineBoundary(tx, boundary.namespace);
      expect(await inspectFrozenV1(tx, boundary)).toEqual({ kind: "empty" });
      await tx.query("CREATE TYPE counterfeit AS ENUM ('x')");
      expect(await inspectFrozenV1(tx, boundary)).toEqual({ kind: "incompatible", reason: "catalog" });
    });
    await db.query("DROP SCHEMA baseline_test CASCADE");
    await db.query("CREATE SCHEMA baseline_test");
    await db.transaction(async (tx) => {
      await baselineBoundary(tx, boundary.namespace);
      for (const unit of frozenV1Units) await tx.query(unit);
      await seedBaselineRows(tx, "00000000-0000-4000-8000-000000000001");
    });
    await db.transaction(async (tx) => {
      await baselineBoundary(tx, boundary.namespace);
      expect(await inspectFrozenV1(tx, boundary)).toMatchObject({
        kind: "compatible",
        admission: "catalog-v1",
      });
      expect(await inspectFrozenV1(tx, { ...boundary, namespace: "other" })).toEqual({
        kind: "incompatible",
        reason: "boundary",
      });
    });
    await db.transaction(async (tx) => {
      await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      await tx.query("SET LOCAL search_path TO baseline_test,pg_catalog");
      expect((await inspectFrozenV1(tx, boundary)).kind).toBe("compatible");
    });
    for (const [scenario, units] of baselineMutations) {
      await expect(
        db.transaction(async (tx) => {
          await baselineBoundary(tx, boundary.namespace);
          for (const unit of units) await tx.query(unit);
          const before = await independentCatalog(tx, boundary.namespace);
          const beforeRows = sha256(await baselineRows(tx));
          expect((await inspectFrozenV1(tx, boundary)).kind).toBe("incompatible");
          expect(await independentCatalog(tx, boundary.namespace)).toBe(before);
          expect(sha256(await baselineRows(tx))).toBe(beforeRows);
          if (scenario === "operator")
            expect(
              await tx.query("SELECT count(*)::pg_catalog.int4 AS calls FROM pg_temp.operator_calls"),
            ).toEqual([{ calls: 0 }]);
          throw rollback;
        }),
      ).rejects.toBe(rollback);
    }
    await expect(
      db.transaction(async (tx) => {
        await baselineBoundary(tx, boundary.namespace);
        await tx.query("ALTER TABLE devices INHERIT baseline_external.parent");
        expect((await inspectFrozenV1(tx, boundary)).kind).toBe("incompatible");
        throw rollback;
      }),
    ).rejects.toBe(rollback);
    await expect(
      db.transaction(async (tx) => {
        await baselineBoundary(tx, boundary.namespace);
        await tx.query("CREATE TEMP TABLE temporary_namespace(id int)");
        await tx.query("CREATE DOMAIN pg_temp.oid AS pg_catalog.text");
        await tx.query("CREATE DOMAIN pg_temp.jsonb AS pg_catalog.text");
        expect((await inspectFrozenV1(tx, boundary)).kind).toBe("incompatible");
        throw rollback;
      }),
    ).rejects.toBe(rollback);
  } finally {
    await db.close();
  }
}, 30_000);
