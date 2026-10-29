import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { migrate, openDatabase } from "../src/database.js";

test("migration and readiness reject unknown or incomplete version histories", async () => {
  const db = await openDatabase("local");
  const app = await buildApp(db, parseConfig({ NODE_ENV: "test", DEPLOYMENT_STAGE: "production" }));
  try {
    await migrate(db);
    await migrate(db);
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(200);

    await db.query("INSERT INTO schema_migrations(version) VALUES (11)");
    await expect(migrate(db)).rejects.toThrow("Unsupported database migration history");
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(503);
    expect(await db.query("SELECT version FROM schema_migrations ORDER BY version")).toEqual(
      Array.from({ length: 11 }, (_, index) => ({ version: index + 1 })),
    );

    await db.query("DELETE FROM schema_migrations WHERE version IN (1,11)");
    await expect(migrate(db)).rejects.toThrow("Unsupported database migration history");
    expect((await app.inject({ url: "/health/ready" })).statusCode).toBe(503);
    expect(await db.query("SELECT version FROM schema_migrations ORDER BY version")).toEqual(
      Array.from({ length: 9 }, (_, index) => ({ version: index + 2 })),
    );
  } finally {
    await app.close();
    await db.close();
  }
}, 30_000);
