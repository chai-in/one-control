import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { openTestDatabase } from "./database-fixture.js";

test("independent database fixtures never inherit another suite's fleet", async () => {
  const first = await openTestDatabase();
  try {
    const second = await openTestDatabase();
    try {
      await first.query("INSERT INTO devices(id,hostname) VALUES ($1,'test-isolation-fixture')", [
        randomUUID(),
      ]);
      expect((await first.query("SELECT id FROM devices")).length).toBe(1);
      expect(await second.query("SELECT id FROM devices")).toEqual([]);
    } finally {
      await second.close();
    }
    expect((await first.query("SELECT id FROM devices")).length).toBe(1);
  } finally {
    await first.close();
  }
}, 30_000);
