import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import type { Database } from "../src/database.js";
import { hash } from "../src/security.js";
import { openTestDatabase } from "./database-fixture.js";

for (const revoked of ["device", "credential"] as const) {
  test(`rotation refuses ${revoked} revocation committed after authentication`, async () => {
    const db = await openTestDatabase();
    const device = randomUUID();
    const token = "test-agent-token-".repeat(4);
    const replacement = hash("replacement-".repeat(8));
    let release!: () => void;
    let observed!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const authenticated = new Promise<void>((resolve) => {
      observed = resolve;
    });
    const wrapped: Database = {
      async query<T extends Record<string, unknown>>(sql: string, params?: unknown[]) {
        const result = await db.query<T>(sql, params);
        if (sql.includes("SELECT c.device_id, c.context, c.hash")) {
          observed();
          await barrier;
        }
        return result;
      },
      transaction: db.transaction.bind(db),
      close: db.close.bind(db),
    };
    await db.query("INSERT INTO devices(id,hostname) VALUES($1,'rotation-fixture')", [device]);
    await db.query(
      "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES($1,$2,'system',now()+interval '1 day')",
      [hash(token), device],
    );
    const app = await buildApp(wrapped, parseConfig({ NODE_ENV: "test", DEPLOYMENT_STAGE: "production" }));
    try {
      const request = app.inject({
        method: "POST",
        url: "/v1/agent/credentials/rotate",
        headers: { authorization: `Bearer ${token}` },
        payload: { credentialHash: replacement },
      });
      await authenticated;
      if (revoked === "device") await db.query("UPDATE devices SET revoked_at=now() WHERE id=$1", [device]);
      else await db.query("UPDATE credentials SET revoked_at=now() WHERE hash=$1", [hash(token)]);
      release();
      expect((await request).statusCode).toBe(401);
      expect(await db.query("SELECT hash FROM credentials WHERE hash=$1", [replacement])).toEqual([]);
    } finally {
      release();
      await app.close();
      await db.close();
    }
  }, 30_000);
}
