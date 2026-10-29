import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import type { Database } from "../src/database.js";
import { hash } from "../src/security.js";
import { openTestDatabase } from "./database-fixture.js";

for (const operation of ["claim", "renew", "report"] as const) {
  for (const revoked of ["device", "credential"] as const) {
    test(`${operation} refuses ${revoked} revocation after authentication`, async () => {
      const db = await openTestDatabase();
      const device = randomUUID();
      const batch = randomUUID();
      const job = randomUUID();
      const token = "test-agent-token-".repeat(4);
      const lease = "test-lease-token-".repeat(4);
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
      await db.query("INSERT INTO devices(id,hostname) VALUES($1,'dispatch-fixture')", [device]);
      await db.query(
        "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES($1,$2,'system',now()+interval '1 day')",
        [hash(token), device],
      );
      await db.query("INSERT INTO batches(id,created_by,command,ring) VALUES($1,'fixture',$2,'canary')", [
        batch,
        JSON.stringify({ kind: "inventory.scan" }),
      ]);
      await db.query(
        "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at,lease_hash,lease_expires_at) VALUES($1,$2,$3,'system','inventory.scan',$4,$5,now()-interval '1 hour',now()+interval '1 hour',$6,$7)",
        [
          job,
          batch,
          device,
          JSON.stringify({ kind: "inventory.scan" }),
          operation === "claim" ? "queued" : "leased",
          operation === "claim" ? null : hash(lease),
          operation === "claim" ? null : new Date(Date.now() + 60_000).toISOString(),
        ],
      );
      const before = await db.query(
        "SELECT state,attempt,lease_hash,lease_expires_at FROM jobs WHERE id=$1",
        [job],
      );
      const app = await buildApp(wrapped, parseConfig({ NODE_ENV: "test", DEPLOYMENT_STAGE: "production" }));
      try {
        const request = app.inject({
          method: "POST",
          url: operation === "claim" ? "/v1/agent/claim" : `/v1/agent/jobs/${job}/${operation}`,
          headers: { authorization: `Bearer ${token}` },
          payload:
            operation === "claim"
              ? {}
              : operation === "renew"
                ? { leaseToken: lease }
                : { leaseToken: lease, state: "succeeded", result: { fixture: true } },
        });
        await authenticated;
        if (revoked === "device") await db.query("UPDATE devices SET revoked_at=now() WHERE id=$1", [device]);
        else await db.query("UPDATE credentials SET revoked_at=now() WHERE hash=$1", [hash(token)]);
        release();
        expect((await request).statusCode).toBe(401);
        expect(
          await db.query("SELECT state,attempt,lease_hash,lease_expires_at FROM jobs WHERE id=$1", [job]),
        ).toEqual(before);
      } finally {
        release();
        await app.close();
        await db.close();
      }
    }, 30_000);
  }
}
