import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { expect, test } from "vitest";
import { buildApp } from "../../src/app.js";
import { parseConfig } from "../../src/config.js";
import type { Database, TransactionQuery } from "../../src/database.js";
import { hash } from "../../src/security.js";
import { openPostgresFixture } from "../postgres-fixture.js";
import { withCleanup } from "./cleanup.js";

for (const operation of ["claim", "renew", "report"] as const) {
  test(`PostgreSQL ${operation} commits before competing credential revocation`, async () => {
    await withCleanup(async (own) => {
      const db = await openPostgresFixture();
      own("fixture", () => db.close());
      const device = randomUUID(),
        batch = randomUUID(),
        job = randomUUID();
      const token = "test-agent-token-".repeat(4),
        lease = "test-lease-token-".repeat(4);
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
      let release!: () => void, observed!: (pid: number) => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      const locked = new Promise<number>((resolve) => {
        observed = resolve;
      });
      const wrapped: Database = {
        query: db.query.bind(db),
        transaction: (work) =>
          db.transaction(async (tx) => {
            const pid = (await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid"))[0]?.pid;
            if (!pid) throw new Error("Missing transaction identity");
            const proxy: TransactionQuery = {
              async query<T extends Record<string, unknown>>(sql: string, params?: unknown[]) {
                const result = await tx.query<T>(sql, params);
                if (
                  sql.startsWith(
                    operation === "claim"
                      ? "UPDATE jobs SET state='leased'"
                      : operation === "renew"
                        ? "UPDATE jobs SET lease_expires_at="
                        : "UPDATE jobs SET state=$1,result=$2",
                  )
                ) {
                  observed(pid);
                  await barrier;
                }
                return result;
              },
            };
            return work(proxy);
          }),
        close: db.close.bind(db),
      };
      const app = await buildApp(wrapped, parseConfig({ NODE_ENV: "test", DEPLOYMENT_STAGE: "production" }));
      own("runtime", () => app.close());
      let request: Promise<{ statusCode: number }> | undefined, revocation: Promise<unknown> | undefined;
      const input = {
        method: "POST" as const,
        url: operation === "claim" ? "/v1/agent/claim" : `/v1/agent/jobs/${job}/${operation}`,
        headers: { authorization: `Bearer ${token}` },
        payload:
          operation === "claim"
            ? {}
            : operation === "renew"
              ? { leaseToken: lease }
              : { leaseToken: lease, state: "succeeded", result: { fixture: true } },
      };
      try {
        request = app.inject(input);
        const pid = await locked;
        revocation = db.query("UPDATE credentials SET revoked_at=now() WHERE hash=$1", [hash(token)]);
        let blocked = false;
        const deadline = Date.now() + 5000;
        while (Date.now() < deadline && !blocked) {
          const [row] = await db.query<{ blocked: boolean }>(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))) AS blocked",
            [pid],
          );
          blocked = row?.blocked === true;
          if (!blocked) await delay(20);
        }
        expect(blocked).toBe(true);
        release();
        expect((await request).statusCode).toBe(200);
        await revocation;
        expect((await app.inject(input)).statusCode).toBe(401);
      } finally {
        release();
        if (request) await request;
        if (revocation) await revocation;
      }
    });
  }, 30_000);
}
