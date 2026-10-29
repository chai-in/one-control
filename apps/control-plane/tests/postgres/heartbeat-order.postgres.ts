import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { expect, test } from "vitest";
import { buildApp } from "../../src/app.js";
import { parseConfig } from "../../src/config.js";
import type { Database, TransactionQuery } from "../../src/database.js";
import { hash } from "../../src/security.js";
import { openPostgresFixture } from "../postgres-fixture.js";
import { withCleanup } from "./cleanup.js";

test("PostgreSQL heartbeat holds its authority locks until commit before a competing revoke", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresFixture();
    own("fixture", () => db.close());
    const device = randomUUID();
    const token = "test-agent-token-".repeat(4);
    await db.query("INSERT INTO devices(id,hostname) VALUES($1,'fixture')", [device]);
    await db.query(
      "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES($1,$2,'system',now()+interval '1 day')",
      [hash(token), device],
    );
    let release!: () => void;
    let observed!: (pid: number) => void;
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
              if (sql.startsWith("UPDATE devices SET last_seen_at")) {
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
    let heartbeat: Promise<{ statusCode: number }> | undefined;
    let revocation: Promise<unknown> | undefined;
    try {
      heartbeat = app.inject({
        method: "POST",
        url: "/v1/agent/heartbeat",
        headers: { authorization: `Bearer ${token}` },
        payload: { inventory: { accepted: true } },
      });
      const pid = await locked;
      revocation = db.query("UPDATE devices SET revoked_at=now() WHERE id=$1", [device]);
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
      expect((await heartbeat).statusCode).toBe(200);
      await revocation;
      expect(
        (
          await app.inject({
            method: "POST",
            url: "/v1/agent/heartbeat",
            headers: { authorization: `Bearer ${token}` },
            payload: {},
          })
        ).statusCode,
      ).toBe(401);
    } finally {
      release();
      if (heartbeat) await heartbeat;
      if (revocation) await revocation;
    }
  });
}, 30_000);
