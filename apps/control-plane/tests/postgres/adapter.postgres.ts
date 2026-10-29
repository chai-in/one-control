import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import pg from "pg";
import { expect, test } from "vitest";
import {
  TransactionAbortedError,
  TransactionCommitUnknownError,
  type TransactionQuery,
} from "../../src/database.js";
import { loadPostgresCustody, openPostgresFixture } from "../postgres-fixture.js";
import { withCleanup } from "./cleanup.js";
import { openProtocolProxy } from "./protocol-proxy.js";

async function observation(filename: string, value: Record<string, unknown>) {
  const custody = await loadPostgresCustody();
  await writeFile(
    path.join(custody.directory, "observations", filename),
    JSON.stringify({ run: custody.run, ...value }),
    { flag: "wx", mode: 0o600 },
  );
}
test.each(["passthrough", "lose-committed-ack", "drop-commit"] as const)(
  "actual wire %s has independently observed durability and exactly one callback",
  async (mode) => {
    const marker = randomUUID();
    let calls = 0;
    let escaped: TransactionQuery | undefined;
    let backend: unknown = null;
    let replacementBackend: unknown = null;
    let durableRows: number | null = null;
    let proxy: Awaited<ReturnType<typeof openProtocolProxy>> | undefined;
    let stage = "fixture";
    const started = Date.now();
    await withCleanup(
      async (own) => {
        const fixture = await openPostgresFixture();
        own("fixture", () => fixture.close());
        stage = "proxy";
        const openedProxy = await openProtocolProxy(mode);
        proxy = openedProxy;
        own("proxy", () => openedProxy.close());
        stage = "runtime";
        const db = await fixture.openRuntimeThrough(proxy.endpoint);
        own("runtime", () => db.close());
        stage = "transaction";
        const outcome = await db
          .transaction(async (tx) => {
            calls++;
            escaped = tx;
            const [row] = await tx.query("SELECT pg_backend_pid() AS pid");
            backend = row?.pid;
            await tx.query("SET LOCAL application_name = 'transaction-local-marker'");
            await tx.query("INSERT INTO devices(id,hostname) VALUES($1,'wire-marker')", [marker]);
            return marker;
          })
          .catch((error: unknown) => error);
        stage = "outcome";
        if (mode === "passthrough") expect(outcome).toBe(marker);
        else expect(outcome).toBeInstanceOf(TransactionCommitUnknownError);
        expect(calls).toBe(1);
        stage = "durability";
        const durable = await fixture.query("SELECT id FROM devices WHERE id=$1", [marker]);
        durableRows = durable.length;
        expect(durable).toEqual(mode === "drop-commit" ? [] : [{ id: marker }]);
        if (!escaped) throw new Error("Callback did not expose its handle");
        await expect(escaped.query("SELECT 1")).rejects.toThrow("callback has closed");
        stage = "replacement";
        const replacement = await db.transaction(
          async (tx) =>
            (
              await tx.query("SELECT pg_backend_pid() AS pid,current_setting('application_name') AS setting")
            )[0],
        );
        replacementBackend = replacement?.pid ?? null;
        if (mode !== "passthrough") expect(replacement?.pid).not.toBe(backend);
        expect(replacement?.setting).not.toBe("transaction-local-marker");
        if (mode === "lose-committed-ack") {
          expect(proxy.observations.commitCommandObserved).toBe(1);
          expect(proxy.observations.idleObservedAfterCommit).toBe(1);
          expect(proxy.observations.withheldBytes).toBeGreaterThan(0);
        }
        stage = "complete";
      },
      async (cleanup) => {
        await observation(`wire-${mode}.json`, {
          mode,
          stage,
          ...(proxy?.observations ?? {}),
          callbackCount: calls,
          durable: durableRows,
          originalBackend: backend,
          replacementBackend,
          milliseconds: Date.now() - started,
          outcome: stage === "complete" ? (mode === "passthrough" ? "confirmed" : "unknown") : "unobserved",
          cleanup,
        });
      },
    );
  },
);
test("actual work failure rolls back domain and audit and permits clean backend reuse", async () => {
  const marker = randomUUID();
  const primary = { original: true };
  let backend: unknown;
  let escaped: TransactionQuery | undefined;
  await withCleanup(async (own) => {
    const db = await openPostgresFixture();
    own("fixture", () => db.close());
    await expect(
      db.transaction(async (tx) => {
        escaped = tx;
        backend = (await tx.query("SELECT pg_backend_pid() AS pid"))[0]?.pid;
        await tx.query("INSERT INTO devices(id,hostname) VALUES($1,'rollback-marker')", [marker]);
        await tx.query(
          "INSERT INTO audit_events(actor,action,subject,detail) VALUES('test','rollback',$1,'{}')",
          [marker],
        );
        throw primary;
      }),
    ).rejects.toBe(primary);
    expect(await db.query("SELECT id FROM devices WHERE id=$1", [marker])).toEqual([]);
    expect(await db.query("SELECT subject FROM audit_events WHERE subject=$1", [marker])).toEqual([]);
    if (!escaped) throw new Error("Callback did not expose its handle");
    await expect(escaped.query("SELECT 1")).rejects.toThrow("callback has closed");
    expect(
      await db.transaction(async (tx) => (await tx.query("SELECT pg_backend_pid() AS pid"))[0]?.pid),
    ).toBe(backend);
  });
});
test("actual swallowed statement failure receives ROLLBACK and cannot return success", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresFixture();
    own("fixture", () => db.close());
    await expect(
      db.transaction(async (tx) => {
        await tx.query("SELECT 1/0").catch(() => {});
        return "must not return";
      }),
    ).rejects.toBeInstanceOf(TransactionAbortedError);
    await expect(db.transaction(async () => 1)).resolves.toBe(1);
  });
});
test("actual socket loss during rollback preserves the original work value and replaces its backend", async () => {
  const primary = { original: true };
  const marker = randomUUID();
  let backend: unknown;
  await withCleanup(async (own) => {
    const fixture = await openPostgresFixture();
    own("fixture", () => fixture.close());
    const proxy = await openProtocolProxy("passthrough");
    own("proxy", () => proxy.close());
    const db = await fixture.openRuntimeThrough(proxy.endpoint);
    own("runtime", () => db.close());
    await expect(
      db.transaction(async (tx) => {
        backend = (await tx.query("SELECT pg_backend_pid() AS pid"))[0]?.pid;
        await tx.query("INSERT INTO devices(id,hostname) VALUES($1,'broken-work')", [marker]);
        proxy.disconnect();
        throw primary;
      }),
    ).rejects.toBe(primary);
    expect(await fixture.query("SELECT id FROM devices WHERE id=$1", [marker])).toEqual([]);
    const replacement = await db.transaction(
      async (tx) => (await tx.query("SELECT pg_backend_pid() AS pid"))[0]?.pid,
    );
    expect(replacement).not.toBe(backend);
  });
});
test("unsupported internal transaction-control SQL is an explicit trust-boundary counterexample", async () => {
  const marker = randomUUID();
  const primary = { unsupportedControl: true };
  await withCleanup(async (own) => {
    const db = await openPostgresFixture();
    own("fixture", () => db.close());
    await expect(
      db.transaction(async (tx) => {
        await tx.query("INSERT INTO devices(id,hostname) VALUES($1,'unsupported-control')", [marker]);
        await tx.query("COMMIT");
        throw primary;
      }),
    ).rejects.toBe(primary);
    expect(await db.query("SELECT id FROM devices WHERE id=$1", [marker])).toEqual([{ id: marker }]);
  });
});
test("actual deferred foreign key ERROR 23503 proves COMMIT rejection without callback replay", async () => {
  await withCleanup(async (own) => {
    const db = await openPostgresFixture();
    own("fixture", () => db.close());
    const custody = await loadPostgresCustody();
    const setup = new pg.Client({
      host: "127.0.0.1",
      port: custody.port,
      user: custody.setup,
      password: custody.password,
      database: custody.database,
    });
    own("setup", () => setup.end());
    await setup.connect();
    let calls = 0;
    const [identity] = await db.query("SELECT current_schema() AS namespace,current_user AS runtime");
    await setup.query(
      `CREATE TABLE ${identity?.namespace}.deferred_probe(id int REFERENCES ${identity?.namespace}.schema_migrations(version) DEFERRABLE INITIALLY DEFERRED)`,
    );
    await setup.query(`GRANT SELECT,INSERT ON ${identity?.namespace}.deferred_probe TO ${identity?.runtime}`);
    const failure = await db
      .transaction(async (tx) => {
        calls++;
        await tx.query("INSERT INTO deferred_probe VALUES(999)");
      })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(pg.DatabaseError);
    expect(failure).toMatchObject({ severity: "ERROR", code: "23503" });
    expect(calls).toBe(1);
    expect(await db.query("SELECT id FROM deferred_probe")).toEqual([]);
    await expect(db.transaction(async () => 1)).resolves.toBe(1);
  });
});
test("injected rejection after real owned runtime close still closes proxy and fixture and preserves undefined", async () => {
  let proxy: Awaited<ReturnType<typeof openProtocolProxy>> | undefined;
  const closed: string[] = [];
  let rejected = false;
  let cleanupFailures: string[] = [];
  try {
    await withCleanup(
      async (own) => {
        const fixture = await openPostgresFixture();
        own("fixture", async () => {
          await fixture.close();
          closed.push("fixture");
        });
        const openedProxy = await openProtocolProxy("passthrough");
        proxy = openedProxy;
        own("proxy", async () => {
          await openedProxy.close();
          closed.push("proxy");
        });
        const db = await fixture.openRuntimeThrough(proxy.endpoint);
        own("runtime", async () => {
          await db.close();
          closed.push("runtime");
          throw new Error("Injected rejection after actual runtime close");
        });
        await expect(db.transaction(async (tx) => (await tx.query("SELECT 1 AS n"))[0]?.n)).resolves.toBe(1);
        throw undefined;
      },
      async (cleanup) => {
        cleanupFailures = cleanup.failed;
      },
    );
  } catch (error) {
    rejected = true;
    expect(error).toBeUndefined();
  }
  expect(rejected).toBe(true);
  expect(closed).toEqual(["runtime", "proxy", "fixture"]);
  expect(cleanupFailures).toEqual(["runtime"]);
  expect(proxy?.observations).toMatchObject({ activeSockets: 0, closed: true });
});
