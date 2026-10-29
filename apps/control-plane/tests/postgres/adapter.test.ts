import pg from "pg";
import { beforeEach, expect, test, vi } from "vitest";
import {
  openDatabase,
  TransactionAbortedError,
  TransactionCommitUnknownError,
  type TransactionQuery,
} from "../../src/database.js";

const seam = vi.hoisted(() => ({
  query: undefined as undefined | ((sql: string) => Promise<unknown>),
  acquireFailed: false,
  acquireError: undefined as unknown,
  releaseFailed: false,
  releaseAfterDisposition: false,
  disposed: 0,
  endPending: false,
  poolEndPending: false,
  releaseCalls: [] as unknown[],
  endCalls: 0,
  queries: [] as string[],
}));
vi.mock("pg", async (original) => {
  const actual = await original<typeof import("pg")>();
  const { EventEmitter } = await import("node:events");
  class Client extends EventEmitter {
    async query(sql: string) {
      seam.queries.push(sql);
      if (seam.query) return seam.query(sql);
      return { rows: [], command: sql.split(" ")[0] };
    }
    release(value: unknown) {
      seam.releaseCalls.push(value);
      if (seam.releaseFailed && !seam.releaseAfterDisposition) throw new Error("synthetic release defect");
      seam.disposed++;
      if (seam.releaseFailed) throw new Error("synthetic release defect");
    }
    async end() {
      seam.endCalls++;
      if (seam.endPending) await new Promise(() => {});
    }
  }
  class Pool extends EventEmitter {
    async connect() {
      if (seam.acquireFailed) throw seam.acquireError;
      return new Client();
    }
    async query(sql: string) {
      return new Client().query(sql);
    }
    async end() {
      if (seam.poolEndPending) await new Promise(() => {});
    }
  }
  return { ...actual, default: { ...actual.default, Pool } };
});
beforeEach(() => {
  seam.query = undefined;
  seam.acquireFailed = false;
  seam.releaseFailed = false;
  seam.releaseAfterDisposition = false;
  seam.disposed = 0;
  seam.endPending = false;
  seam.poolEndPending = false;
  seam.releaseCalls = [];
  seam.queries = [];
  seam.endCalls = 0;
});
const success = (sql: string) => ({ rows: [], command: sql.split(" ")[0] });
async function beforeTransaction<T>(work: (tx: TransactionQuery) => Promise<T>): Promise<T> {
  const client = await new pg.Pool().connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '5s'");
    const result = await work({ query: async (sql, params = []) => (await client.query(sql, params)).rows });
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
test("retained synthetic before control replaces the primary and committed result with cleanup errors", async () => {
  const primary = { original: true };
  const rollback = new Error("before rollback replacement");
  seam.query = async (sql) => {
    if (sql === "ROLLBACK") throw rollback;
    return success(sql);
  };
  await expect(
    beforeTransaction(async () => {
      throw primary;
    }),
  ).rejects.toBe(rollback);
  seam.query = undefined;
  seam.releaseFailed = true;
  await expect(beforeTransaction(async () => 42)).rejects.toThrow("synthetic release defect");
});
test("retained synthetic before control returns false success for ROLLBACK and permits escaped transport", async () => {
  seam.query = async (sql) => ({
    ...success(sql),
    command: sql === "COMMIT" ? "ROLLBACK" : sql.split(" ")[0],
  });
  let escaped: TransactionQuery | undefined;
  await expect(
    beforeTransaction(async (tx) => {
      escaped = tx;
      return 42;
    }),
  ).resolves.toBe(42);
  if (!escaped) throw new Error("Before callback missing");
  const count = seam.queries.length;
  await escaped.query("SELECT 1");
  expect(seam.queries).toHaveLength(count + 1);
});
test("retained synthetic before control loses COMMIT uncertainty and releases without explicit retirement", async () => {
  const transport = new Error("before transport");
  seam.query = async (sql) => {
    if (sql === "COMMIT") throw transport;
    return success(sql);
  };
  await expect(beforeTransaction(async () => 42)).rejects.toBe(transport);
  expect(seam.queries).toContain("ROLLBACK");
  expect(seam.releaseCalls).toEqual([undefined]);
});

test.each([undefined, null, false, 0, "original", { marker: "original" }])(
  "synthetic rollback and release defects preserve exact primary value %j",
  async (primary) => {
    const db = await openDatabase("synthetic");
    seam.query = async (sql) => {
      if (sql === "ROLLBACK") throw new Error("rollback defect");
      return success(sql);
    };
    seam.releaseFailed = true;
    let caught = false;
    await db
      .transaction(async () => {
        throw primary;
      })
      .catch((error) => {
        caught = true;
        expect(error).toBe(primary);
      });
    expect(caught).toBe(true);
    expect(seam.queries).not.toContain("COMMIT");
    expect(seam.releaseCalls).toEqual([true]);
    expect(seam.endCalls).toBe(1);
    const count = seam.queries.length;
    await expect(db.query("SELECT 1")).rejects.toThrow("unavailable");
    await expect(db.transaction(async () => 1)).rejects.toThrow("unavailable");
    expect(seam.queries).toHaveLength(count);
    await db.close();
  },
);
test("synthetic confirmed commit survives release failure and a new handle recovers", async () => {
  const db = await openDatabase("synthetic");
  seam.releaseFailed = true;
  await expect(db.transaction(async () => 42)).resolves.toBe(42);
  expect(seam.releaseCalls).toEqual([false]);
  await expect(db.query("SELECT 1")).rejects.toThrow("unavailable");
  seam.releaseFailed = false;
  const replacement = await openDatabase("synthetic");
  await expect(replacement.transaction(async () => 7)).resolves.toBe(7);
  await replacement.close();
  await db.close();
});
test("synthetic diagnostic failure cannot replace a primary or confirmed commit", async () => {
  const write = vi.spyOn(process.stderr, "write").mockImplementation(() => {
    throw new Error("synthetic diagnostic failure");
  });
  try {
    const primary = { original: true };
    const failed = await openDatabase("synthetic");
    seam.releaseFailed = true;
    seam.query = async (sql) => {
      if (sql === "ROLLBACK") throw new Error("synthetic rollback failure");
      return success(sql);
    };
    await expect(
      failed.transaction(async () => {
        throw primary;
      }),
    ).rejects.toBe(primary);
    await failed.close();
    const committed = await openDatabase("synthetic");
    await expect(committed.transaction(async () => 42)).resolves.toBe(42);
    await expect(committed.query("SELECT 1")).rejects.toThrow("unavailable");
    await committed.close();
  } finally {
    write.mockRestore();
  }
});
test("synthetic release defect after simulated pool disposition preserves COMMIT and never releases twice", async () => {
  const db = await openDatabase("synthetic");
  seam.releaseFailed = true;
  seam.releaseAfterDisposition = true;
  await expect(db.transaction(async () => 42)).resolves.toBe(42);
  expect(seam.releaseCalls).toEqual([false]);
  expect(seam.disposed).toBe(1);
  expect(seam.endCalls).toBe(1);
  await expect(db.transaction(async () => 1)).rejects.toThrow("unavailable");
  await db.close();
});
test("synthetic rollback, client end and pool close deadlines are bounded and clear owned timers", async () => {
  vi.useFakeTimers();
  try {
    const db = await openDatabase("synthetic");
    const primary = { original: true };
    seam.query = async (sql) => (sql === "ROLLBACK" ? new Promise(() => {}) : success(sql));
    seam.releaseFailed = true;
    seam.endPending = true;
    const outcome = db
      .transaction(async () => {
        throw primary;
      })
      .catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(10_001);
    expect(await outcome).toBe(primary);
    expect(seam.releaseCalls).toEqual([true]);
    expect(vi.getTimerCount()).toBe(0);
    seam.poolEndPending = true;
    const closing = db.close().catch((error: unknown) => error);
    expect(db.close().catch(() => {})).toBeInstanceOf(Promise);
    await vi.advanceTimersByTimeAsync(5001);
    expect(await closing).toBeInstanceOf(Error);
    expect(vi.getTimerCount()).toBe(0);
    await expect(db.query("SELECT 1")).rejects.toThrow("unavailable");
  } finally {
    vi.useRealTimers();
  }
});
test.each(["BEGIN", "SET LOCAL lock_timeout = '5s'"])(
  "synthetic %s failure never enters work or sends COMMIT",
  async (boundary) => {
    const original = { boundary };
    const db = await openDatabase("synthetic");
    seam.query = async (sql) => {
      if (sql === boundary) throw original;
      return success(sql);
    };
    let calls = 0;
    await expect(
      db.transaction(async () => {
        calls++;
      }),
    ).rejects.toBe(original);
    expect(calls).toBe(0);
    expect(seam.queries).not.toContain("COMMIT");
    await db.close();
  },
);
test("synthetic acquisition preserves undefined and has no client to release", async () => {
  const db = await openDatabase("synthetic");
  seam.acquireFailed = true;
  seam.acquireError = undefined;
  let caught = false;
  await db
    .transaction(async () => 1)
    .catch((error) => {
      caught = true;
      expect(error).toBeUndefined();
    });
  expect(caught).toBe(true);
  expect(seam.releaseCalls).toEqual([]);
  expect(seam.queries).toEqual([]);
  await db.close();
});
test.each([
  Object.assign(new Error("transport"), { code: "ECONNRESET" }),
  { severity: "ERROR", code: "23503" },
  Object.assign(new pg.DatabaseError("unknown", 0, "error"), { severity: "ERROR", code: "40003" }),
  Object.assign(new pg.DatabaseError("fatal", 0, "error"), { severity: "FATAL", code: "23503" }),
])("synthetic unproved COMMIT rejection remains unknown", async (original) => {
  const db = await openDatabase("synthetic");
  seam.query = async (sql) => {
    if (sql === "COMMIT") throw original;
    return success(sql);
  };
  let calls = 0;
  const error = await db
    .transaction(async () => {
      calls++;
    })
    .catch((error: unknown) => error);
  expect(error).toBeInstanceOf(TransactionCommitUnknownError);
  expect((error as Error).cause).toBeUndefined();
  expect(Object.keys(error as object)).not.toContain("cause");
  expect(calls).toBe(1);
  expect(seam.queries).not.toContain("ROLLBACK");
  expect(seam.releaseCalls).toEqual([true]);
  await db.close();
});
test("synthetic ROLLBACK command tag never returns the callback value", async () => {
  const db = await openDatabase("synthetic");
  seam.query = async (sql) => ({
    ...success(sql),
    command: sql === "COMMIT" ? "ROLLBACK" : sql.split(" ")[0],
  });
  await expect(db.transaction(async () => "would be false success")).rejects.toBeInstanceOf(
    TransactionAbortedError,
  );
  expect(seam.releaseCalls).toEqual([false]);
  await db.close();
});
test.each([false, true])("query-only capability closes before settlement with failure=%s", async (fail) => {
  const db = await openDatabase("synthetic");
  let escaped: TransactionQuery | undefined;
  await db
    .transaction(async (tx) => {
      escaped = tx;
      expect(Object.keys(tx)).toEqual(["query"]);
      if (fail) throw new Error("work");
    })
    .catch(() => {});
  const count = seam.queries.length;
  if (!escaped) throw new Error("Callback did not expose its handle");
  await expect(escaped.query("SELECT 1")).rejects.toThrow("callback has closed");
  expect(seam.queries).toHaveLength(count);
  await db.close();
});
test.each([false, true])(
  "PGlite capability closes and preserves exclusive snapshots with failure=%s",
  async (fail) => {
    const db = await openDatabase("local");
    let escaped: TransactionQuery | undefined;
    await db.query("CREATE TABLE marker(id int)");
    await db
      .transaction(async (tx) => {
        escaped = tx;
        expect(Object.keys(tx)).toEqual(["query"]);
        await tx.query("INSERT INTO marker VALUES(1)");
        if (fail) throw new Error("work");
      })
      .catch(() => {});
    if (!escaped || !db.snapshotLocal) throw new Error("Local callback capability missing");
    await expect(escaped.query("INSERT INTO marker VALUES(2)")).rejects.toThrow("callback has closed");
    expect(await db.query("SELECT id FROM marker")).toEqual(fail ? [] : [{ id: 1 }]);
    expect((await db.snapshotLocal()).size).toBeGreaterThan(0);
    await db.close();
  },
);
