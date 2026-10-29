import { afterEach, expect, test, vi } from "vitest";

afterEach(() => {
  vi.restoreAllMocks();
  vi.resetModules();
  vi.doUnmock("../src/config.js");
  vi.doUnmock("../src/database.js");
  vi.doUnmock("../src/app.js");
  vi.doUnmock("../src/coordinator.js");
  vi.doUnmock("fastify");
});
function dependencies() {
  const order: string[] = [];
  const db = {
    close: vi.fn(async () => {
      order.push("db");
    }),
  };
  const app = {
    close: vi.fn(async () => {
      order.push("app");
    }),
    listen: vi.fn(async () => {}),
    log: { error: vi.fn() },
  };
  const migrate = vi.fn(async () => {});
  const openDatabase = vi.fn(async () => db);
  const buildApp = vi.fn(async () => app);
  const reconcile = vi.fn(async () => {});
  vi.doMock("../src/config.js", () => ({
    parseConfig: () => ({ NODE_ENV: "test", DATABASE_URL: "fixture", HOST: "127.0.0.1", PORT: 1 }),
  }));
  vi.doMock("../src/database.js", () => ({
    openDatabase,
    migrate,
    TransactionCommitUnknownError: class extends Error {},
  }));
  vi.doMock("../src/app.js", () => ({ buildApp }));
  vi.doMock("../src/coordinator.js", () => ({ reconcileExpiredJobs: reconcile }));
  const signals: (() => void)[] = [];
  vi.spyOn(process, "on").mockImplementation(((_signal: string, callback: () => void) => {
    signals.push(callback);
    return process;
  }) as typeof process.on);
  let tick: (() => void) | undefined;
  vi.spyOn(globalThis, "setInterval").mockImplementation(((callback: () => void) => {
    tick = callback;
    return { unref() {} };
  }) as unknown as typeof setInterval);
  vi.spyOn(globalThis, "clearInterval").mockImplementation(() => {});
  return { order, db, app, migrate, openDatabase, buildApp, signals, reconcile, tick: () => tick?.() };
}
test.each([undefined, null, false, 0, "", { primary: true }])(
  "actual main preserves startup failure %j and closes database",
  async (error) => {
    const fixture = dependencies();
    fixture.migrate.mockRejectedValue(error);
    const outcome = await import("../src/main.js").then(
      () => ({ failed: false }),
      (caught: unknown) => ({ failed: true, error: caught }),
    );
    expect(outcome).toEqual({ failed: true, error });
    expect(fixture.order).toEqual(["db"]);
  },
);
test("actual main closes database after buildApp failure", async () => {
  const fixture = dependencies();
  const failure = {};
  fixture.buildApp.mockRejectedValue(failure);
  await expect(import("../src/main.js")).rejects.toBe(failure);
  expect(fixture.order).toEqual(["db"]);
});
test("actual main acquisition failure has no database ownership to close", async () => {
  const fixture = dependencies();
  const failure = {};
  fixture.openDatabase.mockRejectedValue(failure);
  await expect(import("../src/main.js")).rejects.toBe(failure);
  expect(fixture.db.close).not.toHaveBeenCalled();
  expect(fixture.buildApp).not.toHaveBeenCalled();
});
test("actual main preserves listen failure despite app and database cleanup failures", async () => {
  const fixture = dependencies();
  const failure = {};
  fixture.app.listen.mockRejectedValue(failure);
  fixture.app.close.mockImplementation(async () => {
    fixture.order.push("app");
    throw null;
  });
  fixture.db.close.mockImplementation(async () => {
    fixture.order.push("db");
    throw false;
  });
  await expect(import("../src/main.js")).rejects.toBe(failure);
  expect(fixture.order).toEqual(["app", "db"]);
});
test("actual main shares repeated shutdown and attempts database after close failure", async () => {
  const fixture = dependencies();
  fixture.app.close.mockImplementation(async () => {
    fixture.order.push("app");
    throw false;
  });
  const oldExit = process.exitCode;
  try {
    await import("../src/main.js");
    fixture.signals[0]?.();
    fixture.signals[1]?.();
    await vi.waitFor(() => expect(fixture.db.close).toHaveBeenCalledTimes(1));
    expect(fixture.app.close).toHaveBeenCalledTimes(1);
    expect(fixture.order).toEqual(["app", "db"]);
  } finally {
    process.exitCode = oldExit;
  }
});
test.each([undefined, null, false, 0, "", {}])(
  "actual migration entrypoint preserves primary %j",
  async (error) => {
    const fixture = dependencies();
    fixture.migrate.mockRejectedValue(error);
    fixture.db.close.mockRejectedValue(new Error("close"));
    const outcome = await import("../src/migrate.js").then(
      () => ({ failed: false }),
      (caught: unknown) => ({ failed: true, error: caught }),
    );
    expect(outcome).toEqual({ failed: true, error });
    expect(fixture.db.close).toHaveBeenCalledTimes(1);
  },
);
test("actual main joins acquired sweep after app-close failure before database cleanup", async () => {
  const fixture = dependencies();
  let release: (() => void) | undefined;
  fixture.reconcile.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
  );
  fixture.app.close.mockImplementation(async () => {
    fixture.order.push("app");
    throw null;
  });
  const oldExit = process.exitCode;
  try {
    await import("../src/main.js");
    fixture.tick();
    fixture.signals[0]?.();
    await Promise.resolve();
    await Promise.resolve();
    expect(fixture.db.close).not.toHaveBeenCalled();
    release?.();
    await vi.waitFor(() => expect(fixture.db.close).toHaveBeenCalledTimes(1));
    expect(fixture.order).toEqual(["app", "db"]);
  } finally {
    process.exitCode = oldExit;
  }
});
test("actual buildApp closes its unreturned partial registration without masking the primary", async () => {
  const failure = {};
  const close = vi.fn(async () => {
    throw null;
  });
  vi.doMock("fastify", () => ({
    default: () => ({
      register: async () => {
        throw failure;
      },
      close,
    }),
  }));
  const { buildApp } = await import("../src/app.js");
  const { parseConfig } = await import("../src/config.js");
  const db = {
    async query() {
      return [];
    },
    async close() {},
    async transaction() {},
  };
  await expect(buildApp(db as never, parseConfig({ NODE_ENV: "test" }))).rejects.toBe(failure);
  expect(close).toHaveBeenCalledTimes(1);
});
test("actual migration success still fails when its acquired database cannot close", async () => {
  const fixture = dependencies();
  const failure = {};
  fixture.db.close.mockRejectedValue(failure);
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  await expect(import("../src/migrate.js")).rejects.toBe(failure);
  expect(log).not.toHaveBeenCalled();
});
test("actual main classifies an unknown sweep without retaining or replaying its callback", async () => {
  const fixture = dependencies();
  const { TransactionCommitUnknownError } = await import("../src/database.js");
  fixture.reconcile.mockRejectedValueOnce(new TransactionCommitUnknownError());
  await import("../src/main.js");
  fixture.tick();
  await vi.waitFor(() =>
    expect(fixture.app.log.error).toHaveBeenCalledWith(
      { databaseOutcome: "unknown", retryAllowed: false },
      "Coordinator commit outcome is unknown; inspect current durable state",
    ),
  );
  expect(fixture.reconcile).toHaveBeenCalledTimes(1);
  fixture.tick();
  await vi.waitFor(() => expect(fixture.reconcile).toHaveBeenCalledTimes(2));
  fixture.signals[0]?.();
  await vi.waitFor(() => expect(fixture.db.close).toHaveBeenCalledTimes(1));
});
