import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { type Database, TransactionCommitUnknownError } from "../src/database.js";
import { ApiError } from "../src/security.js";

test("only the actual adapter error receives the fixed unknown envelope", async () => {
  const db: Database = {
    async query() {
      return [];
    },
    async transaction(work) {
      return work(this);
    },
    async close() {},
  };
  const app = await buildApp(db, parseConfig({ NODE_ENV: "test" }));
  const failures = [
    new TransactionCommitUnknownError(),
    { outcome: "unknown", retryAllowed: false },
    new ApiError(409, "known_conflict"),
    new SyntaxError("SECRET_CANARY"),
    new Error("SECRET_CANARY"),
  ];
  for (const [index, failure] of failures.entries())
    app.post(`/fixture/${index}`, async () => {
      throw failure;
    });
  try {
    const unknown = await app.inject({ method: "POST", url: "/fixture/0" });
    expect(unknown.statusCode).toBe(500);
    expect(unknown.json()).toEqual({
      error: "database_commit_unknown",
      databaseOutcome: "unknown",
      retryAllowed: false,
      requestId: expect.any(String),
    });
    expect(unknown.headers["retry-after"]).toBeUndefined();
    for (const [index, status, code] of [
      [1, 500, "internal_error"],
      [2, 409, "known_conflict"],
      [3, 400, "invalid_request"],
      [4, 500, "internal_error"],
    ] as const) {
      const reply = await app.inject({ method: "POST", url: `/fixture/${index}` });
      expect(reply.statusCode).toBe(status);
      expect(reply.json().error).toBe(code);
      expect(reply.body).not.toContain("SECRET_CANARY");
    }
    expect((await app.inject("/health/live")).json().status).toBe("ok");
  } finally {
    await app.close();
  }
});
test("complete ordinary serialized logs retain incoming request context without canaries", () => {
  const fixture = fileURLToPath(new URL("./fixtures/http-unknown-log.ts", import.meta.url));
  const env = Object.fromEntries(
    ["PATH", "SystemRoot", "TEMP", "TMP"].flatMap((name) =>
      process.env[name] ? [[name, process.env[name]]] : [],
    ),
  );
  const child = spawnSync(process.execPath, ["--import", "tsx", fixture], {
    env,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 131_072,
  });
  expect(child.error).toBeUndefined();
  expect(child.status).toBe(0);
  expect(child.stderr).toBe("");
  expect(child.stdout).not.toMatch(/(?:QUERY|AUTH|COOKIE|BODY|SQL|PARAM|CAUSE)_CANARY/);
  const lines = child.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(lines.find((line) => line.msg === "incoming request")).toMatchObject({
    reqId: "req-1",
    req: { method: "POST" },
  });
  expect(lines.find((line) => line.fixtureResponse)).toMatchObject({
    status: 500,
    callbacks: 1,
    retryAfter: null,
    fixtureResponse: { databaseOutcome: "unknown", retryAllowed: false },
  });
  expect(lines.filter((line) => line.msg === "incoming request")).toHaveLength(3);
  for (const scenario of ["lookalike", "generic"])
    expect(lines.find((line) => line.scenario === scenario)).toMatchObject({
      status: 500,
      callbacks: 1,
      retryAfter: null,
      fixtureResponse: { error: "internal_error" },
    });
});
