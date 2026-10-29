import { randomUUID } from "node:crypto";
import { commandSchema } from "@one-control/protocol";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import type { Database } from "../src/database.js";
import { openTestDatabase } from "./database-fixture.js";

const operator = "product-operator-".repeat(5);
const headers = { authorization: `Bearer ${operator}` };
let db: Database;
let app: FastifyInstance;
let deviceId: string;

beforeAll(async () => {
  db = await openTestDatabase();
  app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: "product-approver-".repeat(5),
    }),
  );
  const issued = await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers, payload: {} });
  expect(issued.statusCode).toBe(201);
  const enrolled = await app.inject({
    method: "POST",
    url: "/v1/agent/enroll",
    payload: { token: issued.json().token, hostname: "product-boundary-fixture" },
  });
  expect(enrolled.statusCode).toBe(201);
  deviceId = enrolled.json().deviceId;
}, 30_000);

afterAll(async () => {
  await app?.close();
  await db?.close();
});

test.each(["crm.status", "crm.update", "android.lock", "amapi.command", "shell.exec"])(
  "%s is rejected before persisting any operation or audit event",
  async (kind) => {
    const before = await db.query("SELECT sequence FROM audit_events ORDER BY sequence");
    expect(commandSchema.safeParse({ kind }).success).toBe(false);
    const response = await app.inject({
      method: "POST",
      url: "/v1/batches",
      headers: { ...headers, "idempotency-key": randomUUID() },
      payload: {
        targets: [deviceId],
        ring: "canary",
        command: { kind },
        startsAt: new Date(Date.now() - 1000).toISOString(),
        endsAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    expect(response.statusCode).toBe(400);
    expect(await db.query("SELECT id FROM batches")).toEqual([]);
    expect(await db.query("SELECT id FROM jobs")).toEqual([]);
    expect(await db.query("SELECT sequence FROM audit_events ORDER BY sequence")).toEqual(before);
  },
);

test("a supported command cannot smuggle removed provider fields", () => {
  expect(
    commandSchema.safeParse({ kind: "inventory.scan", crmPublisherThumbprint: "A".repeat(40) }).success,
  ).toBe(false);
});
