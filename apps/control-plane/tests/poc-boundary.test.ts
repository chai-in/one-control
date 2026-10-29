import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import type { Database } from "../src/database.js";
import { openTestDatabase } from "./database-fixture.js";

const operator = "poc-operator-".repeat(5);
const approver = "poc-approver-".repeat(5);
const viewer = "poc-viewer-".repeat(5);
const headers = { authorization: `Bearer ${operator}` };
let db: Database;
let app: FastifyInstance;
let devices: { deviceId: string; credential: string }[] = [];
let unusedToken = "";
beforeAll(async () => {
  db = await openTestDatabase();
  app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      POC_DEVICE_LIMIT: "2",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: approver,
      DEV_VIEWER_TOKEN: viewer,
    }),
  );
}, 30_000);
afterAll(async () => {
  await app?.close();
  await db?.close();
});
async function issue() {
  const response = await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers, payload: {} });
  expect(response.statusCode).toBe(201);
  return response.json().token as string;
}
const enroll = (token: string) =>
  app.inject({
    method: "POST",
    url: "/v1/agent/enroll",
    payload: { token, hostname: "POC-BOUNDARY-FIXTURE" },
  });

test("the workspace discloses the enforced POC limits only to authorised console users", async () => {
  expect((await app.inject({ url: "/v1/workspace" })).statusCode).toBe(401);
  expect((await app.inject({ url: "/v1/workspace", headers })).json()).toMatchObject({
    deploymentStage: "poc",
    deviceLimit: 2,
  });
  expect(parseConfig({}).DEPLOYMENT_STAGE).toBe("poc");
});
test("a viewer can inspect the POC but cannot enroll or create an operation", async () => {
  const viewerHeaders = { authorization: `Bearer ${viewer}` };
  expect((await app.inject({ url: "/v1/me", headers: viewerHeaders })).json()).toEqual({
    subject: "local-viewer",
    roles: ["viewer"],
  });
  expect((await app.inject({ url: "/v1/devices", headers: viewerHeaders })).statusCode).toBe(200);
  expect(
    (await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers: viewerHeaders, payload: {} }))
      .statusCode,
  ).toBe(403);
  expect(
    (await app.inject({ method: "POST", url: "/v1/batches", headers: viewerHeaders, payload: {} }))
      .statusCode,
  ).toBe(403);
  expect(() =>
    parseConfig({ DEV_OPERATOR_TOKEN: operator, DEV_APPROVER_TOKEN: approver, DEV_VIEWER_TOKEN: operator }),
  ).toThrow();
});
test("concurrent enrolments cannot exceed the limit or consume a rejected token", async () => {
  const tokens = await Promise.all([issue(), issue(), issue()]);
  const responses = await Promise.all(tokens.map(enroll));
  expect(responses.map((value) => value.statusCode).sort()).toEqual([201, 201, 409]);
  devices = responses.filter((value) => value.statusCode === 201).map((value) => value.json());
  const rejectedIndex = responses.findIndex((value) => value.statusCode === 409);
  unusedToken = tokens[rejectedIndex] ?? "";
  expect(responses[rejectedIndex]?.json().error).toBe("poc_device_limit_reached");
  expect((await db.query("SELECT id FROM devices WHERE revoked_at IS NULL")).length).toBe(2);
  expect((await db.query("SELECT hash FROM enrollment_tokens WHERE used_at IS NULL")).length).toBe(1);
  expect(
    (
      await app.inject({
        url: "/v1/workspace",
        headers: { authorization: `Bearer ${devices[0]?.credential}` },
      })
    ).statusCode,
  ).toBe(401);
});
test("POC rings cannot be expanded through the API", async () => {
  for (const ring of ["pilot", "broad"]) {
    expect(
      (
        await app.inject({
          method: "PATCH",
          url: `/v1/devices/${devices[0]?.deviceId}/ring`,
          headers,
          payload: { ring },
        })
      ).json().error,
    ).toBe("poc_canary_only");
    const response = await app.inject({
      method: "POST",
      url: "/v1/batches",
      headers: { ...headers, "idempotency-key": randomUUID() },
      payload: {
        targets: [devices[0]?.deviceId],
        ring,
        command: { kind: "inventory.scan" },
        startsAt: new Date(Date.now() - 1000).toISOString(),
        endsAt: new Date(Date.now() + 3600_000).toISOString(),
      },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().error).toBe("poc_canary_only");
  }
});
test("a pre-existing wider ring cannot dispatch after switching to POC mode", async () => {
  const device = devices[0];
  await db.query("UPDATE devices SET ring='pilot' WHERE id=$1", [device?.deviceId]);
  const claim = await app.inject({
    method: "POST",
    url: "/v1/agent/claim",
    headers: { authorization: `Bearer ${device?.credential}` },
    payload: {},
  });
  expect(claim.statusCode).toBe(200);
  expect(claim.json()).toEqual({ lease: null });
  expect((await db.query("SELECT hash FROM credentials WHERE revoked_at IS NOT NULL")).length).toBe(0);
});
test("explicit revocation frees capacity without invalidating the previously unused token", async () => {
  expect(
    (
      await app.inject({
        method: "POST",
        url: `/v1/devices/${devices[0]?.deviceId}/revoke`,
        headers,
        payload: {},
      })
    ).statusCode,
  ).toBe(200);
  expect((await enroll(unusedToken)).statusCode).toBe(201);
  expect((await db.query("SELECT id FROM devices WHERE revoked_at IS NULL")).length).toBe(2);
});
