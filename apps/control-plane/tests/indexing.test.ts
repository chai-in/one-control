import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

test("indexing status dispatches read-only and configuration needs separate approval and selected authority", async () => {
  const db = await openTestDatabase();
  const operator = "indexing-operator-".repeat(4),
    approver = "indexing-approver-".repeat(4);
  const native = await nativeFixture(operator, { features: ["indexing"] });
  const app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: approver,
      ...native.config,
    }),
  );
  const headers = { authorization: `Bearer ${operator}` };
  try {
    await native.prepare(app);
    const device = await native.enroll(app);
    const create = async (command: unknown) =>
      app.inject({
        method: "POST",
        url: "/v1/batches",
        headers: { ...headers, "idempotency-key": randomUUID() },
        payload: {
          targets: [device.deviceId],
          ring: "canary",
          command,
          startsAt: new Date(Date.now() - 1000).toISOString(),
          endsAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });
    const created = await create({ kind: "indexing.status" });
    expect(created.statusCode, created.body).toBe(201);
    const agentHeaders = { authorization: `Bearer ${device.credential}` };
    const claimed = await native.inject(app, {
      method: "POST",
      url: "/v1/agent/native-claim",
      headers: agentHeaders,
      payload: {},
    });
    expect(claimed.statusCode, claimed.body).toBe(200);
    const lease = claimed.json().lease;
    expect(lease.command.kind).toBe("indexing.status");
    expect(lease.moduleId).toBe("indexing");
    const receipt = await native.inject(app, {
      method: "POST",
      url: `/v1/agent/native-jobs/${lease.id}/report`,
      headers: agentHeaders,
      payload: {
        leaseToken: lease.leaseToken,
        state: "succeeded",
        result: { after: { supported: false, service: "not-installed" } },
      },
    });
    expect(receipt.statusCode, receipt.body).toBe(200);
    const change = await create({ kind: "indexing.enable", startup: "automatic-delayed" });
    expect(change.statusCode, change.body).toBe(201);
    const batch = change.json().batchId;
    expect((await db.query("SELECT state FROM jobs WHERE batch_id=$1", [batch]))[0]?.state).toBe(
      "awaiting_approval",
    );
    expect(
      (
        await native.inject(app, {
          method: "POST",
          url: "/v1/agent/native-claim",
          headers: agentHeaders,
          payload: {},
        })
      ).json().lease,
    ).toBeNull();
    const review = await app.inject({ url: `/v1/batches/${batch}`, headers });
    const self = await app.inject({
      method: "POST",
      url: `/v1/batches/${batch}/approve`,
      headers,
      payload: { reviewDigest: review.json().reviewDigest },
    });
    expect(self.statusCode).toBe(403);
    const invalid = await create({ kind: "indexing.enable", startup: "boot" });
    expect(invalid.statusCode).toBe(400);
    const version = (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
      .version;
    const disabled = await app.inject({
      method: "PUT",
      url: `/v1/scopes/${native.scopeId}/server-modules`,
      headers,
      payload: { expectedVersion: version, enabled: [] },
    });
    expect(disabled.statusCode, disabled.body).toBe(200);
    const denied = await create({ kind: "indexing.status" });
    expect(denied.statusCode).toBe(403);
  } finally {
    await app.close();
    await db.close();
    await native.close();
  }
}, 30_000);
