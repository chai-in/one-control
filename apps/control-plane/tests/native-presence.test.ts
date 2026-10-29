import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

test("enrollment presence survives disabling every optional module but revocation still denies it", async () => {
  const db = await openTestDatabase();
  const operator = "presence-operator-".repeat(4);
  const native = await nativeFixture(operator);
  const app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: "presence-approver-".repeat(4),
      ...native.config,
    }),
  );
  const headers = { authorization: `Bearer ${operator}` };
  try {
    await native.prepare(app);
    const enrolled = await native.enroll(app);
    const version = (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
      .version;
    expect(
      (
        await app.inject({
          method: "PUT",
          url: `/v1/scopes/${native.scopeId}/server-modules`,
          headers,
          payload: { expectedVersion: version, enabled: [] },
        })
      ).statusCode,
    ).toBe(200);
    const request = {
      method: "POST" as const,
      url: "/v1/agent/native-heartbeat",
      headers: { authorization: `Bearer ${enrolled.credential}` },
      payload: {},
    };
    const response = await app.inject(request);
    expect(response.statusCode).toBe(200);
    expect(response.json().enrollmentId).toBe(enrolled.enrollmentId);
    expect(
      (await db.query("SELECT last_seen_at FROM devices WHERE id=$1", [enrolled.deviceId]))[0]?.last_seen_at,
    ).not.toBeNull();
    expect(
      (
        await app.inject({
          method: "POST",
          url: `/v1/scopes/${native.scopeId}/native-enrollments/${enrolled.enrollmentId}/revoke`,
          headers,
          payload: {},
        })
      ).statusCode,
    ).toBe(200);
    expect((await app.inject(request)).statusCode).toBe(401);
  } finally {
    await app.close();
    await db.close();
    await native.close();
  }
}, 30_000);
