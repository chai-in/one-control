import { expect, test } from "vitest";
import { authorizeRead } from "../../artifacts/src/policy.js";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

test("artifact capabilities follow selection and enrollment revocation", async () => {
  const db = await openTestDatabase();
  const operator = "artifact-operator-".repeat(4);
  const native = await nativeFixture(operator);
  const app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: "artifact-approver-".repeat(4),
      ...native.config,
    }),
  );
  const headers = { authorization: `Bearer ${operator}` };
  try {
    await native.prepare(app);
    const enrolled = await native.enroll(app);
    const request = {
      method: "POST" as const,
      url: "/v1/agent/native-artifact-ticket",
      headers: { authorization: `Bearer ${enrolled.credential}` },
      payload: { id: "inventory", version: "0.1.0", sha256: "a".repeat(64) },
    };
    const response = await app.inject(request);
    expect(response.statusCode, response.body).toBe(200);
    const ticket = response.json();
    const read = await authorizeRead(
      new Request(ticket.url),
      "artifacts.example",
      native.artifactKey,
      Date.now(),
      true,
    );
    expect(read).toMatchObject({ kind: "native-package", sha256: request.payload.sha256, size: 100 });
    expect(
      await authorizeRead(
        new Request(ticket.url),
        "artifacts.example",
        native.artifactKey,
        Date.now() + 61_000,
        true,
      ),
    ).toBeNull();
    expect(
      (await app.inject({ ...request, payload: { ...request.payload, sha256: "b".repeat(64) } })).statusCode,
    ).toBe(403);
    const version = (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
      .version;
    const [selection] = await db.query<{ catalog_id: string }>(
      "SELECT catalog_id FROM native_selections WHERE scope_id=$1",
      [native.scopeId],
    );
    const disabled = await app.inject({
      method: "PUT",
      url: `/v1/scopes/${native.scopeId}/native-modules/selection`,
      headers,
      payload: {
        expectedVersion: version,
        platform: "win-x64",
        catalogId: selection!.catalog_id,
        enabled: {},
        disabled: [],
        allowedPermissions: [],
        bootstrapVersion: "0.1.0",
      },
    });
    expect(disabled.statusCode, disabled.body).toBe(200);
    expect((await app.inject(request)).statusCode).toBe(403);
    const revoke = await app.inject({
      method: "POST",
      url: `/v1/scopes/${native.scopeId}/native-enrollments/${enrolled.enrollmentId}/revoke`,
      headers,
      payload: {},
    });
    expect(revoke.statusCode, revoke.body).toBe(200);
    expect((await app.inject(request)).statusCode).toBe(401);
  } finally {
    await app.close();
    await db.close();
    await native.close();
  }
}, 30_000);
