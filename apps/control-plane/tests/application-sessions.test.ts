import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

test("selected-user updates bind one computer and logon, require independent approval, and preserve uncertainty", async () => {
  const db = await openTestDatabase();
  const operator = "session-operator-".repeat(4),
    approver = "session-approver-".repeat(4);
  const native = await nativeFixture(operator, { features: ["user-session-host", "application-updates"] });
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
    const agentHeaders = { authorization: `Bearer ${device.credential}` };
    const session = { sessionId: 7, userSid: "S-1-5-21-10-20-30-1001", logonId: "00000000abcdef12" };
    const create = (command: unknown, targets = [device.deviceId]) =>
      app.inject({
        method: "POST",
        url: "/v1/batches",
        headers: { ...headers, "idempotency-key": randomUUID() },
        payload: {
          targets,
          ring: "canary",
          command,
          startsAt: new Date(Date.now() - 1000).toISOString(),
          endsAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });
    const claim = () =>
      native.inject(app, {
        method: "POST",
        url: "/v1/agent/native-claim",
        headers: agentHeaders,
        payload: {},
      });
    const report = (lease: { id: string; leaseToken: string }, state: string, result: unknown) =>
      native.inject(app, {
        method: "POST",
        url: `/v1/agent/native-jobs/${lease.id}/report`,
        headers: agentHeaders,
        payload: { leaseToken: lease.leaseToken, state, result },
      });
    const listing = await create({ kind: "sessions.list" });
    expect(listing.statusCode, listing.body).toBe(201);
    const listed = (await claim()).json().lease;
    expect(listed.moduleId).toBe("user-session-host");
    expect((await report(listed, "succeeded", { sessions: [], partial: false })).statusCode).toBe(200);
    const check = await create({ kind: "applications.check", session });
    expect(check.statusCode, check.body).toBe(201);
    const checked = (await claim()).json().lease;
    expect(checked.moduleId).toBe("application-updates");
    expect(checked.command.session).toEqual(session);
    expect(
      (
        await report(checked, "failed", {
          reason: "selected_user_provider_unavailable",
          executionStarted: false,
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (await create({ kind: "applications.check", session: { ...session, logonId: "" } })).statusCode,
    ).toBe(400);
    expect(
      (await create({ kind: "applications.check", session }, [device.deviceId, randomUUID()])).statusCode,
    ).toBe(400);
    const command = { kind: "applications.upgrade", session, packageId: "Example.App", version: "1.2.3" };
    expect((await create({ ...command, version: "latest" })).statusCode).toBe(400);
    const created = await create(command);
    expect(created.statusCode, created.body).toBe(201);
    const batch = created.json().batchId;
    expect((await claim()).json().lease).toBeNull();
    const review = (await app.inject({ url: `/v1/batches/${batch}`, headers })).json();
    const approve = (authorization: string) =>
      app.inject({
        method: "POST",
        url: `/v1/batches/${batch}/approve`,
        headers: { authorization },
        payload: { reviewDigest: review.reviewDigest },
      });
    expect((await approve(`Bearer ${operator}`)).statusCode).toBe(403);
    const approved = await approve(`Bearer ${approver}`);
    expect(approved.statusCode, approved.body).toBe(200);
    const lease = (await claim()).json().lease;
    expect(lease.command).toEqual(command);
    expect(
      (
        await report(lease, "indeterminate", {
          reason: "user_provider_outcome_unresolved",
          executionStarted: true,
          session,
        })
      ).statusCode,
    ).toBe(200);
    expect((await claim()).json().lease).toBeNull();
    expect((await db.query("SELECT state FROM jobs WHERE batch_id=$1", [batch]))[0]?.state).toBe(
      "indeterminate",
    );
  } finally {
    await app.close();
    await db.close();
    await native.close();
  }
}, 30_000);
