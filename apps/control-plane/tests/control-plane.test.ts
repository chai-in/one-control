import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance, InjectOptions } from "fastify";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { reconcileExpiredJobs } from "../src/coordinator.js";
import type { Database } from "../src/database.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

const operator = "operator-".repeat(8);
const approver = "approver-".repeat(8);
let db: Database;
let app: FastifyInstance;
let deviceId: string;
let credential: string;
let native: Awaited<ReturnType<typeof nativeFixture>>;
const headers = { authorization: `Bearer ${operator}` };
function window() {
  return {
    startsAt: new Date(Date.now() - 1000).toISOString(),
    endsAt: new Date(Date.now() + 3600_000).toISOString(),
  };
}
async function batch(command: unknown, targets = [deviceId], ring = "canary") {
  return app.inject({
    method: "POST",
    url: "/v1/batches",
    headers: { ...headers, "idempotency-key": randomUUID() },
    payload: { targets, ring, command, ...window() },
  });
}
async function enroll() {
  const issued = await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers, payload: {} });
  expect(issued.statusCode).toBe(201);
  return app.inject({
    method: "POST",
    url: "/v1/agent/enroll",
    payload: { token: issued.json().token, hostname: "test-workstation" },
  });
}
beforeAll(async () => {
  db = await openTestDatabase();
  native = await nativeFixture(operator);
  app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEPLOYMENT_STAGE: "production",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: approver,
      ...native.config,
    }),
  );
  app.get("/v1/agent/rate-test", { config: { rateLimit: { max: 1, timeWindow: "1 minute" } } }, async () => ({
    ok: true,
  }));
  await native.prepare(app);
  const response = await enroll();
  expect(response.statusCode).toBe(201);
  ({ deviceId, credential } = response.json());
}, 30_000);
afterAll(async () => {
  await app?.close();
  await db?.close();
  await native?.close();
});
describe("trust and enrollment", () => {
  test("EMA inventory requires an administrator and remains optional", async () => {
    const url = "/v1/integrations/ema/endpoints";
    expect((await app.inject({ url })).statusCode).toBe(401);
    expect((await app.inject({ url, headers: { authorization: `Bearer ${credential}` } })).statusCode).toBe(
      401,
    );
    const response = await app.inject({ url: `${url}?scopeId=${native.scopeId}`, headers });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ configured: false, endpoints: [] });
  });
  test("verified devices behind one NAT address receive independent rate budgets", async () => {
    const firstHeaders = { authorization: `Bearer ${credential}` };
    expect((await app.inject({ url: "/v1/agent/rate-test", headers: firstHeaders })).statusCode).toBe(200);
    expect((await app.inject({ url: "/v1/agent/rate-test", headers: firstHeaders })).statusCode).toBe(429);
    const second = (await enroll()).json();
    expect(
      (
        await app.inject({
          url: "/v1/agent/rate-test",
          headers: { authorization: `Bearer ${second.credential}` },
        })
      ).statusCode,
    ).toBe(200);
  });
  test("authentication cannot be omitted or substituted with an agent token", async () => {
    expect((await app.inject({ url: "/v1/devices" })).statusCode).toBe(401);
    expect(
      (await app.inject({ url: "/v1/devices", headers: { authorization: `Bearer ${credential}` } }))
        .statusCode,
    ).toBe(401);
  });
  test("enrollment tokens are single-use under concurrent requests", async () => {
    const issued = await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers, payload: {} });
    const requests = await Promise.all(
      [1, 2].map(() =>
        app.inject({
          method: "POST",
          url: "/v1/agent/enroll",
          payload: { token: issued.json().token, hostname: "concurrent" },
        }),
      ),
    );
    expect(requests.map((r) => r.statusCode).sort()).toEqual([201, 401]);
  });
  test("production rejects local databases and development credentials", () => {
    expect(() => parseConfig({ NODE_ENV: "production" })).toThrow();
    expect(() =>
      parseConfig({ HOST: "0.0.0.0", DEV_OPERATOR_TOKEN: operator, DEV_APPROVER_TOKEN: approver }),
    ).toThrow();
    expect(() => parseConfig({ DEV_OPERATOR_TOKEN: operator, DEV_APPROVER_TOKEN: operator })).toThrow();
  });
  test("production requires verified PostgreSQL TLS", () => {
    const production = {
      NODE_ENV: "production",
      DATABASE_URL: "postgres://one-control@db.example/one-control?sslmode=verify-full",
      OIDC_ISSUER: "https://identity.example",
      OIDC_AUDIENCE: "one-control",
      RELEASE_PUBLIC_KEY_FILE: "/run/secrets/release.pem",
      ARTIFACT_HOSTS: "updates.example",
      OPERATOR_SUBJECTS: "operator",
      APPROVER_SUBJECTS: "approver",
    };
    expect(parseConfig(production).NODE_ENV).toBe("production");
    for (const DATABASE_URL of [
      "postgres://one-control@db.example/one-control",
      "postgres://one-control@db.example/one-control?sslmode=no-verify",
      "postgres://one-control@db.example/one-control?sslmode=verify-full&ssl=false",
      "postgres://one-control@db.example/one-control?sslmode=verify-full&sslmode=disable",
    ])
      expect(() => parseConfig({ ...production, DATABASE_URL })).toThrow();
    expect(() => parseConfig({ ...production, NODE_TLS_REJECT_UNAUTHORIZED: "0" })).toThrow();
  });
  test("durably chosen credentials survive a lost rotation response without replaying issuance", async () => {
    const victim = (await enroll()).json();
    const auth = { authorization: `Bearer ${victim.credential}` };
    expect(
      (await app.inject({ method: "POST", url: "/v1/agent/rotate", headers: auth, payload: {} })).statusCode,
    ).toBe(410);
    const next = randomBytes(32).toString("base64url");
    const credentialHash = createHash("sha256").update(next).digest("hex");
    const request = {
      method: "POST" as const,
      url: "/v1/agent/credentials/rotate",
      headers: auth,
      payload: { credentialHash },
    };
    const responses = await Promise.all([app.inject(request), app.inject(request)]);
    expect(responses.map((response) => response.statusCode)).toEqual([200, 200]);
    expect(responses[0]?.body).not.toContain(next);
    const issued = await db.query("SELECT expires_at FROM credentials WHERE hash=$1", [credentialHash]);
    const overlap = await db.query("SELECT expires_at FROM credentials WHERE device_id=$1 AND hash<>$2", [
      victim.deviceId,
      credentialHash,
    ]);
    expect(issued).toHaveLength(1);
    expect((await app.inject(request)).statusCode).toBe(200);
    expect(await db.query("SELECT expires_at FROM credentials WHERE hash=$1", [credentialHash])).toEqual(
      issued,
    );
    expect(
      await db.query("SELECT expires_at FROM credentials WHERE device_id=$1 AND hash<>$2", [
        victim.deviceId,
        credentialHash,
      ]),
    ).toEqual(overlap);
    await db.query(
      "UPDATE credentials SET expires_at=now()-interval '1 second' WHERE device_id=$1 AND hash<>$2",
      [victim.deviceId, credentialHash],
    );
    expect(
      (await app.inject({ method: "POST", url: "/v1/agent/heartbeat", headers: auth, payload: {} }))
        .statusCode,
    ).toBe(401);
    const nextAuth = { authorization: `Bearer ${next}` };
    expect(
      (await app.inject({ method: "POST", url: "/v1/agent/heartbeat", headers: nextAuth, payload: {} }))
        .statusCode,
    ).toBe(200);
    await app.inject({ method: "POST", url: `/v1/devices/${victim.deviceId}/revoke`, headers });
    expect(
      (await app.inject({ method: "POST", url: "/v1/agent/heartbeat", headers: nextAuth, payload: {} }))
        .statusCode,
    ).toBe(401);
  });
});
describe("native scoped dispatch", () => {
  beforeAll(async () => {
    ({ deviceId, credential } = await native.enroll(app));
  }, 30_000);
  const nativeInject = (options: InjectOptions) => native.inject(app, options);
  async function enroll() {
    const enrolled = await native.enroll(app);
    return { statusCode: 201, json: () => enrolled };
  }
  async function reviewDigest(id: string) {
    const response = await nativeInject({ url: `/v1/batches/${id}`, headers });
    expect(response.statusCode).toBe(200);
    return response.json().reviewDigest;
  }
  test("approval exposes the exact command and every target, and rejects unreviewed content", async () => {
    const second = (await enroll()).json();
    const command = { kind: "windows.install", updates: [{ id: randomUUID(), revision: 7 }] };
    const created = await batch(command, [deviceId, second.deviceId]);
    expect(created.statusCode).toBe(201);
    const id = created.json().batchId;
    const reviewUrl = `/v1/batches/${id}`;
    expect((await nativeInject({ url: reviewUrl })).statusCode).toBe(401);
    const review = (await nativeInject({ url: reviewUrl, headers })).json();
    expect(review.command).toEqual(command);
    expect(review.createdBy).toBeTruthy();
    expect(review.targets.map((target: { deviceId: string }) => target.deviceId).sort()).toEqual(
      [deviceId, second.deviceId].sort(),
    );
    const approval = {
      method: "POST" as const,
      url: `${reviewUrl}/approve`,
      headers: { authorization: `Bearer ${approver}` },
    };
    expect((await nativeInject({ ...approval, payload: {} })).statusCode).toBe(400);
    expect((await nativeInject({ ...approval, payload: { reviewDigest: "0".repeat(64) } })).statusCode).toBe(
      409,
    );
    expect((await db.query("SELECT approved_by FROM batches WHERE id=$1", [id]))[0]?.approved_by).toBeNull();
    expect(
      (await nativeInject({ ...approval, payload: { reviewDigest: review.reviewDigest } })).statusCode,
    ).toBe(200);
    const feed = (await nativeInject({ url: "/v1/jobs", headers })).json().jobs;
    expect(feed.find((job: { batch_id: string }) => job.batch_id === id).command).toEqual(command);
    expect(
      (await nativeInject({ ...approval, payload: { reviewDigest: review.reviewDigest } })).statusCode,
    ).toBe(409);
    await nativeInject({ method: "POST", url: `${reviewUrl}/cancel`, headers });
  });
  test("offline computers have expired work reconciled once by competing coordinators", async () => {
    const offline = (await enroll()).json();
    const operation = await batch({ kind: "windows.install", updates: [{ id: randomUUID(), revision: 1 }] }, [
      offline.deviceId,
    ]);
    const id = operation.json().batchId;
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/batches/${id}/approve`,
          headers: { authorization: `Bearer ${approver}` },
          payload: { reviewDigest: await reviewDigest(id) },
        })
      ).statusCode,
    ).toBe(200);
    const auth = { authorization: `Bearer ${offline.credential}` };
    const lease = (
      await nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} })
    ).json().lease;
    const pending = await batch({ kind: "inventory.scan" }, [offline.deviceId]);
    await db.query("UPDATE jobs SET lease_expires_at=now()-interval '1 minute' WHERE id=$1", [lease.id]);
    await db.query(
      "UPDATE jobs SET starts_at=now()-interval '2 hours',ends_at=now()-interval '1 hour' WHERE id=$1",
      [pending.json().jobIds[0]],
    );
    await Promise.all([reconcileExpiredJobs(db), reconcileExpiredJobs(db)]);
    expect((await db.query("SELECT state FROM jobs WHERE id=$1", [lease.id]))[0]?.state).toBe(
      "indeterminate",
    );
    expect((await db.query("SELECT state FROM jobs WHERE id=$1", [pending.json().jobIds[0]]))[0]?.state).toBe(
      "cancelled",
    );
    expect(
      await db.query("SELECT sequence FROM audit_events WHERE subject=$1 AND action='job.lease_expired'", [
        lease.id,
      ]),
    ).toHaveLength(1);
    expect(
      (
        await nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} })
      ).json().lease,
    ).toBeNull();
  });
  test("idempotency replay returns the same jobs; changed input conflicts", async () => {
    const payload = { targets: [deviceId], ring: "canary", command: { kind: "inventory.scan" }, ...window() };
    const idempotentHeaders = { ...headers, "idempotency-key": randomUUID() };
    const first = await nativeInject({
      method: "POST",
      url: "/v1/batches",
      headers: idempotentHeaders,
      payload,
    });
    expect(first.statusCode).toBe(201);
    const second = await nativeInject({
      method: "POST",
      url: "/v1/batches",
      headers: idempotentHeaders,
      payload,
    });
    expect(second.json()).toEqual(first.json());
    expect(
      (
        await nativeInject({
          method: "POST",
          url: "/v1/batches",
          headers: idempotentHeaders,
          payload: { ...payload, command: { kind: "windows.scan" } },
        })
      ).statusCode,
    ).toBe(409);
  });
  test("concurrent pollers receive at most one lease per computer", async () => {
    const auth = { authorization: `Bearer ${credential}` };
    const responses = await Promise.all(
      [1, 2].map(() =>
        nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} }),
      ),
    );
    expect(responses.map((r) => r.statusCode)).toEqual([200, 200]);
    const leases = responses.map((r) => r.json().lease).filter(Boolean);
    expect(leases).toHaveLength(1);
    const lease = leases[0];
    const stale = await nativeInject({
      method: "POST",
      url: `/v1/agent/native-jobs/${lease.id}/report`,
      headers: auth,
      payload: { leaseToken: "A".repeat(43), state: "succeeded", result: { ok: true } },
    });
    expect(stale.statusCode).toBe(409);
    const receipt = {
      leaseToken: lease.leaseToken,
      state: "succeeded",
      result: { hostname: "test-workstation", rebootPending: false },
    };
    const result = await nativeInject({
      method: "POST",
      url: `/v1/agent/native-jobs/${lease.id}/report`,
      headers: auth,
      payload: receipt,
    });
    expect(result.statusCode).toBe(200);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/agent/native-jobs/${lease.id}/report`,
          headers: auth,
          payload: receipt,
        })
      ).statusCode,
    ).toBe(200);
  });
  test("mutations require a separate approver, and expired mutations never requeue", async () => {
    const response = await batch({ kind: "windows.install", updates: [{ id: randomUUID(), revision: 1 }] });
    expect(response.statusCode).toBe(201);
    const { batchId, jobIds } = response.json();
    expect(
      (await nativeInject({ method: "POST", url: `/v1/batches/${batchId}/approve`, headers })).statusCode,
    ).toBe(403);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: "/v1/agent/native-claim",
          headers: { authorization: `Bearer ${credential}` },
          payload: {},
        })
      ).json().lease,
    ).toBeNull();
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/batches/${batchId}/approve`,
          headers: { authorization: `Bearer ${approver}` },
          payload: { reviewDigest: await reviewDigest(batchId) },
        })
      ).statusCode,
    ).toBe(200);
    const leaseResponse = await nativeInject({
      method: "POST",
      url: "/v1/agent/native-claim",
      headers: { authorization: `Bearer ${credential}` },
      payload: {},
    });
    expect(leaseResponse.json().lease.id).toBe(jobIds[0]);
    await db.query("UPDATE jobs SET lease_expires_at=now()-interval '1 minute' WHERE id=$1", [jobIds[0]]);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: "/v1/agent/native-claim",
          headers: { authorization: `Bearer ${credential}` },
          payload: {},
        })
      ).json().lease,
    ).toBeNull();
    expect((await db.query("SELECT state FROM jobs WHERE id=$1", [jobIds[0]]))[0]?.state).toBe(
      "indeterminate",
    );
    const another = await batch({ kind: "inventory.scan" });
    expect(another.statusCode).toBe(201);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: "/v1/agent/native-claim",
          headers: { authorization: `Bearer ${credential}` },
          payload: {},
        })
      ).json().lease,
    ).toBeNull();
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/jobs/${jobIds[0]}/reconcile`,
          headers,
          payload: { state: "failed", evidence: "Test verified no installer remains running on the target." },
        })
      ).statusCode,
    ).toBe(200);
    const resumed = (
      await nativeInject({
        method: "POST",
        url: "/v1/agent/native-claim",
        headers: { authorization: `Bearer ${credential}` },
        payload: {},
      })
    ).json().lease;
    expect(resumed.id).toBe(another.json().jobIds[0]);
    await nativeInject({
      method: "POST",
      url: `/v1/agent/native-jobs/${resumed.id}/report`,
      headers: { authorization: `Bearer ${credential}` },
      payload: { leaseToken: resumed.leaseToken, state: "succeeded", result: {} },
    });
  });
  test("expired native reads require new admission and old fencing tokens lose authority", async () => {
    const response = await batch({ kind: "inventory.scan" });
    expect(response.statusCode).toBe(201);
    const auth = { authorization: `Bearer ${credential}` };
    const original = (
      await nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} })
    ).json().lease;
    await db.query("UPDATE jobs SET lease_expires_at=now()-interval '1 minute' WHERE id=$1", [original.id]);
    expect(
      (
        await nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} })
      ).json().lease,
    ).toBeNull();
    expect((await db.query("SELECT state FROM jobs WHERE id=$1", [original.id]))[0]?.state).toBe("failed");
    const replacement = await batch({ kind: "inventory.scan" });
    expect(replacement.statusCode).toBe(201);
    const retry = (
      await nativeInject({ method: "POST", url: "/v1/agent/native-claim", headers: auth, payload: {} })
    ).json().lease;
    expect(retry.id).toBe(replacement.json().jobIds[0]);
    expect(retry.leaseToken).not.toBe(original.leaseToken);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/agent/native-jobs/${original.id}/renew`,
          headers: auth,
          payload: { leaseToken: original.leaseToken },
        })
      ).statusCode,
    ).toBe(409);
    await nativeInject({
      method: "POST",
      url: `/v1/agent/native-jobs/${retry.id}/report`,
      headers: auth,
      payload: { leaseToken: retry.leaseToken, state: "succeeded", result: {} },
    });
  });
  test("a later ring cannot be approved without a successful previous ring", async () => {
    const enrolled = await enroll();
    const pilot = enrolled.json();
    await nativeInject({
      method: "PATCH",
      url: `/v1/scopes/${native.scopeId}/native-enrollments/${pilot.enrollmentId}/ring`,
      headers,
      payload: {
        ring: "pilot",
        expectedVersion: (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
          .version,
      },
    });
    const response = await batch(
      { kind: "winget.upgrade", packageId: "Microsoft.PowerToys", version: "0.1.0" },
      [pilot.deviceId],
      "pilot",
    );
    expect(response.statusCode).toBe(201);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/batches/${response.json().batchId}/approve`,
          headers: { authorization: `Bearer ${approver}` },
          payload: { reviewDigest: await reviewDigest(response.json().batchId) },
        })
      ).statusCode,
    ).toBe(409);
  });
  test("rollout ring cannot change beneath unfinished approved work", async () => {
    const computer = (await enroll()).json();
    const pending = await batch({ kind: "inventory.scan" }, [computer.deviceId]);
    const request = {
      method: "PATCH" as const,
      url: `/v1/scopes/${native.scopeId}/native-enrollments/${computer.enrollmentId}/ring`,
      headers,
      payload: {
        ring: "pilot",
        expectedVersion: (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
          .version,
      },
    };
    expect((await nativeInject(request)).statusCode).toBe(409);
    await nativeInject({ method: "POST", url: `/v1/batches/${pending.json().batchId}/cancel`, headers });
    expect((await nativeInject(request)).statusCode).toBe(200);
  });
  test("latest audit view includes new events beyond the first page", async () => {
    await db.query(
      "INSERT INTO audit_events(actor,action,subject,detail) SELECT 'test','pagination.fixture',generate_series::text,'{}'::jsonb FROM generate_series(1,510)",
    );
    const latest = (await nativeInject({ url: "/v1/audit?direction=latest", headers })).json().events;
    expect(latest).toHaveLength(500);
    expect(
      latest.some(
        (event: { action: string; subject: string }) =>
          event.action === "pagination.fixture" && event.subject === "510",
      ),
    ).toBe(true);
    expect(Number(latest[0].sequence)).toBeGreaterThan(Number(latest[1].sequence));
    const forward = (await nativeInject({ url: `/v1/audit?after=${latest[1].sequence}`, headers })).json()
      .events;
    expect(
      forward.some((event: { sequence: string | number }) => event.sequence === latest[0].sequence),
    ).toBe(true);
    expect(
      forward.every(
        (event: { sequence: string | number }) => Number(event.sequence) > Number(latest[1].sequence),
      ),
    ).toBe(true);
  });
  test("unknown fields and arbitrary shell commands are rejected", async () => {
    expect(
      (await batch({ kind: "winget.upgrade", packageId: "Microsoft.PowerToys", version: "latest" }))
        .statusCode,
    ).toBe(400);
    expect((await batch({ kind: "shell", script: "echo unsupported" })).statusCode).toBe(400);
    expect((await batch({ kind: "inventory.scan", script: "unsupported" })).statusCode).toBe(400);
    expect((await batch({ kind: "winget.upgrade", packageId: "--all", version: "latest" })).statusCode).toBe(
      400,
    );
  });
  test("revocation rejects device credentials and cancels pending jobs", async () => {
    const enrolled = await enroll();
    const victim = enrolled.json();
    await batch({ kind: "inventory.scan" }, [victim.deviceId]);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: `/v1/scopes/${native.scopeId}/native-enrollments/${victim.enrollmentId}/revoke`,
          headers,
          payload: {},
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await nativeInject({
          method: "POST",
          url: "/v1/agent/native-claim",
          headers: { authorization: `Bearer ${victim.credential}` },
          payload: {},
        })
      ).statusCode,
    ).toBe(401);
    expect(
      (await db.query("SELECT state FROM jobs WHERE device_id=$1", [victim.deviceId])).every(
        (j) => j.state === "cancelled",
      ),
    ).toBe(true);
  });
  test("audit records changes without reusable credentials", async () => {
    const response = await nativeInject({ url: "/v1/audit", headers });
    expect(response.statusCode).toBe(200);
    expect(response.json().events.length).toBeGreaterThan(0);
    expect(response.body).not.toContain(credential);
    expect(response.body).not.toContain(operator);
  });
});
