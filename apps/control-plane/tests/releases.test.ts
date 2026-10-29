import { constants, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { verifyRelease } from "../src/security.js";
import { openTestDatabase } from "./database-fixture.js";

const directory = mkdtempSync(join(tmpdir(), "one-control-trust-"));
const keys = generateKeyPairSync("rsa", { modulusLength: 3072 });
const path = join(directory, "public.pem");
writeFileSync(path, keys.publicKey.export({ type: "spki", format: "pem" }));
const config = parseConfig({
  NODE_ENV: "test",
  RELEASE_PUBLIC_KEY_FILE: path,
  ARTIFACT_HOSTS: "updates.example.com",
});
const manifest = {
  schemaVersion: 1,
  packageId: "one-control-agent",
  sequence: 1,
  version: "0.1.0",
  artifactUrl: "https://updates.example.com/agent.msi",
  sha256: "a".repeat(64),
  size: 1000,
  publisherThumbprint: "A".repeat(40),
  expiresAt: new Date(Date.now() + 3600000).toISOString(),
};
function envelope(value: unknown) {
  const payload = Buffer.from(JSON.stringify(value));
  return {
    payload: payload.toString("base64"),
    signature: sign("sha256", payload, {
      key: keys.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    }).toString("base64"),
  };
}
afterAll(() => rmSync(directory, { recursive: true, force: true }));
test("exact signed bytes verify; tampered manifest fails", () => {
  const signed = envelope(manifest);
  expect(verifyRelease(signed, config)).toEqual(manifest);
  expect(() =>
    verifyRelease({ ...signed, payload: envelope({ ...manifest, sequence: 2 }).payload }, config),
  ).toThrow("invalid_release_signature");
});
test.each([
  "http://updates.example.com/agent.msi",
  "https://foreign.example.com/agent.msi",
  "https://updates.example.com/agent.exe",
  "https://user:password@updates.example.com/agent.msi",
])("signed untrusted artifact is rejected: %s", (artifactUrl) => {
  expect(() => verifyRelease(envelope({ ...manifest, artifactUrl }), config)).toThrow(
    "artifact_origin_forbidden",
  );
});
test("expired metadata is rejected even with a valid signature", () => {
  expect(() =>
    verifyRelease(envelope({ ...manifest, expiresAt: new Date(Date.now() - 1000).toISOString() }), config),
  ).toThrow("release_expired");
});

test.each(["1.2.3.4", "256.0.0", "1.256.0", "1.2.65536"])(
  "agent payload cannot use ambiguous Windows Installer version %s",
  (version) => {
    expect(() => verifyRelease(envelope({ ...manifest, version }), config)).toThrow();
  },
);

test("an agent update cannot target an older or unavailable recovery bootstrap", async () => {
  const db = await openTestDatabase();
  const operator = "release-operator-".repeat(4);
  const approver = "release-approver-".repeat(4);
  const app = await buildApp(db, { ...config, DEV_OPERATOR_TOKEN: operator, DEV_APPROVER_TOKEN: approver });
  const headers = { authorization: `Bearer ${operator}` };
  try {
    const token = await app.inject({ method: "POST", url: "/v1/enrollment-tokens", headers, payload: {} });
    expect(token.statusCode).toBe(201);
    const enrollment = await app.inject({
      method: "POST",
      url: "/v1/agent/enroll",
      payload: { token: token.json().token, hostname: "recovery-capability-canary" },
    });
    expect(enrollment.statusCode).toBe(201);
    const enrolled = enrollment.json();
    const release = await app.inject({
      method: "POST",
      url: "/v1/releases",
      headers,
      payload: envelope(manifest),
    });
    expect(release.statusCode).toBe(201);
    const request = () =>
      app.inject({
        method: "POST",
        url: "/v1/batches",
        headers: { ...headers, "idempotency-key": randomUUID() },
        payload: {
          targets: [enrolled.deviceId],
          ring: "canary",
          command: { kind: "package.install", releaseId: release.json().id },
          startsAt: new Date(Date.now() - 1000).toISOString(),
          endsAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });
    const blocked = await request();
    expect(blocked.statusCode).toBe(409);
    expect(blocked.json().error).toBe("agent_recovery_unavailable");
    await app.inject({
      method: "POST",
      url: "/v1/agent/heartbeat",
      headers: { authorization: `Bearer ${enrolled.credential}` },
      payload: { inventory: { agentRecoveryReady: true } },
    });
    expect((await request()).statusCode).toBe(201);
  } finally {
    await app.close();
    await db.close();
  }
}, 30000);
