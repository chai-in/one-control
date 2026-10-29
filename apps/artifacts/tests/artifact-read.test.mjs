import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { issueReadUrl } from "../dist/policy.js";
import { serveArtifact } from "../dist/worker.js";

const now = 1_792_209_000_000;
const secret = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const host = "artifacts.example.com";
const bytes = new TextEncoder().encode("signed MSI byte fixture");
const input = {
  origin: `https://${host}`,
  sha256: "a".repeat(64),
  version: "0.2.3",
  size: bytes.length,
  expires: Math.floor(now / 1000) + 3600,
};
const url = () => issueReadUrl(input, secret, now);
function fixture(overrides = {}) {
  const calls = [];
  return {
    calls,
    env: {
      ARTIFACT_PUBLIC_HOST: host,
      ARTIFACT_READ_KEY: secret,
      ARTIFACTS: {
        async head(key) {
          calls.push(["head", key]);
          return { size: bytes.length, ...overrides };
        },
        async get(key) {
          calls.push(["get", key]);
          return { size: bytes.length, body: new Blob([bytes]).stream(), ...overrides };
        },
      },
    },
  };
}

test("authorization matches an independent HMAC-SHA256 implementation", async () => {
  const issued = new URL(await url());
  const canonical = `one-control-artifact-read-v1\n${host}\n/v1/artifacts/${input.sha256}/one-control-agent-0.2.3.msi\n${input.expires}\n${input.size}`;
  const signature = createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(canonical)
    .digest("base64url");
  assert.equal(issued.searchParams.get("s"), signature);
});

test("an exact authorized GET streams the stored bytes without redirects or caching", async () => {
  const { env, calls } = fixture();
  const response = await serveArtifact(new Request(await url()), env, now);
  assert.equal(response.status, 200);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
  assert.equal(response.headers.get("content-length"), String(bytes.length));
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("location"), null);
  assert.deepEqual(calls, [["get", `artifacts/${input.sha256}/one-control-agent-0.2.3.msi`]]);
});

test("HEAD uses metadata without reading the stored body", async () => {
  const { env, calls } = fixture();
  const response = await serveArtifact(new Request(await url(), { method: "HEAD" }), env, now);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
  assert.equal(calls[0][0], "head");
});

test("invalid, expired, cross-host and modified authorizations never reach storage", async () => {
  const valid = await url();
  const rejected = [
    valid.replace(host, "other.example.com"),
    valid.replace("https:", "http:"),
    valid.replace("/one-control-agent-0.2.3", "/one-control-agent-0.2.4"),
    valid.replace(`/${input.sha256}`, `/${"b".repeat(64)}`),
    valid.replace(`n=${bytes.length}`, `n=${bytes.length + 1}`),
    valid.replace("s=", "s=x"),
    `${valid}&e=1792209001`,
    `${valid}&extra=true`,
    valid.replace(".msi?", ".exe?"),
    valid.replace("/v1/artifacts/", "/v1/agent/"),
    valid.replace("https://", "https://user:password@"),
  ];
  for (const value of rejected) {
    const { env, calls } = fixture();
    // Request itself refuses embedded credentials; it is rejected before the Worker can inspect it.
    let request;
    try {
      request = new Request(value);
    } catch {
      continue;
    }
    assert.equal((await serveArtifact(request, env, now)).status, 404, value);
    assert.equal(calls.length, 0);
  }
  for (const time of [input.expires * 1000, now - 25 * 60 * 60 * 1000]) {
    const { env, calls } = fixture();
    assert.equal((await serveArtifact(new Request(valid), env, time)).status, 404);
    assert.equal(calls.length, 0);
  }
});

test("download authority never permits uploads, deletion, enumeration or private key access", async () => {
  for (const method of ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"]) {
    const { env, calls } = fixture();
    assert.equal((await serveArtifact(new Request(await url(), { method }), env, now)).status, 404);
    assert.equal(calls.length, 0);
  }
  for (const path of [
    "/",
    "/health",
    "/v1/artifacts/",
    "/release-private.pem",
    "/v1/artifacts/../secret.key",
  ]) {
    const { env, calls } = fixture();
    assert.equal((await serveArtifact(new Request(`https://${host}${path}`), env, now)).status, 404);
    assert.equal(calls.length, 0);
  }
});

test("unconfigured or noncanonical secrets fail closed", async () => {
  for (const value of [undefined, "", `${secret}=`, "a".repeat(43)]) {
    const { env, calls } = fixture();
    env.ARTIFACT_READ_KEY = value;
    assert.equal((await serveArtifact(new Request(await url()), env, now)).status, 404);
    assert.equal(calls.length, 0);
  }
});

test("missing and size-mismatched objects cannot become installer downloads", async () => {
  const { env } = fixture({ size: bytes.length + 1 });
  assert.equal((await serveArtifact(new Request(await url()), env, now)).status, 503);
  env.ARTIFACTS.get = async () => null;
  assert.equal((await serveArtifact(new Request(await url()), env, now)).status, 404);
  env.ARTIFACTS.get = async () => {
    throw new Error("sensitive provider details");
  };
  const failed = await serveArtifact(new Request(await url()), env, now);
  assert.equal(failed.status, 503);
  assert.equal(await failed.text(), "");
});

test("partial responses are refused after authorization", async () => {
  const { env, calls } = fixture();
  assert.equal(
    (await serveArtifact(new Request(await url(), { headers: { Range: "bytes=0-10" } }), env, now)).status,
    416,
  );
  assert.equal(calls.length, 0);
});

test("issuance rejects alternate origins, private file types, ambiguous versions and unbounded reads", async () => {
  for (const change of [
    { origin: "http://artifacts.example.com" },
    { origin: "https://artifacts.example.com:4447" },
    { origin: "https://artifacts.example.com/path" },
    { origin: "https://artifacts.example.com/?key=value" },
    { origin: "https://artifacts..example.com" },
    { origin: `https://${"a".repeat(64)}.example.com` },
    { origin: "https://-artifacts.example.com" },
    { sha256: "../private" },
    { sha256: `${"b".repeat(64)}/../${input.sha256}` },
    { version: "0.2.3.exe" },
    { version: "256.0.0" },
    { version: "0.01.0" },
    { size: 0 },
    { size: 2_147_483_649 },
    { expires: Math.floor(now / 1000) },
    { expires: Math.floor(now / 1000) + 86401 },
  ])
    await assert.rejects(() => issueReadUrl({ ...input, ...change }, secret, now));
});
