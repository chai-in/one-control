import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import { parseWire } from "../../../packages/module-contracts/src/validate.mjs";
import * as policy from "../dist/policy.js";
import { serveArtifact } from "../dist/worker.js";

const now = 1_792_209_000_000;
const secret = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const host = "artifacts.example.com";
const bytes = Buffer.from("504b0506000000000000000000000000000000000000", "hex");
const digest = createHash("sha256").update(bytes).digest("hex");
const path = `/v1/artifacts/${digest}/package.zip`;
const key = `artifacts/${digest}/package.zip`;
const input = {
  origin: `https://${host}`,
  sha256: digest,
  size: bytes.length,
  expires: Math.floor(now / 1000) + 3600,
};
const issue = (change = {}) => policy.issueNativePackageReadUrl({ ...input, ...change }, secret, now);
function signed({ pathname = path, e = String(input.expires), n = String(input.size) } = {}) {
  const signature = createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`one-control-artifact-read-v1\n${host}\n${pathname}\n${e}\n${n}`)
    .digest("base64url");
  return `https://${host}${pathname}?e=${e}&n=${n}&s=${signature}`;
}
function fixture() {
  const calls = [];
  const env = {
    ARTIFACT_PUBLIC_HOST: host,
    ARTIFACT_READ_KEY: secret,
    ARTIFACT_NATIVE_PACKAGES_ENABLED: "true",
    ARTIFACTS: {
      async head(value) {
        calls.push(["head", value]);
        return { size: bytes.length };
      },
      async get(value, options) {
        calls.push(["get", value, options]);
        return {
          size: bytes.length,
          body: new Blob([bytes]).stream(),
          httpMetadata: { contentType: "text/html", contentEncoding: "gzip" },
        };
      },
    },
  };
  return { env, calls };
}
async function assertEmpty(response, status) {
  assert.equal(response.status, status);
  assert.equal(await response.text(), "");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("location"), null);
}

test("native issuance uses the fixed path and existing independent HMAC and shared Artifact parser", async () => {
  const url = await issue();
  assert.equal(url, signed());
  const artifact = { url, sha256: digest, size: bytes.length };
  assert.deepEqual(parseWire("Artifact", new TextEncoder().encode(JSON.stringify(artifact))), artifact);
});

test("native GET returns exact ZIP bytes, digest and safe headers using a bounded storage read", async () => {
  const { env, calls } = fixture();
  const response = await serveArtifact(new Request(await issue()), env, now);
  assert.equal(response.status, 200);
  const actual = Buffer.from(await response.arrayBuffer());
  assert.deepEqual(actual, bytes);
  assert.equal(createHash("sha256").update(actual).digest("hex"), digest);
  assert.equal(response.headers.get("content-type"), "application/zip");
  assert.equal(response.headers.get("content-length"), String(bytes.length));
  assert.equal(response.headers.get("content-disposition"), 'attachment; filename="package.zip"');
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  for (const name of ["content-encoding", "transfer-encoding", "content-range", "location"])
    assert.equal(response.headers.get(name), null);
  assert.deepEqual(calls, [["get", key, { range: { offset: 0, length: bytes.length + 1 } }]]);
});

test("native HEAD shares read authority and reads metadata only", async () => {
  const { env, calls } = fixture();
  const response = await serveArtifact(new Request(signed(), { method: "HEAD" }), env, now);
  assert.equal(response.status, 200);
  assert.equal(response.body, null);
  assert.equal(response.headers.get("content-type"), "application/zip");
  assert.equal(response.headers.get("content-length"), String(bytes.length));
  assert.deepEqual(calls, [["head", key]]);
});

test("native access requires exact opt-in before even resolving the bucket binding", async () => {
  for (const enabled of [undefined, "false", "TRUE", " true", "true ", "1", true, null]) {
    for (const method of ["GET", "HEAD"]) {
      const { env } = fixture();
      env.ARTIFACT_NATIVE_PACKAGES_ENABLED = enabled;
      Object.defineProperty(env, "ARTIFACTS", {
        get() {
          assert.fail("disabled native request resolved storage");
        },
      });
      await assertEmpty(await serveArtifact(new Request(signed(), { method }), env, now), 404);
    }
  }
});

test("disabled native availability leaves MSI issuance and delivery unchanged", async () => {
  const { env, calls } = fixture();
  env.ARTIFACT_NATIVE_PACKAGES_ENABLED = "false";
  const url = await policy.issueReadUrl({ ...input, version: "0.2.3" }, secret, now);
  const response = await serveArtifact(new Request(url), env, now);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/octet-stream");
  assert.deepEqual(calls, [["get", `artifacts/${digest}/one-control-agent-0.2.3.msi`, undefined]]);
});

test("native grammar and signed malformed authorities are denied without storage", async () => {
  const urls = [
    ...[
      path.replace("package.zip", "other.zip"),
      path.replace("package.zip", "package.ZIP"),
      path.replace("package.zip", "package.exe"),
      path.replace(digest, digest.toUpperCase()),
      path.replace(digest, "a".repeat(63)),
      path.replace("package.zip", "%70ackage.zip"),
      path.replace("/package.zip", "//package.zip"),
      path.replace("/package.zip", "/extra/package.zip"),
      path.replace("/package.zip", "/%2e%2e/private.key"),
      path.replace("/v1/", "/v2/"),
    ].map((pathname) => signed({ pathname })),
    ...["0", "-1", "01", "1.0", "1e2", "NaN", "67108865", "2147483648"].map((n) => signed({ n })),
    ...["0", "01", String(now / 1000), String(now / 1000 + 86401), "9007199254740992"].map((e) =>
      signed({ e }),
    ),
    signed().replace(host, "other.example.com"),
    signed().replace("https:", "http:"),
    signed().replace(host, `${host}:4447`),
    signed().replace("s=", "s=x"),
    signed().replace("s=", `s=${"A".repeat(43)}&extra=`),
    `${signed()}&e=${input.expires}`,
    `${signed()}&n=${bytes.length}`,
    `${signed()}&s=abc`,
    `${signed()}&extra=true`,
    `${signed()}#fragment`,
    signed().replace(/&s=[^&]+/, ""),
    signed().replace(`n=${bytes.length}`, `n=${bytes.length + 1}`),
    signed().replace(digest, "b".repeat(64)),
  ];
  for (const url of urls) {
    const { env, calls } = fixture();
    await assertEmpty(await serveArtifact(new Request(url), env, now), 404);
    assert.equal(calls.length, 0);
  }
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    const { env, calls } = fixture();
    await assertEmpty(await serveArtifact(new Request(signed(), { method }), env, now), 404);
    assert.equal(calls.length, 0);
  }
});

test("native issuer and verifier enforce the 64 MiB ceiling without archive allocation", async () => {
  assert.equal(await issue({ size: 67_108_864 }), signed({ n: "67108864" }));
  assert.equal(
    (await policy.authorizeRead(new Request(signed({ n: "67108864" })), host, secret, now, true))?.size,
    67_108_864,
  );
  assert.equal(
    await policy.authorizeRead(new Request(signed({ n: "67108865" })), host, secret, now, true),
    null,
  );
  assert.equal(await policy.authorizeRead(new Request(signed()), host, secret, now), null);
  for (const change of [
    { size: 0 },
    { size: -1 },
    { size: 1.5 },
    { size: 67_108_865 },
    { size: Number.NaN },
    { sha256: digest.toUpperCase() },
    { sha256: `${digest}/../${digest}` },
    { origin: "http://artifacts.example.com" },
    { origin: `https://${host}/path` },
    { origin: `https://${host}/?query=value` },
    { origin: `https://${host}:4447` },
    { expires: now / 1000 },
    { expires: now / 1000 + 86401 },
  ])
    await assert.rejects(() => issue(change));
});

test("native authority requires canonical keys and signatures and a bounded current lifetime", async () => {
  for (const value of [undefined, "", `${secret}=`, "a".repeat(43)]) {
    const { env, calls } = fixture();
    env.ARTIFACT_READ_KEY = value;
    await assertEmpty(await serveArtifact(new Request(signed()), env, now), 404);
    assert.equal(calls.length, 0);
  }
  const url = new URL(signed());
  const signature = url.searchParams.get("s");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  url.searchParams.set("s", signature.slice(0, -1) + alphabet[alphabet.indexOf(signature.at(-1)) + 1]);
  const { env, calls } = fixture();
  await assertEmpty(await serveArtifact(new Request(url), env, now), 404);
  assert.equal(calls.length, 0);
  for (const time of [input.expires * 1000, now - 25 * 3600 * 1000, Number.NaN]) {
    await assertEmpty(await serveArtifact(new Request(signed()), env, time), 404);
    assert.equal(calls.length, 0);
  }
  assert.equal(await issue({ expires: now / 1000 + 86400 }), signed({ e: String(now / 1000 + 86400) }));
});

test("all client range forms are rejected after authority and before storage", async () => {
  for (const method of ["GET", "HEAD"]) {
    for (const range of ["", "garbage", "bytes=0-1", "bytes=1-", "bytes=-1", "bytes=0-1,3-4"]) {
      for (const valid of [true, false]) {
        const { env, calls } = fixture();
        const url = valid ? signed() : signed().replace("s=", "s=x");
        await assertEmpty(
          await serveArtifact(new Request(url, { method, headers: { Range: range } }), env, now),
          valid ? 416 : 404,
        );
        assert.equal(calls.length, 0);
      }
    }
  }
});

test("missing native objects and provider failures return sanitized empty errors", async () => {
  for (const method of ["GET", "HEAD"]) {
    for (const status of [404, 503]) {
      const { env } = fixture();
      env.ARTIFACTS[method === "HEAD" ? "head" : "get"] = async () => {
        if (status === 503) throw new Error("private provider exception");
        return null;
      };
      await assertEmpty(await serveArtifact(new Request(signed(), { method }), env, now), status);
    }
  }
  const { env } = fixture();
  env.ARTIFACTS.get = async () => ({ size: bytes.length });
  await assertEmpty(await serveArtifact(new Request(signed()), env, now), 503);
});

test("native invalid size metadata cancels the stored body before a sanitized failure", async () => {
  for (const size of [
    0,
    -1,
    bytes.length - 1,
    bytes.length + 1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    "22",
  ]) {
    const { env } = fixture();
    let cancelled = false;
    env.ARTIFACTS.get = async () => ({
      size,
      body: new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
    });
    await assertEmpty(await serveArtifact(new Request(signed()), env, now), 503);
    assert.equal(cancelled, true);
    env.ARTIFACTS.head = async () => ({ size });
    await assertEmpty(await serveArtifact(new Request(signed(), { method: "HEAD" }), env, now), 503);
  }
});

test("a native storage stream failure rejects consumption after response creation", async () => {
  const { env } = fixture();
  env.ARTIFACTS.get = async () => ({
    size: bytes.length,
    body: new ReadableStream({
      pull(controller) {
        controller.error(new Error("storage stream failed"));
      },
    }),
  });
  const response = await serveArtifact(new Request(signed()), env, now);
  assert.equal(response.status, 200);
  await assert.rejects(() => response.arrayBuffer());
});

test("a failed cancellation cannot expose provider details or serve a mismatched native body", async () => {
  const { env } = fixture();
  env.ARTIFACTS.get = async () => ({
    size: bytes.length + 1,
    body: new ReadableStream({
      cancel() {
        throw new Error("private cancellation exception");
      },
    }),
  });
  await assertEmpty(await serveArtifact(new Request(signed()), env, now), 503);
});
