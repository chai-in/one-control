import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { issueNativePackageReadUrl } from "../dist/policy.js";
import { localArtifactServer } from "../server/local.mjs";

test("server-computer artifact origin delivers only exact authorized immutable bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "one-control-artifacts-"));
  const secret = randomBytes(32).toString("base64url");
  const bytes = Buffer.from("inert native archive fixture; never executed");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const directory = join(root, "artifacts", digest);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "package.zip"), bytes);
  const server = await localArtifactServer({ root, secret, host: "artifacts.example" });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  async function get(path, method = "GET", headers = {}) {
    return new Promise((resolve, reject) => {
      const call = request(
        {
          host: "127.0.0.1",
          port: server.address().port,
          path,
          method,
          headers: { host: "artifacts.example", ...headers },
        },
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("error", reject);
          response.on("end", () =>
            resolve({ status: response.statusCode, body: Buffer.concat(chunks), headers: response.headers }),
          );
        },
      );
      call.on("error", reject);
      call.end();
    });
  }
  try {
    const signed = new URL(
      await issueNativePackageReadUrl(
        {
          origin: "https://artifacts.example",
          sha256: digest,
          size: bytes.length,
          expires: Math.floor(Date.now() / 1000) + 60,
        },
        secret,
        Date.now(),
      ),
    );
    const path = signed.pathname + signed.search;
    const response = await get(path);
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, bytes);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal((await get(path, "HEAD")).body.length, 0);
    assert.equal((await get(signed.pathname)).status, 404);
    assert.equal((await get(path, "GET", { host: "elsewhere.example" })).status, 404);
    assert.equal((await get(path, "GET", { range: "bytes=0-9" })).status, 416);
    await writeFile(join(directory, "package.zip"), Buffer.concat([bytes, bytes]));
    assert.equal((await get(path)).status, 503);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
