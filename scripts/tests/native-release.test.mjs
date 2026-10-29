import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants, createHash, generateKeyPairSync, verify } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

test("offline publisher signs exact build bytes and publication never overwrites a live artifact", async () => {
  const root = await mkdtemp(join(tmpdir(), "one-control-release-"));
  const build = join(root, "build");
  const store = join(root, "store");
  const custody = join(root, "publisher.json");
  await mkdir(build);
  await mkdir(store);
  const save = (path, value) => writeFile(path, JSON.stringify(value));
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  const archive = Buffer.from("inert release fixture; never installed or executed");
  const host = Buffer.from("inert host fixture");
  const pair = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const keyFile = join(root, "disposable-publisher.pem");
  await writeFile(keyFile, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await save(custody, {
    credentialRoot: root,
    privateKeyFile: keyFile,
    keyId: "fixture-publisher",
    publisher: "fixture",
    rootVersion: "1",
  });
  await writeFile(join(build, "host.exe"), host);
  await writeFile(join(build, "inventory-0.1.0-win-x64.zip"), archive);
  const digest = hash(archive);
  const now = Math.floor(Date.now() / 1000);
  const request = {
    schemaVersion: 1,
    id: "inventory",
    version: "0.1.0",
    platform: "win-x64",
    publisher: "fixture",
    layout: "native-host-v1",
    archiveSha256: digest,
    archiveSize: archive.length,
    files: [{ path: "bin/host.exe", sha256: hash(host), size: host.length }],
    issuedAt: now - 1,
    expiresAt: now + 600,
  };
  await save(join(build, "publisher-request.json"), request);
  await save(join(build, "manifest.json"), {
    schemaVersion: 1,
    id: "inventory",
    version: "0.1.0",
    kind: "feature",
    minimumBootstrap: "0.1.0",
    permissions: ["inventory.read"],
    dependencies: {},
    artifacts: {
      "win-x64": {
        url: `https://artifacts.example/v1/artifacts/${digest}/package.zip`,
        sha256: digest,
        size: archive.length,
      },
    },
  });
  await save(join(build, "build.json"), {
    archive: "inventory-0.1.0-win-x64.zip",
    platform: "win-x64",
    sha256: digest,
    size: archive.length,
  });
  const run = (script, args) =>
    spawnSync(process.execPath, [resolve("scripts", script), ...args], {
      encoding: "utf8",
      windowsHide: true,
    });
  try {
    const signed = run("sign-native-feature.mjs", ["--build", build, "--custody", custody]);
    assert.equal(signed.status, 0, signed.stderr);
    const publication = JSON.parse(await readFile(join(build, "signed-module.json"), "utf8"));
    const envelopeBytes = Buffer.from(publication.attestation, "base64url");
    const envelope = JSON.parse(envelopeBytes);
    const parts = [Buffer.from("ONECONTROL-SIGNED-V1\n")];
    for (const part of [
      Buffer.from("fixture-publisher"),
      Buffer.from(envelope.protected, "base64url"),
      Buffer.from(envelope.payload, "base64url"),
    ]) {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(part.length);
      parts.push(length, part);
    }
    assert.ok(
      verify(
        "sha256",
        Buffer.concat(parts),
        { key: pair.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        Buffer.from(envelope.signature, "base64url"),
      ),
    );
    assert.equal(publication.entry.platforms["win-x64"].attestationSha256, hash(envelopeBytes));
    const published = run("publish-native-artifact.mjs", ["--build", build, "--store", store]);
    assert.equal(published.status, 0, published.stderr);
    assert.deepEqual(await readFile(join(store, "artifacts", digest, "package.zip")), archive);
    assert.notEqual(run("publish-native-artifact.mjs", ["--build", build, "--store", store]).status, 0);
    await writeFile(join(build, "inventory-0.1.0-win-x64.zip"), Buffer.from("modified artifact"));
    assert.notEqual(run("sign-native-feature.mjs", ["--build", build, "--custody", custody]).status, 0);
    assert.notEqual(run("publish-native-artifact.mjs", ["--build", build, "--store", store]).status, 0);
    assert.deepEqual(await readFile(join(store, "artifacts", digest, "package.zip")), archive);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
