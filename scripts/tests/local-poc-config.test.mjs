import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import {
  configuration,
  loadSettings,
  ports,
  repository,
  systemEnvironment,
} from "../lib/local-poc-config.mjs";

test("local POC cannot inherit production credentials or expose a public backend", () => {
  const root = join(tmpdir(), "poc-fixture");
  const value = {
    schemaVersion: 1,
    root,
    repoRoot: repository,
    id: "00000000-0000-4000-8000-000000000001",
    ...ports,
  };
  const env = {
    NODE_ENV: "development",
    DEPLOYMENT_STAGE: "poc",
    POC_DEVICE_LIMIT: "5",
    HOST: "127.0.0.1",
    PORT: "4347",
    DATABASE_URL: "local",
    LOCAL_DB_PATH: join(root, "database"),
    DEV_OPERATOR_TOKEN: "a".repeat(43),
    DEV_APPROVER_TOKEN: "b".repeat(43),
    DEV_VIEWER_TOKEN: "c".repeat(43),
  };
  assert.equal(configuration(root, value, env), value);
  for (const change of [
    { HOST: "0.0.0.0" },
    { DATABASE_URL: "postgres://other" },
    { LOCAL_DB_PATH: join(root, "..", "other") },
    { FALCON_CLIENT_SECRET: "unexpected" },
    { DEV_VIEWER_TOKEN: env.DEV_OPERATOR_TOKEN },
  ])
    assert.throws(() => configuration(root, value, { ...env, ...change }));
  assert.throws(() => configuration(root, { ...value, tlsPort: value.apiPort }, env));
  const releaseTrust = {
    RELEASE_PUBLIC_KEY_FILE: join(root, "release-public.pem"),
    ARTIFACT_HOSTS: "downloads.example.com",
  };
  assert.equal(configuration(root, value, { ...env, ...releaseTrust }), value);
  assert.throws(() => configuration(root, value, { ...env, ...releaseTrust, ARTIFACT_HOSTS: "" }));
  assert.throws(() =>
    configuration(root, value, { ...env, ...releaseTrust, ARTIFACT_HOSTS: "https://downloads.example.com" }),
  );
  assert.throws(() =>
    configuration(root, value, {
      ...env,
      ...releaseTrust,
      RELEASE_PUBLIC_KEY_FILE: join(root, "..", "private.pem"),
    }),
  );
});

test("interface environment excludes backend secrets and TLS overrides", () => {
  assert.deepEqual(
    systemEnvironment({
      PATH: "tools",
      SystemRoot: "Windows",
      DEV_OPERATOR_TOKEN: "private",
      FALCON_CLIENT_SECRET: "private",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      VITE_OIDC_CLIENT_ID: "unrelated",
    }),
    { PATH: "tools", SystemRoot: "Windows" },
  );
});

test("public workspace settings load without access to backend credentials", () => {
  const directory = mkdtempSync(join(tmpdir(), "one-control-poc-config-"));
  try {
    writeFileSync(join(directory, "workspace.json"), JSON.stringify({ ...ports }));
    assert.deepEqual(loadSettings(directory), ports);
  } finally {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.match(basename(target), /^one-control-poc-config-[a-zA-Z0-9]+$/);
    rmSync(target, { recursive: true, force: true });
  }
});
