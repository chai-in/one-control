import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../alpha/preflight.mjs", import.meta.url));
const keys = generateKeyPairSync("rsa", { modulusLength: 3072 });
const publicPem = keys.publicKey.export({ type: "spki", format: "pem" });
const envText = (env) =>
  Object.entries(env)
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
function fixture(change = () => {}) {
  const dir = mkdtempSync(join(tmpdir(), "oc-alpha-preflight-"));
  const keyPath = join(dir, "release.pem");
  const config = {
    schemaVersion: 1,
    profile: "production",
    consoleOrigin: "https://control.alpha-fixture.dev",
    oidc: {
      issuer: "https://identity.alpha-fixture.dev/realm",
      publicClientId: "one-control-browser",
      audience: "one-control-api",
      operatorSubjects: ["owner-123"],
      approverSubjects: ["owner-123"],
      viewerSubjects: [],
    },
    images: {
      api: `registry.alpha-fixture.dev/one/api@sha256:${"a".repeat(64)}`,
      console: `registry.alpha-fixture.dev/one/console@sha256:${"b".repeat(64)}`,
    },
    database: {
      runtimeRole: "oc_runtime",
      migrationRole: "oc_migrate",
      runtimeDdl: "forbidden",
      migrationExecution: "explicit-one-shot",
    },
    releasePublicKeyFile: keyPath,
    artifactHosts: ["artifacts.alpha-fixture.dev"],
    deployment: { stage: "poc", deviceLimit: 5 },
  };
  const migration = {
    NODE_ENV: "production",
    DEPLOYMENT_STAGE: "poc",
    POC_DEVICE_LIMIT: "5",
    HOST: "0.0.0.0",
    PORT: "4317",
    DATABASE_URL:
      "postgresql://oc_migrate:Fresh-78z-migration@db.alpha-fixture.dev/one_control?sslmode=verify-full",
    OIDC_ISSUER: config.oidc.issuer,
    OIDC_AUDIENCE: config.oidc.audience,
    OPERATOR_SUBJECTS: "owner-123",
    APPROVER_SUBJECTS: "owner-123",
    VIEWER_SUBJECTS: "",
    RELEASE_PUBLIC_KEY_FILE: keyPath,
    ARTIFACT_HOSTS: "artifacts.alpha-fixture.dev",
  };
  const runtime = {
    ...migration,
    DATABASE_URL:
      "postgresql://oc_runtime:Fresh-12q-runtime@db.alpha-fixture.dev/one_control?sslmode=verify-full",
    VITE_OIDC_ISSUER: config.oidc.issuer,
    VITE_OIDC_CLIENT_ID: config.oidc.publicClientId,
    VITE_OIDC_AUDIENCE: config.oidc.audience,
    ONE_CONTROL_HOST: "control.alpha-fixture.dev",
    OIDC_ORIGIN: "https://identity.alpha-fixture.dev",
  };
  const input = { dir, keyPath, config, runtime, migration, pem: publicPem };
  change(input);
  writeFileSync(join(dir, "config.json"), input.rawConfig ?? JSON.stringify(config));
  writeFileSync(join(dir, "runtime.env"), input.rawRuntime ?? envText(runtime));
  writeFileSync(join(dir, "migration.env"), input.rawMigration ?? envText(migration));
  if (input.pem !== null) writeFileSync(keyPath, input.pem);
  return input;
}
function run(input, options = {}) {
  const before = readdirSync(input.dir).sort();
  const result = spawnSync(
    process.execPath,
    [
      cli,
      "--config",
      join(input.dir, "config.json"),
      "--runtime-env",
      join(input.dir, "runtime.env"),
      "--migration-env",
      join(input.dir, "migration.env"),
    ],
    { encoding: "utf8", cwd: input.dir, ...options },
  );
  assert.ifError(result.error);
  assert.equal(result.stderr, "");
  assert.deepEqual(readdirSync(input.dir).sort(), before);
  return { ...result, output: JSON.parse(result.stdout) };
}
function withInput(change, check) {
  const input = fixture(change);
  try {
    check(input);
  } finally {
    rmSync(input.dir, { recursive: true, force: true });
  }
}
function invalid(name, change, path, code) {
  test(name, () =>
    withInput(change, (input) => {
      const result = run(input);
      assert.equal(result.status, 1);
      assert.equal(result.output.status, "configuration-invalid");
      assert.equal(result.output.productionAcceptance, false);
      assert.ok(
        result.output.diagnostics.some((diagnostic) => diagnostic.path === path && diagnostic.code === code),
        result.stdout,
      );
    }),
  );
}
test("complete production input validates configuration without claiming acceptance or writing files", () =>
  withInput(undefined, (input) => {
    const result = run(input);
    assert.equal(result.status, 0);
    assert.deepEqual(result.output, {
      status: "configuration-valid",
      productionAcceptance: false,
      diagnostics: [],
    });
  }));
test("explicit files ignore hostile ambient configuration", () =>
  withInput(undefined, (input) => {
    const result = run(input, {
      env: {
        ...process.env,
        NODE_ENV: "development",
        DATABASE_URL: "local",
        DEV_OPERATOR_TOKEN: "hostile",
        NODE_TLS_REJECT_UNAUTHORIZED: "0",
        OIDC_ISSUER: "http://localhost",
        NODE_OPTIONS: "",
        RELEASE_PUBLIC_KEY_FILE: "does-not-exist",
      },
    });
    assert.equal(result.status, 0);
  }));
test("rehearsal permits .test names while retaining production mode and no acceptance", () =>
  withInput(
    (input) => {
      input.config.profile = "disposable-rehearsal";
      const transform = (value) => value.replaceAll("alpha-fixture.dev", "alpha-fixture.test");
      input.rawConfig = transform(JSON.stringify(input.config));
      input.rawRuntime = transform(envText(input.runtime));
      input.rawMigration = transform(envText(input.migration));
    },
    (input) => {
      const result = run(input);
      assert.equal(result.status, 0);
      assert.equal(result.output.productionAcceptance, false);
    },
  ));
invalid(
  "invalid JSON",
  (i) => {
    i.rawConfig = '{"bad":';
  },
  "config",
  "invalid-json",
);
invalid(
  "duplicate JSON member",
  (i) => {
    i.rawConfig = JSON.stringify(i.config).replace(
      '"schemaVersion":1',
      '"schemaVersion":1,"schemaVersion":1',
    );
  },
  "config",
  "duplicate-key",
);
invalid(
  "unknown manifest key",
  (i) => {
    i.config.startupMigration = true;
  },
  "config",
  "unknown-key",
);
invalid(
  "missing manifest field",
  (i) => {
    delete i.config.consoleOrigin;
  },
  "config.consoleOrigin",
  "required",
);
invalid(
  "missing environment field",
  (i) => {
    delete i.runtime.OIDC_AUDIENCE;
  },
  "runtimeEnv.OIDC_AUDIENCE",
  "required",
);
invalid(
  "placeholder password",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("Fresh-12q-runtime", "REQUIRED_PASSWORD");
  },
  "runtimeEnv.DATABASE_URL",
  "placeholder",
);
invalid(
  "empty password",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("Fresh-12q-runtime", "");
  },
  "runtimeEnv.DATABASE_URL",
  "invalid-string",
);
invalid(
  "empty database name",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("/one_control?", "/?");
  },
  "runtimeEnv.DATABASE_URL",
  "invalid-postgres-url",
);
invalid(
  "wrong protocol",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("postgresql:", "https:");
  },
  "runtimeEnv.DATABASE_URL",
  "invalid-postgres-url",
);
invalid(
  "unverified TLS",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("verify-full", "require");
  },
  "runtimeEnv.DATABASE_URL",
  "tls-policy",
);
invalid(
  "duplicate TLS mode",
  (i) => {
    i.runtime.DATABASE_URL += "&sslmode=verify-full";
  },
  "runtimeEnv.DATABASE_URL",
  "tls-policy",
);
invalid(
  "TLS override",
  (i) => {
    i.runtime.DATABASE_URL += "&ssl=false";
  },
  "runtimeEnv.DATABASE_URL",
  "tls-policy",
);
invalid(
  "unreviewed database parameter",
  (i) => {
    i.runtime.DATABASE_URL += "&options=-c";
  },
  "runtimeEnv.DATABASE_URL",
  "tls-policy",
);
invalid(
  "same database roles",
  (i) => {
    i.config.database.migrationRole = "oc_runtime";
  },
  "config.database",
  "distinct-roles-required",
);
invalid(
  "URL username mismatch",
  (i) => {
    i.runtime.DATABASE_URL = i.runtime.DATABASE_URL.replace("oc_runtime", "another_role");
  },
  "runtimeEnv.DATABASE_URL",
  "role-mismatch",
);
invalid(
  "same database password",
  (i) => {
    i.migration.DATABASE_URL = i.migration.DATABASE_URL.replace("Fresh-78z-migration", "Fresh-12q-runtime");
  },
  "database",
  "distinct-passwords-required",
);
invalid(
  "different target databases",
  (i) => {
    i.migration.DATABASE_URL = i.migration.DATABASE_URL.replace("/one_control?", "/another?");
  },
  "database",
  "database-target-mismatch",
);
invalid(
  "runtime DDL request",
  (i) => {
    i.config.database.runtimeDdl = "allowed";
  },
  "config.database.runtimeDdl",
  "runtime-ddl-forbidden",
);
invalid(
  "startup migration request",
  (i) => {
    i.config.database.migrationExecution = "at-start";
  },
  "config.database.migrationExecution",
  "explicit-migration-required",
);
invalid(
  "nonproduction mode",
  (i) => {
    i.runtime.NODE_ENV = "development";
  },
  "runtimeEnv.NODE_ENV",
  "mismatch",
);
invalid(
  "development authentication",
  (i) => {
    i.runtime.DEV_OPERATOR_TOKEN = "abc";
  },
  "runtimeEnv",
  "unknown-key",
);
invalid(
  "TLS verification bypass variable",
  (i) => {
    i.runtime.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  },
  "runtimeEnv",
  "unknown-key",
);
invalid(
  "NODE_OPTIONS forbidden",
  (i) => {
    i.runtime.NODE_OPTIONS = "--require=other";
  },
  "runtimeEnv",
  "unknown-key",
);
invalid(
  "console issuer mismatch",
  (i) => {
    i.runtime.VITE_OIDC_ISSUER += "/";
  },
  "runtimeEnv.VITE_OIDC_ISSUER",
  "mismatch",
);
invalid(
  "console audience mismatch",
  (i) => {
    i.runtime.VITE_OIDC_AUDIENCE = "other";
  },
  "runtimeEnv.VITE_OIDC_AUDIENCE",
  "mismatch",
);
invalid(
  "Caddy origin mismatch",
  (i) => {
    i.runtime.OIDC_ORIGIN += "/realm";
  },
  "runtimeEnv.OIDC_ORIGIN",
  "mismatch",
);
invalid(
  "Caddy host mismatch",
  (i) => {
    i.runtime.ONE_CONTROL_HOST = "another.alpha-fixture.dev";
  },
  "runtimeEnv.ONE_CONTROL_HOST",
  "mismatch",
);
invalid(
  "console origin path",
  (i) => {
    i.config.consoleOrigin += "/callback";
  },
  "config.consoleOrigin",
  "invalid-https-url",
);
invalid(
  "subject whitespace",
  (i) => {
    i.config.oidc.operatorSubjects = [" owner-123"];
  },
  "config.oidc.operatorSubjects",
  "invalid-string",
);
invalid(
  "mutable image tag",
  (i) => {
    i.config.images.api = "registry.alpha-fixture.dev/one/api:latest";
  },
  "config.images.api",
  "immutable-image-required",
);
invalid(
  "invalid device cap",
  (i) => {
    i.config.deployment.deviceLimit = 11;
  },
  "config.deployment.deviceLimit",
  "invalid-device-limit",
);
invalid(
  "production rejects .test host",
  (i) => {
    i.config.consoleOrigin = "https://control.alpha-fixture.test";
  },
  "config.consoleOrigin",
  "invalid-host",
);
invalid(
  "production rejects reserved example domain",
  (i) => {
    i.config.consoleOrigin = "https://control.example.com";
  },
  "config.consoleOrigin",
  "placeholder",
);
invalid(
  "production rejects localhost",
  (i) => {
    i.config.consoleOrigin = "https://localhost";
  },
  "config.consoleOrigin",
  "invalid-host",
);
invalid(
  "duplicate environment key",
  (i) => {
    i.rawRuntime = `${envText(i.runtime)}\nNODE_ENV=production`;
  },
  "runtimeEnv.NODE_ENV",
  "duplicate-key",
);
invalid(
  "unknown environment key",
  (i) => {
    i.runtime.MIGRATE_AT_START = "true";
  },
  "runtimeEnv",
  "unknown-key",
);
invalid(
  "quoted environment value",
  (i) => {
    i.runtime.OIDC_AUDIENCE = '"one-control-api"';
  },
  "runtimeEnv",
  "invalid-assignment",
);
invalid(
  "export syntax rejected",
  (i) => {
    i.rawRuntime = `export ${envText(i.runtime)}`;
  },
  "runtimeEnv",
  "invalid-assignment",
);
invalid(
  "shell expansion rejected",
  (i) => {
    // biome-ignore lint/suspicious/noTemplateCurlyInString: The fixture is a literal shell expansion attempt.
    i.runtime.OIDC_AUDIENCE = "${VALUE}";
  },
  "runtimeEnv",
  "invalid-assignment",
);
invalid(
  "missing release key",
  (i) => {
    i.pem = null;
  },
  "config.releasePublicKeyFile",
  "unreadable-file",
);
invalid(
  "wrong algorithm key",
  (i) => {
    i.pem = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
  },
  "config.releasePublicKeyFile",
  "rsa-3072-required",
);
invalid(
  "undersized RSA key",
  (i) => {
    i.pem = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
      type: "spki",
      format: "pem",
    });
  },
  "config.releasePublicKeyFile",
  "rsa-3072-required",
);
invalid(
  "private key refused",
  (i) => {
    i.pem = keys.privateKey.export({ type: "pkcs8", format: "pem" });
  },
  "config.releasePublicKeyFile",
  "invalid-public-key",
);
invalid(
  "garbled release key",
  (i) => {
    i.pem = "garbled";
  },
  "config.releasePublicKeyFile",
  "invalid-public-key",
);
invalid(
  "regular file required",
  (i) => {
    i.config.releasePublicKeyFile = i.dir;
  },
  "config.releasePublicKeyFile",
  "invalid-file",
);
invalid(
  "bounded file size",
  (i) => {
    i.pem = "x".repeat(1_048_577);
  },
  "config.releasePublicKeyFile",
  "invalid-file",
);
test("custom CA path is explicit and is not read by the offline checker", () =>
  withInput(
    (i) => {
      i.runtime.NODE_EXTRA_CA_CERTS = join(i.dir, "operator-ca.pem");
      i.migration.NODE_EXTRA_CA_CERTS = join(i.dir, "operator-ca.pem");
    },
    (i) => {
      assert.equal(run(i).status, 0);
    },
  ));
invalid(
  "custom CA path must be absolute",
  (i) => {
    i.runtime.NODE_EXTRA_CA_CERTS = "./ca.pem";
  },
  "runtimeEnv.NODE_EXTRA_CA_CERTS",
  "absolute-path-required",
);
invalid(
  "custom CA path must not be placeholder",
  (i) => {
    i.runtime.NODE_EXTRA_CA_CERTS = "REQUIRED_CA_PATH";
  },
  "runtimeEnv.NODE_EXTRA_CA_CERTS",
  "placeholder",
);
test("diagnostics redact hostile keys, passwords, URLs, parser text and private key bytes", () =>
  withInput(
    (i) => {
      i.sentinel = "REDAC7_9u%2Fp";
      i.runtime.DATABASE_URL = `postgresql://oc_runtime:${i.sentinel}@db.alpha-fixture.dev/one_control?sslmode=disable`;
      i.runtime[i.sentinel] = i.sentinel;
      i.config[i.sentinel] = i.sentinel;
      i.pem = keys.privateKey.export({ type: "pkcs8", format: "pem" });
    },
    (i) => {
      const result = run(i);
      assert.equal(result.status, 1);
      for (const secret of [
        i.sentinel,
        decodeURIComponent(i.sentinel),
        encodeURIComponent(i.sentinel),
        i.runtime.DATABASE_URL,
        i.pem,
        "PRIVATE KEY",
      ])
        assert.equal(result.stdout.includes(secret), false);
      assert.ok(
        result.output.diagnostics.every(
          (d) => /^[A-Za-z.]+$/.test(d.path.replaceAll("_", "")) && /^[a-z0-9-]+$/.test(d.code),
        ),
      );
    },
  ));
test("missing named input and invalid arguments produce fixed diagnostics", () => {
  const result = spawnSync(
    process.execPath,
    [
      cli,
      "--config",
      resolve(tmpdir(), "does-not-exist.json"),
      "--runtime-env",
      "missing.env",
      "--migration-env",
      "missing.env",
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  assert.ok(
    JSON.parse(result.stdout).diagnostics.some((d) => d.path === "config" && d.code === "unreadable-file"),
  );
  const bad = spawnSync(process.execPath, [cli, "--unknown-secret-value", "secret-value"], {
    encoding: "utf8",
  });
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout.includes("secret-value"), false);
});
