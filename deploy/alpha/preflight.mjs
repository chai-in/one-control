import { createPublicKey } from "node:crypto";
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute } from "node:path";

// AlphaDeploymentV1 is a closed manifest. Environment files use literal NAME=value,
// one assignment per line. Blank lines and full-line # comments are allowed.
// Quoting, export, interpolation, multiline values and inline comments are unsupported.
const apiKeys = [
  "NODE_ENV",
  "DEPLOYMENT_STAGE",
  "POC_DEVICE_LIMIT",
  "HOST",
  "PORT",
  "DATABASE_URL",
  "OIDC_ISSUER",
  "OIDC_AUDIENCE",
  "OPERATOR_SUBJECTS",
  "APPROVER_SUBJECTS",
  "VIEWER_SUBJECTS",
  "RELEASE_PUBLIC_KEY_FILE",
  "ARTIFACT_HOSTS",
];
const consoleKeys = [
  "VITE_OIDC_ISSUER",
  "VITE_OIDC_CLIENT_ID",
  "VITE_OIDC_AUDIENCE",
  "ONE_CONTROL_HOST",
  "OIDC_ORIGIN",
];
const errors = [];
const deny = (path, code) => errors.push({ path, code });
const placeholder = (value) =>
  /required|replace|change.?me|placeholder|dummy|example|<|>|\$\{|\$\(|`/i.test(value) ||
  /^(password\d*|secret\d*|postgres|admin|test|local|todo|xxx+)$/i.test(value);
const text = (value, path, empty = false) => {
  if (typeof value !== "string" || (!empty && !value) || value.trim() !== value || /\p{Cc}/u.test(value)) {
    deny(path, "invalid-string");
    return false;
  }
  if (value && placeholder(value)) {
    deny(path, "placeholder");
    return false;
  }
  return true;
};
function closed(value, keys, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    deny(path, "invalid-object");
    return false;
  }
  if (Object.keys(value).some((key) => !keys.includes(key))) deny(path, "unknown-key");
  for (const key of keys) if (!Object.hasOwn(value, key)) deny(`${path}.${key}`, "required");
  return true;
}
function read(file, path) {
  let fd;
  try {
    fd = openSync(file, "r");
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 1_048_576) {
      deny(path, "invalid-file");
      return undefined;
    }
    const bytes = Buffer.alloc(1_048_577);
    const length = readSync(fd, bytes, 0, bytes.length, 0);
    if (length > 1_048_576) {
      deny(path, "invalid-file");
      return undefined;
    }
    return bytes.subarray(0, length).toString("utf8");
  } catch {
    deny(path, "unreadable-file");
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
function manifest(file) {
  const source = read(file, "config");
  if (source === undefined) return undefined;
  try {
    const parsed = JSON.parse(source);
    const tokens = source.match(/"(?:\\.|[^"\\])*"|[{}[\]:,]|[^\s{}[\]:,]+/g) ?? [];
    const stack = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token === "{") stack.push(new Set());
      else if (token === "[") stack.push(null);
      else if (token === "}" || token === "]") stack.pop();
      else if (token.startsWith('"') && tokens[i + 1] === ":") {
        const key = JSON.parse(token);
        const keys = stack.at(-1);
        if (keys.has(key)) {
          deny("config", "duplicate-key");
          return undefined;
        }
        keys.add(key);
      }
    }
    return parsed;
  } catch {
    deny("config", "invalid-json");
    return undefined;
  }
}
function environment(file, path, keys) {
  const source = read(file, path);
  if (source === undefined) return undefined;
  const result = Object.create(null);
  for (const line of source.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    const match = /^([A-Z][A-Z0-9_]*)=([^\r\n]*)$/.exec(line);
    if (!match || /['"`]|\$|\s#/.test(match[2])) {
      deny(path, "invalid-assignment");
      continue;
    }
    const [, key, value] = match;
    if (!keys.includes(key) && key !== "NODE_EXTRA_CA_CERTS") {
      deny(path, "unknown-key");
      continue;
    }
    if (Object.hasOwn(result, key)) {
      deny(`${path}.${key}`, "duplicate-key");
      continue;
    }
    result[key] = value;
  }
  for (const key of keys) {
    if (!Object.hasOwn(result, key)) deny(`${path}.${key}`, "required");
    else text(result[key], `${path}.${key}`, key === "VIEWER_SUBJECTS");
  }
  if (Object.hasOwn(result, "NODE_EXTRA_CA_CERTS")) {
    if (
      text(result.NODE_EXTRA_CA_CERTS, `${path}.NODE_EXTRA_CA_CERTS`) &&
      !isAbsolute(result.NODE_EXTRA_CA_CERTS)
    )
      deny(`${path}.NODE_EXTRA_CA_CERTS`, "absolute-path-required");
  }
  return result;
}
function hostname(value, path, profile) {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !value.includes(".") ||
    !value.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)) ||
    /^\d+(?:\.\d+){3}$/.test(value) ||
    /(?:^|\.)(localhost|local|invalid|example)$/.test(value) ||
    /(?:^|\.)example\.(com|net|org)$/.test(value) ||
    (profile !== "disposable-rehearsal" && /(?:^|\.)test$/.test(value))
  ) {
    deny(path, "invalid-host");
    return false;
  }
  return text(value, path);
}
function https(value, path, profile, originOnly = false) {
  if (!text(value, path)) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (originOnly && value !== url.origin)
    ) {
      deny(path, "invalid-https-url");
      return undefined;
    }
    hostname(url.hostname, path, profile);
    return url;
  } catch {
    deny(path, "invalid-https-url");
    return undefined;
  }
}
function strings(values, path, allowEmpty = false) {
  if (!Array.isArray(values) || (!allowEmpty && !values.length)) {
    deny(path, "invalid-list");
    return;
  }
  if (new Set(values).size !== values.length) deny(path, "duplicate-value");
  for (const value of values) if (text(value, path) && value.includes(",")) deny(path, "invalid-list-item");
}
function database(value, path, role, profile) {
  if (!text(value, path)) return undefined;
  try {
    const url = new URL(value);
    if (
      !["postgres:", "postgresql:"].includes(url.protocol) ||
      url.hash ||
      !url.hostname ||
      !/^\/[A-Za-z_][A-Za-z0-9_-]*$/.test(url.pathname)
    )
      deny(path, "invalid-postgres-url");
    hostname(url.hostname, path, profile);
    const user = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    text(user, path);
    text(password, path);
    if (user !== role) deny(path, "role-mismatch");
    if (placeholder(url.pathname.slice(1))) deny(path, "placeholder");
    if (
      url.searchParams.getAll("sslmode").length !== 1 ||
      url.searchParams.get("sslmode") !== "verify-full" ||
      [...url.searchParams.keys()].some((key) => key !== "sslmode")
    )
      deny(path, "tls-policy");
    return { url, password };
  } catch {
    deny(path, "invalid-postgres-url");
    return undefined;
  }
}
function validate(config, runtime, migration) {
  if (
    !closed(
      config,
      [
        "schemaVersion",
        "profile",
        "consoleOrigin",
        "oidc",
        "images",
        "database",
        "releasePublicKeyFile",
        "artifactHosts",
        "deployment",
      ],
      "config",
    )
  )
    return;
  if (config.schemaVersion !== 1) deny("config.schemaVersion", "unsupported-version");
  if (!["production", "disposable-rehearsal"].includes(config.profile))
    deny("config.profile", "invalid-profile");
  const consoleUrl = https(config.consoleOrigin, "config.consoleOrigin", config.profile, true);
  let issuer;
  if (
    closed(
      config.oidc,
      ["issuer", "publicClientId", "audience", "operatorSubjects", "approverSubjects", "viewerSubjects"],
      "config.oidc",
    )
  ) {
    issuer = https(config.oidc.issuer, "config.oidc.issuer", config.profile);
    text(config.oidc.publicClientId, "config.oidc.publicClientId");
    text(config.oidc.audience, "config.oidc.audience");
    for (const key of ["operatorSubjects", "approverSubjects", "viewerSubjects"])
      strings(config.oidc[key], `config.oidc.${key}`, key === "viewerSubjects");
  }
  if (closed(config.images, ["api", "console"], "config.images")) {
    for (const key of ["api", "console"]) {
      const value = config.images[key];
      if (text(value, `config.images.${key}`) && !/^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(value))
        deny(`config.images.${key}`, "immutable-image-required");
    }
  }
  if (
    closed(
      config.database,
      ["runtimeRole", "migrationRole", "runtimeDdl", "migrationExecution"],
      "config.database",
    )
  ) {
    for (const key of ["runtimeRole", "migrationRole"]) {
      if (
        text(config.database[key], `config.database.${key}`) &&
        !/^[a-z_][a-z0-9_]{0,62}$/.test(config.database[key])
      )
        deny(`config.database.${key}`, "invalid-role");
    }
    if (config.database.runtimeRole === config.database.migrationRole)
      deny("config.database", "distinct-roles-required");
    if (config.database.runtimeDdl !== "forbidden")
      deny("config.database.runtimeDdl", "runtime-ddl-forbidden");
    if (config.database.migrationExecution !== "explicit-one-shot")
      deny("config.database.migrationExecution", "explicit-migration-required");
  }
  if (closed(config.deployment, ["stage", "deviceLimit"], "config.deployment")) {
    if (!["poc", "production"].includes(config.deployment.stage))
      deny("config.deployment.stage", "invalid-stage");
    if (
      !Number.isInteger(config.deployment.deviceLimit) ||
      config.deployment.deviceLimit < 1 ||
      config.deployment.deviceLimit > 10
    )
      deny("config.deployment.deviceLimit", "invalid-device-limit");
  }
  strings(config.artifactHosts, "config.artifactHosts");
  if (Array.isArray(config.artifactHosts))
    for (const host of config.artifactHosts) hostname(host, "config.artifactHosts", config.profile);
  if (text(config.releasePublicKeyFile, "config.releasePublicKeyFile")) {
    if (!isAbsolute(config.releasePublicKeyFile))
      deny("config.releasePublicKeyFile", "absolute-path-required");
    else {
      const pem = read(config.releasePublicKeyFile, "config.releasePublicKeyFile");
      if (pem !== undefined) {
        try {
          if (/PRIVATE KEY/.test(pem) || !/^-----BEGIN (?:RSA )?PUBLIC KEY-----\r?\n/.test(pem))
            throw new Error();
          const key = createPublicKey(pem);
          if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 3072)
            deny("config.releasePublicKeyFile", "rsa-3072-required");
        } catch {
          deny("config.releasePublicKeyFile", "invalid-public-key");
        }
      }
    }
  }
  const dbs = [];
  for (const [env, path, role] of [
    [runtime, "runtimeEnv", config.database?.runtimeRole],
    [migration, "migrationEnv", config.database?.migrationRole],
  ]) {
    if (!env) continue;
    const match = (key, value) => {
      if (env[key] !== value) deny(`${path}.${key}`, "mismatch");
    };
    match("NODE_ENV", "production");
    match("HOST", "0.0.0.0");
    match("PORT", "4317");
    match("DEPLOYMENT_STAGE", config.deployment?.stage);
    match("POC_DEVICE_LIMIT", String(config.deployment?.deviceLimit));
    match("OIDC_ISSUER", config.oidc?.issuer);
    match("OIDC_AUDIENCE", config.oidc?.audience);
    match("RELEASE_PUBLIC_KEY_FILE", config.releasePublicKeyFile);
    match("ARTIFACT_HOSTS", Array.isArray(config.artifactHosts) ? config.artifactHosts.join(",") : undefined);
    for (const [key, field] of [
      ["OPERATOR_SUBJECTS", "operatorSubjects"],
      ["APPROVER_SUBJECTS", "approverSubjects"],
      ["VIEWER_SUBJECTS", "viewerSubjects"],
    ])
      match(key, Array.isArray(config.oidc?.[field]) ? config.oidc[field].join(",") : undefined);
    dbs.push(database(env.DATABASE_URL, `${path}.DATABASE_URL`, role, config.profile));
  }
  if (dbs.length === 2 && dbs.every(Boolean)) {
    if (dbs[0].password === dbs[1].password) deny("database", "distinct-passwords-required");
    if (dbs[0].url.host !== dbs[1].url.host || dbs[0].url.pathname !== dbs[1].url.pathname)
      deny("database", "database-target-mismatch");
  }
  if (runtime) {
    for (const [key, value] of [
      ["VITE_OIDC_ISSUER", config.oidc?.issuer],
      ["VITE_OIDC_CLIENT_ID", config.oidc?.publicClientId],
      ["VITE_OIDC_AUDIENCE", config.oidc?.audience],
      ["ONE_CONTROL_HOST", consoleUrl?.host],
      ["OIDC_ORIGIN", issuer?.origin],
    ])
      if (runtime[key] !== value) deny(`runtimeEnv.${key}`, "mismatch");
  }
}
function main() {
  const args = process.argv.slice(2);
  const options = Object.create(null);
  for (let i = 0; i < args.length; i += 2) {
    if (
      !["--config", "--runtime-env", "--migration-env"].includes(args[i]) ||
      !args[i + 1] ||
      args[i + 1].startsWith("--") ||
      Object.hasOwn(options, args[i])
    ) {
      deny("arguments", "invalid-arguments");
      break;
    }
    options[args[i]] = args[i + 1];
  }
  if (Object.keys(options).length !== 3) deny("arguments", "required");
  if (!errors.length) {
    const config = manifest(options["--config"]);
    const runtime = environment(options["--runtime-env"], "runtimeEnv", [...apiKeys, ...consoleKeys]);
    const migration = environment(options["--migration-env"], "migrationEnv", apiKeys);
    if (config !== undefined) validate(config, runtime, migration);
  }
}
try {
  main();
} catch {
  deny("config", "invalid-configuration");
}
const diagnostics = [...new Map(errors.map((error) => [`${error.path}:${error.code}`, error])).values()];
console.log(
  JSON.stringify({
    status: diagnostics.length ? "configuration-invalid" : "configuration-valid",
    productionAcceptance: false,
    diagnostics,
  }),
);
process.exitCode = diagnostics.length ? 1 : 0;
