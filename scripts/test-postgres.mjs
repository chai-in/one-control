import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { lstat, mkdir, open, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(root, "apps/control-plane/package.json"));
const { Client } = require("pg");
const expectedVersion = "postgres (PostgreSQL) 18.6";
const evidenceRoot = path.join(
  root,
  ".local/orchestrate/full-build/evidence/database-fixture-ci-implementation",
);
export const serviceImage = "postgres:18.6-bookworm";
const serviceData = "/var/lib/postgresql/18/docker";
const requiredSuites = [
  "control-plane.test.ts",
  "heartbeat-revocation.test.ts",
  "rotation-revocation.test.ts",
  "dispatch-revocation.test.ts",
  "releases.test.ts",
  "native-presence.test.ts",
  "native-artifacts.test.ts",
  "audit-history.test.ts",
  "product-boundary.test.ts",
  "poc-boundary.test.ts",
  "database-fixture.test.ts",
  "postgres/fixture.postgres.ts",
  "postgres/heartbeat-order.postgres.ts",
  "postgres/rotation-order.postgres.ts",
  "postgres/dispatch-order.postgres.ts",
  "postgres/adapter.postgres.ts",
  "postgres/migration-baseline.postgres.ts",
  "postgres/ordered-migrations.postgres.ts",
].map((file) => `apps/control-plane/tests/${file}`);
const activeCommands = new Set();
class RunnerError extends Error {}

async function bounded(promise, message, milliseconds = 5_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new RunnerError(message)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function closePreserving(client, primary) {
  try {
    await bounded(client.end(), "Owned connection close deadline expired");
  } catch (cleanup) {
    if (primary !== undefined)
      throw new AggregateError([primary, cleanup], "PostgreSQL operation and connection cleanup failed");
    throw cleanup;
  }
}

function safeFailure(error) {
  return error instanceof RunnerError ? error.message : "Runner operation failed; raw diagnostic withheld";
}

function failureDetails(error, depth = 0) {
  return {
    message: safeFailure(error),
    ...(typeof error?.code === "string" && /^[0-9A-Z]{5}$/.test(error.code) ? { sqlState: error.code } : {}),
    ...(error instanceof AggregateError && depth < 3
      ? { causes: error.errors.slice(0, 5).map((item) => failureDetails(item, depth + 1)) }
      : {}),
  };
}

function sanitizeFixture(fixture) {
  const output = {};
  for (const key of ["namespace", "owner", "migrator", "runtime"])
    if (/^oc_[a-z]+_[a-f0-9]{32}$/.test(fixture[key] ?? "")) output[key] = fixture[key];
  if (["not-started", "failed-resources-retained", "exact-resources-removed"].includes(fixture.cleanup))
    output.cleanup = fixture.cleanup;
  output.createdRoles = (fixture.createdRoles ?? [])
    .filter(
      (role) => /^oc_(owner|migrator|runtime)_[a-f0-9]{32}$/.test(role.name) && Number.isInteger(role.oid),
    )
    .map((role) => ({ name: role.name, oid: role.oid }));
  output.roles = (fixture.roles ?? []).map((role) =>
    Object.fromEntries(
      Object.entries(role).filter(
        ([key, value]) =>
          (key === "oid" && Number.isInteger(value)) ||
          (key === "rolname" && /^oc_[a-z]+_[a-f0-9]{32}$/.test(value)) ||
          ([
            "rolcanlogin",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
          ].includes(key) &&
            typeof value === "boolean"),
      ),
    ),
  );
  for (const key of ["migration", "authority"])
    output[key] = Object.fromEntries(
      Object.entries(fixture[key] ?? {}).filter(
        ([name, value]) =>
          (["actor", "current"].includes(name) && /^oc_[a-z]+_[a-f0-9]{32}$/.test(value)) ||
          ([
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
            "owner_member",
            "migrator_member",
            "database_create",
            "public_create",
          ].includes(name) &&
            typeof value === "boolean"),
      ),
    );
  if (
    Number.isInteger(fixture.schema?.oid) &&
    Number.isInteger(fixture.schema?.owner) &&
    /^one-control-fixture:[a-f0-9]{32}:[a-f0-9]{32}$/.test(fixture.schema?.marker ?? "")
  )
    output.schema = { oid: fixture.schema.oid, owner: fixture.schema.owner, marker: fixture.schema.marker };
  if (fixture.fileReadDenials?.migrator === true && fixture.fileReadDenials?.runtime === true)
    output.fileReadDenials = { migrator: true, runtime: true };
  return output;
}

const wireModes = ["passthrough", "lose-committed-ack", "drop-commit"];
const wireCounters = [
  "frontendFrames",
  "backendFrames",
  "commitForwarded",
  "commitCommandObserved",
  "idleObservedAfterCommit",
  "withheldBytes",
  "activeSockets",
];
function exactKeys(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !keys.includes(key))
  )
    throw new RunnerError("Wire observation contains an invalid shape");
}
export function sanitizeWireObservation(value, run, filename) {
  exactKeys(value, [
    "run",
    "mode",
    "stage",
    ...wireCounters,
    "frontendTypes",
    "backendTypes",
    "closed",
    "callbackCount",
    "durable",
    "originalBackend",
    "replacementBackend",
    "milliseconds",
    "outcome",
    "cleanup",
  ]);
  if (
    !/^[a-f0-9]{32}$/.test(run) ||
    value.run !== run ||
    !wireModes.includes(value.mode) ||
    filename !== `wire-${value.mode}.json` ||
    ![
      "fixture",
      "proxy",
      "runtime",
      "transaction",
      "outcome",
      "durability",
      "replacement",
      "complete",
    ].includes(value.stage) ||
    !["confirmed", "unknown", "unobserved"].includes(value.outcome)
  )
    throw new RunnerError("Wire observation identity or outcome mismatch");
  const integer = (item, max = 1_048_576) => Number.isSafeInteger(item) && item >= 0 && item <= max;
  if (
    !integer(value.callbackCount, 1) ||
    !integer(value.milliseconds, 180_000) ||
    !(value.durable === null || integer(value.durable, 1)) ||
    [value.originalBackend, value.replacementBackend].some(
      (item) => item !== null && (!integer(item, 2_147_483_647) || item === 0),
    )
  )
    throw new RunnerError("Wire observation has invalid counters");
  const output = {
    run,
    mode: value.mode,
    stage: value.stage,
    callbackCount: value.callbackCount,
    durable: value.durable,
    originalBackend: value.originalBackend,
    replacementBackend: value.replacementBackend,
    milliseconds: value.milliseconds,
    outcome: value.outcome,
  };
  for (const key of wireCounters) {
    if (Object.hasOwn(value, key)) {
      if (!integer(value[key])) throw new RunnerError("Wire observation has invalid frame counters");
      output[key] = value[key];
    }
  }
  for (const key of ["frontendTypes", "backendTypes"]) {
    if (Object.hasOwn(value, key)) {
      const types =
        key === "frontendTypes"
          ? ["startup", "Q", "p", "X", "P", "B", "D", "E", "S"]
          : ["R", "S", "K", "Z", "T", "D", "C", "E", "N", "1", "2", "n"];
      exactKeys(value[key], types);
      output[key] = {};
      for (const type of types)
        if (Object.hasOwn(value[key], type)) {
          if (!integer(value[key][type]))
            throw new RunnerError("Wire observation has invalid frame counters");
          output[key][type] = value[key][type];
        }
    }
  }
  if (Object.hasOwn(value, "closed")) {
    if (typeof value.closed !== "boolean")
      throw new RunnerError("Wire observation has invalid closure status");
    output.closed = value.closed;
  }
  exactKeys(value.cleanup, ["result", "attempted", "failed"]);
  if (
    !["passed", "failed"].includes(value.cleanup.result) ||
    [value.cleanup.attempted, value.cleanup.failed].some(
      (items) =>
        !Array.isArray(items) ||
        items.length > 3 ||
        new Set(items).size !== items.length ||
        items.some((item) => !["runtime", "proxy", "fixture"].includes(item)),
    ) ||
    value.cleanup.failed.some((item) => !value.cleanup.attempted.includes(item))
  )
    throw new RunnerError("Wire observation has invalid cleanup status");
  output.cleanup = {
    result: value.cleanup.result,
    attempted: [...value.cleanup.attempted],
    failed: [...value.cleanup.failed],
  };
  const lostAcknowledgement = value.mode === "lose-committed-ack";
  if (
    value.cleanup.result === "passed" &&
    (value.stage !== "complete" ||
      value.callbackCount !== 1 ||
      value.durable !== (value.mode === "drop-commit" ? 0 : 1) ||
      value.closed !== true ||
      value.activeSockets !== 0 ||
      value.outcome !== (value.mode === "passthrough" ? "confirmed" : "unknown") ||
      value.cleanup.failed.length ||
      value.cleanup.attempted.join() !== "runtime,proxy,fixture" ||
      wireCounters.some((key) => !Object.hasOwn(value, key)) ||
      !value.originalBackend ||
      !value.replacementBackend ||
      value.commitForwarded !== (value.mode === "drop-commit" ? 1 : 2) ||
      value.commitCommandObserved !== Number(lostAcknowledgement) ||
      value.idleObservedAfterCommit !== Number(lostAcknowledgement) ||
      (lostAcknowledgement ? value.withheldBytes === 0 : value.withheldBytes !== 0) ||
      (value.mode === "passthrough"
        ? value.originalBackend !== value.replacementBackend
        : value.originalBackend === value.replacementBackend) ||
      !value.frontendTypes ||
      !value.backendTypes)
  )
    throw new RunnerError("Successful wire observation is incomplete");
  return output;
}

export const baselineScenarios = Object.freeze([
  "empty",
  "counterfeit",
  "frozen",
  "locks",
  "check",
  "default",
  "type",
  "nullability",
  "index",
  "predicate",
  "extra",
  "missing",
  "dropped",
  "routine",
  "enum",
  "domain",
  "view",
  "policy",
  "rule",
  "marker",
  "markerExtra",
  "rows",
  "runtimeDdl",
  "runtimeHistory",
  "composite",
  "markerMissing",
  "foreignKey",
  "sequence",
  "collation",
  "inheritance",
  "enforcement",
  "temporaryMarker",
  "unsafeDependency",
  "operator",
  "readOnly",
]);
export function sanitizeMigrationBaselineObservation(value, run) {
  exactKeys(value, ["run", "sourceSha256", "catalogSha256", "observations", "cleanup"]);
  if (
    !/^[a-f0-9]{32}$/.test(run) ||
    value.run !== run ||
    value.sourceSha256 !== "f250dca873ac00b206a74af1401351c75a137fe3ffe5f0750e7ba3b517111bc1" ||
    !(
      value.catalogSha256 === null ||
      (typeof value.catalogSha256 === "string" && /^[a-f0-9]{64}$/.test(value.catalogSha256))
    ) ||
    !["passed", "failed"].includes(value.cleanup)
  )
    throw new RunnerError("Migration baseline observation identity rejected");
  exactKeys(value.observations, baselineScenarios);
  if (Object.values(value.observations).some((item) => typeof item !== "boolean"))
    throw new RunnerError("Migration baseline observation values rejected");
  return {
    run,
    sourceSha256: value.sourceSha256,
    catalogSha256: value.catalogSha256,
    observations: { ...value.observations },
    cleanup: value.cleanup,
  };
}
export function requireMigrationBaselineObservation(value, run) {
  const observation = sanitizeMigrationBaselineObservation(value, run);
  if (
    observation.cleanup !== "passed" ||
    observation.catalogSha256 !== "7648810dad3ecf14fc5949072c986e4b1a38191d5e06b3b87a6523e71d01c8b0" ||
    baselineScenarios.some((scenario) => observation.observations[scenario] !== true)
  )
    throw new RunnerError("Required migration baseline observation inventory incomplete");
  return observation;
}
export async function collectMigrationBaselineObservation(directory, run) {
  const file = path.join(directory, "observations", "migration-baseline.json");
  let metadata;
  try {
    metadata = await lstat(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 4096)
    throw new RunnerError("Migration baseline observation file boundary rejected");
  let value;
  try {
    value = JSON.parse(await readFile(file, "utf8"));
  } catch {
    throw new RunnerError("Migration baseline observation JSON rejected");
  }
  return sanitizeMigrationBaselineObservation(value, run);
}
export async function collectWireObservations(directory, run) {
  const folder = path.join(directory, "observations");
  let names;
  try {
    names = await readdir(folder);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  if (
    names.length > 4 ||
    names.some(
      (name) => name !== "migration-baseline.json" && !wireModes.some((mode) => name === `wire-${mode}.json`),
    )
  )
    throw new RunnerError("Wire observation file inventory rejected");
  const output = [];
  for (const filename of names.filter((name) => name !== "migration-baseline.json").sort()) {
    const file = path.join(folder, filename);
    const metadata = await lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 16_384)
      throw new RunnerError("Wire observation file boundary rejected");
    let value;
    try {
      value = JSON.parse(await readFile(file, "utf8"));
    } catch {
      throw new RunnerError("Wire observation JSON rejected");
    }
    output.push(sanitizeWireObservation(value, run, filename));
  }
  return output;
}

export function options(args, env = process.env, platform = process.platform) {
  if (args.length !== 2 || args[0] !== "--profile" || !["owned-local", "ci-service"].includes(args[1])) {
    throw new RunnerError(
      "Specify --profile owned-local or ci-service. Other custody profiles are unsupported.",
    );
  }
  if (
    env.TEST_DATABASE_URL ||
    env.ONE_CONTROL_POSTGRES_CUSTODY ||
    env.PGHOST ||
    env.PGSERVICE ||
    env.PGOPTIONS ||
    env.DATABASE_URL
  ) {
    throw new RunnerError("Inherited database targets and custody receipts are rejected.");
  }
  if (
    args[1] === "ci-service" &&
    (platform !== "linux" ||
      env.GITHUB_ACTIONS !== "true" ||
      !/^[a-f0-9]{64}$/.test(env.ONE_CONTROL_PG_SERVICE_ID ?? "") ||
      !/^github_network_[a-zA-Z0-9]+$/.test(env.ONE_CONTROL_PG_SERVICE_NETWORK ?? "") ||
      !/^\d+$/.test(env.ONE_CONTROL_PG_SERVICE_PORT ?? "") ||
      Number(env.ONE_CONTROL_PG_SERVICE_PORT) < 1 ||
      Number(env.ONE_CONTROL_PG_SERVICE_PORT) > 65535 ||
      !env.ONE_CONTROL_PG_PASSWORD)
  )
    throw new RunnerError("Dedicated GitHub PostgreSQL service identity missing");
  return args[1];
}

async function protect(directory) {
  if (process.platform === "win32") {
    const account = execFileSync("whoami.exe", [], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 10_000,
    }).trim();
    execFileSync("icacls.exe", [directory, "/inheritance:r", "/grant:r", `${account}:(OI)(CI)F`], {
      windowsHide: true,
      stdio: "pipe",
      timeout: 10_000,
    });
  }
}

export async function command(executable, args, env = process.env, cwd = root, timeout = 30_000) {
  const child = spawn(executable, args, { env, cwd, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  activeCommands.add(child);
  let output = "";
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (data) => {
      output = (output + data).slice(-65536);
    });
  let timer;
  let timedOut = false;
  try {
    return await Promise.race([
      once(child, "close").then(([code]) => {
        if (timedOut) throw new RunnerError("Owned command deadline expired");
        return { code, output };
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
          bounded(once(child, "close"), "Owned command termination deadline expired").then(
            () => reject(new RunnerError("Owned command deadline expired")),
            reject,
          );
        }, timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    activeCommands.delete(child);
  }
}

export function validateService(observed, expected) {
  const bindings = observed.ports?.["5432/tcp"];
  if (
    observed.id !== expected.id ||
    observed.running !== true ||
    !Number.isInteger(observed.pid) ||
    observed.pid < 1 ||
    !Number.isFinite(Date.parse(observed.started)) ||
    observed.image !== serviceImage ||
    !/^sha256:[a-f0-9]{64}$/.test(observed.imageId ?? "") ||
    !observed.networks?.[expected.network] ||
    !Array.isArray(bindings) ||
    !bindings.some((item) => item.HostIp === "127.0.0.1" && item.HostPort === String(expected.port))
  ) {
    throw new RunnerError("Dedicated PostgreSQL container custody mismatch");
  }
  return observed;
}

export function parsePostmasterFile(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 4096)
    throw new RunnerError("Postmaster identity file invalid");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new RunnerError("Postmaster identity file invalid");
  }
  const lines = text.split("\n").map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line));
  const positive = (value) => /^[1-9][0-9]*$/.test(value ?? "");
  if (
    text.includes("\0") ||
    lines.length < 5 ||
    !positive(lines[0]) ||
    !Number.isSafeInteger(Number(lines[0])) ||
    Number(lines[0]) > 2_147_483_647 ||
    !lines[1] ||
    [...lines[1]].some((character) => character.charCodeAt(0) < 32) ||
    !positive(lines[2]) ||
    !positive(lines[3]) ||
    Number(lines[3]) > 65535
  )
    throw new RunnerError("Postmaster identity file invalid");
  return { pid: Number(lines[0]), dataDirectory: lines[1], startEpoch: lines[2], port: Number(lines[3]) };
}

export async function readPostmasterFile(dataDirectory) {
  const handle = await open(path.join(dataDirectory, "postmaster.pid"), "r");
  let value;
  let primary;
  let failed = false;
  try {
    const bytes = Buffer.alloc(4097);
    let size = 0;
    while (size < bytes.length) {
      const result = await handle.read(bytes, size, bytes.length - size, size);
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
    }
    value = parsePostmasterFile(bytes.subarray(0, size));
  } catch (error) {
    failed = true;
    primary = error;
  }
  try {
    await handle.close();
  } catch (cleanup) {
    if (failed) throw new AggregateError([primary, cleanup], "Postmaster file observation and close failed");
    throw cleanup;
  }
  if (failed) throw primary;
  return value;
}

export function validatePostmaster(actual, expected) {
  if (
    !actual ||
    !expected ||
    actual.pid !== expected.pid ||
    actual.dataDirectory !== expected.dataDirectory ||
    actual.startEpoch !== expected.startEpoch ||
    actual.port !== expected.port
  )
    throw new RunnerError("Pre-DDL owned PostgreSQL identity mismatch");
  return actual;
}

export async function observeService(expected) {
  const format =
    '{"id":{{json .Id}},"image":{{json .Config.Image}},"imageId":{{json .Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}';
  const inspected = await command("docker", ["inspect", "--type=container", "--format", format, expected.id]);
  if (inspected.code !== 0) throw new RunnerError("Dedicated PostgreSQL container inspection failed");
  const observed = validateService(JSON.parse(inspected.output), expected);
  async function inside(args) {
    const result = await command("docker", ["exec", "--user", "postgres", expected.id, ...args]);
    if (result.code !== 0) throw new RunnerError("Independent PostgreSQL container observation failed");
    return result.output.trim();
  }
  const binaryVersion = await inside(["postgres", "--version"]);
  if (
    !/^postgres \(PostgreSQL\) 18\.6(?: \(Debian [A-Za-z0-9.+~:-]+\))?$/.test(binaryVersion) ||
    (await inside(["readlink", "-f", serviceData])) !== serviceData
  )
    throw new RunnerError("Dedicated PostgreSQL engine or directory mismatch");
  const control = await inside(["pg_controldata", "-D", serviceData]);
  const system = control.match(/^Database system identifier:\s+(\d+)\s*$/m)?.[1];
  let rawPid;
  try {
    rawPid = execFileSync(
      "docker",
      ["exec", "--user", "postgres", expected.id, "head", "-c", "4097", `${serviceData}/postmaster.pid`],
      { timeout: 10_000, maxBuffer: 8192, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch {
    throw new RunnerError("Independent PostgreSQL cluster identity missing");
  }
  const pid = parsePostmasterFile(rawPid);
  if (!system || pid.dataDirectory !== serviceData || pid.port !== 5432)
    throw new RunnerError("Independent PostgreSQL cluster identity missing");
  if (
    expected.observed &&
    (observed.imageId !== expected.observed.imageId ||
      observed.started !== expected.observed.started ||
      observed.pid !== expected.observed.pid ||
      system !== expected.system ||
      pid.pid !== expected.postmasterPid ||
      pid.startEpoch !== expected.startEpoch ||
      pid.pid !== expected.postmaster.pid ||
      pid.startEpoch !== expected.postmaster.startEpoch ||
      pid.port !== expected.postmaster.port ||
      pid.dataDirectory !== expected.postmaster.dataDirectory)
  )
    throw new RunnerError("Dedicated PostgreSQL service identity changed");
  return {
    ...expected,
    observed,
    system,
    startEpoch: pid.startEpoch,
    postmasterPid: pid.pid,
    postmaster: pid,
    dataDirectory: serviceData,
    binaryVersion,
  };
}

async function availablePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return port;
}

export function validateServer(row, expected) {
  if (
    !row ||
    row.actor !== expected.setup ||
    row.version !== 180006 ||
    row.checksums !== "on" ||
    row.directory !== expected.dataDirectory ||
    row.system !== expected.system ||
    typeof row.started !== "string" ||
    !row.started ||
    (expected.serverStart !== undefined && row.started !== expected.serverStart)
  )
    throw new RunnerError("Pre-DDL owned PostgreSQL identity mismatch");
  validatePostmaster(row.postmaster, expected.postmaster);
  return row;
}

export async function verifyOwnedTarget(client, expected) {
  const {
    rows: [row],
  } = await client.query(`SELECT current_user AS actor,
    current_setting('server_version_num')::int AS version,current_setting('data_directory') AS directory,
    current_setting('data_checksums') AS checksums,pg_postmaster_start_time()::text AS started,
    floor(extract(epoch FROM pg_postmaster_start_time()))::text AS sql_start_epoch,
    pg_read_binary_file('postmaster.pid',0,4097,false) AS postmaster_file,
    (pg_control_system()).system_identifier::text AS system`);
  const directory =
    expected.profile === "ci-service" ? expected.dataDirectory : await realpath(expected.dataDirectory);
  const postmaster = parsePostmasterFile(row?.postmaster_file);
  if (expected.profile !== "ci-service") postmaster.dataDirectory = await realpath(postmaster.dataDirectory);
  const { postmaster_file: _withheld, ...safeRow } = row;
  return validateServer(
    row && {
      ...safeRow,
      postmaster,
      directory: expected.profile === "ci-service" ? row.directory : await realpath(row.directory),
    },
    {
      ...expected,
      dataDirectory: directory,
      postmaster: {
        ...expected.postmaster,
        dataDirectory:
          expected.profile === "ci-service"
            ? expected.postmaster.dataDirectory
            : await realpath(expected.postmaster.dataDirectory),
      },
    },
  );
}

async function assertOwnedDirectory(directory, run, identity) {
  const parent = await realpath(path.join(root, ".local/database-tests"));
  const stat = await lstat(directory);
  if (
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.dev !== identity.dev ||
    stat.ino !== identity.ino ||
    (await realpath(directory)) !== path.join(parent, run)
  )
    throw new RunnerError("Owned PostgreSQL directory identity mismatch");
  async function noLinks(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const next = path.join(current, entry.name);
      const item = await lstat(next);
      if (item.isSymbolicLink() || !(await realpath(next)).startsWith(`${directory}${path.sep}`)) {
        throw new RunnerError("PostgreSQL cleanup encountered an unowned link; directory retained");
      }
      if (item.isDirectory()) await noLinks(next);
    }
  }
  await noLinks(directory);
}

export async function run(args = process.argv.slice(2)) {
  const profile = options(args);
  const bin = path.join(root, ".tools/postgresql/pgsql/bin");
  const executable = (name) => path.join(bin, `${name}${process.platform === "win32" ? ".exe" : ""}`);
  const binaryVersion =
    profile === "ci-service"
      ? expectedVersion
      : execFileSync(executable("postgres"), ["--version"], {
          encoding: "utf8",
          windowsHide: true,
          timeout: 10_000,
        }).trim();
  if (binaryVersion !== expectedVersion)
    throw new RunnerError("PostgreSQL binary version must be exactly 18.6");
  const run = randomBytes(16).toString("hex");
  const receipt = {
    version: 1,
    profile,
    run,
    startedAt: new Date().toISOString(),
    binaryVersion: profile === "owned-local" ? binaryVersion : null,
    node: process.version,
    driverVersion: require("pg/package.json").version,
    revision: execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
      windowsHide: true,
      timeout: 10_000,
    }).trim(),
    hashes: {},
    observations: [],
    result: "failed",
    cleanup: "not-started",
  };
  const sourcePaths = [
    "scripts/test-postgres.mjs",
    "scripts/test-postgres-service-custody.mjs",
    "apps/control-plane/tests/postgres-fixture.ts",
    "apps/control-plane/tests/database-fixture.ts",
    "apps/control-plane/tests/native-fixture.ts",
    "apps/control-plane/tests/native-presence.test.ts",
    "apps/control-plane/tests/native-artifacts.test.ts",
    "apps/control-plane/tests/audit-history.test.ts",
    "apps/control-plane/src/audit-history.ts",
    "apps/control-plane/src/runtime-privileges.ts",
    "modules/native-distribution/server/publication.ts",
    "modules/native-distribution/server/artifacts.ts",
    "apps/control-plane/tests/postgres/fixture.postgres.ts",
    "apps/control-plane/tests/postgres/adapter.postgres.ts",
    "apps/control-plane/tests/postgres/adapter.test.ts",
    "apps/control-plane/tests/postgres/protocol-proxy.ts",
    "apps/control-plane/tests/postgres/cleanup.ts",
    "apps/control-plane/tests/postgres/cleanup.test.ts",
    "apps/control-plane/vitest.postgres.config.ts",
    "scripts/tests/postgres-runner.test.mjs",
    "package.json",
    ".github/workflows/verify.yml",
    "docs/database-postgres-tests.md",
    "apps/control-plane/src/database.ts",
    "apps/control-plane/src/coordinator.ts",
    "apps/control-plane/src/routes/context.ts",
    "apps/control-plane/src/routes/jobs.ts",
    "apps/control-plane/src/schema.ts",
    "apps/control-plane/src/local-backup.ts",
    "apps/control-plane/src/frozen-v1.ts",
    "apps/control-plane/src/migration-baseline.ts",
    "apps/control-plane/tests/migration-baseline.test.ts",
    "apps/control-plane/tests/fixtures/frozen-v1.ts",
    "apps/control-plane/tests/fixtures/frozen-v1-catalog/pglite.json",
    "apps/control-plane/tests/fixtures/frozen-v1-catalog/postgres.json",
    "apps/control-plane/tests/postgres/migration-baseline.postgres.ts",
    "docs/migration-baseline.md",
  ];
  for (const filename of sourcePaths)
    receipt.hashes[filename] = createHash("sha256")
      .update(await readFile(path.join(root, filename)))
      .digest("hex");
  const parent = path.join(root, ".local/database-tests");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const canonicalParent = await realpath(parent);
  const directory = path.join(canonicalParent, run);
  await mkdir(directory, { mode: 0o700 });
  const identity = await lstat(directory);
  let postmaster;
  let postmasterExit;
  let postmasterError;
  const failures = [];
  let service;
  let databaseCreated = false;
  let target;
  let config;
  let expected;
  let database;
  let interrupted = false;
  let cleaning = false;
  const interrupt = () => {
    interrupted = true;
    if (!cleaning) for (const child of activeCommands) child.kill("SIGKILL");
  };
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);
  const assertRunning = () => {
    if (interrupted) throw new RunnerError("Required PostgreSQL run interrupted");
  };
  const dataDirectory = path.join(directory, "data");
  const reobserve = async () => {
    if (service) {
      await observeService(service);
      return;
    }
    if (!postmaster?.pid || postmasterError || postmaster.exitCode !== null || postmaster.signalCode !== null)
      throw new RunnerError("Owned PostgreSQL process invocation changed");
    const current = await readPostmasterFile(dataDirectory);
    current.dataDirectory = await realpath(current.dataDirectory);
    validatePostmaster(current, expected.postmaster);
    await assertOwnedDirectory(directory, run, identity);
  };
  try {
    await protect(directory);
    const setup = profile === "ci-service" ? "oc_setup_00000000000000000000000000000000" : `oc_setup_${run}`;
    database = `oc_db_${run}`;
    const password =
      profile === "ci-service" ? process.env.ONE_CONTROL_PG_PASSWORD : randomBytes(32).toString("hex");
    let port;
    let pid;
    if (profile === "ci-service") {
      service = await observeService({
        id: process.env.ONE_CONTROL_PG_SERVICE_ID,
        network: process.env.ONE_CONTROL_PG_SERVICE_NETWORK,
        port: Number(process.env.ONE_CONTROL_PG_SERVICE_PORT),
      });
      port = service.port;
      pid = service.postmasterPid;
      expected = { ...service, setup, profile };
      receipt.binaryVersion = service.binaryVersion;
      receipt.service = {
        id: service.id,
        network: service.network,
        port,
        image: service.observed.image,
        imageId: service.observed.imageId,
        containerStarted: service.observed.started,
        hostPid: service.observed.pid,
      };
    } else {
      const pwfile = path.join(directory, "password");
      await writeFile(pwfile, `${password}\n`, { flag: "wx", mode: 0o600 });
      const init = await command(executable("initdb"), [
        "-D",
        dataDirectory,
        "-U",
        setup,
        "--pwfile",
        pwfile,
        "--auth=scram-sha-256",
        "--data-checksums",
        "--encoding=UTF8",
        "--locale=C",
      ]);
      if (init.code !== 0) throw new RunnerError("Owned PostgreSQL initialization failed");
      port = await availablePort();
      postmaster = spawn(
        executable("postgres"),
        [
          "-D",
          dataDirectory,
          "-p",
          String(port),
          "-h",
          "127.0.0.1",
          "-c",
          "log_statement=none",
          "-c",
          "log_min_error_statement=panic",
          "-c",
          "unix_socket_directories=",
        ],
        { windowsHide: true, stdio: ["ignore", "ignore", "ignore"] },
      );
      postmasterExit = once(postmaster, "exit").catch((error) => {
        postmasterError = error;
      });
    }
    config = {
      host: "127.0.0.1",
      port,
      user: setup,
      password,
      database: "postgres",
      connectionTimeoutMillis: 1000,
      query_timeout: 10_000,
      statement_timeout: 10_000,
      options: "-c log_min_error_statement=panic -c log_statement=none",
    };
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      assertRunning();
      if (postmaster && (postmasterError || !postmaster.pid || postmaster.exitCode !== null))
        throw new RunnerError("Owned PostgreSQL process exited during startup");
      const probe = new Client(config);
      try {
        await probe.connect();
        ready = true;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      } finally {
        await bounded(probe.end(), "Owned readiness connection close deadline expired");
      }
      if (ready) break;
    }
    if (!ready) throw new RunnerError("Owned PostgreSQL readiness deadline expired");
    if (profile === "owned-local") {
      const postmasterIdentity = await readPostmasterFile(dataDirectory);
      pid = postmasterIdentity.pid;
      if (pid !== postmaster.pid) throw new RunnerError("Direct child and actual postmaster identity differ");
      postmasterIdentity.dataDirectory = await realpath(postmasterIdentity.dataDirectory);
      if (
        postmasterIdentity.dataDirectory !== (await realpath(dataDirectory)) ||
        postmasterIdentity.port !== port
      )
        throw new RunnerError("Direct child and actual postmaster identity differ");
      const controlData = execFileSync(executable("pg_controldata"), ["-D", dataDirectory], {
        encoding: "utf8",
        windowsHide: true,
        timeout: 10_000,
      });
      const system = controlData.match(/^Database system identifier:\s+(\d+)\s*$/m)?.[1];
      if (!system) throw new RunnerError("Owned cluster control identity missing");
      expected = {
        setup,
        dataDirectory: await realpath(dataDirectory),
        system,
        postmaster: postmasterIdentity,
        profile,
      };
    }
    const setupClient = new Client(config);
    await setupClient.connect();
    let setupFailure;
    try {
      const before = (await setupClient.query("SELECT oid FROM pg_database ORDER BY oid")).rows;
      let wrongIdentityRejected = false;
      try {
        await verifyOwnedTarget(setupClient, { ...expected, system: "invalid-owned-system" });
      } catch (error) {
        if (error instanceof Error && error.message === "Pre-DDL owned PostgreSQL identity mismatch")
          wrongIdentityRejected = true;
        else throw error;
      }
      const after = (await setupClient.query("SELECT oid FROM pg_database ORDER BY oid")).rows;
      if (!wrongIdentityRejected || JSON.stringify(before) !== JSON.stringify(after))
        throw new RunnerError("Pre-DDL mismatch negative control failed");
      const actual = await verifyOwnedTarget(setupClient, expected);
      expected.serverStart = actual.started;
      await reobserve();
      assertRunning();
      receipt.preDdlIdentity = {
        wrongIdentityRejected,
        catalogUnchanged: true,
        systemIdentifier: actual.system,
        serverStart: actual.started,
        postmasterPid: pid,
        versionNumber: actual.version,
        pidFileStartEpoch: actual.postmaster.startEpoch,
        sqlStartEpoch: actual.sql_start_epoch,
        postmaster: actual.postmaster,
      };
      await setupClient.query(`CREATE DATABASE ${database}`);
      databaseCreated = true;
    } catch (error) {
      setupFailure = error;
      throw error;
    } finally {
      await closePreserving(setupClient, setupFailure);
    }
    const observer = new Client({ ...config, database });
    await observer.connect();
    let observerFailure;
    try {
      await verifyOwnedTarget(observer, expected);
      await reobserve();
      await observer.query("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
      await observer.query(`REVOKE CREATE ON DATABASE ${database} FROM PUBLIC`);
      await observer.query(`COMMENT ON DATABASE ${database} IS 'one-control-owned-run:${run}'`);
      const {
        rows: [row],
      } = await observer.query(`SELECT current_user AS actor, d.oid::int AS oid,
        current_setting('server_version_num')::int AS version, current_setting('data_directory') AS directory,
        current_setting('data_checksums') AS checksums, pg_postmaster_start_time()::text AS started,
        (pg_control_system()).system_identifier::text AS system FROM pg_database d WHERE d.datname=current_database()`);
      if (
        row.version !== 180006 ||
        row.actor !== setup ||
        row.checksums !== "on" ||
        row.started !== expected.serverStart ||
        row.system !== expected.system ||
        (profile === "ci-service"
          ? row.directory !== serviceData
          : (await realpath(row.directory)) !== (await realpath(dataDirectory)))
      ) {
        throw new RunnerError("Owned PostgreSQL target observation failed");
      }
      target = row;
      receipt.observations.push({
        engine: "PostgreSQL",
        versionNumber: row.version,
        database,
        databaseOid: row.oid,
        setup,
        postmasterPid: pid,
        serverStart: row.started,
        systemIdentifier: row.system,
        dataChecksums: row.checksums,
      });
    } catch (error) {
      observerFailure = error;
      throw error;
    } finally {
      await closePreserving(observer, observerFailure);
    }
    const custody = {
      version: 1,
      profile,
      run,
      directory,
      dataDirectory: expected.dataDirectory,
      runnerPid: process.pid,
      postmasterPid: pid,
      port,
      setup,
      password,
      database,
      databaseOid: target.oid,
      serverStart: target.started,
      systemIdentifier: target.system,
      postmaster: expected.postmaster,
      ...(service
        ? {
            service: {
              id: service.id,
              network: service.network,
              port: service.port,
              observed: {
                imageId: service.observed.imageId,
                started: service.observed.started,
                pid: service.observed.pid,
              },
              system: service.system,
              startEpoch: service.startEpoch,
              postmasterPid: service.postmasterPid,
              postmaster: service.postmaster,
            },
          }
        : {}),
    };
    const filename = path.join(directory, "custody.json");
    await mkdir(path.join(directory, "observations"), { mode: 0o700 });
    await writeFile(filename, JSON.stringify(custody), { flag: "wx", mode: 0o600 });
    const env = {
      ...process.env,
      ONE_CONTROL_POSTGRES_PROFILE: profile,
      ONE_CONTROL_POSTGRES_CUSTODY: filename,
    };
    delete env.TEST_DATABASE_URL;
    assertRunning();
    const vitest = path.join(root, "apps/control-plane/node_modules/vitest/vitest.mjs");
    const test = await command(
      process.execPath,
      [
        vitest,
        "run",
        "--config",
        "vitest.postgres.config.ts",
        "--reporter=json",
        "--outputFile",
        path.join(directory, "results.json"),
      ],
      env,
      path.join(root, "apps/control-plane"),
      180_000,
    );
    let results;
    try {
      results = JSON.parse(await readFile(path.join(directory, "results.json"), "utf8"));
    } catch {
      throw new RunnerError("Required PostgreSQL test results missing");
    }
    receipt.tests = {
      total: results.numTotalTests,
      passed: results.numPassedTests,
      failed: results.numFailedTests,
      pending: results.numPendingTests,
      todo: results.numTodoTests,
      exitCode: test.code,
      suites: results.testResults.map((suite) => ({
        file: requiredSuites.includes(path.relative(root, suite.name).split(path.sep).join("/"))
          ? path.relative(root, suite.name).split(path.sep).join("/")
          : "unrecognized-required-suite",
        status: suite.status,
        assertions: suite.assertionResults.map((assertion) => ({ status: assertion.status })),
      })),
    };
    if (
      test.code !== 0 ||
      results.numFailedTests !== 0 ||
      results.numPendingTests !== 0 ||
      results.numTodoTests !== 0 ||
      !results.numTotalTests ||
      results.numTotalTests !== results.numPassedTests ||
      requiredSuites.some(
        (file) =>
          !receipt.tests.suites.some(
            (suite) =>
              suite.file === file &&
              suite.status === "passed" &&
              suite.assertions.length > 0 &&
              suite.assertions.every((assertion) => assertion.status === "passed"),
          ),
      ) ||
      receipt.tests.suites.length !== requiredSuites.length
    ) {
      throw new RunnerError("Required PostgreSQL suite failed or contained skipped tests");
    }
    receipt.result = "passed";
    assertRunning();
  } catch (error) {
    failures.push(error);
    receipt.failure = safeFailure(error);
    receipt.failureDetails = failureDetails(error);
  }
  try {
    await assertOwnedDirectory(directory, run, identity);
    receipt.wireObservations = await collectWireObservations(directory, run);
    receipt.migrationBaselineObservation = await collectMigrationBaselineObservation(directory, run);
    if (receipt.result === "passed")
      requireMigrationBaselineObservation(receipt.migrationBaselineObservation, run);
    if (
      receipt.result === "passed" &&
      (receipt.wireObservations.length !== 3 ||
        receipt.wireObservations.some((observation) => observation.cleanup.result !== "passed"))
    )
      throw new RunnerError("Required successful wire observation inventory incomplete");
  } catch (error) {
    failures.push(error);
    receipt.result = "failed";
    receipt.wireFailure = safeFailure(error);
  }
  try {
    cleaning = true;
    if (service && databaseCreated) {
      await observeService(service);
      const cleanup = new Client({ ...config, database });
      await cleanup.connect();
      let validationFailure;
      try {
        await verifyOwnedTarget(cleanup, expected);
        const {
          rows: [current],
        } = await cleanup.query(
          "SELECT oid::int,datdba::int AS owner,shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=current_database()",
        );
        if (
          !target ||
          current.oid !== target.oid ||
          current.marker !== `one-control-owned-run:${run}` ||
          current.owner !==
            (await cleanup.query("SELECT oid::int FROM pg_roles WHERE rolname=current_user")).rows[0].oid
        )
          throw new RunnerError("Database cleanup ownership mismatch; resources retained");
      } catch (error) {
        validationFailure = error;
        throw error;
      } finally {
        await closePreserving(cleanup, validationFailure);
      }
      const admin = new Client(config);
      await admin.connect();
      let removalFailure;
      try {
        await verifyOwnedTarget(admin, expected);
        const {
          rows: [current],
        } = await admin.query(
          "SELECT oid::int,shobj_description(oid,'pg_database') AS marker,datdba::int AS owner FROM pg_database WHERE datname=$1",
          [database],
        );
        if (
          current?.oid !== target.oid ||
          current.marker !== `one-control-owned-run:${run}` ||
          current.owner !==
            (await admin.query("SELECT oid::int FROM pg_roles WHERE rolname=current_user")).rows[0].oid
        )
          throw new RunnerError("Database cleanup ownership mismatch; resources retained");
        await admin.query(`DROP DATABASE ${database}`);
        receipt.databaseCleanup = "exact-database-removed-role-cleanup-pending";
        for (const filename of await readdir(directory)) {
          if (!/^fixture-[a-f0-9]{32}\.json$/.test(filename)) continue;
          const fixture = JSON.parse(await readFile(path.join(directory, filename), "utf8"));
          for (const role of fixture.createdRoles.toReversed()) {
            if (!/^oc_(owner|migrator|runtime)_[a-f0-9]{32}$/.test(role.name) || !Number.isInteger(role.oid))
              throw new RunnerError("Role cleanup receipt invalid; resources retained");
            const {
              rows: [current],
            } = await admin.query(
              "SELECT oid::int,shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=$1",
              [role.name],
            );
            if (!current) continue;
            if (
              current.oid !== role.oid ||
              current.marker !== `one-control-fixture:${run}:${filename.slice(8, 40)}`
            )
              throw new RunnerError("Role cleanup ownership mismatch; resources retained");
            await admin.query(`DROP ROLE ${role.name}`);
          }
        }
      } catch (error) {
        removalFailure = error;
        throw error;
      } finally {
        await closePreserving(admin, removalFailure);
      }
      receipt.databaseCleanup = "exact-database-and-recorded-roles-removed";
    }
    if (postmaster?.pid && postmaster.exitCode === null) {
      const current = await readPostmasterFile(dataDirectory);
      if (
        current.pid !== postmaster.pid ||
        (await realpath(current.dataDirectory)) !== (await realpath(dataDirectory)) ||
        current.port !== config.port
      )
        throw new RunnerError("Postmaster cleanup identity mismatch; process retained");
      if (expected?.postmaster) {
        current.dataDirectory = await realpath(current.dataDirectory);
        validatePostmaster(current, expected.postmaster);
      }
      await assertOwnedDirectory(directory, run, identity);
      const stop = await command(executable("pg_ctl"), [
        "stop",
        "-D",
        dataDirectory,
        "-m",
        "fast",
        "-w",
        "-t",
        "20",
      ]);
      if (stop.code !== 0) throw new RunnerError("Owned postmaster stop failed");
      await Promise.race([
        postmasterExit,
        new Promise((_, reject) =>
          setTimeout(() => reject(new RunnerError("Owned postmaster exit deadline expired")), 5_000).unref(),
        ),
      ]);
    }
    await assertOwnedDirectory(directory, run, identity);
    receipt.fixtures = [];
    for (const filename of await readdir(directory)) {
      if (/^fixture-[a-f0-9]{32}\.json$/.test(filename)) {
        const fixture = JSON.parse(await readFile(path.join(directory, filename), "utf8"));
        receipt.fixtures.push(sanitizeFixture(fixture));
      }
    }
    await rm(directory, { recursive: true });
    receipt.cleanup =
      profile === "ci-service"
        ? databaseCreated
          ? "exact-ci-resources-removed-service-owned-by-workflow"
          : "owned-temporary-directory-removed-no-database-created"
        : postmaster
          ? "owned-process-stopped-and-directory-removed"
          : "owned-temporary-directory-removed-no-postmaster-created";
  } catch (error) {
    failures.push(error);
    receipt.result = "failed";
    receipt.cleanup = "failed-resources-retained";
    receipt.cleanupFailure = safeFailure(error);
    receipt.cleanupDetails = failureDetails(error);
  }
  receipt.finishedAt = new Date().toISOString();
  process.removeListener("SIGINT", interrupt);
  process.removeListener("SIGTERM", interrupt);
  try {
    await mkdir(evidenceRoot, { recursive: true });
    await writeFile(path.join(evidenceRoot, `${run}.json`), `${JSON.stringify(receipt, null, 2)}\n`, {
      flag: "wx",
    });
    await mkdir(path.join(evidenceRoot, "upload"), { recursive: true });
    await writeFile(
      path.join(evidenceRoot, "upload/runner-manifest.json"),
      `${JSON.stringify(receipt, null, 2)}\n`,
    );
  } catch (error) {
    failures.push(error);
    receipt.result = "failed";
  }
  if (failures.length > 1) throw new AggregateError(failures, "PostgreSQL run failed at multiple boundaries");
  if (failures.length === 1) throw failures[0];
  process.stdout.write(
    `Required PostgreSQL ${receipt.result}. Cleanup ${receipt.cleanup}. Evidence ${run}.json\n`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(() => {
    process.stderr.write(
      "Required PostgreSQL command failed. See sanitized evidence when a run was created.\n",
    );
    process.exitCode = 1;
  });
}
