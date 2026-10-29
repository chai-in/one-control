import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { observeService, options, serviceImage, verifyOwnedTarget } from "./test-postgres.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(root, "apps/control-plane/package.json"));
const { Client } = require("pg");
const evidenceRoot = path.join(
  root,
  ".local/orchestrate/full-build/evidence/database-startup-identity-implementation/service-custody",
);
const storageRoot = "/var/lib/postgresql";
const dataDirectory = `${storageRoot}/18/docker`;
const tmpfsOptions = "rw,mode=1777,size=256m";
const label = "one-control-custody";
export const previousStorageProjection = `{"id":{{json .Id}},"owner":{{json (index .Config.Labels "${label}")}},"legacyTmpfs":{{json .HostConfig.Tmpfs}},"configuredMounts":{{json .HostConfig.Mounts}},"binds":{{json .HostConfig.Binds}},"volumesFrom":{{json .HostConfig.VolumesFrom}},"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"Type":{{json $m.Type}},"Destination":{{json $m.Destination}},"Source":{{json $m.Source}},"Name":{{json $m.Name}}}{{end}}]}`;
export const storageProjection = previousStorageProjection
  .replace("{{json .HostConfig.Mounts}}", '{{json (index .HostConfig "Mounts")}}')
  .replace("{{json $m.Name}}", '{{json (index $m "Name")}}')
  .replace(
    '"configuredMounts":',
    '"configuredMountsPresent":{{$present := false}}{{range $key,$value := .HostConfig}}{{if eq $key "Mounts"}}{{$present = true}}{{end}}{{end}}{{$present}},"configuredMounts":',
  );
const faults = new WeakMap();
const operations = new Set([
  "image-inspect",
  "network-create",
  "container-create",
  "owner-inspect",
  "storage-inspect",
  "storage-previous-inspect",
  "parent-filesystem",
  "data-filesystem",
  "port-inspect",
  "container-restart",
  "container-remove",
  "container-list",
  "network-inspect",
  "network-remove",
  "network-list",
]);
const stages = new Set([
  "reference",
  "source-hashes",
  "image-inspect",
  "directory-create",
  "directory-protect",
  "credential-create",
  "credential-protect",
  "network-create",
  "container-create",
  "owner-inspect",
  "storage-inspect",
  "storage-previous-inspect",
  "storage-projection-control",
  "storage-validate",
  "parent-filesystem",
  "port-inspect",
  "readiness",
  "service-observe",
  "observation-negative",
  "initial-admission",
  "initial-reobserve",
  "restart",
  "restart-owner-inspect",
  "restart-storage-inspect",
  "restart-storage-previous-inspect",
  "restart-storage-projection-control",
  "restart-storage-validate",
  "restart-parent-filesystem",
  "restart-port-inspect",
  "restart-readiness",
  "restart-service-observe",
  "generation-rejection",
  "restart-admission",
  "data-filesystem",
  "restart-data-filesystem",
  "sql-start-rejection",
  "restart-catalog",
  "complete",
  "cleanup-container-inspect",
  "cleanup-container-remove",
  "cleanup-container-absence",
  "cleanup-network-inspect",
  "cleanup-network-remove",
  "cleanup-network-absence",
  "cleanup-directory-inspect",
  "cleanup-directory-remove",
  "evidence-write",
  "client-close",
]);

function fault(code, details = {}) {
  const error = new Error("Owned probe operation failed");
  faults.set(error, { code, ...details });
  return error;
}

export function sanitizeFailure(error, stage) {
  return {
    stage: stages.has(stage) ? stage : "unclassified",
    ...(faults.get(error) ?? { code: "UNCLASSIFIED_FAILURE" }),
  };
}

export function sanitizeDockerFailure(error, operation) {
  const details = { operation: operations.has(operation) ? operation : "unclassified" };
  if (Number.isInteger(error?.code)) details.exitCode = error.code;
  details.termination =
    error?.killed === true ? "timeout-or-buffer-limit" : error?.signal ? "signal" : "exit-or-spawn";
  return details;
}

function parseDocker(value) {
  try {
    return JSON.parse(value);
  } catch {
    throw fault("DOCKER_OUTPUT_INVALID_JSON");
  }
}

function validateOwner(value, expected) {
  if (
    !/^[a-f0-9]{64}$/.test(expected.id) ||
    !/^[a-f0-9]{64}$/.test(expected.owner) ||
    !value ||
    value.id !== expected.id ||
    value.owner !== expected.owner
  )
    throw fault("CONTAINER_OWNERSHIP_MISMATCH");
}

export function validateOwnedStorage(value, expected) {
  validateOwner(value, expected);
  const keys = ["legacyTmpfs", "configuredMounts", "binds", "volumesFrom", "mounts"];
  if (keys.some((key) => !Object.hasOwn(value, key))) throw fault("STORAGE_PROJECTION_INVALID");
  const record = value.legacyTmpfs;
  if (!record || typeof record !== "object" || Array.isArray(record))
    throw fault("TMPFS_CONFIGURATION_MISMATCH");
  const observation = {
    legacyTmpfsEntries: Math.min(Object.keys(record).length, 129),
    legacyDestination: Object.keys(record).every((key) => key === storageRoot) ? storageRoot : "unexpected",
    legacyOptions: record[storageRoot] === tmpfsOptions ? tmpfsOptions : "unexpected",
    configuredMounts: null,
    binds: null,
    volumesFrom: null,
    userMounts: null,
    previousTypedMountPredicatePassed: false,
  };
  for (const key of ["configuredMounts", "binds", "volumesFrom", "mounts"]) {
    const entries = value[key];
    if ((key !== "mounts" && entries === null) || Array.isArray(entries)) {
      observation[key === "mounts" ? "userMounts" : key] =
        entries === null ? 0 : Math.min(entries.length, 129);
    } else throw fault("STORAGE_PROJECTION_INVALID", { storage: observation });
  }
  observation.previousTypedMountPredicatePassed =
    value.mounts.length === 1 &&
    value.mounts[0]?.Type === "tmpfs" &&
    value.mounts[0]?.Destination === storageRoot;
  observation.mountClassifications = value.mounts.slice(0, 128).map((mount) => ({
    type: ["tmpfs", "bind", "volume"].includes(mount?.Type) ? mount.Type : "unexpected",
    destination: mount?.Destination === storageRoot ? storageRoot : "unexpected",
    sourceEmpty: mount?.Source === "",
    nameEmpty: mount?.Name === "",
  }));
  if (Object.keys(record).length !== 1 || record[storageRoot] !== tmpfsOptions)
    throw fault("TMPFS_CONFIGURATION_MISMATCH", { storage: observation });
  if (observation.configuredMounts || observation.binds || observation.volumesFrom || observation.userMounts)
    throw fault("PERSISTENT_USER_MOUNT", { storage: observation });
  return observation;
}

export function classifyPreviousStorageFailure(error) {
  if (
    !Number.isInteger(error?.code) ||
    error.code === 0 ||
    error.killed ||
    error.signal ||
    typeof error.stderr !== "string" ||
    error.stderr.length > 2048 ||
    !/^(?:template parsing error: )?template: :1:[0-9]+: executing "" at <\.HostConfig\.Mounts>: map has no entry for key "Mounts"\r?\n?$/.test(
      error.stderr,
    )
  )
    throw fault("PREVIOUS_PROJECTION_DIAGNOSTIC_UNRECOGNIZED");
  return { outcome: "optional-configured-mounts-missing", exitCode: error.code };
}

export function validateStorageProjectionControl(previous, current, expected) {
  const observation = validateOwnedStorage(current, expected);
  if (
    !Object.hasOwn(current, "configuredMountsPresent") ||
    typeof current.configuredMountsPresent !== "boolean" ||
    !previous ||
    !Number.isInteger(previous.exitCode)
  )
    throw fault("STORAGE_PROJECTION_CONTROL_INVALID");
  if (!current.configuredMountsPresent) {
    if (
      current.configuredMounts !== null ||
      previous.outcome !== "optional-configured-mounts-missing" ||
      previous.exitCode === 0 ||
      Object.hasOwn(previous, "value")
    )
      throw fault("STORAGE_PROJECTION_CONTROL_INCOHERENT");
  } else {
    if (previous.outcome !== "projected" || previous.exitCode !== 0)
      throw fault("STORAGE_PROJECTION_CONTROL_INCOHERENT");
    validateOwnedStorage(previous.value, expected);
    for (const key of ["legacyTmpfs", "configuredMounts", "binds", "volumesFrom", "mounts"])
      if (JSON.stringify(previous.value[key]) !== JSON.stringify(current[key]))
        throw fault("STORAGE_PROJECTION_CONTROL_INCOHERENT");
  }
  return {
    ...observation,
    projectionControl: {
      apiConfiguredMountsPresent: current.configuredMountsPresent,
      previousOutcome: previous.outcome,
      previousExitCode: previous.exitCode,
      correctedProjectionPassed: true,
    },
  };
}

export function validateTmpfsFilesystem(value, admittedPath) {
  if (admittedPath !== storageRoot && admittedPath !== dataDirectory) throw fault("PGDATA_PATH_MISMATCH");
  if (value !== "tmpfs\n" && value !== "tmpfs") throw fault("TMPFS_FILESYSTEM_MISMATCH");
  return { path: admittedPath, filesystem: "tmpfs" };
}

async function docker(operation, args, trim = true) {
  let result;
  try {
    result = await promisify(execFile)("docker", args, {
      cwd: root,
      env: process.env,
      timeout: 60_000,
      maxBuffer: 65_536,
      windowsHide: true,
    });
  } catch (error) {
    throw fault("DOCKER_PROCESS_FAILURE", sanitizeDockerFailure(error, operation));
  }
  return trim ? result.stdout.trim() : result.stdout;
}

function safeObservation(service) {
  return {
    id: service.id,
    image: service.observed.image,
    imageId: service.observed.imageId,
    hostPid: service.observed.pid,
    containerStarted: service.observed.started,
    postmaster: service.postmaster,
    systemIdentifier: service.system,
    mappedPort: service.port,
  };
}

export async function withProbeClient(client, action, receipt) {
  let primary;
  let failed = false;
  let value;
  try {
    await client.connect();
    value = await action(client);
  } catch (error) {
    primary = error;
    failed = true;
  }
  let timer;
  try {
    await Promise.race([
      client.end(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(fault("CLIENT_CLOSE_DEADLINE_EXPIRED")), 5000);
      }),
    ]);
  } catch (cleanup) {
    const summary = sanitizeFailure(cleanup, "client-close");
    receipt.connectionCleanup ??= [];
    receipt.connectionCleanup.push(summary);
    if (failed) {
      const error = new AggregateError([primary, cleanup], "Owned probe operation and close failed");
      faults.set(error, {
        code: "CLIENT_CLEANUP_FAILED",
        primary: sanitizeFailure(primary, receipt.stage),
        cleanup: summary,
      });
      throw error;
    }
    throw fault("CLIENT_CLEANUP_FAILED", { cleanup: summary });
  } finally {
    clearTimeout(timer);
  }
  if (failed) throw primary;
  return value;
}

export function readinessRetryAllowed(error) {
  return faults.get(error)?.code !== "CLIENT_CLEANUP_FAILED";
}

export async function run() {
  options(["--profile", "ci-service"]);
  const run = randomBytes(16).toString("hex");
  const owner = randomBytes(32).toString("hex");
  const receipt = {
    version: 1,
    run,
    startedAt: new Date().toISOString(),
    stage: "reference",
    hashes: {},
    cleanup: [],
    result: "failed",
  };
  let directory;
  let directoryIdentity;
  let containerId;
  let networkId;
  const network = `github_network_${randomBytes(16).toString("hex")}`;
  const errors = [];
  async function inspectCreated() {
    const observed = parseDocker(
      await docker("owner-inspect", [
        "inspect",
        "--type=container",
        "--format",
        `{"id":{{json .Id}},"owner":{{json (index .Config.Labels "${label}")}}}`,
        containerId,
      ]),
    );
    validateOwner(observed, { id: containerId, owner });
  }
  async function storage(restarted = false) {
    receipt.stage = restarted ? "restart-owner-inspect" : "owner-inspect";
    await inspectCreated();
    receipt.stage = restarted ? "restart-storage-previous-inspect" : "storage-previous-inspect";
    let previous;
    let oldOutput;
    try {
      oldOutput = await promisify(execFile)(
        "docker",
        ["inspect", "--type=container", "--format", previousStorageProjection, containerId],
        { cwd: root, env: process.env, timeout: 60_000, maxBuffer: 65_536, windowsHide: true },
      );
    } catch (error) {
      previous = classifyPreviousStorageFailure(error);
    }
    if (oldOutput) {
      const value = parseDocker(oldOutput.stdout);
      validateOwnedStorage(value, { id: containerId, owner });
      previous = { outcome: "projected", exitCode: 0, value };
    }
    receipt.stage = restarted ? "restart-owner-inspect" : "owner-inspect";
    await inspectCreated();
    receipt.stage = restarted ? "restart-storage-inspect" : "storage-inspect";
    const projection = parseDocker(
      await docker("storage-inspect", [
        "inspect",
        "--type=container",
        "--format",
        storageProjection,
        containerId,
      ]),
    );
    receipt.stage = restarted ? "restart-storage-projection-control" : "storage-projection-control";
    const observation = validateStorageProjectionControl(previous, projection, { id: containerId, owner });
    if (restarted) receipt.restartedStorage = observation;
    else receipt.initialStorage = observation;
    return observation;
  }
  async function filesystem(target, restarted = false) {
    if (target !== storageRoot && target !== dataDirectory) throw fault("PGDATA_PATH_MISMATCH");
    receipt.stage = restarted ? "restart-owner-inspect" : "owner-inspect";
    await inspectCreated();
    receipt.stage =
      target === storageRoot
        ? restarted
          ? "restart-parent-filesystem"
          : "parent-filesystem"
        : restarted
          ? "restart-data-filesystem"
          : "data-filesystem";
    const output = await docker(
      target === storageRoot ? "parent-filesystem" : "data-filesystem",
      ["exec", containerId, "stat", "-f", "--format=%T", "--", target],
      false,
    );
    return validateTmpfsFilesystem(output, target);
  }
  try {
    receipt.stage = "source-hashes";
    for (const filename of [
      "scripts/test-postgres-service-custody.mjs",
      "scripts/test-postgres.mjs",
      "scripts/tests/postgres-runner.test.mjs",
      "apps/control-plane/tests/postgres-fixture.ts",
      "apps/control-plane/tests/postgres/fixture.postgres.ts",
      "docs/database-postgres-tests.md",
      ".github/workflows/verify.yml",
    ])
      receipt.hashes[filename] = createHash("sha256")
        .update(await readFile(path.join(root, filename)))
        .digest("hex");
    receipt.stage = "reference";
    const reference = await observeService({
      id: process.env.ONE_CONTROL_PG_SERVICE_ID,
      network: process.env.ONE_CONTROL_PG_SERVICE_NETWORK,
      port: Number(process.env.ONE_CONTROL_PG_SERVICE_PORT),
    });
    receipt.stage = "image-inspect";
    const imageId = await docker("image-inspect", ["image", "inspect", "--format", "{{.Id}}", serviceImage]);
    if (imageId !== reference.observed.imageId) throw fault("CACHED_IMAGE_MISMATCH");
    receipt.referenceImageId = imageId;
    receipt.stage = "directory-create";
    const parent = path.join(root, ".local/service-custody-probes");
    await mkdir(parent, { recursive: true, mode: 0o700 });
    directory = await mkdtemp(path.join(await realpath(parent), "probe-"));
    receipt.stage = "directory-protect";
    directoryIdentity = await lstat(directory);
    if ((directoryIdentity.mode & 0o077) !== 0) throw fault("DIRECTORY_PROTECTION_FAILED");
    const setup = `oc_setup_${run}`;
    const password = randomBytes(32).toString("hex");
    const envFile = path.join(directory, "environment");
    receipt.stage = "credential-create";
    await writeFile(
      envFile,
      `POSTGRES_USER=${setup}\nPOSTGRES_PASSWORD=${password}\nPOSTGRES_DB=postgres\nPOSTGRES_INITDB_ARGS=--data-checksums --auth-host=scram-sha-256 --auth-local=trust\n`,
      { flag: "wx", mode: 0o600 },
    );
    receipt.stage = "credential-protect";
    if (((await lstat(envFile)).mode & 0o077) !== 0) throw fault("CREDENTIAL_PROTECTION_FAILED");
    receipt.stage = "network-create";
    networkId = await docker("network-create", [
      "network",
      "create",
      "--label",
      `${label}=${owner}`,
      network,
    ]);
    if (!/^[a-f0-9]{64}$/.test(networkId)) throw fault("NETWORK_ID_INVALID");
    receipt.stage = "container-create";
    containerId = await docker("container-create", [
      "run",
      "--detach",
      "--pull=never",
      "--label",
      `${label}=${owner}`,
      "--network",
      network,
      "--publish",
      "127.0.0.1::5432",
      "--env-file",
      envFile,
      "--tmpfs",
      `${storageRoot}:${tmpfsOptions}`,
      serviceImage,
    ]);
    if (!/^[a-f0-9]{64}$/.test(containerId)) throw fault("CONTAINER_ID_INVALID");
    receipt.stage = "owner-inspect";
    await inspectCreated();
    const initialStorage = await storage();
    initialStorage.parent = await filesystem(storageRoot);
    async function mappedPort(restarted = false) {
      receipt.stage = restarted ? "restart-port-inspect" : "port-inspect";
      const bindings = parseDocker(
        await docker("port-inspect", [
          "inspect",
          "--type=container",
          "--format",
          "{{json .NetworkSettings.Ports}}",
          containerId,
        ]),
      );
      const binding = bindings["5432/tcp"];
      if (
        !Array.isArray(binding) ||
        binding.length !== 1 ||
        binding[0].HostIp !== "127.0.0.1" ||
        !/^[0-9]+$/.test(binding[0].HostPort) ||
        Number(binding[0].HostPort) < 1 ||
        Number(binding[0].HostPort) > 65535
      )
        throw fault("LOOPBACK_BINDING_INVALID");
      return Number(binding[0].HostPort);
    }
    const port = await mappedPort();
    const config = {
      host: "127.0.0.1",
      port,
      user: setup,
      password,
      database: "postgres",
      connectionTimeoutMillis: 1000,
      query_timeout: 10_000,
      statement_timeout: 10_000,
      options: "-c log_statement=none -c log_min_error_statement=panic",
    };
    async function ready(endpoint = config, restarted = false) {
      receipt.stage = restarted ? "restart-readiness" : "readiness";
      for (let attempt = 0; attempt < 100; attempt++) {
        try {
          await withProbeClient(new Client(endpoint), (client) => client.query("SELECT 1"), receipt);
          return;
        } catch (error) {
          if (!readinessRetryAllowed(error)) throw error;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      throw fault("READINESS_EXPIRED");
    }
    await ready();
    receipt.stage = "owner-inspect";
    await inspectCreated();
    receipt.stage = "service-observe";
    const initial = await observeService({ id: containerId, network, port });
    if (initial.observed.imageId !== imageId) throw fault("CREATED_IMAGE_MISMATCH");
    const expected = { ...initial, setup, profile: "ci-service" };
    receipt.initial = safeObservation(initial);
    receipt.observationNegatives = [];
    for (const [field, mutation] of [
      ["imageId", { observed: { ...initial.observed, imageId: `sha256:${"0".repeat(64)}` } }],
      ["containerStarted", { observed: { ...initial.observed, started: "2000-01-01T00:00:00Z" } }],
      ["hostPid", { observed: { ...initial.observed, pid: initial.observed.pid + 1 } }],
      ["system", { system: "0" }],
      ["postmasterPid", { postmasterPid: initial.postmasterPid + 1 }],
      ["pidEpoch", { startEpoch: "1" }],
      ...Object.entries({
        pid: initial.postmaster.pid + 1,
        dataDirectory: "/not-owned",
        startEpoch: "1",
        port: 1,
      }).map(([field, value]) => [
        `file-${field}`,
        { postmaster: { ...initial.postmaster, [field]: value } },
      ]),
    ]) {
      receipt.stage = "owner-inspect";
      await inspectCreated();
      receipt.stage = "observation-negative";
      let rejected = false;
      try {
        await observeService({ ...initial, ...mutation });
      } catch (error) {
        if (error.message === "Dedicated PostgreSQL service identity changed") rejected = true;
        else throw error;
      }
      if (!rejected) throw fault("OBSERVATION_NEGATIVE_FAILED");
      receipt.observationNegatives.push({ field, rejected });
    }
    receipt.stage = "initial-admission";
    await withProbeClient(
      new Client(config),
      async (client) => {
        const before = (await client.query("SELECT oid FROM pg_database ORDER BY oid")).rows;
        let rejected = false;
        try {
          await verifyOwnedTarget(client, { ...expected, system: "wrong-created-system" });
        } catch (error) {
          if (error.message === "Pre-DDL owned PostgreSQL identity mismatch") rejected = true;
          else throw error;
        }
        if (
          !rejected ||
          JSON.stringify(before) !==
            JSON.stringify((await client.query("SELECT oid FROM pg_database ORDER BY oid")).rows)
        )
          throw fault("PRE_DDL_NEGATIVE_FAILED");
        const admitted = await verifyOwnedTarget(client, expected);
        expected.serverStart = admitted.started;
        receipt.initialAdmission = {
          passed: true,
          wrongIdentityRejected: true,
          catalogUnchanged: true,
          serverStart: admitted.started,
          pidFileStartEpoch: admitted.postmaster.startEpoch,
          sqlStartEpoch: admitted.sql_start_epoch,
        };
        if (admitted.directory !== dataDirectory) throw fault("PGDATA_PATH_MISMATCH");
        initialStorage.data = await filesystem(admitted.directory);
      },
      receipt,
    );
    receipt.stage = "owner-inspect";
    await inspectCreated();
    receipt.stage = "initial-reobserve";
    await observeService(initial);
    receipt.stage = "restart-owner-inspect";
    await inspectCreated();
    receipt.stage = "restart";
    await docker("container-restart", ["restart", "--time", "10", containerId]);
    const restartedStorage = await storage(true);
    restartedStorage.parent = await filesystem(storageRoot, true);
    const restartedPort = await mappedPort(true);
    const restartedConfig = { ...config, port: restartedPort };
    await ready(restartedConfig, true);
    receipt.stage = "restart-owner-inspect";
    await inspectCreated();
    receipt.stage = "restart-service-observe";
    const restarted = await observeService({ id: containerId, network, port: restartedPort });
    receipt.restarted = safeObservation(restarted);
    receipt.stage = "restart-owner-inspect";
    await inspectCreated();
    receipt.stage = "generation-rejection";
    let generationRejected = false;
    try {
      await observeService({ ...initial, port: restartedPort });
    } catch (error) {
      if (error.message === "Dedicated PostgreSQL service identity changed") generationRejected = true;
      else throw error;
    }
    let pinnedSqlRejected = false;
    receipt.stage = "restart-admission";
    await withProbeClient(
      new Client(restartedConfig),
      async (client) => {
        const before = (await client.query("SELECT oid FROM pg_database ORDER BY oid")).rows;
        const restartedExpected = { ...restarted, setup, profile: "ci-service" };
        const admitted = await verifyOwnedTarget(client, restartedExpected);
        receipt.restartDiagnostic = {
          passed: true,
          serverStart: admitted.started,
          pidFileStartEpoch: admitted.postmaster.startEpoch,
          sqlStartEpoch: admitted.sql_start_epoch,
          serverStartChanged: admitted.started !== expected.serverStart,
        };
        if (!receipt.restartDiagnostic.serverStartChanged) throw fault("SQL_START_UNCHANGED");
        if (admitted.directory !== dataDirectory) throw fault("PGDATA_PATH_MISMATCH");
        restartedStorage.data = await filesystem(admitted.directory, true);
        receipt.stage = "sql-start-rejection";
        try {
          await verifyOwnedTarget(client, {
            ...restartedExpected,
            serverStart: expected.serverStart,
          });
        } catch (error) {
          if (error.message === "Pre-DDL owned PostgreSQL identity mismatch") pinnedSqlRejected = true;
          else throw error;
        }
        receipt.stage = "restart-catalog";
        receipt.restartCatalogUnchanged =
          JSON.stringify(before) ===
          JSON.stringify((await client.query("SELECT oid FROM pg_database ORDER BY oid")).rows);
      },
      receipt,
    );
    if (!generationRejected || !pinnedSqlRejected || !receipt.restartCatalogUnchanged)
      throw fault("GENERATION_REJECTION_FAILED");
    receipt.rejections = { generationRejected, pinnedSqlRejected };
    receipt.stage = "complete";
    receipt.result = "passed";
  } catch (error) {
    errors.push(error);
    receipt.failure = sanitizeFailure(error, receipt.stage);
  }
  let cleanupStage;
  if (containerId) {
    try {
      cleanupStage = "cleanup-container-inspect";
      await inspectCreated();
      cleanupStage = "cleanup-container-remove";
      await docker("container-remove", ["rm", "--force", containerId]);
      cleanupStage = "cleanup-container-absence";
      if (
        await docker("container-list", [
          "container",
          "ls",
          "--all",
          "--no-trunc",
          "--filter",
          `id=${containerId}`,
          "--format",
          "{{.ID}}",
        ])
      )
        throw fault("CONTAINER_REMAINS");
      receipt.cleanup.push({ resource: "exact-created-container", result: "removed" });
    } catch (error) {
      errors.push(error);
      receipt.cleanup.push({
        resource: "exact-created-container",
        result: "retained",
        failure: sanitizeFailure(error, cleanupStage),
      });
    }
  }
  if (networkId) {
    try {
      cleanupStage = "cleanup-network-inspect";
      if (!/^[a-f0-9]{64}$/.test(networkId)) throw fault("NETWORK_ID_INVALID");
      const current = parseDocker(
        await docker("network-inspect", [
          "network",
          "inspect",
          "--format",
          `{"id":{{json .Id}},"owner":{{json (index .Labels "${label}")}},"containers":{{json .Containers}}}`,
          networkId,
        ]),
      );
      if (
        current.id !== networkId ||
        current.owner !== owner ||
        !current.containers ||
        typeof current.containers !== "object" ||
        Array.isArray(current.containers) ||
        Object.keys(current.containers).length !== 0
      )
        throw fault("NETWORK_OWNERSHIP_OR_OCCUPANCY_MISMATCH");
      cleanupStage = "cleanup-network-remove";
      await docker("network-remove", ["network", "rm", networkId]);
      cleanupStage = "cleanup-network-absence";
      if (
        await docker("network-list", [
          "network",
          "ls",
          "--no-trunc",
          "--filter",
          `id=${networkId}`,
          "--format",
          "{{.ID}}",
        ])
      )
        throw fault("NETWORK_REMAINS");
      receipt.cleanup.push({ resource: "exact-created-network", result: "removed" });
    } catch (error) {
      errors.push(error);
      receipt.cleanup.push({
        resource: "exact-created-network",
        result: "retained",
        failure: sanitizeFailure(error, cleanupStage),
      });
    }
  }
  if (directory) {
    try {
      cleanupStage = "cleanup-directory-inspect";
      const current = await lstat(directory);
      if (
        current.isSymbolicLink() ||
        !current.isDirectory() ||
        !directoryIdentity ||
        current.dev !== directoryIdentity.dev ||
        current.ino !== directoryIdentity.ino ||
        (await realpath(directory)) !== directory ||
        !path.basename(directory).startsWith("probe-") ||
        path.dirname(directory) !== (await realpath(path.join(root, ".local/service-custody-probes")))
      )
        throw fault("DIRECTORY_OWNERSHIP_MISMATCH");
      cleanupStage = "cleanup-directory-remove";
      await rm(directory, { recursive: true });
      receipt.cleanup.push({ resource: "exact-created-directory", result: "removed" });
    } catch (error) {
      errors.push(error);
      receipt.cleanup.push({
        resource: "exact-created-directory",
        result: "retained",
        failure: sanitizeFailure(error, cleanupStage),
      });
    }
  }
  if (errors.length) receipt.result = "failed";
  receipt.finishedAt = new Date().toISOString();
  try {
    await mkdir(evidenceRoot, { recursive: true });
    await writeFile(path.join(evidenceRoot, `${run}.json`), `${JSON.stringify(receipt, null, 2)}\n`, {
      flag: "wx",
    });
    await mkdir(path.join(evidenceRoot, "upload"), { recursive: true });
    await writeFile(
      path.join(evidenceRoot, "upload/service-custody-manifest.json"),
      `${JSON.stringify(receipt, null, 2)}\n`,
    );
  } catch (error) {
    errors.push(error);
    process.stderr.write(`${JSON.stringify(sanitizeFailure(error, "evidence-write"))}\n`);
  }
  if (errors.length) throw new AggregateError(errors, "Owned service custody probe failed");
  process.stdout.write(`Owned service custody probe passed. Evidence ${run}.json\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(() => {
    process.stderr.write("Owned service custody probe failed. See sanitized evidence when available.\n");
    process.exitCode = 1;
  });
}
