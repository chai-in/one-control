import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  collectMigrationBaselineObservation,
  collectWireObservations,
  command,
  options,
  parsePostmasterFile,
  readPostmasterFile,
  requireMigrationBaselineObservation,
  sanitizeMigrationBaselineObservation,
  sanitizeWireObservation,
  serviceImage,
  validateServer,
  validateService,
  verifyOwnedTarget,
} from "../test-postgres.mjs";
import {
  classifyPreviousStorageFailure,
  previousStorageProjection,
  readinessRetryAllowed,
  sanitizeDockerFailure,
  sanitizeFailure,
  storageProjection,
  validateOwnedStorage,
  validateStorageProjectionControl,
  validateTmpfsFilesystem,
  withProbeClient,
} from "../test-postgres-service-custody.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const storageOwner = { id: "a".repeat(64), owner: "b".repeat(64) };
const legacyStorage = {
  ...storageOwner,
  legacyTmpfs: { "/var/lib/postgresql": "rw,mode=1777,size=256m" },
  configuredMounts: null,
  binds: null,
  volumesFrom: null,
  mounts: [],
};

test("optional Docker map fields use index while required fields remain strict", () => {
  assert.equal(previousStorageProjection.includes("{{json .HostConfig.Mounts}}"), true);
  assert.equal(previousStorageProjection.includes("{{json $m.Name}}"), true);
  assert.equal(storageProjection.includes('{{json (index .HostConfig "Mounts")}}'), true);
  assert.equal(storageProjection.includes('{{json (index $m "Name")}}'), true);
  for (const required of ["{{json .Id}}", "{{json .HostConfig.Tmpfs}}", "{{json $m.Source}}"])
    assert.equal(storageProjection.includes(required), true);
  assert.equal(storageProjection.includes('eq $key "Mounts"'), true);
  assert.equal(storageProjection.includes("Config.Env"), false);
});

test("same-container projection controls distinguish omitted optional keys from present null or empty", () => {
  const missing = { outcome: "optional-configured-mounts-missing", exitCode: 1 };
  const absent = { ...legacyStorage, configuredMountsPresent: false };
  const result = validateStorageProjectionControl(missing, absent, storageOwner);
  assert.deepEqual(result.projectionControl, {
    apiConfiguredMountsPresent: false,
    previousOutcome: "optional-configured-mounts-missing",
    previousExitCode: 1,
    correctedProjectionPassed: true,
  });
  for (const configuredMounts of [null, []]) {
    const value = { ...legacyStorage, configuredMounts };
    assert.equal(
      validateStorageProjectionControl(
        { outcome: "projected", exitCode: 0, value },
        { ...value, configuredMountsPresent: true },
        storageOwner,
      ).projectionControl.previousOutcome,
      "projected",
    );
  }
  const success = { outcome: "projected", exitCode: 0, value: legacyStorage };
  const present = { ...legacyStorage, configuredMountsPresent: true };
  const canary = "secret-bearing-projection-control";
  for (const [previous, current] of [
    [success, absent],
    [missing, present],
    [missing, { ...absent, configuredMounts: [] }],
    [missing, { ...absent, configuredMountsPresent: null }],
    [missing, legacyStorage],
    [{ ...missing, exitCode: 0 }, absent],
    [{ ...missing, value: legacyStorage }, absent],
    [{ ...missing, outcome: canary }, absent],
    [null, absent],
    [{ ...success, exitCode: 1 }, present],
    [{ ...success, value: { ...legacyStorage, id: "c".repeat(64) } }, present],
    [{ ...success, value: { ...legacyStorage, configuredMounts: [] } }, present],
    [success, { ...present, owner: canary }],
    [success, { ...present, mounts: [{ Type: "bind", Destination: canary, Source: canary }] }],
    [missing, { ...absent, configuredMounts: false }],
  ])
    assert.throws(
      () => validateStorageProjectionControl(previous, current, storageOwner),
      (error) => {
        const safe = sanitizeFailure(error, "storage-projection-control");
        assert.notEqual(safe.code, "UNCLASSIFIED_FAILURE");
        assert.equal(JSON.stringify(safe).includes(canary), false);
        return true;
      },
    );
});

test("previous projection diagnostics accept only the exact optional Mounts error without retaining text", () => {
  const diagnostic =
    'template parsing error: template: :1:215: executing "" at <.HostConfig.Mounts>: map has no entry for key "Mounts"\n';
  assert.deepEqual(classifyPreviousStorageFailure({ code: 1, stderr: diagnostic }), {
    outcome: "optional-configured-mounts-missing",
    exitCode: 1,
  });
  const canary = "secret-bearing-docker-diagnostic";
  for (const value of [
    { code: 1, stderr: `${diagnostic}${canary}` },
    { code: 1, stderr: `${canary}${diagnostic}` },
    { code: 1, stderr: diagnostic.replace(".HostConfig.Mounts", ".HostConfig.Tmpfs") },
    { code: 1, stderr: diagnostic.replace('key "Mounts"', 'key "Name"') },
    { code: 0, stderr: diagnostic },
    { code: "1", stderr: diagnostic },
    { code: 1, stderr: diagnostic, killed: true },
    { code: 1, stderr: diagnostic, signal: canary },
    { code: 1, stderr: canary.repeat(300) },
    { code: 1, message: diagnostic },
    undefined,
  ])
    assert.throws(
      () => classifyPreviousStorageFailure(value),
      (error) => {
        assert.deepEqual(sanitizeFailure(error, "storage-previous-inspect"), {
          stage: "storage-previous-inspect",
          code: "PREVIOUS_PROJECTION_DIAGNOSTIC_UNRECOGNIZED",
        });
        return true;
      },
    );
});

test("owned legacy tmpfs uses its configuration map and disproves the previous typed-mount predicate", () => {
  for (const empty of [null, []]) {
    const observation = validateOwnedStorage(
      { ...legacyStorage, configuredMounts: empty, binds: empty, volumesFrom: empty },
      storageOwner,
    );
    assert.equal(observation.legacyTmpfsEntries, 1);
    assert.equal(observation.legacyDestination, "/var/lib/postgresql");
    assert.equal(observation.legacyOptions, "rw,mode=1777,size=256m");
    assert.equal(observation.userMounts, 0);
    assert.equal(observation.previousTypedMountPredicatePassed, false);
  }
});

test("owned storage rejects missing, confused, additional and persistent mount metadata", () => {
  const canary = "metadata-secret-must-not-be-retained";
  const mutations = [
    ...Object.keys(legacyStorage).map((key) => (value) => {
      delete value[key];
    }),
    ...[null, [], "tmpfs", 1].map((entry) => (value) => {
      value.legacyTmpfs = entry;
    }),
    (value) => {
      value.legacyTmpfs[canary] = "rw";
    },
    (value) => {
      value.legacyTmpfs["/var/lib/postgresql"] = canary;
    },
    ...["configuredMounts", "binds", "volumesFrom"].flatMap((key) => [
      ...[{}, "", 0, undefined].map((entry) => (value) => {
        value[key] = entry;
      }),
      (value) => {
        value[key] = [{ Type: "bind", Source: canary }];
      },
    ]),
    ...[null, {}, "", 0].map((entry) => (value) => {
      value.mounts = entry;
    }),
    ...["bind", "volume", canary].map((Type) => (value) => {
      value.mounts = [{ Type, Destination: canary, Source: canary, Name: canary }];
    }),
    (value) => {
      value.mounts = [null];
    },
    (value) => {
      value.id = "c".repeat(64);
    },
    (value) => {
      value.owner = canary;
    },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(legacyStorage);
    mutate(value);
    assert.throws(
      () => validateOwnedStorage(value, storageOwner),
      (error) => {
        const safe = sanitizeFailure(error, "storage-validate");
        assert.equal(safe.stage, "storage-validate");
        assert.notEqual(safe.code, "UNCLASSIFIED_FAILURE");
        assert.equal(JSON.stringify(safe).includes(canary), false);
        return true;
      },
    );
  }
  assert.throws(
    () => validateOwnedStorage(legacyStorage, { ...storageOwner, id: "a" }),
    (error) => sanitizeFailure(error, "owner-inspect").code === "CONTAINER_OWNERSHIP_MISMATCH",
  );
  assert.throws(
    () => validateOwnedStorage(legacyStorage, { ...storageOwner, owner: "b" }),
    (error) => sanitizeFailure(error, "owner-inspect").code === "CONTAINER_OWNERSHIP_MISMATCH",
  );
});

test("the old typed predicate is diagnostic only and cannot authorize a nonlegacy arrangement", () => {
  assert.throws(
    () =>
      validateOwnedStorage(
        {
          ...legacyStorage,
          mounts: [{ Type: "tmpfs", Destination: "/var/lib/postgresql", Source: "", Name: "" }],
        },
        storageOwner,
      ),
    (error) => {
      const safe = sanitizeFailure(error, "storage-validate");
      assert.equal(safe.code, "PERSISTENT_USER_MOUNT");
      assert.equal(safe.storage.previousTypedMountPredicatePassed, true);
      assert.deepEqual(safe.storage.mountClassifications, [
        { type: "tmpfs", destination: "/var/lib/postgresql", sourceEmpty: true, nameEmpty: true },
      ]);
      return true;
    },
  );
});

test("both fixed filesystem paths require exact tmpfs output", () => {
  for (const target of ["/var/lib/postgresql", "/var/lib/postgresql/18/docker"]) {
    for (const output of ["tmpfs", "tmpfs\n"])
      assert.deepEqual(validateTmpfsFilesystem(output, target), { path: target, filesystem: "tmpfs" });
    for (const output of [
      "ext2/ext3\n",
      "overlayfs\n",
      " tmpfs\n",
      "tmpfs\n\n",
      "tmpfs\r\n",
      "tmpfs\0",
      "",
      null,
      {},
    ])
      assert.throws(
        () => validateTmpfsFilesystem(output, target),
        (error) => sanitizeFailure(error, "data-filesystem").code === "TMPFS_FILESYSTEM_MISMATCH",
      );
  }
  assert.throws(
    () => validateTmpfsFilesystem("tmpfs\n", "/unadmitted"),
    (error) => sanitizeFailure(error, "data-filesystem").code === "PGDATA_PATH_MISMATCH",
  );
});

test("failure receipts retain only minted codes, fixed stages and bounded process classifications", () => {
  const canary = "postgresql://secret-bearing-error-must-not-escape";
  for (const error of [
    new Error(canary),
    Object.assign(new Error(canary), {
      code: "TMPFS_CONFIGURATION_MISMATCH",
      operation: canary,
      stdout: canary,
      stderr: canary,
      cause: new Error(canary),
      storage: { path: canary },
    }),
    new AggregateError([new Error(canary)], canary),
    undefined,
    null,
    false,
    0,
    canary,
  ])
    assert.deepEqual(sanitizeFailure(error, "restart-storage-validate"), {
      stage: "restart-storage-validate",
      code: "UNCLASSIFIED_FAILURE",
    });
  assert.deepEqual(sanitizeFailure(new Error(canary), canary), {
    stage: "unclassified",
    code: "UNCLASSIFIED_FAILURE",
  });
  assert.deepEqual(
    sanitizeDockerFailure({ code: 17, signal: canary, stdout: canary, message: canary }, "storage-inspect"),
    {
      operation: "storage-inspect",
      exitCode: 17,
      termination: "signal",
    },
  );
  assert.deepEqual(
    sanitizeDockerFailure({ code: canary, killed: true, stderr: canary }, "parent-filesystem"),
    {
      operation: "parent-filesystem",
      termination: "timeout-or-buffer-limit",
    },
  );
  assert.deepEqual(sanitizeDockerFailure({ code: 2.5, signal: "", cause: canary }, canary), {
    operation: "unclassified",
    termination: "exit-or-spawn",
  });
});

test("readiness retries require confirmed client close and preserve distinct cleanup uncertainty", {
  timeout: 2000,
}, async () => {
  const canary = "postgresql://connection-close-secret-must-not-escape";
  for (const primary of [new Error(canary), undefined, false]) {
    const receipt = { stage: "readiness" };
    let closes = 0;
    await assert.rejects(
      withProbeClient(
        {
          async connect() {
            throw primary;
          },
          async end() {
            closes++;
          },
        },
        () => assert.fail("failed connection cannot enter the action"),
        receipt,
      ),
      (error) => {
        assert.equal(error, primary);
        assert.equal(readinessRetryAllowed(error), true);
        return true;
      },
    );
    assert.equal(closes, 1);
    assert.equal(receipt.connectionCleanup, undefined);
    const cleanup = new Error(canary);
    await assert.rejects(
      withProbeClient(
        {
          async connect() {
            throw primary;
          },
          async end() {
            throw cleanup;
          },
        },
        () => assert.fail("failed connection cannot enter the action"),
        receipt,
      ),
      (error) => {
        assert.deepEqual(error.errors, [primary, cleanup]);
        assert.equal(readinessRetryAllowed(error), false);
        const safe = sanitizeFailure(error, receipt.stage);
        assert.equal(safe.stage, "readiness");
        assert.equal(safe.code, "CLIENT_CLEANUP_FAILED");
        assert.deepEqual(safe.primary, { stage: "readiness", code: "UNCLASSIFIED_FAILURE" });
        assert.deepEqual(safe.cleanup, { stage: "client-close", code: "UNCLASSIFIED_FAILURE" });
        assert.equal(JSON.stringify(safe).includes(canary), false);
        return true;
      },
    );
    assert.deepEqual(receipt.connectionCleanup, [{ stage: "client-close", code: "UNCLASSIFIED_FAILURE" }]);
  }
  const receipt = { stage: "restart-readiness" };
  await assert.rejects(
    withProbeClient(
      {
        async connect() {},
        async end() {
          throw new Error(canary);
        },
      },
      () => 1,
      receipt,
    ),
    (error) => {
      assert.equal(readinessRetryAllowed(error), false);
      assert.equal(sanitizeFailure(error, receipt.stage).code, "CLIENT_CLEANUP_FAILED");
      return true;
    },
  );
});

const runDirectory = path.join(root, ".local/database-tests");
async function directories() {
  try {
    return (await readdir(runDirectory)).sort();
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

const serviceEnv = {
  GITHUB_ACTIONS: "true",
  ONE_CONTROL_PG_SERVICE_ID: "a".repeat(64),
  ONE_CONTROL_PG_SERVICE_NETWORK: "github_network_test",
  ONE_CONTROL_PG_SERVICE_PORT: "5432",
  ONE_CONTROL_PG_PASSWORD: "test-only-password",
};
const wireRun = "a".repeat(32);
const wire = {
  run: wireRun,
  mode: "passthrough",
  stage: "complete",
  frontendFrames: 1,
  backendFrames: 1,
  frontendTypes: { Q: 1 },
  backendTypes: { Z: 1 },
  commitForwarded: 2,
  commitCommandObserved: 0,
  idleObservedAfterCommit: 0,
  withheldBytes: 0,
  activeSockets: 0,
  closed: true,
  callbackCount: 1,
  durable: 1,
  originalBackend: 12,
  replacementBackend: 12,
  milliseconds: 10,
  outcome: "confirmed",
  cleanup: { result: "passed", attempted: ["runtime", "proxy", "fixture"], failed: [] },
};
const successfulWire = [
  wire,
  {
    ...wire,
    mode: "lose-committed-ack",
    outcome: "unknown",
    commitCommandObserved: 1,
    idleObservedAfterCommit: 1,
    withheldBytes: 41,
    replacementBackend: 13,
  },
  {
    ...wire,
    mode: "drop-commit",
    outcome: "unknown",
    durable: 0,
    commitForwarded: 1,
    replacementBackend: 13,
  },
];
const wireMutations = [
  [
    "stage",
    (value) => {
      value.stage = "replacement";
    },
  ],
  [
    "callback count",
    (value) => {
      value.callbackCount = 0;
    },
  ],
  [
    "outcome",
    (value) => {
      value.outcome = "unobserved";
    },
  ],
  [
    "durability",
    (value) => {
      value.durable = 1 - value.durable;
    },
  ],
  [
    "forwarded commits",
    (value) => {
      value.commitForwarded++;
    },
  ],
  [
    "COMMIT acknowledgement",
    (value) => {
      value.commitCommandObserved = 1 - value.commitCommandObserved;
    },
  ],
  [
    "idle acknowledgement",
    (value) => {
      value.idleObservedAfterCommit = 1 - value.idleObservedAfterCommit;
    },
  ],
  [
    "withheld bytes",
    (value) => {
      value.withheldBytes = value.withheldBytes ? 0 : 1;
    },
  ],
  [
    "backend replacement",
    (value) => {
      value.replacementBackend =
        value.replacementBackend === value.originalBackend ? 13 : value.originalBackend;
    },
  ],
  [
    "missing original backend",
    (value) => {
      value.originalBackend = null;
    },
  ],
  [
    "missing replacement backend",
    (value) => {
      value.replacementBackend = null;
    },
  ],
  [
    "active sockets",
    (value) => {
      value.activeSockets = 1;
    },
  ],
  [
    "closed",
    (value) => {
      value.closed = false;
    },
  ],
  [
    "cleanup result",
    (value) => {
      value.cleanup.result = "failed";
    },
  ],
  [
    "cleanup attempts",
    (value) => {
      value.cleanup.attempted = ["runtime", "proxy"];
    },
  ],
  [
    "cleanup failures",
    (value) => {
      value.cleanup.failed = ["runtime"];
    },
  ],
];
test("each successful wire mode requires its defining observations", () => {
  for (const original of successfulWire) {
    const filename = `wire-${original.mode}.json`;
    assert.deepEqual(sanitizeWireObservation(original, wireRun, filename), original);
    for (const [name, mutate] of wireMutations) {
      const value = structuredClone(original);
      mutate(value);
      if (name === "cleanup result")
        assert.deepEqual(sanitizeWireObservation(value, wireRun, filename), value);
      else
        assert.throws(
          () => sanitizeWireObservation(value, wireRun, filename),
          undefined,
          `${original.mode} ${name}`,
        );
    }
  }
});
const baselineSuccess = {
  run: "a".repeat(32),
  sourceSha256: "f250dca873ac00b206a74af1401351c75a137fe3ffe5f0750e7ba3b517111bc1",
  catalogSha256: "7648810dad3ecf14fc5949072c986e4b1a38191d5e06b3b87a6523e71d01c8b0",
  observations: Object.fromEntries(
    [
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
    ].map((scenario) => [scenario, true]),
  ),
  cleanup: "passed",
};
test("required run rejects every contradictory successful proof and retains failed-run partial evidence", async () => {
  const parent = path.join(
    root,
    ".local/orchestrate/full-build/evidence/database-wire-evidence-gate-fix/runner-controls",
  );
  await mkdir(parent, { recursive: true });
  const control = await mkdtemp(path.join(parent, "gate-"));
  const evidence = path.join(control, "receipts");
  const source = await readFile(path.join(root, "scripts/test-postgres.mjs"), "utf8");
  const operationStart = source.indexOf("    await protect(directory);");
  const operationEnd = source.indexOf(
    "  } catch (error) {\n    ",
    source.indexOf('    receipt.result = "passed";', operationStart),
  );
  assert.ok(operationStart > 0 && operationEnd > operationStart);
  let instrument =
    source.slice(0, operationStart) +
    `    await protect(directory);
    await mkdir(path.join(directory, "observations"));
    for (const value of control.observations) await writeFile(path.join(directory, "observations", "wire-" + value.mode + ".json"), JSON.stringify({...value, run}));
    if (control.baseline) await writeFile(path.join(directory,"observations","migration-baseline.json"),JSON.stringify({...control.baseline,run}));
    receipt.tests = { total: 60, passed: 60, failed: 0, pending: 0, todo: 0 };
    if (control.failed) throw new Error("synthetic prior engine failure");
    receipt.result = "passed";
` +
    source.slice(operationEnd);
  const binaryProbe = `execFileSync(executable("postgres"), ["--version"], {
          encoding: "utf8",
          windowsHide: true,
          timeout: 10_000,
        }).trim()`;
  const binaryDirectory = 'const bin = path.join(root, ".tools/postgresql/pgsql/bin");';
  assert.equal(instrument.split(binaryProbe).length, 2);
  assert.equal(instrument.split(binaryDirectory).length, 2);
  const missingBin = path.join(control, "nonexistent-postgresql-bin");
  await assert.rejects(
    readFile(path.join(missingBin, process.platform === "win32" ? "postgres.exe" : "postgres")),
    { code: "ENOENT" },
  );
  instrument = instrument
    .replace(
      'const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");',
      `const root = ${JSON.stringify(root)};`,
    )
    .replace(
      /const evidenceRoot = path.join\([\s\S]*?\n\);/,
      `const evidenceRoot = ${JSON.stringify(evidence)};`,
    )
    .replace(binaryProbe, "expectedVersion")
    .replace(binaryDirectory, `const bin = ${JSON.stringify(missingBin)};`);
  instrument += "\nexport const control = { observations: [], failed: false, baseline:null };\n";
  const filename = path.join(control, "runner.mjs");
  await writeFile(filename, instrument);
  const module = await import(pathToFileURL(filename).href);
  const before = await directories();
  try {
    const scenarios = [{ name: "valid", observations: successfulWire, accepted: true }];
    for (const [index, original] of successfulWire.entries()) {
      for (const [name, mutate] of wireMutations) {
        const observations = structuredClone(successfulWire);
        mutate(observations[index]);
        scenarios.push({ name: `${original.mode} ${name}`, observations, accepted: false });
      }
    }
    scenarios.push({ name: "missing mode", observations: successfulWire.slice(1), accepted: false });
    scenarios.push({
      name: "missing baseline",
      observations: successfulWire,
      baseline: null,
      accepted: false,
    });
    for (const key of Object.keys(baselineSuccess.observations)) {
      const baseline = structuredClone(baselineSuccess);
      delete baseline.observations[key];
      scenarios.push({
        name: `missing baseline ${key}`,
        observations: successfulWire,
        baseline,
        accepted: false,
      });
    }
    scenarios.push({
      name: "prior failure with partial cleanup",
      observations: [
        {
          ...wire,
          stage: "runtime",
          outcome: "unobserved",
          callbackCount: 0,
          durable: null,
          originalBackend: null,
          replacementBackend: null,
          cleanup: { result: "failed", attempted: ["fixture"], failed: ["fixture"] },
        },
      ],
      accepted: false,
      failed: true,
    });
    for (const scenario of scenarios) {
      module.control.observations = scenario.observations;
      module.control.failed = scenario.failed ?? false;
      module.control.baseline = Object.hasOwn(scenario, "baseline") ? scenario.baseline : baselineSuccess;
      if (scenario.accepted) await module.run(["--profile", "owned-local"]);
      else await assert.rejects(module.run(["--profile", "owned-local"]), undefined, scenario.name);
      const receipt = JSON.parse(await readFile(path.join(evidence, "upload/runner-manifest.json"), "utf8"));
      assert.equal(receipt.result, scenario.accepted ? "passed" : "failed", scenario.name);
      assert.equal(receipt.cleanup, "owned-temporary-directory-removed-no-postmaster-created", scenario.name);
      assert.deepEqual(await directories(), before, scenario.name);
      if (scenario.failed) {
        assert.equal(receipt.wireObservations.length, 1);
        assert.equal(receipt.wireObservations[0].cleanup.result, "failed");
      }
    }
  } finally {
    await rm(control, { recursive: true });
  }
});
test("baseline evidence requires exact observations and rejects secret-bearing or malformed values", async () => {
  const value = baselineSuccess;
  assert.deepEqual(requireMigrationBaselineObservation(value, value.run), value);
  for (const mutation of [
    { run: "b".repeat(32) },
    { sql: "secret-canary" },
    { sourceSha256: "b".repeat(64) },
    { catalogSha256: "secret-canary" },
    { catalogSha256: [value.catalogSha256] },
    { cleanup: "secret-canary" },
    { observations: { ...value.observations, raw: "secret-canary" } },
    { observations: { ...value.observations, rows: "secret-canary" } },
  ])
    assert.throws(() => sanitizeMigrationBaselineObservation({ ...value, ...mutation }, value.run));
  for (const mutation of [
    { catalogSha256: null },
    { catalogSha256: "b".repeat(64) },
    { cleanup: "failed" },
    { observations: { ...value.observations, rows: false } },
  ])
    assert.throws(() => requireMigrationBaselineObservation({ ...value, ...mutation }, value.run));
  const folder = await mkdtemp(path.join(root, ".local/baseline-control-"));
  try {
    await mkdir(path.join(folder, "observations"));
    assert.equal(await collectMigrationBaselineObservation(folder, value.run), null);
    const filename = path.join(folder, "observations/migration-baseline.json");
    await writeFile(filename, JSON.stringify(value), { flag: "wx" });
    assert.deepEqual(await collectMigrationBaselineObservation(folder, value.run), value);
    await assert.rejects(writeFile(filename, "replacement", { flag: "wx" }), { code: "EEXIST" });
    await writeFile(filename, "x".repeat(4097));
    await assert.rejects(collectMigrationBaselineObservation(folder, value.run), /file boundary/);
    await writeFile(filename, "{");
    await assert.rejects(collectMigrationBaselineObservation(folder, value.run), /JSON/);
  } finally {
    await rm(folder, { recursive: true });
  }
});
test("wire evidence rejects unknown keys, identities, raw values and incomplete successful proof", () => {
  assert.deepEqual(sanitizeWireObservation(wire, wireRun, "wire-passthrough.json"), wire);
  for (const mutation of [
    { run: "b".repeat(32) },
    { mode: "unknown" },
    { sql: "raw canary" },
    { stage: "raw canary" },
    { frontendFrames: Infinity },
    { frontendFrames: -1 },
    { withheldBytes: "raw canary" },
    { frontendTypes: { "raw canary": 1 } },
    { backendTypes: { Z: "raw canary" } },
    { cleanup: { ...wire.cleanup, raw: "canary" } },
    { cleanup: { ...wire.cleanup, failed: ["runtime"] } },
    { originalBackend: "raw canary" },
    { closed: false },
    { outcome: "unobserved" },
  ])
    assert.throws(() => sanitizeWireObservation({ ...wire, ...mutation }, wireRun, "wire-passthrough.json"));
  assert.throws(() => sanitizeWireObservation(wire, wireRun, "wire-drop-commit.json"));
});
test("wire evidence collection is bounded and exclusive files preserve the first observation", async () => {
  const folder = await mkdtemp(path.join(root, ".local/wire-control-"));
  try {
    await mkdir(path.join(folder, "observations"));
    const filename = path.join(folder, "observations/wire-passthrough.json");
    await writeFile(filename, JSON.stringify(wire), { flag: "wx" });
    await assert.rejects(writeFile(filename, "replacement", { flag: "wx" }), { code: "EEXIST" });
    assert.deepEqual(await collectWireObservations(folder, wireRun), [wire]);
    assert.deepEqual(JSON.parse(await readFile(filename, "utf8")), wire);
    await writeFile(filename, JSON.stringify({ ...wire, raw: "canary" }));
    await assert.rejects(collectWireObservations(folder, wireRun), /invalid shape/);
    await writeFile(filename, "x".repeat(16_385));
    await assert.rejects(collectWireObservations(folder, wireRun), /file boundary/);
    await writeFile(path.join(folder, "observations/unrecognized.json"), "{}");
    await assert.rejects(collectWireObservations(folder, wireRun), /inventory/);
  } finally {
    await rm(folder, { recursive: true });
  }
});
test("service profile requires independent job identity and rejects inherited targets", () => {
  assert.equal(options(["--profile", "ci-service"], serviceEnv, "linux"), "ci-service");
  for (const mutation of [
    { ONE_CONTROL_PG_SERVICE_ID: "" },
    { ONE_CONTROL_PG_SERVICE_ID: "wrong" },
    { ONE_CONTROL_PG_SERVICE_NETWORK: "" },
    { ONE_CONTROL_PG_SERVICE_PORT: "0" },
    { ONE_CONTROL_PG_SERVICE_PORT: "5432extra" },
    { GITHUB_ACTIONS: "false" },
    { TEST_DATABASE_URL: "postgres://unverified.invalid/database" },
    { PGHOST: "external.invalid" },
  ])
    assert.throws(() => options(["--profile", "ci-service"], { ...serviceEnv, ...mutation }, "linux"));
  assert.throws(() => options(["--profile", "ci-service"], serviceEnv, "win32"));
});

test("service metadata rejects wrong custody and accepts the exact reverse case", () => {
  const expected = { id: "a".repeat(64), network: "github_network_test", port: 5432 };
  const observation = {
    id: expected.id,
    image: serviceImage,
    imageId: `sha256:${"b".repeat(64)}`,
    running: true,
    pid: 12,
    started: "2026-10-20T00:00:00Z",
    networks: { [expected.network]: {} },
    ports: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "5432" }] },
  };
  for (const mutation of [
    { id: "c".repeat(64) },
    { running: false },
    { pid: 0 },
    { started: "invalid" },
    { image: "postgres:18" },
    { imageId: "invented" },
    { networks: {} },
    { ports: { "5432/tcp": [{ HostIp: "0.0.0.0", HostPort: "5432" }] } },
    { ports: { "5432/tcp": [{ HostIp: "127.0.0.1", HostPort: "9999" }] } },
  ])
    assert.throws(() => validateService({ ...observation, ...mutation }, expected), /custody mismatch/);
  assert.deepEqual(validateService(observation, expected), observation);
});

test("command failure and timeout have bounded outcomes", async () => {
  assert.equal((await command(process.execPath, ["-e", "process.exit(7)"])).code, 7);
  await assert.rejects(
    command(process.execPath, ["-e", "setInterval(()=>{},1000)"], process.env, root, 100),
    /deadline expired/,
  );
  await assert.rejects(command(path.join(root, "does-not-exist-executable"), []), /ENOENT/);
});

test("server observations reject engine, principal and cluster mismatches before a reverse success", () => {
  const expected = {
    setup: "oc_setup_test",
    dataDirectory: "/var/lib/postgresql/18/docker",
    system: "123",
    postmaster: { pid: 1, dataDirectory: "/var/lib/postgresql/18/docker", startEpoch: "456", port: 5432 },
    serverStart: "2026-10-20 00:00:00+00",
  };
  const observed = {
    actor: expected.setup,
    version: 180006,
    checksums: "on",
    directory: expected.dataDirectory,
    system: expected.system,
    postmaster: expected.postmaster,
    started: expected.serverStart,
    sql_start_epoch: "457",
  };
  for (const mutation of [
    { actor: "runtime" },
    { version: 180005 },
    { checksums: "off" },
    { directory: "/another" },
    { system: "789" },
    { started: "different-invocation" },
    { postmaster: undefined },
    ...Object.entries({ pid: 2, dataDirectory: "/another", startEpoch: "987", port: 5433 }).map(
      ([key, value]) => ({ postmaster: { ...expected.postmaster, [key]: value } }),
    ),
  ])
    assert.throws(() => validateServer({ ...observed, ...mutation }, expected), /identity mismatch/);
  assert.deepEqual(validateServer(observed, expected), observed);
});

test("PID file parsing accepts complete LF and CRLF identities and rejects malformed bounded bytes", () => {
  const body = "1\n/var/lib/postgresql/18/docker\n456\n5432\n";
  const identity = { pid: 1, dataDirectory: "/var/lib/postgresql/18/docker", startEpoch: "456", port: 5432 };
  assert.deepEqual(parsePostmasterFile(Buffer.from(body)), identity);
  assert.deepEqual(parsePostmasterFile(Buffer.from(body.padEnd(4096, "x"))), identity);
  assert.deepEqual(
    parsePostmasterFile(Buffer.from(`${body.replaceAll("\n", "\r\n")}later status\r\n`)),
    identity,
  );
  for (const bytes of [
    undefined,
    body,
    Buffer.alloc(4097),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(body)]),
    Buffer.from([0xc3, 0x28]),
    Buffer.from(body.replace("456", "0")),
    Buffer.from(body.replace("5432", "65536")),
    Buffer.from(body.replace("1\n", "2147483648\n")),
    Buffer.from(body.replace("1\n", "01\n")),
    Buffer.from(body.replace("456", "-1")),
    Buffer.from(body.replace("5432", "NaN")),
    Buffer.from(body.replace("/var", "\0var")),
    Buffer.from(body.slice(0, -1)),
    Buffer.from("1\n/path\n456\n"),
    Buffer.from("1\n\n456\n5432\n"),
  ])
    assert.throws(() => parsePostmasterFile(bytes), /identity file invalid/);
});

test("fixed SQL file observation rejects each changed identity and preserves file-read failure", async () => {
  const expected = {
    setup: "oc_setup_test",
    profile: "ci-service",
    dataDirectory: "/owned",
    system: "123",
    serverStart: "2026-10-20 00:00:00+00",
    postmaster: { pid: 1, dataDirectory: "/owned", startEpoch: "456", port: 5432 },
  };
  const observed = {
    actor: expected.setup,
    version: 180006,
    checksums: "on",
    directory: "/owned",
    system: "123",
    started: expected.serverStart,
    postmaster_file: Buffer.from("1\n/owned\n456\n5432\n"),
  };
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      return { rows: [observed] };
    },
  };
  const accepted = await verifyOwnedTarget(client, expected);
  assert.deepEqual(accepted.postmaster, expected.postmaster);
  assert.equal(Object.hasOwn(accepted, "postmaster_file"), false);
  assert.match(queries[0], /pg_read_binary_file\('postmaster.pid',0,4097,false\)/);
  for (const [key, value] of Object.entries({
    pid: 2,
    dataDirectory: "/foreign",
    startEpoch: "457",
    port: 1,
  }))
    await assert.rejects(
      verifyOwnedTarget(client, { ...expected, postmaster: { ...expected.postmaster, [key]: value } }),
      /identity mismatch/,
    );
  for (const bytes of [
    undefined,
    Buffer.from("1\n/owned\n456\n5432"),
    Buffer.alloc(4097),
    Buffer.from([0xff]),
  ])
    await assert.rejects(
      verifyOwnedTarget(
        {
          async query() {
            return { rows: [{ ...observed, postmaster_file: bytes }] };
          },
        },
        expected,
      ),
      /identity file invalid/,
    );
  const denied = Object.assign(new Error("file read denied test"), { code: "42501" });
  await assert.rejects(
    verifyOwnedTarget(
      {
        async query() {
          throw denied;
        },
      },
      expected,
    ),
    (error) => error === denied,
  );
});

test("external PID-file observation applies the same byte boundary and closes the exact file", async () => {
  const directory = await mkdtemp(path.join(root, ".local/postmaster-file-control-"));
  try {
    const filename = path.join(directory, "postmaster.pid");
    await writeFile(filename, "1\n/owned\n456\n5432\n");
    assert.equal((await readPostmasterFile(directory)).pid, 1);
    await writeFile(filename, Buffer.alloc(4097));
    await assert.rejects(readPostmasterFile(directory), /identity file invalid/);
    await rm(filename);
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("run preserves operation, cleanup and evidence failures including falsy throws", async () => {
  const source = await readFile(path.join(root, "scripts/test-postgres.mjs"), "utf8");
  const parent = path.join(
    root,
    ".local/orchestrate/full-build/evidence/database-fixture-review-fix/controls",
  );
  await mkdir(parent, { recursive: true });
  for (const scenario of [
    { primary: "new Error('primary')", stdout: true },
    { primary: "new Error('primary')", cleanup: true, evidence: "mkdir", stdout: true },
    { primary: "new Error('primary')", evidence: "mkdir" },
    { primary: "new Error('primary')", evidence: "write" },
    { primary: "new Error('primary')", cleanup: true, evidence: "mkdir" },
    { cleanup: true, evidence: "mkdir" },
    { evidence: "mkdir" },
    {},
    ...["new Error('primary')", "undefined", "null", "false", "0", "''"].map((primary) => ({ primary })),
  ]) {
    const control = await mkdtemp(path.join(parent, "finalizer-"));
    const evidence = path.join(control, "evidence");
    const hasPrimary = Object.hasOwn(scenario, "primary");
    const operationStart = source.indexOf("    await protect(directory);");
    const operationEnd = source.indexOf(
      "  } catch (error) {\n    ",
      source.indexOf('    receipt.result = "passed";', operationStart),
    );
    assert.ok(operationStart > 0 && operationEnd > operationStart);
    let instrument =
      source.slice(0, operationStart) +
      `    await protect(directory);
    await mkdir(path.join(directory, "observations"));
    for (const value of ${JSON.stringify(successfulWire)}) await writeFile(path.join(directory, "observations", "wire-" + value.mode + ".json"), JSON.stringify({...value, run}));
    await writeFile(path.join(directory,"observations","migration-baseline.json"),JSON.stringify({...${JSON.stringify(baselineSuccess)},run}));
${hasPrimary ? "    throw operationFailure;" : '    receipt.result = "passed";'}
` +
      source.slice(operationEnd);
    instrument = instrument
      .replace(
        'const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");',
        `const root = ${JSON.stringify(root)};`,
      )
      .replace(
        /const evidenceRoot = path.join\([\s\S]*?\n\);/,
        `const evidenceRoot = ${JSON.stringify(evidence)};`,
      )
      .replace(
        "  const identity = await lstat(directory);",
        "  ownedDirectories.push(directory);\n  const identity = await lstat(directory);",
      )
      .replace(
        "  process.stdout.write(\n    `Required PostgreSQL ",
        "  terminalStatus(\n    `Required PostgreSQL ",
      );
    const binaryProbe = `execFileSync(executable("postgres"), ["--version"], {
          encoding: "utf8",
          windowsHide: true,
          timeout: 10_000,
        }).trim()`;
    const binaryDirectory = 'const bin = path.join(root, ".tools/postgresql/pgsql/bin");';
    const missingBin = path.join(control, "nonexistent-postgresql-bin");
    assert.equal(instrument.split(binaryProbe).length, 2);
    assert.equal(instrument.split(binaryDirectory).length, 2);
    instrument = instrument
      .replace(binaryProbe, "expectedVersion")
      .replace(binaryDirectory, `const bin = ${JSON.stringify(missingBin)};`);
    await assert.rejects(
      readFile(path.join(missingBin, process.platform === "win32" ? "postgres.exe" : "postgres")),
      { code: "ENOENT" },
    );
    if (scenario.cleanup)
      instrument = instrument.replace(
        "    receipt.fixtures = [];",
        "    throw cleanupFailure;\n    receipt.fixtures = [];",
      );
    instrument += `\nexport const operationFailure = ${scenario.primary ?? "undefined"};\nexport const cleanupFailure = new Error('cleanup');\nexport const ownedDirectories = [];\n`;
    instrument += `export const terminalStatusMessages = [];\nexport function terminalStatus(message) { terminalStatusMessages.push(message); ${scenario.stdout ? "throw new Error('synthetic terminal status failure');" : ""} }\n`;
    if (scenario.evidence === "mkdir") await writeFile(evidence, "test-owned evidence blocker");
    if (scenario.evidence === "write") {
      await mkdir(path.join(evidence, "upload/runner-manifest.json"), { recursive: true });
    }
    const filename = path.join(control, "runner.mjs");
    await writeFile(filename, instrument);
    const module = await import(pathToFileURL(filename).href);
    const before = await directories();
    let rejected = false;
    let observed;
    try {
      await module.run(["--profile", "owned-local"]);
    } catch (error) {
      rejected = true;
      observed = error;
    }
    try {
      const expected = [];
      if (hasPrimary) expected.push(module.operationFailure);
      if (scenario.cleanup) expected.push(module.cleanupFailure);
      if (scenario.evidence) {
        const errors = expected.length ? observed?.errors : [observed];
        assert.ok(errors, JSON.stringify(scenario));
        assert.equal(errors.length, expected.length + 1);
        for (const [index, error] of expected.entries()) assert.equal(errors[index], error);
        assert.equal(errors.at(-1).code, scenario.evidence === "mkdir" ? "EEXIST" : "EISDIR");
      } else if (expected.length) {
        assert.equal(observed, expected[0]);
      } else {
        assert.equal(observed, undefined);
      }
      assert.equal(rejected, expected.length > 0 || Boolean(scenario.evidence));
      assert.equal(module.terminalStatusMessages.length, rejected ? 0 : 1);
      if (!scenario.cleanup) assert.deepEqual(await directories(), before);
    } finally {
      for (const directory of module.ownedDirectories) {
        assert.equal(path.dirname(directory), runDirectory);
        assert.match(path.basename(directory), /^[a-f0-9]{32}$/);
        await rm(directory, { recursive: true, force: true });
      }
      assert.equal(path.dirname(control), parent);
      await rm(control, { recursive: true });
    }
  }
});
for (const [name, args, extraEnv] of [
  ["missing profile", [], {}],
  ["local profile", ["--profile", "local"], {}],
  ["missing service identity", ["--profile", "ci-service"], {}],
  ["malformed options", ["--profile", "owned-local", "--unknown"], {}],
  [
    "unverified URL",
    ["--profile", "owned-local"],
    { TEST_DATABASE_URL: "postgresql://unverified.invalid/never-connect" },
  ],
]) {
  test(`${name} fails before any run directory is created`, async () => {
    const before = await directories();
    const env = { ...process.env, ...extraEnv };
    delete env.ONE_CONTROL_POSTGRES_CUSTODY;
    delete env.ONE_CONTROL_PG_SERVICE_ID;
    const result = spawnSync(process.execPath, ["scripts/test-postgres.mjs", ...args], {
      cwd: root,
      env,
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
    });
    assert.equal(result.status, 1);
    assert.equal(result.signal, null);
    assert.match(result.stderr, /Required PostgreSQL command failed/);
    assert.deepEqual(await directories(), before);
  });
}
