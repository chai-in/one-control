import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ModulePlanError, resolveModulePlan } from "../dist/index.js";

const temp = await mkdtemp(join(tmpdir(), "onecontrol-planner-"));
const capture = join(temp, "captured.jsonl");
let cases;
try {
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      new URL("capture-hook.mjs", import.meta.url).href,
      "--test",
      "--test-reporter=tap",
      fileURLToPath(new URL("../tests/dependencies.test.mjs", import.meta.url)),
      fileURLToPath(new URL("../tests/rollback.test.mjs", import.meta.url)),
    ],
    {
      env: { ...process.env, ONECONTROL_FIXTURE_CAPTURE: capture },
      encoding: "utf8",
    },
  );
  if (result.status !== 0) throw new Error(result.stdout + result.stderr);
  const raw = (await readFile(capture, "utf8")).trim().split("\n").map(JSON.parse);
  cases = raw.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), "en"));
  const tests = /# tests (\d+)/.exec(result.stdout)?.[1];
  if (tests !== "30") throw new Error(`Expected unchanged 30-test corpus; got ${tests}`);
} finally {
  await rm(temp, { recursive: true, force: true });
}
const existingCases = cases.length;
function add(input) {
  const serializedInput = JSON.parse(JSON.stringify(input));
  let expected;
  try {
    expected = { plan: resolveModulePlan(serializedInput) };
  } catch (error) {
    expected = {
      error:
        error instanceof ModulePlanError
          ? { code: error.code, moduleKey: error.moduleKey }
          : { code: "invalid_wire" },
    };
  }
  cases.push({ input: serializedInput, expected });
}
const artifact = { url: "https://modules.example.com/package", sha256: "a".repeat(64), size: 100 };
const module = (id, dependencies = {}, options = {}) => ({
  schemaVersion: 1,
  id,
  version: "1.0.0",
  kind: "feature",
  minimumBootstrap: "1.0.0",
  permissions: [],
  dependencies,
  artifacts: { "win-x64": artifact },
  ...options,
});
const input = (overrides = {}) => ({
  catalog: [],
  enabled: {},
  platform: "win-x64",
  bootstrapVersion: "1.0.0",
  allowedPermissions: [],
  ...overrides,
});
let state = 0x1092026;
function random(max) {
  state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
  return state % max;
}
for (let seed = 0; seed < 256; seed++) {
  const catalog = [];
  const count = 1 + random(14);
  for (let i = 0; i < count; i++) {
    const dependencies = {};
    for (let j = i - 1; j >= 0; j--) if (random(5) === 0) dependencies[`m${j}`] = "1.0.0";
    catalog.push(module(`m${i}`, dependencies, { kind: i < count - 2 ? "shared" : "feature" }));
  }
  const roots = catalog.filter((m) => m.kind === "feature");
  const enabled = {};
  for (const m of roots) if (random(2)) enabled[m.id] = m.version;
  const installed = catalog.map((m) => ({
    id: m.id,
    version: m.version,
    sha256: artifact.sha256,
    size: 100,
    active: !!random(2),
    rollbackPinned: random(7) === 0,
    dependencies: m.dependencies,
  }));
  const value = input({ catalog, enabled, installed });
  switch (seed % 8) {
    case 1:
      value.disabled = [`m${random(count)}`];
      break;
    case 2:
      value.platform = "osx-arm64";
      break;
    case 3:
      value.bootstrapVersion = "0.9.0";
      break;
    case 4:
      value.installed = installed.slice(1);
      break;
    case 5:
      catalog.push(catalog[0]);
      break;
    case 6:
      catalog[count - 1].dependencies.absent = "1.0.0";
      break;
    case 7:
      value.installed.push(installed[0]);
      break;
  }
  add(value);
}
for (const bad of [
  module("files", {}, { installCommand: "bad" }),
  module("files", {}, { artifacts: { "win-x64": { ...artifact, url: "http://bad.example/package" } } }),
  module("files", {}, { version: "00001.0.0" }),
  module("files", {}, { permissions: ["files.read", "files.read"] }),
  module("files", {}, { artifacts: { "win-x64": { ...artifact, size: 1.5 } } }),
  module("files", {}, { artifacts: { "win-x64": { ...artifact, size: 2147483649 } } }),
  module("files", {}, { version: "100000.0.0" }),
])
  add(input({ catalog: [bad], enabled: { files: "1.0.0" } }));
add(
  input({
    catalog: [module("files", {}, { version: "99999.99999.99999" })],
    enabled: { files: "99999.99999.99999" },
    bootstrapVersion: "99999.99999.99999",
  }),
);
for (const count of [512, 513]) {
  const catalog = Array.from({ length: count }, (_, i) => module(`bound${i}`));
  add(input({ catalog }));
  add(
    input({
      installed: catalog.map((m) => ({
        id: m.id,
        version: m.version,
        sha256: artifact.sha256,
        size: 100,
        active: false,
        dependencies: {},
      })),
    }),
  );
}
for (const count of [32, 33]) {
  const catalog = Array.from({ length: count }, (_, i) => module(`edge${i}`, {}, { kind: "shared" }));
  const dependencies = Object.fromEntries(catalog.map((m) => [m.id, m.version]));
  add(input({ catalog: [...catalog, module("files", dependencies)], enabled: { files: "1.0.0" } }));
  const permissions = Array.from({ length: count }, (_, i) => `permission${i}`);
  add(
    input({
      catalog: [module("files", {}, { permissions })],
      enabled: { files: "1.0.0" },
      allowedPermissions: permissions,
    }),
  );
}
for (const size of [1, 2147483648])
  add(
    input({
      catalog: [module("files", {}, { artifacts: { "win-x64": { ...artifact, size } } })],
      enabled: { files: "1.0.0" },
    }),
  );
const artifactURLs = JSON.parse(
  await readFile(new URL("../../module-contracts/tests/artifact-urls.json", import.meta.url), "utf8"),
);
for (const url of [...artifactURLs.accepted, ...artifactURLs.rejected])
  add(
    input({
      catalog: [module("files", {}, { artifacts: { "win-x64": { ...artifact, url } } })],
      enabled: { files: "1.0.0" },
    }),
  );
const output = `${JSON.stringify(
  {
    schemaVersion: 1,
    oracle: "packages/modules/src/index.ts",
    existingTests: 30,
    existingCalls: existingCases,
    seed: 0x1092026,
    cases: cases.map((value, i) => ({ name: `case-${String(i + 1).padStart(3, "0")}`, ...value })),
  },
  null,
  2,
)}\n`;
const path = new URL("../fixtures/planner.json", import.meta.url);
// The fixture lives outside the nested Go module. A generated source digest
// makes corpus regeneration invalidate Go's source-based test cache as well.
const digestPath = new URL("../../../native/internal/selection/conformance_digest_test.go", import.meta.url);
const digestSource = `// Code generated by packages/modules/scripts/export-fixtures.mjs; DO NOT EDIT.\npackage selection\n\nconst oracleCorpusSHA256 = "${createHash("sha256").update(output).digest("hex")}"\n`;
if (process.argv.includes("--check")) {
  if ((await readFile(path, "utf8")) !== output) throw new Error("Planner fixture regeneration drift");
  if ((await readFile(digestPath, "utf8")) !== digestSource) throw new Error("Native fixture digest drift");
} else {
  await writeFile(path, output);
  await writeFile(digestPath, digestSource);
}
console.log(
  JSON.stringify({
    existingTests: 30,
    existingCalls: existingCases,
    totalCases: cases.length,
    check: process.argv.includes("--check"),
  }),
);
