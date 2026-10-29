import assert from "node:assert/strict";
import { test } from "node:test";
import { moduleManifestSchema, resolveModulePlan } from "../dist/index.js";

const artifact = { url: "https://modules.example.com/content/package", sha256: "a".repeat(64), size: 100 };
const module = (id, dependencies = {}, options = {}) => ({
  schemaVersion: 1,
  id,
  version: "1.0.0",
  kind: "feature",
  minimumBootstrap: "1.0.0",
  dependencies,
  permissions: [],
  artifacts: { "win-x64": artifact },
  ...options,
});
const shared = module("transport", {}, { kind: "shared" });
const files = module("files", { transport: "1.0.0" });
const clipboard = module("clipboard", { transport: "1.0.0" });
const receipt = (item, options = {}) => ({
  id: item.id,
  version: item.version,
  dependencies: item.dependencies,
  sha256: artifact.sha256,
  size: artifact.size,
  active: true,
  ...options,
});
const plan = (overrides = {}) =>
  resolveModulePlan({
    catalog: [shared, files, clipboard],
    enabled: {},
    platform: "win-x64",
    bootstrapVersion: "1.0.0",
    allowedPermissions: [],
    ...overrides,
  });

test("a minimal device requests no feature packages", () => assert.deepEqual(plan().packages, []));
test("enabling one feature obtains only its dependency closure", () => {
  assert.deepEqual(
    plan({ enabled: { files: "1.0.0" } }).packages.map((item) => item.key),
    ["transport@1.0.0", "files@1.0.0"],
  );
});
test("two features share one exact dependency and track both references", () => {
  const result = plan({ enabled: { files: "1.0.0", clipboard: "1.0.0" } });
  assert.equal(result.packages.length, 3);
  assert.deepEqual(result.packages[0].requiredBy, ["clipboard", "files"]);
});
test("disabling one feature keeps the dependency used by another", () => {
  const installed = [shared, files, clipboard].map((item) => receipt(item));
  const result = plan({ enabled: { clipboard: "1.0.0" }, installed });
  assert.deepEqual(result.deactivate, ["files@1.0.0"]);
  assert.deepEqual(result.removalCandidates, ["files@1.0.0"]);
  assert.ok(result.packages.every((item) => !item.downloadRequired));
});
test("rollback pins prevent garbage collection but do not keep a disabled feature active", () => {
  const result = plan({ installed: [receipt(files, { rollbackPinned: true }), receipt(shared)] });
  assert.deepEqual(result.deactivate, ["files@1.0.0", "transport@1.0.0"]);
  assert.deepEqual(result.removalCandidates, []);
});
test("changed installed bytes require a verified replacement", () => {
  const result = plan({
    enabled: { files: "1.0.0" },
    installed: [receipt(shared, { sha256: "b".repeat(64), active: false })],
  });
  assert.equal(result.packages[0].downloadRequired, true);
});
for (const [name, overrides, code] of [
  ["unknown or excluded feature", { enabled: { "crm.status": "1.0.0" } }, "missing_manifest"],
  ["missing pinned version", { enabled: { files: "2.0.0" } }, "missing_manifest"],
  ["disabled dependency", { enabled: { files: "1.0.0" }, disabled: ["transport"] }, "module_disabled"],
  ["unsupported platform", { enabled: { files: "1.0.0" }, platform: "osx-arm64" }, "unsupported_platform"],
  ["old bootstrap", { enabled: { files: "1.0.0" }, bootstrapVersion: "0.9.0" }, "bootstrap_upgrade_required"],
  ["shared dependency selected as a feature", { enabled: { transport: "1.0.0" } }, "feature_root_required"],
  [
    "cycle",
    {
      catalog: [
        module("files", { transport: "1.0.0" }),
        module("transport", { files: "1.0.0" }, { kind: "shared" }),
      ],
      enabled: { files: "1.0.0" },
    },
    "dependency_cycle",
  ],
  [
    "permission escalation",
    { catalog: [module("files", {}, { permissions: ["files.read"] })], enabled: { files: "1.0.0" } },
    "permission_not_granted",
  ],
  ["duplicate catalog identity", { catalog: [files, files] }, "duplicate_manifest"],
])
  test(`${name} fails before producing an install plan`, () =>
    assert.throws(() => plan(overrides), { code }));

test("incompatible dependency versions remain separately pinned", () => {
  const newer = module("transport", {}, { version: "2.0.0", kind: "shared" });
  const result = plan({
    catalog: [shared, newer, files, module("clipboard", { transport: "2.0.0" })],
    enabled: { files: "1.0.0", clipboard: "1.0.0" },
  });
  assert.equal(result.packages.filter((item) => item.manifest.id === "transport").length, 2);
});
test("manifests cannot contain shell instructions or insecure download origins", () => {
  assert.equal(moduleManifestSchema.safeParse({ ...files, installCommand: "arbitrary" }).success, false);
  assert.equal(
    moduleManifestSchema.safeParse({
      ...files,
      artifacts: { "win-x64": { ...artifact, url: "http://modules.example.com/package" } },
    }).success,
    false,
  );
});
