import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveModulePlan } from "../dist/index.js";

const installed = (id, dependencies = {}, options = {}) => ({
  id,
  version: "1.0.0",
  dependencies,
  sha256: "a".repeat(64),
  size: 100,
  active: true,
  ...options,
});
const plan = (receipts) =>
  resolveModulePlan({
    catalog: [],
    enabled: {},
    disabled: ["files", "transport", "crypto"],
    platform: "win-x64",
    bootstrapVersion: "1.0.0",
    allowedPermissions: [],
    installed: receipts,
  });

test("a rollback pin retains its complete installed closure without a current catalog or activation", () => {
  const result = plan([
    installed("files", { transport: "1.0.0" }, { rollbackPinned: true }),
    installed("transport", { crypto: "1.0.0" }),
    installed("crypto"),
    installed("unrelated"),
  ]);
  assert.deepEqual(result.packages, []);
  assert.deepEqual(result.deactivate, ["crypto@1.0.0", "files@1.0.0", "transport@1.0.0", "unrelated@1.0.0"]);
  assert.deepEqual(result.removalCandidates, ["unrelated@1.0.0"]);
});

test("shared rollback dependencies survive until the last pin is released", () => {
  const receipts = [
    installed("files", { transport: "1.0.0" }, { rollbackPinned: true }),
    installed("clipboard", { transport: "1.0.0" }, { rollbackPinned: true }),
    installed("transport"),
  ];
  assert.deepEqual(plan(receipts).removalCandidates, []);
  const onePin = receipts.map((item) => (item.id === "files" ? { ...item, rollbackPinned: false } : item));
  assert.deepEqual(plan(onePin).removalCandidates, ["files@1.0.0"]);
  const noPins = receipts.map((item) => ({ ...item, rollbackPinned: false }));
  assert.deepEqual(plan(noPins).removalCandidates, ["clipboard@1.0.0", "files@1.0.0", "transport@1.0.0"]);
});

for (const [name, receipts, code] of [
  [
    "missing dependency of a pin",
    [installed("files", { transport: "1.0.0" }, { rollbackPinned: true })],
    "missing_installed_dependency",
  ],
  [
    "missing dependency of an unpinned record",
    [installed("files", { transport: "1.0.0" })],
    "missing_installed_dependency",
  ],
  ["self-cycle", [installed("files", { files: "1.0.0" })], "installed_dependency_cycle"],
  [
    "disconnected unpinned cycle",
    [installed("files", { transport: "1.0.0" }), installed("transport", { files: "1.0.0" })],
    "installed_dependency_cycle",
  ],
  ["duplicate identity", [installed("files"), installed("files")], "duplicate_installed_module"],
])
  test(`${name} prevents any removal plan`, () => assert.throws(() => plan(receipts), { code }));

for (const change of [
  { dependencies: undefined },
  { sha256: "invalid" },
  { size: -1 },
  { active: "true" },
  { rollbackPinned: "false" },
]) {
  test(`malformed installed receipt ${Object.keys(change)[0]} prevents any plan`, () => {
    assert.throws(() => plan([installed("files", {}, change)]));
  });
}

test("planning keeps installed receipt data unchanged", () => {
  const receipts = [installed("files", {}, { rollbackPinned: true })];
  const before = structuredClone(receipts);
  assert.deepEqual(plan(receipts), plan(receipts));
  assert.deepEqual(receipts, before);
});
