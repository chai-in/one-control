import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applications,
  availableUpdates,
  commonUpdates,
  connection,
  date,
  latestScan,
} from "../src/view-model.ts";

const now = Date.now();
const first = { id: "00000000-0000-4000-8000-000000000001", revision: 2, title: "Security update" };
const second = { id: "00000000-0000-4000-8000-000000000002", revision: 1, title: "Runtime update" };
const scan = (device, updates, completed = now) => ({
  device_id: device,
  kind: "windows.scan",
  state: "succeeded",
  created_at: new Date(now - 3600_000).toISOString(),
  finished_at: new Date(completed).toISOString(),
  result: { updates },
});

test("an install selection includes only exact revisions scanned on every target", () => {
  const result = commonUpdates(
    [scan("one", [first, second]), scan("two", [first, { ...second, revision: 2 }])],
    ["one", "two"],
    now,
  );
  assert.deepEqual(result.updates, [first]);
  assert.deepEqual(result.missing, []);
});
test("a missing, stale, future or failed scan never supplies installation choices", () => {
  for (const jobs of [
    [],
    [scan("one", [first], now - 25 * 3600_000)],
    [scan("one", [first], now + 120_000)],
    [{ ...scan("one", [first]), state: "failed" }],
  ]) {
    assert.deepEqual(commonUpdates(jobs, ["one"], now), { updates: [], missing: ["one"] });
  }
  assert.deepEqual(commonUpdates([scan("one", [first])], [], now).updates, []);
});
test("the latest completed scan supersedes an older applicable update list", () => {
  const older = scan("one", [first], now - 3600_000);
  const newer = scan("one", [], now);
  newer.created_at = older.created_at;
  assert.equal(latestScan([older, newer], "one"), newer);
  assert.deepEqual(commonUpdates([older, newer], ["one"], now).updates, []);
});
test("untrusted or partial receipt data cannot become an update selection", () => {
  assert.equal(date("invalid endpoint observation"), "Not reported");
  assert.deepEqual(
    availableUpdates({
      updates: [
        null,
        [],
        "text",
        { ...first, id: "not-an-update" },
        { ...first, revision: 0 },
        { ...first, revision: 1.2 },
        first,
        first,
      ],
    }),
    [first],
  );
  assert.deepEqual(
    applications({
      applications: [null, {}, { name: "" }, { name: "Runtime", version: {}, publisher: null }],
    }),
    [{ name: "Runtime", version: "—", publisher: "—" }],
  );
});
test("revocation takes priority over a recent heartbeat", () => {
  const device = { last_seen_at: new Date(now).toISOString(), revoked_at: new Date(now).toISOString() };
  assert.equal(connection(device, now).label, "Revoked");
  assert.equal(connection({ ...device, revoked_at: null }, now).label, "Online");
});
