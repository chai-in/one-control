import assert from "node:assert/strict";
import { test } from "node:test";
import { attention, bytes, coverage, disks, memoryCapacity, uptime } from "../src/device-health.ts";

test("missing or corrupt capacities are never displayed as empty or healthy volumes", () => {
  const inventory = {
    hardware: {
      disks: [
        null,
        {},
        { name: "C:\\", status: "available", totalBytes: 100, freeBytes: 0, systemVolume: true },
        { name: "D:\\", status: "available", totalBytes: 100, freeBytes: 101 },
        { name: "E:\\", status: "unavailable", totalBytes: 100, freeBytes: 100 },
        { name: "F:\\", status: "available", totalBytes: 0, freeBytes: 0 },
        { name: "network/share", status: "available", totalBytes: 100, freeBytes: 50 },
      ],
    },
  };
  const result = disks(inventory);
  assert.equal(result.length, 4);
  assert.deepEqual(result[0].capacity, { total: 100, free: 0, percent: 0, low: true });
  assert.equal(result[0].system, true);
  assert.ok(result.slice(1).every((item) => item.capacity === null));
  assert.deepEqual(disks(null), []);
});

test("memory validates totals and available space independently", () => {
  assert.equal(memoryCapacity(null), null);
  assert.equal(memoryCapacity({ hardware: { memory: { totalBytes: -1 } } }), null);
  assert.deepEqual(memoryCapacity({ hardware: { memory: { totalBytes: 1024, availableBytes: 0 } } }), {
    total: 1024,
    available: 0,
  });
  assert.deepEqual(memoryCapacity({ hardware: { memory: { totalBytes: 1024, availableBytes: 2048 } } }), {
    total: 1024,
    available: null,
  });
});

test("capacity and uptime formatting rejects non-finite and unsafe device values", () => {
  for (const value of [null, "1024", -1, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(bytes(value), "Not reported");
    assert.equal(uptime(value), "Not reported");
  }
  assert.equal(bytes(16 * 1024 ** 3), "16 GiB");
  assert.equal(bytes(0), "0 B");
  assert.equal(uptime(90_000), "1d 1h");
});

test("partial inventory is explicit while legacy inventory retains unknown coverage", () => {
  assert.deepEqual(coverage(null), { partial: false, sections: [], machineApplications: false });
  assert.deepEqual(
    coverage({
      collection: {
        status: "partial",
        applicationScope: "machine_registry_32_and_64_bit",
        issues: [
          { section: "hardware.disks" },
          { section: "applications" },
          { section: "hardware.memory" },
          null,
        ],
      },
    }),
    { partial: true, sections: ["Hardware", "Applications"], machineApplications: true },
  );
});

test("fleet attention uses observed conditions and never turns missing values into alarms", () => {
  assert.deepEqual(attention(null), []);
  assert.deepEqual(attention({}), []);
  assert.deepEqual(
    attention({
      agentRecoveryReady: false,
      rebootPending: true,
      collection: { status: "partial" },
      hardware: { disks: [{ name: "C:\\", status: "available", totalBytes: 100, freeBytes: 9 }] },
    }).map((item) => item.code),
    ["recovery", "low_space", "restart", "partial"],
  );
});
