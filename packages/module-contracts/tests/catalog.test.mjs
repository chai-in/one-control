import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWire } from "../src/validate.mjs";

const catalog = {
  schemaVersion: 2,
  authorityEpoch: "1",
  revision: "2",
  issuedAt: 100,
  expiresAt: 200,
  entries: [
    {
      manifest: {
        schemaVersion: 1,
        id: "inventory",
        version: "1.0.0",
        kind: "feature",
        minimumBootstrap: "0.1.0",
        permissions: [],
        dependencies: {},
        artifacts: {
          "win-x64": { url: "https://artifacts.example/inventory.zip", sha256: "a".repeat(64), size: 10 },
        },
      },
      platforms: {
        "win-x64": {
          publisher: "publisher",
          layout: "native-host-v1",
          hostAbi: "one-control-host-v1",
          scope: "machine",
          attestationSha256: "b".repeat(64),
        },
      },
    },
  ],
};

test("catalog v2 has a separate strict shape and cannot extend manifest v1", () => {
  const parse = (value) => parseWire("ModuleCatalog", Buffer.from(JSON.stringify(value)));
  assert.deepEqual(parse(catalog), catalog);
  for (const value of [
    { ...catalog, schemaVersion: 1 },
    { ...catalog, schemaVersion: "2" },
    { ...catalog, command: "cmd.exe" },
    {
      ...catalog,
      entries: [
        {
          ...catalog.entries[0],
          platforms: { "win-x64": { ...catalog.entries[0].platforms["win-x64"], hostAbi: "shell" } },
        },
      ],
    },
  ]) {
    assert.throws(() => parse(value), { code: "invalid_wire" });
  }
  assert.throws(
    () =>
      parseWire(
        "Manifest",
        Buffer.from(JSON.stringify({ ...catalog.entries[0].manifest, publisher: "publisher" })),
      ),
    { code: "invalid_wire" },
  );
  assert.throws(
    () =>
      parseWire(
        "ModuleCatalog",
        Buffer.from(JSON.stringify(catalog).replace('"revision":"2"', '"revision":"2","revision":"3"')),
      ),
    { code: "invalid_wire" },
  );
});
