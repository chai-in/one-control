import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWire } from "../src/validate.mjs";

const attestation = {
  schemaVersion: 1,
  id: "shared.payload",
  version: "1.0.0",
  platform: "win-x64",
  publisher: "fixture.publisher",
  layout: "passive-v1",
  archiveSha256: "a".repeat(64),
  archiveSize: 123,
  files: [{ path: "data/payload.txt", sha256: "b".repeat(64), size: 7 }],
  issuedAt: 100,
  expiresAt: 200,
};
const parse = (value) => parseWire("PackageAttestation", Buffer.from(JSON.stringify(value)));
test("separate package attestation wire shape", () => {
  assert.deepEqual(parse(attestation), attestation);
  for (const change of [
    { schemaVersion: 2 },
    { layout: "shell" },
    { archiveSize: 0 },
    { archiveSize: 2147483649 },
    { archiveSha256: "A".repeat(64) },
    { platform: "other" },
    { command: "host.exe" },
    { permissions: ["execute"] },
    { files: [{ ...attestation.files[0], mode: "executable" }] },
  ])
    assert.throws(() => parse({ ...attestation, ...change }), { code: "invalid_wire" });
  assert.throws(() => parseWire("Manifest", Buffer.from(JSON.stringify(attestation))), {
    code: "invalid_wire",
  });
  assert.throws(
    () =>
      parseWire(
        "PackageAttestation",
        Buffer.from(
          JSON.stringify(attestation).replace(
            '"publisher":"fixture.publisher"',
            '"publisher":"fixture.publisher","publisher":"other"',
          ),
        ),
      ),
    { code: "invalid_wire" },
  );
});
