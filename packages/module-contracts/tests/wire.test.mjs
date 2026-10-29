import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWire } from "../src/validate.mjs";

const valid =
  '{"schemaVersion":1,"domain":"device-policy.v1","alg":"PS256","rootVersion":"1","keyId":"policy"}';
test("strict shared schema parser", () => {
  assert.equal(parseWire("Protected", Buffer.from(valid)).keyId, "policy");
  for (const raw of [
    valid.replace('"keyId":"policy"', '"keyId":"policy","keyId":"other"'),
    valid.replace('"schemaVersion":1', '"schemaVersion":1e0'),
    valid.replace('"schemaVersion":1', '"schemaVersion":{"numberToken":"1"}'),
    valid.replace('"rootVersion":"1"', '"rootVersion":"01"'),
    valid.replace('"rootVersion":"1"', '"rootVersion":"18446744073709551616"'),
    valid.replace('"keyId":"policy"', '"keyId":"\\ud800"'),
    valid.replace('"keyId":"policy"', '"keyId":"policy","shell":"bad"'),
    `${valid}{}`,
  ])
    assert.throws(() => parseWire("Protected", Buffer.from(raw)), { code: "invalid_wire" });
  assert.throws(() => parseWire("Protected", Buffer.concat([Buffer.from(valid), Buffer.from([255])])), {
    code: "invalid_wire",
  });
  assert.throws(
    () => parseWire("Protected", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(valid)])),
    { code: "invalid_wire" },
  );
});
