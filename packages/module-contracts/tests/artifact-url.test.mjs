import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { artifactSchema } from "../../modules/dist/index.js";
import { parseWire } from "../src/validate.mjs";

const cases = JSON.parse(readFileSync(new URL("artifact-urls.json", import.meta.url), "utf8"));
test("artifact URL contract agrees with the TypeScript reference schema", () => {
  for (const [group, urls] of Object.entries(cases)) {
    for (const url of urls) {
      const artifact = { url, sha256: "a".repeat(64), size: 1 };
      if (group === "accepted") {
        assert.equal(artifactSchema.parse(artifact).url, url);
        assert.equal(parseWire("Artifact", Buffer.from(JSON.stringify(artifact))).url, url);
      } else {
        assert.throws(() => artifactSchema.parse(artifact), `reference accepted ${JSON.stringify(url)}`);
        assert.throws(() => parseWire("Artifact", Buffer.from(JSON.stringify(artifact))), {
          code: "invalid_wire",
        });
      }
    }
  }
});
