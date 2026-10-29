import assert from "node:assert/strict";
import test from "node:test";
import { apiError } from "../src/api-errors.ts";

test("database uncertainty asks for current-state inspection", () => {
  assert.equal(
    apiError("database_commit_unknown"),
    "The database outcome is unknown. Inspect the current state before submitting another change.",
  );
  assert.match(apiError("forbidden"), /role/);
});
