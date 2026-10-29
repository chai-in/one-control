import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { resolveGo } from "../check-native.mjs";

const root = resolve("native-tooling-fixture");
const working = { status: 0, stdout: "go version go1.27.2 test/host\n" };

test("an explicit Go path takes precedence and disables automatic toolchain downloads", () => {
  const calls = [];
  const result = resolveGo({
    root,
    environment: { ONE_CONTROL_GO: "custom/go", GOTOOLCHAIN: "auto" },
    run(command, args, options) {
      calls.push({ command, args, options });
      return working;
    },
  });
  assert.equal(result.command, resolve(root, "custom/go"));
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, ["version"]);
  assert.equal(calls[0].options.env.GOTOOLCHAIN, "local");
});

test("an invalid explicit Go path fails without trying a different executable", () => {
  const calls = [];
  assert.throws(
    () =>
      resolveGo({
        root,
        environment: { ONE_CONTROL_GO: "missing/go" },
        run(command) {
          calls.push(command);
          return { status: null, stdout: "", error: new Error("not found") };
        },
      }),
    /ONE_CONTROL_GO is not a working Go executable/u,
  );
  assert.deepEqual(calls, [resolve(root, "missing/go")]);
  assert.throws(() => resolveGo({ environment: { ONE_CONTROL_GO: " " } }), /must name a Go executable/u);
});

test("Go resolves from PATH before the workspace toolchain", () => {
  const calls = [];
  const result = resolveGo({
    root,
    environment: {},
    run(command) {
      calls.push(command);
      return working;
    },
  });
  assert.equal(result.command, "go");
  assert.deepEqual(calls, ["go"]);
});

test("the workspace Go toolchain is the final fallback and absence is a failure", () => {
  const calls = [];
  const local = join(root, ".tools", "go", "bin", process.platform === "win32" ? "go.exe" : "go");
  const result = resolveGo({
    root,
    environment: {},
    run(command) {
      calls.push(command);
      return command === local ? working : { status: 1, stdout: "" };
    },
  });
  assert.equal(result.command, local);
  assert.deepEqual(calls, ["go", local]);
  assert.throws(
    () => resolveGo({ root, environment: {}, run: () => ({ status: 0, stdout: "unrelated tool" }) }),
    /Go is required/u,
  );
});
