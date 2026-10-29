import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { repository, systemEnvironment } from "../lib/local-poc-config.mjs";

test("the real API child captures only inherited current-run requests, preserves duplicates and closes cleanly", {
  timeout: 45_000,
}, async () => {
  const root = mkdtempSync(join(tmpdir(), "one-control-backup-process-"));
  const runId = randomUUID(),
    workspaceId = randomUUID(),
    requestId = randomUUID();
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", resolve);
  });
  const address = probe.address();
  assert.ok(address && typeof address === "object");
  const port = address.port;
  await new Promise((resolve) => probe.close(resolve));
  const token = () => randomBytes(32).toString("base64url");
  const operator = token(),
    approver = token();
  writeFileSync(
    join(root, "workspace.json"),
    JSON.stringify({ schemaVersion: 1, id: workspaceId, root, repoRoot: repository }),
  );
  const child = fork(join(repository, "scripts/run-local-poc-child.mjs"), ["api", root, runId], {
    cwd: repository,
    windowsHide: true,
    execArgv: [],
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    env: {
      ...systemEnvironment(),
      NODE_ENV: "development",
      DEPLOYMENT_STAGE: "poc",
      POC_DEVICE_LIMIT: "5",
      HOST: "127.0.0.1",
      PORT: String(port),
      DATABASE_URL: "local",
      LOCAL_DB_PATH: join(root, "database"),
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: approver,
    },
  });
  const exit = new Promise((resolve) => child.once("exit", (code) => resolve(code)));
  const acknowledgments = new Map();
  child.on("message", (message) => {
    if (message?.type === "one-control-poc:backup-finished")
      acknowledgments.set(message.requestId, (acknowledgments.get(message.requestId) ?? 0) + 1);
  });
  async function waitForAck(id, count) {
    const deadline = Date.now() + 20_000;
    while ((acknowledgments.get(id) ?? 0) < count) {
      assert.ok(Date.now() < deadline, "Fixture backup acknowledgment did not arrive");
      assert.equal(child.exitCode, null);
      await delay(50);
    }
  }
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error("Fixture API readiness timed out")), 15_000);
      const onMessage = (message) => {
        if (message?.type === "ready" && message.role === "api") finish();
      };
      const onExit = () => finish(new Error("Fixture API exited before readiness"));
      const finish = (error) => {
        clearTimeout(timer);
        child.off("message", onMessage);
        child.off("exit", onExit);
        error ? reject(error) : resolve();
      };
      child.on("message", onMessage);
      child.once("exit", onExit);
      child.once("error", finish);
    });
    const origin = `http://127.0.0.1:${port}`;
    const headers = { authorization: `Bearer ${operator}`, "content-type": "application/json" };
    const issued = await fetch(`${origin}/v1/enrollment-tokens`, { method: "POST", headers, body: "{}" });
    assert.equal(issued.status, 201);
    const enrollment = await issued.json();
    const enrolled = await fetch(`${origin}/v1/agent/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: enrollment.token, hostname: "backup-ipc-fixture" }),
    });
    assert.equal(enrolled.status, 201);
    assert.equal((await fetch(`${origin}/v1/backups`, { headers })).status, 404);
    child.send({ type: "one-control-poc:backup", runId: randomUUID(), requestId });
    await delay(60);
    assert.equal(existsSync(join(root, "backups", requestId)), false);
    child.send({ type: "one-control-poc:backup", runId, requestId });
    const resultPath = join(root, "backups", requestId, "result.json");
    const deadline = Date.now() + 20_000;
    while (!existsSync(resultPath)) {
      assert.ok(Date.now() < deadline, "Fixture backup did not finish");
      assert.equal(child.exitCode, null);
      await delay(50);
    }
    const result = JSON.parse(readFileSync(resultPath, "utf8"));
    assert.equal(result.state, "succeeded");
    assert.deepEqual(result.identity, { workspaceId, runId, requestId });
    const manifest = JSON.parse(readFileSync(join(root, "backups", requestId, "manifest.json"), "utf8"));
    assert.equal(manifest.database.tables.devices.rows, 1);
    assert.equal(manifest.database.tables.credentials.rows, 1);
    const path = join(root, "backups", requestId, "database.tar.gz");
    const hash = () => createHash("sha256").update(readFileSync(path)).digest("hex");
    const original = hash();
    await waitForAck(requestId, 1);
    child.send({ type: "one-control-poc:backup", runId, requestId });
    await waitForAck(requestId, 2);
    const shutdownCapture = randomUUID();
    child.send({ type: "one-control-poc:backup", runId, requestId: shutdownCapture });
    child.send("one-control-poc:stop");
    const timeout = new AbortController();
    try {
      assert.equal(
        await Promise.race([
          exit,
          delay(10_000, null, { signal: timeout.signal }).then(() => {
            throw new Error("Fixture API did not close cleanly");
          }),
        ]),
        0,
      );
    } finally {
      timeout.abort();
    }
    assert.equal(hash(), original);
    assert.equal(JSON.parse(readFileSync(resultPath, "utf8")).state, "succeeded");
    assert.equal(
      JSON.parse(readFileSync(join(root, "backups", shutdownCapture, "result.json"), "utf8")).state,
      "succeeded",
    );
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await exit;
    }
    const path = resolve(root);
    assert.equal(dirname(path), resolve(tmpdir()));
    assert.match(basename(path), /^one-control-backup-process-[a-zA-Z0-9]+$/);
    assert.equal(lstatSync(path).isSymbolicLink(), false);
    rmSync(path, { recursive: true, force: true });
  }
});
