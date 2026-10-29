import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { backupRequest, pendingBackupRequests } from "../lib/local-poc-backup.mjs";

test("backup authority is bound to one runtime, one request and a bounded live window", () => {
  const now = Date.now(),
    runId = randomUUID(),
    requestId = randomUUID();
  const value = {
    schemaVersion: 1,
    runId,
    requestId,
    createdAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
  };
  assert.deepEqual(backupRequest(value, runId, now), value);
  for (const change of [
    { runId: randomUUID() },
    { requestId: "../other" },
    { expiresAt: new Date(now).toISOString() },
    { createdAt: new Date(now + 1).toISOString() },
    { expiresAt: new Date(now + 120_001).toISOString() },
    { extra: "unexpected" },
  ])
    assert.equal(backupRequest({ ...value, ...change }, runId, now), null);
});
test("the supervisor ignores old runs, partial files and handled requests without replay", () => {
  const root = mkdtempSync(join(tmpdir(), "one-control-backup-requests-"));
  try {
    const directory = join(root, "backup-requests");
    mkdirSync(directory);
    const now = Date.now(),
      runId = randomUUID(),
      requestId = randomUUID();
    const value = {
      schemaVersion: 1,
      runId,
      requestId,
      createdAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };
    writeFileSync(join(directory, `${requestId}.new`), "partial");
    assert.equal(pendingBackupRequests(root, runId, new Set(), now).length, 0);
    writeFileSync(join(directory, `${requestId}.json`), JSON.stringify(value));
    assert.equal(pendingBackupRequests(root, runId, new Set(), now).length, 1);
    assert.equal(pendingBackupRequests(root, randomUUID(), new Set(), now).length, 0);
    assert.equal(pendingBackupRequests(root, runId, new Set([`${requestId}.json`]), now).length, 0);
  } finally {
    const path = resolve(root);
    assert.equal(dirname(path), resolve(tmpdir()));
    assert.match(basename(path), /^one-control-backup-requests-[a-zA-Z0-9]+$/);
    rmSync(path, { recursive: true, force: true });
  }
});
