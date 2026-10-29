import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { gunzipSync, gzipSync } from "node:zlib";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, expect, test } from "vitest";
import { type Database, migrate, openDatabase } from "../src/database.js";
import { createLocalBackup, restoreLocalBackup, verifyLocalBackup } from "../src/local-backup.js";
import { frozenV1Units, seedBaselineRows } from "./fixtures/frozen-v1.js";

let db: Database;
let snapshotLocal: () => Promise<Blob>;
let root: string;
let backup: string;
const identity = { workspaceId: randomUUID(), runId: randomUUID(), requestId: randomUUID() };
const device = randomUUID();
const batch = randomUUID();
const terminal = randomUUID();
const scope = randomUUID();
const enrollment = randomUUID();
const states = ["awaiting_approval", "queued", "leased", "succeeded", "failed", "cancelled", "indeterminate"];
beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "one-control-backup-"));
  db = await openDatabase("local");
  if (!db.snapshotLocal) throw new Error("Fixture must support local snapshots");
  snapshotLocal = db.snapshotLocal;
  await migrate(db);
  await db.query("INSERT INTO devices(id,hostname,inventory) VALUES($1,'backup-pilot',$2)", [
    device,
    JSON.stringify({ serialNumber: "fixture", applications: [{ name: "Example application" }] }),
  ]);
  await db.query(
    "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES('fixture-system-hash',$1,'system',now()+interval '1 day')",
    [device],
  );
  await db.query(
    "INSERT INTO enrollment_tokens(hash,context,expires_at,created_by) VALUES('fixture-unused-enrollment','system',now()+interval '1 day','fixture-admin')",
  );
  await db.query("INSERT INTO batches(id,created_by,command,ring) VALUES($1,'fixture-admin','{}','canary')", [
    batch,
  ]);
  for (const state of states) {
    const jobBatch = state === "succeeded" ? batch : randomUUID();
    if (jobBatch !== batch)
      await db.query(
        "INSERT INTO batches(id,created_by,command,ring) VALUES($1,'fixture-admin','{}','canary')",
        [jobBatch],
      );
    await db.query(
      "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at,lease_hash,lease_expires_at,result) VALUES($1,$2,$3,'system','agent.update','{}',$4,now()-interval '1 minute',now()+interval '1 hour',$5,$6,$7)",
      [
        state === "succeeded" ? terminal : randomUUID(),
        jobBatch,
        device,
        state,
        state === "leased" ? "fixture-lease-hash" : null,
        state === "leased" ? new Date(Date.now() + 60_000) : null,
        JSON.stringify({ summary: `original-${state}` }),
      ],
    );
  }
  await db.query(
    "INSERT INTO audit_events(actor,action,subject,detail) VALUES('fixture','fixture.created',$1,'{}')",
    [device],
  );
  await db.query(
    "INSERT INTO idempotency_keys(actor,key,request_hash,response) VALUES('fixture','fixture-key','fixture-request-hash','{\"id\":1}')",
  );
  await db.query(
    "UPDATE authority_runtime SET state='active',authority_epoch=18446744073709551615,root_version=18446744073709551615,custody_reference='test-only-reference'",
  );
  await db.query(
    "INSERT INTO management_scopes(id,kind,name,version) VALUES($1,'personal','restore-fixture',18446744073709551615)",
    [scope],
  );
  await db.query(
    "INSERT INTO scope_grants(scope_id,issuer,subject,permission) VALUES($1,'test-issuer','test-owner','owner')",
    [scope],
  );
  for (const invitation of ["a", "b"])
    await db.query(
      "INSERT INTO native_invitations(hash,scope_id,device_id,existing_device,hostname,platform,machine_id,issuer,subject,expires_at,used_at) VALUES(repeat($1,64),$2,$3,true,'backup-pilot','win-x64','fixture-machine','test-issuer','test-owner',now()+interval '1 day',$4)",
      [invitation, scope, device, invitation === "a" ? new Date() : null],
    );
  await db.query(
    "INSERT INTO native_enrollments(id,scope_id,device_id,invitation_hash,platform,machine_id) VALUES($1,$2,$3,repeat('a',64),'win-x64','fixture-machine')",
    [enrollment, scope, device],
  );
  await db.query("UPDATE credentials SET enrollment_id=$1", [enrollment]);
  await db.query(
    "INSERT INTO module_states(scope_id,module_id,state,settings,version) VALUES($1,'inventory','enabled','{\"retained\":true}',18446744073709551615)",
    [scope],
  );
  backup = join(root, "capture");
  await createLocalBackup(snapshotLocal, backup, identity);
}, 30_000);
afterAll(async () => {
  await db?.close();
  if (root) {
    const path = resolve(root);
    expect(dirname(path)).toBe(resolve(tmpdir()));
    expect(basename(path)).toMatch(/^one-control-backup-[a-zA-Z0-9]+$/);
    expect((await lstat(path)).isSymbolicLink()).toBe(false);
    await rm(path, { recursive: true, force: true });
  }
});

test("a checkpointed snapshot restores the complete versioned table fingerprints and identities", async () => {
  const manifest = await verifyLocalBackup(backup);
  expect(manifest.identity).toEqual(identity);
  expect(Object.keys(manifest.database.tables)).toHaveLength(43);
  expect(manifest.schemaVersion).toBe(10);
  expect(manifest.database.tables.jobs.rows).toBe(states.length);
  expect(manifest.database.tables.credentials.rows).toBe(1);
  expect(manifest.database.tables.idempotency_keys.rows).toBe(1);
  expect((await db.query("SELECT hostname FROM devices WHERE id=$1", [device]))[0]?.hostname).toBe(
    "backup-pilot",
  );
}, 15_000);

test("restore quarantines every nonterminal job and old authentication without changing the source or terminal receipts", async () => {
  const original = await db.query("SELECT to_jsonb(j)::text AS row FROM jobs j WHERE id=$1", [terminal]);
  const destination = join(root, "restore");
  const result = await restoreLocalBackup(backup, destination);
  expect(result.state).toBe("quarantined");
  expect(result.quarantined).toEqual({
    jobs: 3,
    credentials: 1,
    enrollments: 1,
    scopes: 1,
    grants: 1,
    invitations: 1,
    nativeEnrollments: 1,
    modules: 1,
    policyCanaries: 0,
  });
  expect(result.runtimeStarted).toBe(false);
  const restored = new PGlite(join(destination, "database"));
  try {
    await restored.waitReady;
    expect(
      (await restored.query("SELECT state,authority_epoch::text,root_version::text FROM authority_runtime"))
        .rows,
    ).toEqual([
      { state: "quarantined", authority_epoch: "18446744073709551615", root_version: "18446744073709551615" },
    ]);
    expect((await restored.query("SELECT state,version::text,settings FROM module_states")).rows).toEqual([
      { state: "disabled", version: "18446744073709551615", settings: { retained: true } },
    ]);
    expect((await restored.query("SELECT subject FROM scope_grants WHERE revoked_at IS NULL")).rows).toEqual(
      [],
    );
    expect((await restored.query("SELECT id FROM native_enrollments WHERE revoked_at IS NULL")).rows).toEqual(
      [],
    );
    expect((await restored.query("SELECT hash FROM native_invitations WHERE used_at IS NULL")).rows).toEqual(
      [],
    );
    expect(
      (await restored.query("SELECT to_jsonb(j)::text AS row FROM jobs j WHERE id=$1", [terminal])).rows,
    ).toEqual(original);
    expect(
      (await restored.query("SELECT id FROM jobs WHERE state IN ('awaiting_approval','queued','leased')"))
        .rows,
    ).toHaveLength(0);
    expect((await restored.query("SELECT hash FROM credentials WHERE revoked_at IS NULL")).rows).toHaveLength(
      0,
    );
    expect(
      (await restored.query("SELECT hash FROM enrollment_tokens WHERE used_at IS NULL")).rows,
    ).toHaveLength(0);
    expect(
      (await restored.query("SELECT action FROM audit_events ORDER BY sequence DESC LIMIT 1")).rows[0],
    ).toEqual({ action: "database.restore.quarantined" });
  } finally {
    await restored.close();
  }
  expect(await db.query("SELECT hash FROM credentials WHERE revoked_at IS NULL")).toHaveLength(1);
  expect(await db.query("SELECT id FROM jobs WHERE state='leased'")).toHaveLength(1);
  await expect(restoreLocalBackup(backup, destination)).rejects.toThrow();
}, 20_000);

test("snapshot waits for the whole transaction and never captures a half-applied change", async () => {
  let release!: () => void;
  let entered!: () => void;
  const enteredPromise = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const releasePromise = new Promise<void>((resolve) => {
    release = resolve;
  });
  const transaction = db.transaction(async (tx) => {
    await tx.query("UPDATE devices SET hostname='transaction-first-half' WHERE id=$1", [device]);
    entered();
    await releasePromise;
    await tx.query("UPDATE devices SET hostname='transaction-complete' WHERE id=$1", [device]);
  });
  await enteredPromise;
  let captured = false;
  const snapshot = snapshotLocal().then((blob) => {
    captured = true;
    return blob;
  });
  try {
    await delay(25);
    expect(captured).toBe(false);
  } finally {
    release();
  }
  await transaction;
  const restored = new PGlite({ loadDataDir: await snapshot });
  try {
    await restored.waitReady;
    expect((await restored.query("SELECT hostname FROM devices WHERE id=$1", [device])).rows[0]).toEqual({
      hostname: "transaction-complete",
    });
  } finally {
    await restored.close();
  }
  await db.query("UPDATE devices SET hostname='backup-pilot' WHERE id=$1", [device]);
}, 15_000);

test("failed and duplicate captures preserve claimed state and never replace a completed archive", async () => {
  const hash = async () =>
    createHash("sha256")
      .update(await readFile(join(backup, "database.tar.gz")))
      .digest("hex");
  const before = await hash();
  await expect(createLocalBackup(snapshotLocal, backup, identity)).rejects.toThrow();
  expect(await hash()).toBe(before);
  const failed = join(root, "failed-capture");
  await expect(
    createLocalBackup(
      async () => {
        throw new Error("private source detail");
      },
      failed,
      { ...identity, requestId: randomUUID() },
    ),
  ).rejects.toThrow("preserve");
  expect(await readFile(join(failed, "result.json"), "utf8")).not.toContain("private source detail");
  await expect(createLocalBackup(snapshotLocal, failed, identity)).rejects.toThrow();
});

test("truncated or altered archive bytes cannot produce a restore destination", async () => {
  const altered = join(root, "altered");
  const fs = await import("node:fs/promises");
  await fs.mkdir(altered);
  await fs.copyFile(join(backup, "manifest.json"), join(altered, "manifest.json"));
  await writeFile(join(altered, "database.tar.gz"), Buffer.from("truncated"));
  const destination = join(root, "must-not-exist");
  await expect(restoreLocalBackup(altered, destination)).rejects.toThrow("integrity");
  await expect(lstat(destination)).rejects.toMatchObject({ code: "ENOENT" });
});

test("a manifest cannot authorize traversal, archive links or another table set", async () => {
  const fs = await import("node:fs/promises");
  const dangerous = join(root, "dangerous");
  await fs.mkdir(dangerous);
  const manifest = JSON.parse(await readFile(join(backup, "manifest.json"), "utf8"));
  manifest.archive.file = "../database.tar.gz";
  await writeFile(join(dangerous, "manifest.json"), JSON.stringify(manifest));
  await expect(verifyLocalBackup(dangerous)).rejects.toThrow();
  const tar = gunzipSync(await readFile(join(backup, "database.tar.gz")));
  tar.fill(0, 0, 100);
  tar.write("/../../escape", 0, "utf8");
  tar.fill(32, 148, 156);
  let checksum = 0;
  for (const byte of tar.subarray(0, 512)) checksum += byte;
  tar.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  const bytes = gzipSync(tar);
  manifest.archive = {
    file: "database.tar.gz",
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  await writeFile(join(dangerous, "manifest.json"), JSON.stringify(manifest));
  await writeFile(join(dangerous, "database.tar.gz"), bytes);
  await expect(verifyLocalBackup(dangerous)).rejects.toThrow("Unsafe database archive path");
  const link = join(root, "linked");
  await symlink(backup, link, process.platform === "win32" ? "junction" : "dir");
  await expect(verifyLocalBackup(link)).rejects.toThrow();
});

test("a valid frozen v1 archive restores into current quarantine without inventing grants or enrollment", async () => {
  const legacy = await openDatabase("local");
  try {
    for (const unit of frozenV1Units) await legacy.query(unit);
    await legacy.transaction((tx) => seedBaselineRows(tx, randomUUID()));
    if (!legacy.snapshotLocal) throw new Error("Missing snapshot capability");
    const source = join(root, "legacy-capture");
    expect(
      (await createLocalBackup(legacy.snapshotLocal, source, { ...identity, requestId: randomUUID() }))
        .schemaVersion,
    ).toBe(1);
    expect((await verifyLocalBackup(source)).database.schemaVersions).toEqual([1]);
    const destination = join(root, "legacy-restore");
    await restoreLocalBackup(source, destination);
    const restored = new PGlite(join(destination, "database"));
    try {
      await restored.waitReady;
      expect((await restored.query("SELECT version FROM schema_migrations ORDER BY version")).rows).toEqual(
        Array.from({ length: 10 }, (_, index) => ({ version: index + 1 })),
      );
      expect((await restored.query("SELECT state FROM authority_runtime")).rows).toEqual([
        { state: "quarantined" },
      ]);
      expect((await restored.query("SELECT * FROM native_enrollments")).rows).toEqual([]);
      expect((await restored.query("SELECT * FROM scope_grants")).rows).toEqual([]);
      expect((await restored.query("SELECT hash FROM credentials WHERE revoked_at IS NULL")).rows).toEqual(
        [],
      );
    } finally {
      await restored.close();
    }
  } finally {
    await legacy.close();
  }
}, 30_000);

test("failed quarantine never publishes a restoration receipt or persistent database", async () => {
  const damaged = new PGlite({ loadDataDir: await snapshotLocal() });
  try {
    await damaged.waitReady;
    await damaged.query("DELETE FROM authority_runtime");
    const source = join(root, "failed-quarantine-capture");
    await createLocalBackup(() => damaged.dumpDataDir("gzip"), source, {
      ...identity,
      requestId: randomUUID(),
    });
    const destination = join(root, "failed-quarantine-restore");
    await expect(restoreLocalBackup(source, destination)).rejects.toThrow("not quarantined");
    await expect(lstat(join(destination, "restoration.json"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(destination, "database"))).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await damaged.close();
  }
}, 30_000);
