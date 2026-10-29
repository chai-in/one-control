import { randomBytes, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import pg from "pg";
import { expect, test } from "vitest";
import { loadPostgresCustody, openPostgresFixture } from "../postgres-fixture.js";

async function setupConnection() {
  const custody = await loadPostgresCustody();
  const client = new pg.Client({
    host: "127.0.0.1",
    port: custody.port,
    user: custody.setup,
    password: custody.password,
    database: custody.database,
  });
  await client.connect();
  return client;
}

test("required profile rejects missing, local, malformed and external configuration", async () => {
  await expect(loadPostgresCustody({})).rejects.toThrow("custody profile rejected");
  await expect(loadPostgresCustody({ ONE_CONTROL_POSTGRES_PROFILE: "local" })).rejects.toThrow(
    "custody profile rejected",
  );
  await expect(loadPostgresCustody({ ONE_CONTROL_POSTGRES_PROFILE: "owned-local" })).rejects.toThrow(
    "receipt missing",
  );
  await expect(
    loadPostgresCustody({
      ONE_CONTROL_POSTGRES_PROFILE: "owned-local",
      TEST_DATABASE_URL: "postgresql://invalid",
    }),
  ).rejects.toThrow("custody profile rejected");
});

test("runtime authenticates separately, cannot create or assume authority and performs ordinary transactions", async () => {
  const db = await openPostgresFixture();
  try {
    const [identity] = await db.query(
      "SELECT session_user AS actor, current_user AS current, current_schema() AS namespace",
    );
    expect(identity?.actor).toMatch(/^oc_runtime_[a-f0-9]{32}$/);
    expect(identity?.current).toBe(identity?.actor);
    const [owner] = await db.query(
      "SELECT pg_get_userbyid(nspowner) AS name FROM pg_namespace WHERE nspname=current_schema()",
    );
    await expect(db.query("CREATE SCHEMA forbidden_runtime_schema")).rejects.toMatchObject({ code: "42501" });
    await expect(db.query("CREATE TABLE public.forbidden_runtime_table(id int)")).rejects.toMatchObject({
      code: "42501",
    });
    await expect(
      db.query(`CREATE TABLE ${identity?.namespace}.forbidden_runtime_table(id int)`),
    ).rejects.toMatchObject({ code: "42501" });
    await expect(db.query(`SET ROLE ${owner?.name}`)).rejects.toMatchObject({ code: "42501" });
    await expect(
      db.query(`SET ROLE ${String(owner?.name).replace("oc_owner_", "oc_migrator_")}`),
    ).rejects.toMatchObject({ code: "42501" });
    const id = randomUUID();
    await db.transaction(async (tx) => {
      await tx.query("INSERT INTO devices(id,hostname) VALUES($1,'restricted-runtime')", [id]);
    });
    expect(await db.query("SELECT id FROM devices WHERE id=$1", [id])).toEqual([{ id }]);
  } finally {
    await db.close();
  }
});

test("a missing runtime write grant rejects real writes and restoring that grant permits them", async () => {
  const db = await openPostgresFixture();
  const setup = await setupConnection();
  try {
    const [identity] = await db.query("SELECT session_user AS actor,current_schema() AS namespace");
    await setup.query(`REVOKE INSERT ON ${identity?.namespace}.devices FROM ${identity?.actor}`);
    await expect(
      db.query("INSERT INTO devices(id,hostname) VALUES($1,'grant-negative')", [randomUUID()]),
    ).rejects.toMatchObject({ code: "42501" });
    await setup.query(`GRANT INSERT ON ${identity?.namespace}.devices TO ${identity?.actor}`);
    const id = randomUUID();
    await db.query("INSERT INTO devices(id,hostname) VALUES($1,'grant-positive')", [id]);
    expect(await db.query("SELECT id FROM devices WHERE id=$1", [id])).toEqual([{ id }]);
  } finally {
    await db.close();
    await setup.end();
  }
});

test("identity mismatches and malformed receipts fail before creating any fixture resources", async () => {
  const filename = process.env.ONE_CONTROL_POSTGRES_CUSTODY;
  if (!filename) throw new Error("Required custody file missing");
  const bytes = await readFile(filename, "utf8");
  const custody = JSON.parse(bytes);
  const setup = await setupConnection();
  try {
    const { rows: before } = await setup.query("SELECT oid FROM pg_namespace ORDER BY oid");
    for (const mutation of [
      { databaseOid: custody.databaseOid + 1 },
      { serverStart: "invalid-start" },
      { systemIdentifier: "invalid-system" },
      { version: 2 },
      { port: 0 },
      { postmaster: undefined },
      { postmaster: { ...custody.postmaster, pid: custody.postmaster.pid + 1 } },
      { postmaster: { ...custody.postmaster, startEpoch: "1" } },
      { postmaster: { ...custody.postmaster, dataDirectory: "/not-owned" } },
      { postmaster: { ...custody.postmaster, port: 1 } },
      { runnerPid: 2_147_483_647 },
    ]) {
      await writeFile(filename, JSON.stringify({ ...custody, ...mutation }));
      await expect(openPostgresFixture()).rejects.toBeDefined();
      expect((await setup.query("SELECT oid FROM pg_namespace ORDER BY oid")).rows).toEqual(before);
    }
  } finally {
    await writeFile(filename, bytes);
    await setup.end();
  }
});

test("changed independent invocation rejects cleanup and retains the exact schema", async () => {
  const db = await openPostgresFixture();
  const setup = await setupConnection();
  const filename = process.env.ONE_CONTROL_POSTGRES_CUSTODY;
  if (!filename) throw new Error("Required custody file missing");
  const bytes = await readFile(filename, "utf8");
  try {
    const [schema] = await db.query("SELECT current_schema() AS name");
    const { rows: before } = await setup.query(
      "SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1",
      [schema?.name],
    );
    const custody = JSON.parse(bytes);
    custody.postmaster.startEpoch = "1";
    await writeFile(filename, JSON.stringify(custody));
    await expect(db.close()).rejects.toThrow("cleanup failed");
    expect(
      (await setup.query("SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1", [schema?.name]))
        .rows,
    ).toEqual(before);
  } finally {
    await writeFile(filename, bytes);
    await setup.end();
  }
});

test("separate runtime credentials deny schema-qualified access to another fixture", async () => {
  const first = await openPostgresFixture();
  const second = await openPostgresFixture();
  try {
    const [schema] = await first.query("SELECT current_schema() AS name");
    await first.query("INSERT INTO devices(id,hostname) VALUES($1,'private-fleet')", [randomUUID()]);
    await expect(second.query(`SELECT id FROM ${schema?.name}.devices`)).rejects.toMatchObject({
      code: "42501",
    });
    expect(await second.query("SELECT id FROM devices")).toEqual([]);
  } finally {
    await second.close();
    await first.close();
  }
});

test("creation collision never adopts or drops the pre-existing schema", async () => {
  const setup = await setupConnection();
  const suffix = randomBytes(16).toString("hex");
  const name = `oc_schema_${suffix}`;
  try {
    await setup.query(`CREATE SCHEMA ${name}`);
    const {
      rows: [before],
    } = await setup.query("SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1", [name]);
    await expect(openPostgresFixture(suffix)).rejects.toMatchObject({ code: "42P06" });
    const {
      rows: [after],
    } = await setup.query("SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1", [name]);
    expect(after).toEqual(before);
    await setup.query(`DROP SCHEMA ${name}`);
  } finally {
    await setup.end();
  }
});

test("cleanup retains a schema whose ownership marker changed", async () => {
  const db = await openPostgresFixture();
  const setup = await setupConnection();
  try {
    const [schema] = await db.query("SELECT current_schema() AS name");
    const {
      rows: [before],
    } = await setup.query("SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1", [schema?.name]);
    await setup.query(`COMMENT ON SCHEMA ${schema?.name} IS 'fixture-cleanup-negative-control'`);
    await expect(db.close()).rejects.toThrow("cleanup failed");
    const {
      rows: [after],
    } = await setup.query("SELECT oid::int,nspowner::int FROM pg_namespace WHERE nspname=$1", [schema?.name]);
    expect(after).toEqual(before);
  } finally {
    await setup.end();
  }
});

test("cleanup retains a role with a mismatched ownership marker and observes its exact identity", async () => {
  const db = await openPostgresFixture();
  const setup = await setupConnection();
  const custody = await loadPostgresCustody();
  try {
    const [schema] = await db.query("SELECT current_schema() AS name");
    const role = String(schema?.name).replace("oc_schema_", "oc_runtime_");
    const {
      rows: [before],
    } = await setup.query(
      "SELECT oid::int,shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=$1",
      [role],
    );
    await setup.query(`COMMENT ON ROLE ${role} IS 'cleanup-negative-control'`);
    await expect(db.close()).rejects.toThrow("cleanup failed");
    const {
      rows: [after],
    } = await setup.query("SELECT oid::int FROM pg_roles WHERE rolname=$1", [role]);
    expect(after?.oid).toBe(before?.oid);
    expect(before?.marker).toBe(`one-control-fixture:${custody.run}:${role.slice(11)}`);
    await setup.query(`COMMENT ON ROLE ${role} IS '${before?.marker}'`);
  } finally {
    await setup.end();
  }
});
