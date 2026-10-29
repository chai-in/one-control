import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { hash } from "../src/security.js";
import { openTestDatabase } from "./database-fixture.js";

test("audit pagination includes authorized native events and never leaks a partially authorized batch", async () => {
  const db = await openTestDatabase();
  const viewer = "audit-viewer-".repeat(4);
  const app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: "audit-operator-".repeat(4),
      DEV_APPROVER_TOKEN: "audit-approver-".repeat(4),
      DEV_VIEWER_TOKEN: viewer,
    }),
  );
  const scopes = [randomUUID(), randomUUID()];
  const devices = [randomUUID(), randomUUID()];
  const enrollments = [randomUUID(), randomUUID()];
  const batch = randomUUID();
  const jobs = [randomUUID(), randomUUID()];
  const issuer = "urn:one-control:local-development";
  const headers = { authorization: `Bearer ${viewer}` };
  try {
    for (let index = 0; index < 2; index++) {
      const scope = scopes[index],
        device = devices[index],
        enrollment = enrollments[index],
        invitation = hash(randomUUID());
      await db.query("INSERT INTO management_scopes(id,kind,name) VALUES($1,'company','Audit fixture')", [
        scope,
      ]);
      await db.query("INSERT INTO devices(id,hostname) VALUES($1,'Audit fixture')", [device]);
      await db.query(
        "INSERT INTO native_invitations(hash,scope_id,device_id,existing_device,hostname,platform,machine_id,issuer,subject,expires_at) VALUES($1,$2,$3,false,'Audit fixture','win-x64','fixture',$4,'owner',now()+interval '1 hour')",
        [invitation, scope, device, issuer],
      );
      await db.query(
        "INSERT INTO native_enrollments(id,scope_id,device_id,invitation_hash,platform,machine_id) VALUES($1,$2,$3,$4,'win-x64','fixture')",
        [enrollment, scope, device, invitation],
      );
    }
    await db.query(
      "INSERT INTO scope_grants(scope_id,issuer,subject,permission) VALUES($1,$2,'local-viewer','view')",
      [scopes[0], issuer],
    );
    await db.query(
      "INSERT INTO batches(id,created_by,command,ring) VALUES($1,'fixture','{\"kind\":\"inventory.refresh\"}','canary')",
      [batch],
    );
    for (let index = 0; index < 2; index++)
      await db.query(
        "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at) VALUES($1,$2,$3,'system','inventory.refresh','{\"kind\":\"inventory.refresh\"}','succeeded',now(),now()+interval '1 hour')",
        [jobs[index], batch, devices[index]],
      );
    const emit = async (action: string, subject: string, detail = {}) => {
      const [row] = await db.query<{ sequence: string }>(
        "INSERT INTO audit_events(actor,action,subject,detail) VALUES('fixture',$1,$2,$3) RETURNING sequence",
        [action, subject, JSON.stringify(detail)],
      );
      return Number(row?.sequence);
    };
    const visible = await emit("native.job_reported", jobs[0]!);
    await emit("native.job_reported", jobs[1]!);
    await emit("native.credential_rotated", enrollments[0]!);
    await emit("batch.approved", batch);
    await emit("native.unresolved", randomUUID());
    const latest = await emit("native.invitation_created", randomUUID(), { scope: scopes[0] });
    const read = async (query = "") => {
      const response = await app.inject({ url: `/v1/audit${query}`, headers });
      expect(response.statusCode).toBe(200);
      return response.json().events as { sequence: string; action: string; subject: string }[];
    };
    const events = await read();
    expect(events.map((event) => event.action)).toEqual([
      "native.job_reported",
      "native.credential_rotated",
      "native.invitation_created",
    ]);
    expect((await read(`?after=${visible}`)).map((event) => event.action)).toEqual([
      "native.credential_rotated",
      "native.invitation_created",
    ]);
    expect(Number((await read("?direction=latest"))[0]?.sequence)).toBe(latest);
    await db.query(
      "INSERT INTO scope_grants(scope_id,issuer,subject,permission) VALUES($1,$2,'local-viewer','view')",
      [scopes[1], issuer],
    );
    expect((await read()).some((event) => event.subject === batch)).toBe(true);
    await db.query("UPDATE scope_grants SET revoked_at=now() WHERE scope_id=$1", [scopes[0]]);
    expect((await read()).map((event) => event.subject)).toEqual([jobs[1]]);
  } finally {
    await app.close();
    await db.close();
  }
}, 30_000);
