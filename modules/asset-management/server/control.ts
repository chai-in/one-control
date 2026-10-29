// SPDX-License-Identifier: GPL-3.0-only
// Desktop employee/asset workflows adapted from TIBCON Sentry src/routes/inventory.ts.
import { z } from "zod";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { audit } from "../../../apps/control-plane/src/routes/context.js";
import { type Actor, ApiError } from "../../../apps/control-plane/src/security.js";

const optionalText = z.string().trim().min(1).max(255).nullable().default(null);
export const personInput = z
  .strictObject({
    name: z.string().trim().min(1).max(255),
    email: z.email().toLowerCase().nullable().default(null),
    department: optionalText,
    employeeCode: optionalText,
    title: optionalText,
    location: optionalText,
    identityIssuer: z.string().min(1).max(2048).nullable().default(null),
    identitySubject: optionalText,
    state: z.enum(["active", "offboarded"]).default("active"),
  })
  .refine((value) => Boolean(value.identityIssuer) === Boolean(value.identitySubject));
export const assetInput = z.strictObject({
  kind: z.enum(["windows", "macos", "other"]),
  identifier: z.string().trim().min(1).max(255),
  identifierType: z.enum(["asset-tag", "serial", "hostname", "other"]),
  label: z.string().trim().min(1).max(255),
  employeeId: z.uuid().nullable().default(null),
  notes: z.string().max(4000).default(""),
  state: z.enum(["stock", "assigned", "repair", "lost", "retired"]).default("stock"),
});
export const linkSource = z.enum(["native", "falcon", "ema"]);
const actorKey = (actor: Actor) => JSON.stringify([actor.issuer, actor.id]);
async function company(tx: TransactionQuery, scope: string) {
  const [row] = await tx.query<{ kind: string }>("SELECT kind FROM management_scopes WHERE id=$1", [scope]);
  if (row?.kind !== "company") throw new ApiError(403, "company_people_only");
}
async function asset(tx: TransactionQuery, scope: string, id: string) {
  const [row] = await tx.query<{ id: string; employee_id: string | null; state: string }>(
    "SELECT id,employee_id,state FROM managed_assets WHERE scope_id=$1 AND id=$2",
    [scope, id],
  );
  if (!row) throw new ApiError(404, "asset_not_found");
  return row;
}
export const assetControl = {
  async snapshot(tx: TransactionQuery, scope: string, version: string) {
    const [owner] = await tx.query<{ kind: string }>("SELECT kind FROM management_scopes WHERE id=$1", [
      scope,
    ]);
    const people = await tx.query(
      `SELECT p.id,p.name,p.email,p.department,p.employee_code,p.title,p.location,p.identity_issuer,p.identity_subject,p.state,p.offboarded_at,
      (SELECT count(*)::int FROM managed_assets a WHERE a.scope_id=p.scope_id AND a.employee_id=p.id AND a.state<>'retired') AS asset_count
      FROM company_people p WHERE p.scope_id=$1 ORDER BY p.name,p.id`,
      [scope],
    );
    const assets = await tx.query(
      `SELECT a.id,a.kind,a.identifier,a.identifier_type,a.label,a.employee_id,a.notes,a.state,a.assigned_at,a.updated_at,p.name AS employee_name,p.state AS employee_state
      FROM managed_assets a LEFT JOIN company_people p ON p.scope_id=a.scope_id AND p.id=a.employee_id WHERE a.scope_id=$1 ORDER BY a.label,a.id`,
      [scope],
    );
    const links = await tx.query(
      `SELECT l.asset_id,l.source,l.source_ref,l.verification,l.created_at,
      CASE WHEN l.source='native' THEN (e.id IS NOT NULL AND e.revoked_at IS NULL AND d.revoked_at IS NULL) ELSE NULL END AS native_active
      FROM asset_links l LEFT JOIN native_enrollments e ON l.source='native' AND l.source_ref=e.id::text AND e.scope_id=l.scope_id
      LEFT JOIN devices d ON d.id=e.device_id WHERE l.scope_id=$1 ORDER BY l.asset_id,l.source`,
      [scope],
    );
    const devices = await tx.query(
      `SELECT e.id AS enrollment_id,e.device_id,e.platform,d.hostname,d.last_seen_at,l.asset_id
      FROM native_enrollments e JOIN devices d ON d.id=e.device_id
      LEFT JOIN asset_links l ON l.scope_id=e.scope_id AND l.source='native' AND l.source_ref=e.id::text
      WHERE e.scope_id=$1 AND e.revoked_at IS NULL AND d.revoked_at IS NULL ORDER BY d.hostname,e.id`,
      [scope],
    );
    return { version, kind: owner?.kind, people, assets, links, devices };
  },
  async savePerson(tx: TransactionQuery, scope: string, id: string, raw: unknown, actor: Actor) {
    await company(tx, scope);
    const input = personInput.parse(raw);
    if (
      input.email &&
      (
        await tx.query(
          "SELECT id FROM company_people WHERE scope_id=$1 AND lower(email)=lower($2) AND id<>$3",
          [scope, input.email, id],
        )
      ).length
    )
      throw new ApiError(409, "employee_email_in_use");
    await tx.query(
      `INSERT INTO company_people(scope_id,id,name,email,department,employee_code,title,location,identity_issuer,identity_subject,state,offboarded_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CASE WHEN $11='offboarded' THEN clock_timestamp() ELSE NULL END)
      ON CONFLICT(scope_id,id) DO UPDATE SET name=EXCLUDED.name,email=EXCLUDED.email,department=EXCLUDED.department,employee_code=EXCLUDED.employee_code,title=EXCLUDED.title,location=EXCLUDED.location,
      identity_issuer=EXCLUDED.identity_issuer,identity_subject=EXCLUDED.identity_subject,state=EXCLUDED.state,
      offboarded_at=CASE WHEN EXCLUDED.state='offboarded' THEN COALESCE(company_people.offboarded_at,clock_timestamp()) ELSE NULL END,updated_at=clock_timestamp()`,
      [
        scope,
        id,
        input.name,
        input.email,
        input.department,
        input.employeeCode,
        input.title,
        input.location,
        input.identityIssuer,
        input.identitySubject,
        input.state,
      ],
    );
    await audit(tx, actorKey(actor), "person.saved", id, { scope, state: input.state });
    return { id };
  },
  async offboard(tx: TransactionQuery, scope: string, id: string, actor: Actor) {
    await company(tx, scope);
    const [person] = await tx.query(
      "UPDATE company_people SET state='offboarded',offboarded_at=COALESCE(offboarded_at,clock_timestamp()),updated_at=clock_timestamp() WHERE scope_id=$1 AND id=$2 RETURNING id,state",
      [scope, id],
    );
    if (!person) throw new ApiError(404, "person_not_found");
    const assets = await tx.query(
      "SELECT id,label,kind,state FROM managed_assets WHERE scope_id=$1 AND employee_id=$2 AND state<>'retired' ORDER BY id",
      [scope, id],
    );
    await audit(tx, actorKey(actor), "person.offboarded", id, {
      scope,
      assignedAssetIds: assets.map((row) => row.id),
      deviceAction: "none",
    });
    return { person, assets, deviceAction: "none", identityAccessRevoked: false };
  },
  async saveAsset(tx: TransactionQuery, scope: string, id: string, raw: unknown, actor: Actor) {
    const input = assetInput.parse(raw);
    if (input.employeeId) {
      await company(tx, scope);
      if (
        !(
          await tx.query(
            "SELECT p.id FROM company_people p WHERE p.scope_id=$1 AND p.id=$2 AND (p.state='active' OR EXISTS(SELECT 1 FROM managed_assets a WHERE a.scope_id=p.scope_id AND a.employee_id=p.id AND a.id=$3))",
            [scope, input.employeeId, id],
          )
        ).length
      )
        throw new ApiError(409, "active_employee_required");
    }
    const [prior] = await tx.query<{
      employee_id: string | null;
      identifier: string;
      identifier_type: string;
      kind: string;
    }>("SELECT employee_id,identifier,identifier_type,kind FROM managed_assets WHERE scope_id=$1 AND id=$2", [
      scope,
      id,
    ]);
    await tx.query(
      `INSERT INTO managed_assets(scope_id,id,kind,identifier,identifier_type,label,employee_id,notes,state,assigned_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $7::uuid IS NOT NULL THEN clock_timestamp() ELSE NULL END)
      ON CONFLICT(scope_id,id) DO UPDATE SET kind=EXCLUDED.kind,identifier=EXCLUDED.identifier,identifier_type=EXCLUDED.identifier_type,label=EXCLUDED.label,employee_id=EXCLUDED.employee_id,notes=EXCLUDED.notes,state=EXCLUDED.state,
      assigned_at=CASE WHEN managed_assets.employee_id IS NOT DISTINCT FROM EXCLUDED.employee_id THEN managed_assets.assigned_at ELSE EXCLUDED.assigned_at END,updated_at=clock_timestamp()`,
      [
        scope,
        id,
        input.kind,
        input.identifier,
        input.identifierType,
        input.label,
        input.employeeId,
        input.notes,
        input.state,
      ],
    );
    // An identity edit creates a new reconciliation decision rather than carrying old links across it.
    const identityChanged =
      prior &&
      (prior.identifier !== input.identifier ||
        prior.identifier_type !== input.identifierType ||
        prior.kind !== input.kind);
    if (identityChanged)
      await tx.query("DELETE FROM asset_links WHERE scope_id=$1 AND asset_id=$2", [scope, id]);
    await audit(tx, actorKey(actor), "asset.saved", id, {
      scope,
      previousEmployeeId: prior?.employee_id ?? null,
      employeeId: input.employeeId,
      state: input.state,
      linksCleared: Boolean(identityChanged),
    });
    return { id };
  },
  async removeAsset(tx: TransactionQuery, scope: string, id: string, actor: Actor) {
    const prior = await asset(tx, scope, id);
    await tx.query("DELETE FROM asset_links WHERE scope_id=$1 AND asset_id=$2", [scope, id]);
    await tx.query("DELETE FROM managed_assets WHERE scope_id=$1 AND id=$2", [scope, id]);
    await audit(tx, actorKey(actor), "asset.deleted", id, {
      scope,
      employeeId: prior.employee_id,
      deviceAction: "none",
    });
    return { id, deviceAction: "none" };
  },
  async link(
    tx: TransactionQuery,
    scope: string,
    id: string,
    source: z.infer<typeof linkSource>,
    raw: unknown,
    actor: Actor,
  ) {
    await asset(tx, scope, id);
    const input = z.strictObject({ reference: z.string().trim().min(1).max(255) }).parse(raw);
    if (source === "native" || source === "falcon") input.reference = input.reference.toLowerCase();
    let verification = "operator-recorded";
    if (source === "native") {
      z.uuid().parse(input.reference);
      if (
        !(
          await tx.query(
            "SELECT e.id FROM native_enrollments e JOIN devices d ON d.id=e.device_id WHERE e.scope_id=$1 AND e.id=$2 AND e.revoked_at IS NULL AND d.revoked_at IS NULL",
            [scope, input.reference],
          )
        ).length
      )
        throw new ApiError(409, "active_native_enrollment_required");
      verification = "native-enrollment";
    }
    if (source === "falcon")
      z.string()
        .regex(/^[a-fA-F0-9]{32}$/)
        .parse(input.reference);
    if (
      (
        await tx.query(
          "SELECT asset_id FROM asset_links WHERE scope_id=$1 AND source=$2 AND source_ref=$3 AND asset_id<>$4",
          [scope, source, input.reference, id],
        )
      ).length
    )
      throw new ApiError(409, "device_already_linked_to_asset");
    await tx.query("DELETE FROM asset_links WHERE scope_id=$1 AND asset_id=$2 AND source=$3", [
      scope,
      id,
      source,
    ]);
    await tx.query(
      "INSERT INTO asset_links(scope_id,asset_id,source,source_ref,verification,recorded_by) VALUES($1,$2,$3,$4,$5,$6)",
      [scope, id, source, input.reference, verification, actorKey(actor)],
    );
    await audit(tx, actorKey(actor), "asset.linked", id, { scope, source, verification });
    return { id, source, verification, commandTargetVerified: false };
  },
  async unlink(tx: TransactionQuery, scope: string, id: string, source: string, actor: Actor) {
    await asset(tx, scope, id);
    await tx.query("DELETE FROM asset_links WHERE scope_id=$1 AND asset_id=$2 AND source=$3", [
      scope,
      id,
      source,
    ]);
    await audit(tx, actorKey(actor), "asset.unlinked", id, { scope, source });
    return { id, source };
  },
};
