// SPDX-License-Identifier: GPL-3.0-only
// Policy/version/group/canary semantics adapted from TIBCON Sentry; see docs/sentry-integration.json.
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { audit } from "../../../apps/control-plane/src/routes/context.js";
import { type Actor, ApiError } from "../../../apps/control-plane/src/security.js";
import {
  buildDesktopPolicy,
  type DesktopPolicy,
  desktopPolicyTemplates,
  policyDigest,
  policyId,
  policyModules,
} from "./policy.js";

type Policy = { id: string; version: string; document: DesktopPolicy; digest: string };
type Assignment = {
  device_id: string;
  enrollment_id: string;
  hostname: string;
  group_id: string | null;
  policy_id: string | null;
  group_policy_id: string | null;
};
type Canary = {
  id: string;
  policy_id: string;
  base_version: string;
  candidate: DesktopPolicy;
  digest: string;
  state: string;
};
const confirmations = {
  confirmBitlockerDecryption: z.boolean().optional(),
  confirmBitlockerSuspension: z.boolean().optional(),
};
export const desktopOperations = {
  save: z.strictObject({ document: z.unknown() }),
  remove: z.strictObject({}),
  clone: z.strictObject({ id: policyId, displayName: z.string().trim().min(1).max(120), ...confirmations }),
  rollback: z.strictObject({ version: z.string().regex(/^[1-9][0-9]{0,19}$/), ...confirmations }),
  group: z.strictObject({ name: z.string().trim().min(1).max(120), policyId: policyId.nullable() }),
  deleteGroup: z.strictObject({}),
  assign: z
    .strictObject({
      deviceIds: z
        .array(z.uuid())
        .min(1)
        .max(500)
        .transform((ids) => [...new Set(ids)].sort()),
      groupId: z.uuid().nullable().optional(),
      policyId: policyId.nullable().optional(),
    })
    .refine((value) => value.groupId !== undefined || value.policyId !== undefined),
  default: z.strictObject({ policyId: policyId.nullable() }),
  stage: z.strictObject({
    document: z.unknown(),
    deviceIds: z
      .array(z.uuid())
      .min(1)
      .max(100)
      .transform((ids) => [...new Set(ids)].sort()),
  }),
  abort: z.strictObject({}),
  promote: z.strictObject({ ...confirmations }),
} as const;
const actorKey = (actor: Actor) => JSON.stringify([actor.issuer, actor.id]);

async function livePolicy(tx: TransactionQuery, scope: string, id: string) {
  const [policy] = await tx.query<Policy>(
    "SELECT id,version::text,document,digest FROM desktop_policies WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL",
    [scope, id],
  );
  if (!policy) throw new ApiError(404, "policy_not_found");
  return policy;
}
async function noActiveCanary(tx: TransactionQuery, scope: string, id: string) {
  if (
    (
      await tx.query(
        "SELECT id FROM desktop_policy_canaries WHERE scope_id=$1 AND policy_id=$2 AND state IN ('pending','healthy')",
        [scope, id],
      )
    ).length
  )
    throw new ApiError(409, "abort_policy_canary_before_editing");
}
async function policyScope(tx: TransactionQuery, scope: string, document: DesktopPolicy) {
  if (document.monitoring.foregroundTracking || document.monitoring.screenshots) {
    const [row] = await tx.query<{ kind: string }>("SELECT kind FROM management_scopes WHERE id=$1", [scope]);
    if (row?.kind !== "company") throw new ApiError(403, "company_monitoring_only");
  }
}
async function writePolicy(
  tx: TransactionQuery,
  scope: string,
  id: string,
  document: DesktopPolicy,
  actor: Actor,
  reason: string,
) {
  await policyScope(tx, scope, document);
  const [head] = await tx.query<{ version: string; deleted_at: Date | null }>(
    "SELECT version::text,deleted_at FROM desktop_policies WHERE scope_id=$1 AND id=$2",
    [scope, id],
  );
  if (head?.deleted_at) throw new ApiError(409, "policy_id_retired");
  const next = head ? BigInt(head.version) + 1n : 1n;
  if (next > 18446744073709551615n) throw new ApiError(409, "policy_version_exhausted");
  const digest = policyDigest(document);
  await tx.query(
    `INSERT INTO desktop_policies(scope_id,id,version,document,digest) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(scope_id,id) DO UPDATE SET version=EXCLUDED.version,document=EXCLUDED.document,digest=EXCLUDED.digest,updated_at=clock_timestamp()`,
    [scope, id, next.toString(), JSON.stringify(document), digest],
  );
  await tx.query(
    "INSERT INTO desktop_policy_versions(scope_id,policy_id,version,document,digest,actor,reason) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [scope, id, next.toString(), JSON.stringify(document), digest, actorKey(actor), reason],
  );
  return { id, version: next.toString(), document, digest };
}
async function assignments(tx: TransactionQuery, scope: string) {
  return tx.query<Assignment>(
    `SELECT e.device_id,e.id AS enrollment_id,d.hostname,a.group_id,a.policy_id,g.policy_id AS group_policy_id
    FROM native_enrollments e JOIN devices d ON d.id=e.device_id
    LEFT JOIN desktop_assignments a ON a.scope_id=e.scope_id AND a.device_id=e.device_id AND a.enrollment_id=e.id
    LEFT JOIN desktop_groups g ON g.scope_id=a.scope_id AND g.id=a.group_id
    WHERE e.scope_id=$1 AND e.revoked_at IS NULL AND d.revoked_at IS NULL ORDER BY d.hostname,e.device_id`,
    [scope],
  );
}
function resolve(assignment: Assignment, fallback: string | null) {
  if (assignment.policy_id) return { policyId: assignment.policy_id, source: "device", groupId: null };
  if (assignment.group_policy_id)
    return { policyId: assignment.group_policy_id, source: "group", groupId: assignment.group_id };
  return { policyId: fallback, source: "default", groupId: null };
}
async function fleetDefault(tx: TransactionQuery, scope: string) {
  const [fleet] = await tx.query<{ default_policy_id: string | null }>(
    "SELECT default_policy_id FROM desktop_fleets WHERE scope_id=$1",
    [scope],
  );
  return fleet?.default_policy_id ?? null;
}
async function abortCanaries(tx: TransactionQuery, scope: string) {
  return (
    await tx.query<{ id: string }>(
      "UPDATE desktop_policy_canaries SET state='aborted',finished_at=clock_timestamp() WHERE scope_id=$1 AND state IN ('pending','healthy') RETURNING id",
      [scope],
    )
  ).map((row) => row.id);
}
async function currentCanary(tx: TransactionQuery, scope: string, id: string) {
  const [row] = await tx.query<Canary>(
    "SELECT id,policy_id,base_version::text,candidate,digest,state FROM desktop_policy_canaries WHERE scope_id=$1 AND id=$2",
    [scope, id],
  );
  if (!row) throw new ApiError(404, "canary_not_found");
  return row;
}

/** All calls run inside ModuleControl's scope lock, grant check and module admission. */
export async function desktopPolicyForEnrollment(tx: TransactionQuery, scope: string, enrollmentId: string) {
  const assignment = (await assignments(tx, scope)).find((device) => device.enrollment_id === enrollmentId);
  if (!assignment) throw new ApiError(404, "scoped_device_not_found");
  const effective = resolve(assignment, await fleetDefault(tx, scope));
  if (!effective.policyId) throw new ApiError(409, "desktop_policy_unassigned");
  const policy = await livePolicy(tx, scope, effective.policyId);
  const [canary] = await tx.query<Canary>(
    "SELECT c.id,c.policy_id,c.base_version::text,c.candidate,c.digest,c.state FROM desktop_policy_canaries c JOIN desktop_canary_targets t ON t.scope_id=c.scope_id AND t.canary_id=c.id WHERE c.scope_id=$1 AND c.policy_id=$2 AND t.enrollment_id=$3 AND c.state IN ('pending','healthy')",
    [scope, policy.id, enrollmentId],
  );
  return {
    policyId: policy.id,
    version: policy.version,
    document: canary?.candidate ?? policy.document,
    digest: canary?.digest ?? policy.digest,
    canaryId: canary?.id ?? null,
    source: effective.source,
  };
}
export const desktopControl = {
  async snapshot(tx: TransactionQuery, scope: string, version: string) {
    const fallback = await fleetDefault(tx, scope);
    return {
      version,
      defaultPolicyId: fallback,
      templates: desktopPolicyTemplates,
      policies: await tx.query<Policy>(
        "SELECT id,version::text,document,digest FROM desktop_policies WHERE scope_id=$1 AND deleted_at IS NULL ORDER BY id",
        [scope],
      ),
      groups: await tx.query(
        "SELECT id,name,policy_id FROM desktop_groups WHERE scope_id=$1 ORDER BY name,id",
        [scope],
      ),
      devices: (await assignments(tx, scope)).map((device) => ({
        ...device,
        effective: resolve(device, fallback),
      })),
      canaries: await tx.query(
        `SELECT c.id,c.policy_id,c.base_version::text,c.digest,c.state,c.created_at,c.finished_at,
        (SELECT count(*)::int FROM desktop_canary_targets t WHERE t.scope_id=c.scope_id AND t.canary_id=c.id) AS targets,
        (SELECT count(*)::int FROM desktop_canary_targets t WHERE t.scope_id=c.scope_id AND t.canary_id=c.id AND t.observed_digest=c.digest AND t.observation_reference IS NOT NULL) AS observed
        FROM desktop_policy_canaries c WHERE c.scope_id=$1 ORDER BY c.created_at DESC LIMIT 100`,
        [scope],
      ),
      execution: "not-connected" as const,
    };
  },
  async versions(tx: TransactionQuery, scope: string, id: string) {
    return {
      versions: await tx.query(
        "SELECT version::text,document,digest,actor,reason,created_at FROM desktop_policy_versions WHERE scope_id=$1 AND policy_id=$2 ORDER BY version DESC LIMIT 100",
        [scope, id],
      ),
    };
  },
  async effective(tx: TransactionQuery, scope: string, deviceId: string) {
    const device = (await assignments(tx, scope)).find((row) => row.device_id === deviceId);
    if (!device) throw new ApiError(404, "scoped_device_not_found");
    const resolved = resolve(device, await fleetDefault(tx, scope));
    if (!resolved.policyId) return { ...resolved, document: null, execution: "not-connected" };
    const policy = await livePolicy(tx, scope, resolved.policyId);
    const [canary] = await tx.query<Canary>(
      `SELECT c.id,c.policy_id,c.base_version::text,c.candidate,c.digest,c.state FROM desktop_policy_canaries c
      JOIN desktop_canary_targets t ON t.scope_id=c.scope_id AND t.canary_id=c.id
      WHERE c.scope_id=$1 AND c.policy_id=$2 AND c.state IN ('pending','healthy') AND t.device_id=$3 AND t.enrollment_id=$4`,
      [scope, policy.id, deviceId, device.enrollment_id],
    );
    const document = canary?.candidate ?? policy.document;
    const desiredModules = policyModules(document);
    const enabled = new Set(
      (
        await tx.query<{ module_id: string }>(
          "SELECT module_id FROM module_states WHERE scope_id=$1 AND state='enabled'",
          [scope],
        )
      ).map((row) => row.module_id),
    );
    return {
      ...resolved,
      version: policy.version,
      document,
      digest: canary?.digest ?? policy.digest,
      canaryId: canary?.id ?? null,
      desiredModules,
      disabledModules: desiredModules.filter((id) => !enabled.has(id)),
      execution: "not-connected",
    };
  },
  async mutate(
    tx: TransactionQuery,
    scope: string,
    actor: Actor,
    operation: keyof typeof desktopOperations,
    key: string | undefined,
    raw: unknown,
    version: string,
  ) {
    let result: unknown;
    switch (operation) {
      case "save": {
        const input = desktopOperations.save.parse(raw);
        const id = policyId.parse(key);
        await noActiveCanary(tx, scope, id);
        result = await writePolicy(tx, scope, id, buildDesktopPolicy(input.document), actor, "saved");
        break;
      }
      case "clone": {
        const input = desktopOperations.clone.parse(raw);
        const source = await livePolicy(tx, scope, policyId.parse(key));
        if (
          (await tx.query("SELECT id FROM desktop_policies WHERE scope_id=$1 AND id=$2", [scope, input.id]))
            .length
        )
          throw new ApiError(409, "policy_exists");
        const document = buildDesktopPolicy({
          ...source.document,
          displayName: input.displayName,
          confirmBitlockerDecryption: input.confirmBitlockerDecryption,
          confirmBitlockerSuspension: input.confirmBitlockerSuspension,
        });
        result = await writePolicy(
          tx,
          scope,
          input.id,
          document,
          actor,
          `cloned:${source.id}@${source.version}`,
        );
        break;
      }
      case "rollback": {
        const input = desktopOperations.rollback.parse(raw);
        const id = policyId.parse(key);
        await livePolicy(tx, scope, id);
        await noActiveCanary(tx, scope, id);
        const [prior] = await tx.query<{ document: DesktopPolicy }>(
          "SELECT document FROM desktop_policy_versions WHERE scope_id=$1 AND policy_id=$2 AND version=$3",
          [scope, id, input.version],
        );
        if (!prior) throw new ApiError(404, "policy_version_not_found");
        const document = buildDesktopPolicy({
          ...prior.document,
          confirmBitlockerDecryption: input.confirmBitlockerDecryption,
          confirmBitlockerSuspension: input.confirmBitlockerSuspension,
        });
        result = await writePolicy(tx, scope, id, document, actor, `rollback:${input.version}`);
        break;
      }
      case "remove": {
        desktopOperations.remove.parse(raw);
        const id = policyId.parse(key);
        await livePolicy(tx, scope, id);
        await noActiveCanary(tx, scope, id);
        const [refs] = await tx.query<{ referenced: boolean }>(
          `SELECT EXISTS(SELECT 1 FROM desktop_assignments WHERE scope_id=$1 AND policy_id=$2)
          OR EXISTS(SELECT 1 FROM desktop_groups WHERE scope_id=$1 AND policy_id=$2)
          OR EXISTS(SELECT 1 FROM desktop_fleets WHERE scope_id=$1 AND default_policy_id=$2) AS referenced`,
          [scope, id],
        );
        if (refs?.referenced) throw new ApiError(409, "policy_in_use");
        await tx.query(
          "UPDATE desktop_policies SET deleted_at=clock_timestamp() WHERE scope_id=$1 AND id=$2",
          [scope, id],
        );
        result = { deleted: id };
        break;
      }
      case "group": {
        const input = desktopOperations.group.parse(raw);
        const id = z.uuid().parse(key);
        if (input.policyId) await livePolicy(tx, scope, input.policyId);
        await tx.query(
          "INSERT INTO desktop_groups(scope_id,id,name,policy_id) VALUES($1,$2,$3,$4) ON CONFLICT(scope_id,id) DO UPDATE SET name=EXCLUDED.name,policy_id=EXCLUDED.policy_id",
          [scope, id, input.name, input.policyId],
        );
        result = { id, abortedCanaries: await abortCanaries(tx, scope) };
        break;
      }
      case "deleteGroup": {
        desktopOperations.deleteGroup.parse(raw);
        const id = z.uuid().parse(key);
        await tx.query("UPDATE desktop_assignments SET group_id=NULL WHERE scope_id=$1 AND group_id=$2", [
          scope,
          id,
        ]);
        const removed = await tx.query(
          "DELETE FROM desktop_groups WHERE scope_id=$1 AND id=$2 RETURNING id",
          [scope, id],
        );
        if (!removed.length) throw new ApiError(404, "group_not_found");
        result = { deleted: id, abortedCanaries: await abortCanaries(tx, scope) };
        break;
      }
      case "assign": {
        const input = desktopOperations.assign.parse(raw);
        if (input.policyId) await livePolicy(tx, scope, input.policyId);
        if (
          input.groupId &&
          !(
            await tx.query("SELECT id FROM desktop_groups WHERE scope_id=$1 AND id=$2", [
              scope,
              input.groupId,
            ])
          ).length
        )
          throw new ApiError(404, "group_not_found");
        const enrolled = new Map((await assignments(tx, scope)).map((row) => [row.device_id, row]));
        for (const id of input.deviceIds) {
          const device = enrolled.get(id);
          if (!device) throw new ApiError(404, "scoped_device_not_found");
          await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [id]);
          await tx.query(
            `INSERT INTO desktop_assignments(scope_id,device_id,enrollment_id,group_id,policy_id) VALUES($1,$2,$3,$4,$5)
            ON CONFLICT(scope_id,device_id) DO UPDATE SET enrollment_id=EXCLUDED.enrollment_id,group_id=EXCLUDED.group_id,policy_id=EXCLUDED.policy_id`,
            [
              scope,
              id,
              device.enrollment_id,
              input.groupId === undefined ? device.group_id : input.groupId,
              input.policyId === undefined ? device.policy_id : input.policyId,
            ],
          );
        }
        result = { assigned: input.deviceIds, abortedCanaries: await abortCanaries(tx, scope) };
        break;
      }
      case "default": {
        const input = desktopOperations.default.parse(raw);
        if (input.policyId) await livePolicy(tx, scope, input.policyId);
        await tx.query(
          "INSERT INTO desktop_fleets(scope_id,default_policy_id) VALUES($1,$2) ON CONFLICT(scope_id) DO UPDATE SET default_policy_id=EXCLUDED.default_policy_id",
          [scope, input.policyId],
        );
        result = { defaultPolicyId: input.policyId, abortedCanaries: await abortCanaries(tx, scope) };
        break;
      }
      case "stage": {
        const input = desktopOperations.stage.parse(raw);
        const policy = await livePolicy(tx, scope, policyId.parse(key));
        await noActiveCanary(tx, scope, policy.id);
        const document = buildDesktopPolicy(input.document);
        await policyScope(tx, scope, document);
        const enrolled = new Map((await assignments(tx, scope)).map((row) => [row.device_id, row]));
        const fallback = await fleetDefault(tx, scope);
        const id = randomUUID();
        await tx.query(
          "INSERT INTO desktop_policy_canaries(scope_id,id,policy_id,base_version,candidate,digest,state,actor) VALUES($1,$2,$3,$4,$5,$6,'pending',$7)",
          [
            scope,
            id,
            policy.id,
            policy.version,
            JSON.stringify(document),
            policyDigest(document),
            actorKey(actor),
          ],
        );
        for (const target of input.deviceIds) {
          const device = enrolled.get(target);
          if (!device || resolve(device, fallback).policyId !== policy.id)
            throw new ApiError(409, "canary_target_policy_mismatch");
          await tx.query(
            "INSERT INTO desktop_canary_targets(scope_id,canary_id,device_id,enrollment_id) VALUES($1,$2,$3,$4)",
            [scope, id, target, device.enrollment_id],
          );
        }
        result = { id, state: "pending", execution: "not-connected" };
        break;
      }
      case "abort": {
        desktopOperations.abort.parse(raw);
        const canary = await currentCanary(tx, scope, z.uuid().parse(key));
        if (canary.state !== "pending" && canary.state !== "healthy")
          throw new ApiError(409, "canary_terminal");
        await tx.query(
          "UPDATE desktop_policy_canaries SET state='aborted',finished_at=clock_timestamp() WHERE scope_id=$1 AND id=$2",
          [scope, canary.id],
        );
        result = { id: canary.id, state: "aborted" };
        break;
      }
      case "promote": {
        const input = desktopOperations.promote.parse(raw);
        const canary = await currentCanary(tx, scope, z.uuid().parse(key));
        if (canary.state !== "pending" && canary.state !== "healthy")
          throw new ApiError(409, "canary_terminal");
        const policy = await livePolicy(tx, scope, canary.policy_id);
        if (policy.version !== canary.base_version) throw new ApiError(409, "canary_base_changed");
        const [health] = await tx.query<{ healthy: boolean }>(
          `SELECT count(*)>0 AND bool_and(COALESCE(t.observed_digest=$3 AND t.observation_reference IS NOT NULL AND t.observed_at>=c.created_at AND e.revoked_at IS NULL AND d.revoked_at IS NULL,false)) AS healthy
          FROM desktop_canary_targets t JOIN desktop_policy_canaries c ON c.scope_id=t.scope_id AND c.id=t.canary_id
          JOIN native_enrollments e ON e.id=t.enrollment_id JOIN devices d ON d.id=t.device_id
          WHERE t.scope_id=$1 AND t.canary_id=$2`,
          [scope, canary.id, canary.digest],
        );
        if (health?.healthy !== true) throw new ApiError(409, "canary_verified_health_required");
        const document = buildDesktopPolicy({
          ...canary.candidate,
          confirmBitlockerDecryption: input.confirmBitlockerDecryption,
          confirmBitlockerSuspension: input.confirmBitlockerSuspension,
        });
        result = await writePolicy(tx, scope, policy.id, document, actor, `canary:${canary.id}`);
        await tx.query(
          "UPDATE desktop_policy_canaries SET state='promoted',finished_at=clock_timestamp() WHERE scope_id=$1 AND id=$2",
          [scope, canary.id],
        );
        break;
      }
    }
    await audit(tx, actorKey(actor), `desktop.${operation}`, scope, {
      scope,
      key,
      version,
      result: operation === "assign" ? result : undefined,
    });
    return { version, result };
  },
};
