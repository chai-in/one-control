import { randomUUID } from "node:crypto";
import { isMutation } from "@one-control/protocol";
import { z } from "zod";
import { nativeCommandSelected } from "../../../modules/native-dispatch/server/jobs.js";
import { nativePublicationControl } from "../../../modules/native-distribution/server/publication.js";
import {
  requireRecoveryStepUp,
  revealInput,
  revealRecoveryKey,
} from "../../../modules/recovery-escrow/server/escrow.js";
import type { Config } from "./config.js";
import type { Database, TransactionQuery } from "./database.js";
import { audit } from "./routes/context.js";
import { type Actor, ApiError, hash } from "./security.js";
import { serverModules } from "./server-modules.js";

const uuid = z.uuid();
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const token = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
const version = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const permission = z.enum(["owner", "view", "enroll", "configure", "approve", "command", "reveal"]);
const platform = z.enum(["win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"]);
const identity = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
type Permission = z.infer<typeof permission>;
type Scope = { id: string; name: string; kind: string; state: string; version: string };
type Enrollment = {
  id: string;
  scope_id: string;
  device_id: string;
  platform: string;
  machine_id: string;
  revoked_at: Date | null;
};
type Invitation = {
  hash: string;
  scope_id: string;
  device_id: string;
  existing_device: boolean;
  hostname: string;
  platform: string;
  machine_id: string;
  issuer: string;
  subject: string;
  used_at: Date | null;
};

function role(actor: Actor, required: "operator" | "viewer") {
  if (!actor.roles.has(required) || !actor.issuer || !actor.id) throw new ApiError(403, "forbidden");
}
async function runtime(tx: TransactionQuery) {
  const [row] = await tx.query<{ state: string }>(
    "SELECT state FROM authority_runtime WHERE singleton=true FOR SHARE",
  );
  if (!row || row.state === "quarantined") throw new ApiError(503, "authority_quarantined");
  // Unconfigured custody permits explicit administration, never signing or feature execution.
}
async function scopeLock(tx: TransactionQuery, id: string): Promise<Scope> {
  const [scope] = await tx.query<Scope>(
    "SELECT id,name,kind,state,version::text FROM management_scopes WHERE id=$1 FOR UPDATE",
    [id],
  );
  if (scope?.state !== "active") throw new ApiError(403, "scope_unavailable");
  return scope;
}
async function grant(
  tx: TransactionQuery,
  scope: string,
  actor: Pick<Actor, "issuer" | "id">,
  required: Permission,
) {
  const rows = await tx.query(
    "SELECT permission FROM scope_grants WHERE scope_id=$1 AND issuer=$2 AND subject=$3 AND permission IN ('owner',$4) AND revoked_at IS NULL",
    [scope, actor.issuer, actor.id, required],
  );
  if (!rows.length) throw new ApiError(403, "scope_forbidden");
}
async function advance(tx: TransactionQuery, scope: string, expected: string) {
  const [row] = await tx.query<{ version: string }>(
    "UPDATE management_scopes SET version=version+1 WHERE id=$1 AND version=$2::numeric AND version<18446744073709551615 RETURNING version::text",
    [scope, expected],
  );
  if (!row) throw new ApiError(409, "scope_version_conflict");
  return row.version;
}
async function stopJobs(tx: TransactionQuery, device: string) {
  await tx.query(
    "UPDATE jobs SET state=CASE WHEN state='leased' THEN 'indeterminate' ELSE 'cancelled' END,lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp() WHERE device_id=$1 AND state IN ('awaiting_approval','queued','leased')",
    [device],
  );
}
function actorKey(actor: Pick<Actor, "issuer" | "id">) {
  return JSON.stringify([actor.issuer, actor.id]);
}

/** Owns scoped administration, enrollment and signed native publication. */
export function createModuleControl(db: Database, config: Config) {
  async function selection(tx: TransactionQuery, id: string) {
    const [scope] = await tx.query<{ permission_ceiling: string[] }>(
      "SELECT permission_ceiling FROM management_scopes WHERE id=$1",
      [id],
    );
    const states = await tx.query<{ module_id: string }>(
      "SELECT module_id FROM module_states WHERE scope_id=$1 AND state='enabled' ORDER BY module_id",
      [id],
    );
    return { enabled: states.map((row) => row.module_id), permissions: scope?.permission_ceiling ?? [] };
  }
  async function nativeCredential(tx: TransactionQuery, credentialHash: string) {
    const [locator] = await tx.query<{
      id: string;
      scope_id: string;
      device_id: string;
      issuer: string;
      subject: string;
    }>(
      "SELECT e.id,e.scope_id,e.device_id,i.issuer,i.subject FROM credentials c JOIN native_enrollments e ON e.id=c.enrollment_id JOIN native_invitations i ON i.hash=e.invitation_hash WHERE c.hash=$1",
      [credentialHash],
    );
    if (!locator) throw new ApiError(401, "unauthorized");
    await runtime(tx);
    await scopeLock(tx, locator.scope_id);
    await grant(tx, locator.scope_id, { issuer: locator.issuer, id: locator.subject }, "enroll");
    if (
      !(
        await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
          locator.device_id,
        ])
      ).length
    )
      throw new ApiError(401, "unauthorized");
    const [enrollment] = await tx.query<Enrollment>(
      "SELECT id,scope_id,device_id,platform,machine_id,revoked_at FROM native_enrollments WHERE id=$1 FOR UPDATE",
      [locator.id],
    );
    if (
      !enrollment ||
      enrollment.revoked_at ||
      enrollment.scope_id !== locator.scope_id ||
      enrollment.device_id !== locator.device_id
    )
      throw new ApiError(401, "unauthorized");
    if (
      !(
        await tx.query(
          "SELECT hash FROM credentials WHERE hash=$1 AND enrollment_id=$2 AND device_id=$3 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
          [credentialHash, enrollment.id, enrollment.device_id],
        )
      ).length
    )
      throw new ApiError(401, "unauthorized");
    return enrollment;
  }
  async function distribution(tx: TransactionQuery, id: string) {
    const current = await selection(tx, id);
    try {
      serverModules.requireEnabled(
        "route",
        "POST /v1/agent/native-configuration",
        current.enabled,
        current.permissions,
      );
    } catch {
      throw new ApiError(403, "module_disabled");
    }
  }
  return Object.freeze({
    ...nativePublicationControl(db, config, {
      async scope(tx, actor, id, permission) {
        role(actor, permission === "view" ? "viewer" : "operator");
        uuid.parse(id);
        await runtime(tx);
        const scope = await scopeLock(tx, id);
        await grant(tx, id, actor, permission);
        await distribution(tx, id);
        return scope;
      },
      credential: nativeCredential,
      selectionGrant: (tx, id, issuer, subject) => grant(tx, id, { issuer, id: subject }, "configure"),
      distribution,
      async reportAdmission(tx, id, kind) {
        const current = await selection(tx, id);
        try {
          serverModules.requireEnabled(
            "route",
            "POST /v1/agent/native-report",
            current.enabled,
            current.permissions,
          );
          if (kind === "inventory")
            serverModules.requireEnabled("command", "inventory.scan", current.enabled, current.permissions);
        } catch {
          throw new ApiError(403, "module_disabled");
        }
      },
      advance,
      async escrowAdmission(tx, id) {
        const current = await selection(tx, id);
        try {
          serverModules.requireEnabled(
            "route",
            "POST /v1/agent/native-recovery-key",
            current.enabled,
            current.permissions,
          );
        } catch {
          throw new ApiError(403, "module_disabled");
        }
      },
      async dispatch(tx, id) {
        const current = await selection(tx, id);
        try {
          serverModules.requireEnabled(
            "route",
            "POST /v1/agent/native-claim",
            current.enabled,
            current.permissions,
          );
        } catch {
          throw new ApiError(403, "module_disabled");
        }
      },
      async command(tx, id, command, admission, policy) {
        const current = await selection(tx, id);
        const owner = serverModules.commandOwner(command.kind);
        if (owner !== admission.module_id) throw new ApiError(403, "native_command_owner_mismatch");
        try {
          serverModules.requireEnabled("command", command.kind, current.enabled, current.permissions);
          serverModules.requireEnabled(
            "route",
            "POST /v1/agent/native-claim",
            current.enabled,
            current.permissions,
          );
        } catch {
          throw new ApiError(403, "module_disabled");
        }
        nativeCommandSelected(command, admission, policy);
        const definition = serverModules.modules.find((module) => module.id === owner)!;
        if (definition.permissions.some((permission) => !policy.allowedPermissions.includes(permission)))
          throw new ApiError(403, "native_command_permission_missing");
        await grant(tx, id, { issuer: admission.creator_issuer, id: admission.creator_subject }, "command");
        if (isMutation(command))
          await grant(
            tx,
            id,
            { issuer: admission.approver_issuer!, id: admission.approver_subject! },
            "approve",
          );
      },
    }),
    async revealRecoveryKey(actor: Actor, id: string, keyId: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(id);
      uuid.parse(keyId);
      const input = revealInput.parse(raw);
      requireRecoveryStepUp(actor, config);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "reveal");
        const current = await selection(tx, id);
        try {
          serverModules.requireEnabled(
            "route",
            "POST /v1/scopes/:id/recovery-keys/:keyId/reveal",
            current.enabled,
            current.permissions,
          );
        } catch {
          throw new ApiError(403, "module_disabled");
        }
        return revealRecoveryKey(tx, config, id, keyId, actor, input.reason);
      });
    },
    async service<T>(
      scopeId: string,
      kind: "route" | "background",
      entry: string,
      work: (tx: TransactionQuery) => Promise<T>,
    ): Promise<T> {
      uuid.parse(scopeId);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, scopeId);
        const current = await selection(tx, scopeId);
        try {
          serverModules.requireEnabled(kind, entry, current.enabled, current.permissions);
        } catch {
          throw new ApiError(403, "module_disabled");
        }
        return work(tx);
      });
    },
    async listScopes(actor: Actor) {
      role(actor, "viewer");
      return db.transaction(async (tx) => {
        await runtime(tx);
        return {
          scopes: await tx.query(
            "SELECT s.id,s.name,s.kind,s.version::text FROM management_scopes s WHERE s.state='active' AND EXISTS(SELECT 1 FROM scope_grants g WHERE g.scope_id=s.id AND g.issuer=$1 AND g.subject=$2 AND g.permission IN ('owner','view') AND g.revoked_at IS NULL) ORDER BY s.name,s.id",
            [actor.issuer, actor.id],
          ),
        };
      });
    },
    async scopedRoute<T>(
      actor: Actor,
      id: string,
      route: string,
      expectedVersion: string | undefined,
      work: (tx: TransactionQuery, version: string) => Promise<T>,
    ): Promise<T> {
      const write = !route.startsWith("GET ");
      role(actor, write ? "operator" : "viewer");
      uuid.parse(id);
      if (write) version.parse(expectedVersion);
      return db.transaction(async (tx) => {
        await runtime(tx);
        const scope = await scopeLock(tx, id);
        await grant(tx, id, actor, write ? "configure" : "view");
        const current = await selection(tx, id);
        try {
          serverModules.requireEnabled("route", route, current.enabled, current.permissions);
        } catch {
          throw new ApiError(403, "module_disabled");
        }
        const next = write ? await advance(tx, id, expectedVersion as string) : scope.version;
        return work(tx, next);
      });
    },
    async scopeAudit(actor: Actor, id: string) {
      role(actor, "viewer");
      uuid.parse(id);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "view");
        return {
          events: await tx.query(
            "SELECT sequence,actor,action,subject,detail,created_at FROM audit_events WHERE subject=$1 OR detail->>'scope'=$1 OR subject IN (SELECT id::text FROM native_enrollments WHERE scope_id=$1::uuid) ORDER BY sequence DESC LIMIT 500",
            [id],
          ),
        };
      });
    },
    async history<T>(
      actor: Actor,
      targets: readonly string[],
      permission: "view" | "command",
      work: (tx: TransactionQuery) => Promise<T>,
    ): Promise<T> {
      role(actor, permission === "view" ? "viewer" : "operator");
      return db.transaction(async (tx) => {
        await runtime(tx);
        const scopes = await tx.query<{ scope_id: string }>(
          "SELECT DISTINCT scope_id FROM native_enrollments WHERE device_id=ANY($1::uuid[]) ORDER BY scope_id",
          [[...targets]],
        );
        for (const scope of scopes) {
          await scopeLock(tx, scope.scope_id);
          await grant(tx, scope.scope_id, actor, permission);
        }
        return work(tx);
      });
    },
    async enrollment(credential: string) {
      return db.transaction(async (tx) => {
        const enrollment = await nativeCredential(tx, hash(credential));
        return {
          deviceId: enrollment.device_id,
          enrollmentId: enrollment.id,
          platform: enrollment.platform,
          scope: { kind: "machine", machineId: enrollment.machine_id },
        };
      });
    },
    async command<T>(
      actor: Actor,
      targets: readonly string[],
      kind: string,
      stage: "create" | "approve",
      work: (tx: TransactionQuery) => Promise<T>,
    ): Promise<T> {
      if (!actor.roles.has(stage === "create" ? "operator" : "approver"))
        throw new ApiError(403, "forbidden");
      const owner = serverModules.commandOwner(kind);
      if (!owner) throw new ApiError(403, "unregistered_module_command");
      return db.transaction(async (tx) => {
        await runtime(tx);
        const enrollments = await tx.query<{ id: string; device_id: string; scope_id: string }>(
          "SELECT id,device_id,scope_id FROM native_enrollments WHERE device_id=ANY($1::uuid[]) AND revoked_at IS NULL ORDER BY device_id",
          [[...targets]],
        );
        if (enrollments.length !== targets.length)
          throw new ApiError(409, "native_scope_assignment_required");
        for (const scope of [...new Set(enrollments.map((row) => row.scope_id))].sort()) {
          await scopeLock(tx, scope);
          await grant(tx, scope, actor, stage === "create" ? "command" : "approve");
          const current = await selection(tx, scope);
          try {
            serverModules.requireEnabled("command", kind, current.enabled, current.permissions);
          } catch {
            throw new ApiError(403, "module_disabled");
          }
        }
        for (const enrollment of enrollments) {
          if (
            !(
              await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
                enrollment.device_id,
              ])
            ).length
          )
            throw new ApiError(409, "device_unavailable");
        }
        for (const enrollment of enrollments) {
          if (
            !(
              await tx.query(
                "SELECT id FROM native_enrollments WHERE id=$1 AND scope_id=$2 AND device_id=$3 AND revoked_at IS NULL FOR UPDATE",
                [enrollment.id, enrollment.scope_id, enrollment.device_id],
              )
            ).length
          )
            throw new ApiError(409, "enrollment_changed");
        }
        return work(tx);
      });
    },
    async setPermissionCeiling(actor: Actor, id: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(id);
      const input = z
        .strictObject({
          expectedVersion: version,
          permissions: z.array(z.string().regex(/^[a-z][a-z0-9.-]{0,199}$/)).max(128),
        })
        .parse(raw);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "owner");
        const current = await selection(tx, id);
        try {
          serverModules.resolve(current.enabled, input.permissions);
        } catch {
          throw new ApiError(409, "disable_modules_before_reducing_permissions");
        }
        const next = await advance(tx, id, input.expectedVersion);
        await tx.query("UPDATE management_scopes SET permission_ceiling=$2 WHERE id=$1", [
          id,
          JSON.stringify(input.permissions),
        ]);
        await audit(tx, actorKey(actor), "scope.permissions_configured", id, {
          permissions: input.permissions,
          version: next,
        });
        return { version: next };
      });
    },
    async configureServerModules(actor: Actor, id: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(id);
      const input = z
        .strictObject({ expectedVersion: version, enabled: z.array(z.string()).max(128) })
        .parse(raw);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "configure");
        const current = await selection(tx, id);
        let enabled: readonly string[];
        try {
          enabled = serverModules.resolve(input.enabled, current.permissions);
        } catch {
          throw new ApiError(400, "invalid_module_selection_or_permissions");
        }
        if (
          (enabled.includes("falcon") && config.FALCON_MANAGEMENT_SCOPE !== id) ||
          (enabled.includes("ema") && config.EMA_MANAGEMENT_SCOPE !== id)
        )
          throw new ApiError(503, "integration_scope_unconfigured");
        const next = await advance(tx, id, input.expectedVersion);
        for (const module of serverModules.modules) {
          await tx.query(
            "INSERT INTO module_states(scope_id,module_id,state,version,settings) VALUES($1,$2,$3,$4,jsonb_build_object('selectedRoot',$5::boolean)) ON CONFLICT(scope_id,module_id) DO UPDATE SET state=EXCLUDED.state,version=EXCLUDED.version,settings=jsonb_set(module_states.settings,'{selectedRoot}',to_jsonb($5::boolean))",
            [
              id,
              module.id,
              enabled.includes(module.id) ? "enabled" : "disabled",
              next,
              input.enabled.includes(module.id),
            ],
          );
        }
        const disabled = current.enabled.filter((module) => !enabled.includes(module));
        if (disabled.includes("desktop-policies"))
          await tx.query(
            "UPDATE desktop_policy_canaries SET state='aborted',finished_at=clock_timestamp() WHERE scope_id=$1 AND state IN ('pending','healthy')",
            [id],
          );
        const dispatchDisabled =
          disabled.includes("native-distribution") || disabled.includes("native-dispatch");
        const kinds = serverModules.modules
          .filter((module) => dispatchDisabled || disabled.includes(module.id))
          .flatMap((module) => [...module.commands]);
        const devices = await tx.query<{ device_id: string }>(
          "SELECT DISTINCT device_id FROM native_enrollments WHERE scope_id=$1 ORDER BY device_id",
          [id],
        );
        for (const device of devices) {
          await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [device.device_id]);
          await tx.query(
            "UPDATE jobs SET state=CASE WHEN state='leased' THEN 'indeterminate' ELSE 'cancelled' END,lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp() WHERE device_id=$1 AND kind=ANY($2::text[]) AND state IN ('queued','awaiting_approval','leased')",
            [device.device_id, kinds],
          );
        }
        await audit(tx, actorKey(actor), "scope.modules_configured", id, { enabled, version: next });
        return { version: next, enabled };
      });
    },
    async integration<T>(
      actor: Actor,
      scopeId: string,
      route: string,
      operation: (signal: AbortSignal) => Promise<T>,
    ): Promise<T> {
      role(actor, "viewer");
      uuid.parse(scopeId);
      const owner = serverModules.routeOwner(route);
      if (!owner) throw new ApiError(403, "unregistered_module_route");
      if (
        (owner === "falcon" && config.FALCON_MANAGEMENT_SCOPE !== scopeId) ||
        (owner === "ema" && config.EMA_MANAGEMENT_SCOPE !== scopeId)
      )
        throw new ApiError(503, "integration_scope_unconfigured");
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, scopeId);
        await grant(tx, scopeId, actor, "view");
        const current = await selection(tx, scopeId);
        try {
          serverModules.requireEnabled("route", route, current.enabled, current.permissions);
        } catch {
          throw new ApiError(403, "module_disabled");
        }
        const abort = new AbortController();
        const timer = setTimeout(() => abort.abort(), 5000);
        try {
          const result = await operation(abort.signal);
          abort.signal.throwIfAborted();
          return result;
        } finally {
          clearTimeout(timer);
          abort.abort();
        }
      });
    },
    async createScope(actor: Actor, raw: unknown) {
      role(actor, "operator");
      const input = z
        .strictObject({
          id: uuid,
          name: z.string().trim().min(1).max(120),
          kind: z.enum(["personal", "company"]),
        })
        .parse(raw);
      return db.transaction(async (tx) => {
        await runtime(tx);
        const created = await tx.query(
          "INSERT INTO management_scopes(id,name,kind) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING RETURNING id",
          [input.id, input.name, input.kind],
        );
        const scope = await scopeLock(tx, input.id);
        if (!created.length) {
          await grant(tx, input.id, actor, "owner");
          if (scope.name !== input.name || scope.kind !== input.kind)
            throw new ApiError(409, "scope_conflict");
          return scope;
        }
        await tx.query(
          "INSERT INTO scope_grants(scope_id,issuer,subject,permission) VALUES($1,$2,$3,'owner')",
          [input.id, actor.issuer, actor.id],
        );
        await audit(tx, actorKey(actor), "scope.created", input.id, { kind: input.kind });
        return scope;
      });
    },
    async readScope(actor: Actor, id: string) {
      role(actor, "viewer");
      uuid.parse(id);
      return db.transaction(async (tx) => {
        await runtime(tx);
        const scope = await scopeLock(tx, id);
        await grant(tx, id, actor, "view");
        const modules = await tx.query<{
          module_id: string;
          state: string;
          version: string;
          settings: { selectedRoot?: boolean };
        }>(
          "SELECT module_id,state,version::text,settings FROM module_states WHERE scope_id=$1 ORDER BY module_id",
          [id],
        );
        return {
          ...scope,
          actorPermissions: (
            await tx.query<{ permission: string }>(
              "SELECT permission FROM scope_grants WHERE scope_id=$1 AND issuer=$2 AND subject=$3 AND revoked_at IS NULL ORDER BY permission",
              [id, actor.issuer, actor.id],
            )
          ).map((row) => row.permission),
          permissionCeiling: (await selection(tx, id)).permissions,
          registeredModules: serverModules.modules,
          selectedRoots: modules
            .filter((module) => module.state === "enabled" && module.settings.selectedRoot !== false)
            .map((module) => module.module_id),
          modules: modules.map(({ settings: _settings, ...module }) => module),
        };
      });
    },
    async changeGrant(actor: Actor, id: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(id);
      const input = z
        .strictObject({
          issuer: z.string().min(1).max(2048),
          subject: z.string().min(1).max(255),
          permission,
          enabled: z.boolean(),
          expectedVersion: version,
        })
        .parse(raw);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "owner");
        const next = await advance(tx, id, input.expectedVersion);
        if (!input.enabled && input.permission === "owner") {
          const others = await tx.query(
            "SELECT subject FROM scope_grants WHERE scope_id=$1 AND permission='owner' AND revoked_at IS NULL AND (issuer<>$2 OR subject<>$3)",
            [id, input.issuer, input.subject],
          );
          if (!others.length) throw new ApiError(409, "last_scope_owner");
        }
        await tx.query(
          "INSERT INTO scope_grants(scope_id,issuer,subject,permission,revoked_at) VALUES($1,$2,$3,$4,CASE WHEN $5 THEN NULL ELSE clock_timestamp() END) ON CONFLICT(scope_id,issuer,subject,permission) DO UPDATE SET revoked_at=EXCLUDED.revoked_at",
          [id, input.issuer, input.subject, input.permission, input.enabled],
        );
        await audit(tx, actorKey(actor), input.enabled ? "scope.grant_enabled" : "scope.grant_revoked", id, {
          issuer: input.issuer,
          subject: input.subject,
          permission: input.permission,
          version: next,
        });
        return { version: next };
      });
    },
    async readGrants(actor: Actor, id: string) {
      role(actor, "operator");
      uuid.parse(id);
      return db.transaction(async (tx) => {
        await runtime(tx);
        const scope = await scopeLock(tx, id);
        await grant(tx, id, actor, "owner");
        const grants = await tx.query<{
          issuer: string;
          subject: string;
          permission: string;
          revoked_at: Date | null;
        }>(
          "SELECT issuer,subject,permission,revoked_at FROM scope_grants WHERE scope_id=$1 ORDER BY issuer,subject,permission",
          [id],
        );
        return { version: scope.version, grants };
      });
    },
    async invite(actor: Actor, id: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(id);
      const input = z
        .strictObject({
          tokenHash: digest,
          deviceId: uuid.optional(),
          hostname: z.string().min(1).max(255),
          platform,
          machineId: identity,
        })
        .parse(raw);
      const deviceId = input.deviceId ?? randomUUID();
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, id);
        await grant(tx, id, actor, "enroll");
        if (input.deviceId) {
          if (
            !(
              await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
                deviceId,
              ])
            ).length
          )
            throw new ApiError(404, "device_not_found");
          if (
            (
              await tx.query("SELECT id FROM native_enrollments WHERE device_id=$1 AND scope_id<>$2", [
                deviceId,
                id,
              ])
            ).length
          )
            throw new ApiError(409, "explicit_reenrollment_required");
        }
        const [created] = await tx.query<{ expires_at: Date }>(
          "INSERT INTO native_invitations(hash,scope_id,device_id,existing_device,hostname,platform,machine_id,issuer,subject,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '15 minutes') ON CONFLICT(hash) DO NOTHING RETURNING expires_at",
          [
            input.tokenHash,
            id,
            deviceId,
            !!input.deviceId,
            input.hostname,
            input.platform,
            input.machineId,
            actor.issuer,
            actor.id,
          ],
        );
        if (!created) throw new ApiError(409, "invitation_conflict");
        await audit(tx, actorKey(actor), "native.invitation_created", deviceId, { scope: id });
        return {
          deviceId,
          scopeId: id,
          platform: input.platform,
          machineId: input.machineId,
          expiresAt: new Date(created.expires_at).toISOString(),
        };
      });
    },
    async redeem(raw: unknown, deviceProof?: string) {
      const input = z.strictObject({ token, credentialHash: digest }).parse(raw);
      return db.transaction(async (tx) => {
        const [locator] = await tx.query<Invitation>("SELECT * FROM native_invitations WHERE hash=$1", [
          hash(input.token),
        ]);
        if (!locator) throw new ApiError(401, "invalid_native_invitation");
        await runtime(tx);
        await scopeLock(tx, locator.scope_id);
        await grant(tx, locator.scope_id, { issuer: locator.issuer, id: locator.subject }, "enroll");
        // The POC capacity fence precedes device locks, as in legacy enrollment.
        if (!locator.existing_device && config.DEPLOYMENT_STAGE === "poc") {
          await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
            "one-control:poc-enrollment-limit",
          ]);
          const [count] = await tx.query<{ count: number }>(
            "SELECT count(*)::int AS count FROM devices WHERE revoked_at IS NULL",
          );
          if ((count?.count ?? 0) >= config.POC_DEVICE_LIMIT)
            throw new ApiError(409, "poc_device_limit_reached");
        }
        const [invitation] = await tx.query<Invitation>(
          "SELECT * FROM native_invitations WHERE hash=$1 AND used_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
          [locator.hash],
        );
        if (
          !invitation ||
          invitation.scope_id !== locator.scope_id ||
          invitation.device_id !== locator.device_id
        )
          throw new ApiError(401, "invalid_native_invitation");
        if (invitation.existing_device) {
          if (
            !(
              await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
                invitation.device_id,
              ])
            ).length
          )
            throw new ApiError(401, "unauthorized");
          await tx.query("SELECT id FROM native_enrollments WHERE device_id=$1 ORDER BY id FOR UPDATE", [
            invitation.device_id,
          ]);
          if (
            !deviceProof ||
            !(
              await tx.query(
                "SELECT hash FROM credentials c WHERE hash=$1 AND device_id=$2 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND (enrollment_id IS NULL OR EXISTS(SELECT 1 FROM native_enrollments e WHERE e.id=c.enrollment_id AND e.revoked_at IS NULL AND e.scope_id=$3)) FOR UPDATE",
                [hash(deviceProof), invitation.device_id, invitation.scope_id],
              )
            ).length
          )
            throw new ApiError(401, "device_proof_required");
          if (
            (
              await tx.query("SELECT id FROM native_enrollments WHERE device_id=$1 AND scope_id<>$2", [
                invitation.device_id,
                invitation.scope_id,
              ])
            ).length
          )
            throw new ApiError(409, "explicit_reenrollment_required");
          await tx.query(
            "UPDATE native_enrollments SET revoked_at=clock_timestamp() WHERE device_id=$1 AND revoked_at IS NULL",
            [invitation.device_id],
          );
          await tx.query(
            "UPDATE credentials SET revoked_at=clock_timestamp() WHERE device_id=$1 AND revoked_at IS NULL",
            [invitation.device_id],
          );
          await stopJobs(tx, invitation.device_id);
        } else {
          await tx.query("INSERT INTO devices(id,hostname) VALUES($1,$2)", [
            invitation.device_id,
            invitation.hostname,
          ]);
        }
        const enrollmentId = randomUUID();
        await tx.query(
          "INSERT INTO native_enrollments(id,scope_id,device_id,invitation_hash,platform,machine_id) VALUES($1,$2,$3,$4,$5,$6)",
          [
            enrollmentId,
            invitation.scope_id,
            invitation.device_id,
            invitation.hash,
            invitation.platform,
            invitation.machine_id,
          ],
        );
        const credentials = await tx.query(
          "INSERT INTO credentials(hash,device_id,context,enrollment_id,expires_at) VALUES($1,$2,'system',$3,clock_timestamp()+interval '90 days') ON CONFLICT(hash) DO NOTHING RETURNING hash",
          [input.credentialHash, invitation.device_id, enrollmentId],
        );
        if (!credentials.length) throw new ApiError(409, "credential_conflict");
        const consumed = await tx.query(
          "UPDATE native_invitations SET used_at=clock_timestamp() WHERE hash=$1 AND used_at IS NULL AND expires_at>clock_timestamp() RETURNING hash",
          [invitation.hash],
        );
        if (!consumed.length) throw new ApiError(401, "invalid_native_invitation");
        await audit(tx, `device:${invitation.device_id}`, "native.enrolled", enrollmentId, {
          scope: invitation.scope_id,
        });
        return {
          deviceId: invitation.device_id,
          enrollmentId,
          platform: invitation.platform,
          scope: { kind: "machine", machineId: invitation.machine_id },
        };
      });
    },
    async rotate(credential: string, raw: unknown) {
      const input = z.strictObject({ credentialHash: digest }).parse(raw);
      const previous = hash(credential);
      if (input.credentialHash === previous) throw new ApiError(400, "new_credential_required");
      return db.transaction(async (tx) => {
        const enrollment = await nativeCredential(tx, previous);
        const [prior] = await tx.query<{
          enrollment_id: string;
          device_id: string;
          revoked_at: Date | null;
          live: boolean;
        }>(
          "SELECT enrollment_id,device_id,revoked_at,expires_at>clock_timestamp() AS live FROM credentials WHERE hash=$1",
          [input.credentialHash],
        );
        if (prior) {
          if (
            prior.enrollment_id !== enrollment.id ||
            prior.device_id !== enrollment.device_id ||
            prior.revoked_at ||
            !prior.live
          )
            throw new ApiError(409, "credential_conflict");
          return { enrollmentId: enrollment.id };
        }
        const inserted = await tx.query(
          "INSERT INTO credentials(hash,device_id,context,enrollment_id,expires_at) VALUES($1,$2,'system',$3,clock_timestamp()+interval '90 days') ON CONFLICT(hash) DO NOTHING RETURNING hash",
          [input.credentialHash, enrollment.device_id, enrollment.id],
        );
        if (!inserted.length) throw new ApiError(409, "credential_conflict");
        await tx.query(
          "UPDATE credentials SET expires_at=LEAST(expires_at,clock_timestamp()+interval '5 minutes') WHERE hash=$1",
          [previous],
        );
        await audit(tx, `device:${enrollment.device_id}`, "native.credential_rotated", enrollment.id);
        return { enrollmentId: enrollment.id };
      });
    },
    async revokeEnrollment(actor: Actor, scopeId: string, enrollmentId: string) {
      role(actor, "operator");
      uuid.parse(scopeId);
      uuid.parse(enrollmentId);
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, scopeId);
        await grant(tx, scopeId, actor, "enroll");
        const [locator] = await tx.query<Enrollment>(
          "SELECT id,scope_id,device_id,platform,machine_id,revoked_at FROM native_enrollments WHERE id=$1 AND scope_id=$2",
          [enrollmentId, scopeId],
        );
        if (!locator) throw new ApiError(404, "enrollment_not_found");
        await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [locator.device_id]);
        await tx.query(
          "UPDATE native_enrollments SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 AND scope_id=$2",
          [enrollmentId, scopeId],
        );
        await tx.query(
          "UPDATE credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE enrollment_id=$1",
          [enrollmentId],
        );
        if (!locator.revoked_at) await stopJobs(tx, locator.device_id);
        await audit(tx, actorKey(actor), "native.enrollment_revoked", enrollmentId, { scope: scopeId });
        return { ok: true };
      });
    },
    async nativeRing(actor: Actor, scopeId: string, enrollmentId: string, raw: unknown) {
      role(actor, "operator");
      uuid.parse(scopeId);
      uuid.parse(enrollmentId);
      const input = z
        .strictObject({ expectedVersion: version, ring: z.enum(["canary", "pilot", "broad"]) })
        .parse(raw);
      if (config.DEPLOYMENT_STAGE === "poc" && input.ring !== "canary")
        throw new ApiError(403, "poc_canary_only");
      return db.transaction(async (tx) => {
        await runtime(tx);
        await scopeLock(tx, scopeId);
        await grant(tx, scopeId, actor, "configure");
        const [enrollment] = await tx.query<{ device_id: string }>(
          "SELECT device_id FROM native_enrollments WHERE id=$1 AND scope_id=$2 AND revoked_at IS NULL",
          [enrollmentId, scopeId],
        );
        if (!enrollment) throw new ApiError(404, "enrollment_not_found");
        await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [enrollment.device_id]);
        if (
          (
            await tx.query(
              "SELECT id FROM jobs WHERE device_id=$1 AND state IN ('awaiting_approval','queued','leased','indeterminate') LIMIT 1",
              [enrollment.device_id],
            )
          ).length
        )
          throw new ApiError(409, "device_has_unfinished_jobs");
        const next = await advance(tx, scopeId, input.expectedVersion);
        const changed = await tx.query(
          "UPDATE devices SET ring=$2 WHERE id=$1 AND revoked_at IS NULL RETURNING id",
          [enrollment.device_id, input.ring],
        );
        if (!changed.length) throw new ApiError(404, "device_not_found");
        await audit(tx, actorKey(actor), "native.ring_changed", enrollmentId, {
          scope: scopeId,
          ring: input.ring,
          version: next,
        });
        return { version: next };
      });
    },
  });
}
